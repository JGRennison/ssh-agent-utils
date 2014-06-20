//  ssh-agent-utils
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version. See: COPYING-GPL.txt
//
//  This program  is distributed in the  hope that it will  be useful, but
//  WITHOUT   ANY  WARRANTY;   without  even   the  implied   warranty  of
//  MERCHANTABILITY  or FITNESS  FOR A  PARTICULAR PURPOSE.   See  the GNU
//  General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <http://www.gnu.org/licenses/>.
//
//  2014 - Jonathan G Rennison <j.g.rennison@gmail.com>
//==========================================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/file.h>

#include <b64/encode.h>
#include <b64/decode.h>

#include <cstring>
#include <sstream>
#include <algorithm>

#include "ssh-agent-utils.h"

namespace SSHAgentUtils {

	const size_t read_size = 8192;

	bool force_exit = false;

	void sighandler(int sig) {
		force_exit = true;
	}

	struct sigchld_pending_op {
		sau_state *ss;
		pid_t pid;
		std::function<void(sau_state &, pid_t pid, int /* wait status */)> handler;

		sigchld_pending_op(sau_state &ss_, pid_t pid_, std::function<void(sau_state &, pid_t, int /* wait status */)> handler_)
				: ss(&ss_), pid(pid_), handler(std::move(handler_)) { }
	};

	namespace {
		std::vector<sigchld_pending_op> sigchld_ops;
		std::string single_lock_path;
		std::string lockfile;
	};

	// This handler must only get called when signals are unblocked during ppoll
	void sigchld_handler(int sig) {
		while(true) {
			int status;
			pid_t pid = waitpid(-1, &status, WNOHANG);
			if(pid == -1) return;

#ifdef DEBUG
			fprintf(stderr, "sigchld_handler called for pid: %d, result: 0x%X\n", pid, status);
#endif

			auto it = std::find_if(sigchld_ops.begin(), sigchld_ops.end(), [&](const sigchld_pending_op &op) {
				return op.pid == pid;
			});
			if(it != sigchld_ops.end()) {
				// Found a handler for this pid

#ifdef DEBUG
				fprintf(stderr, "sigchld_handler found handler\n");
#endif

				// Remove handler before calling it in case calling it adds another handler
				sau_state *ss = it->ss;
				auto handler = std::move(it->handler);
				sigchld_ops.erase(it);

				if(handler) handler(*ss, pid, status);
			}
		}
	}

	// Remove all SIGCHLD pending ops which use a given sau_state, this is to stop the sau_state being used after it is finished/destructed
	void remove_sigchld_pending_ops(sau_state &ss) {
		sigchld_ops.erase(std::remove_if(sigchld_ops.begin(), sigchld_ops.end(), [&](const sigchld_pending_op &op) {
			return op.ss == &ss;
		}), sigchld_ops.end());
	}

	// optionally also set O_CLOEXEC here
	void setnonblock(int fd, bool setcloexec) {
		int flags = fcntl(fd, F_GETFL, 0);
		flags |= O_NONBLOCK;
		if(setcloexec) flags |= O_CLOEXEC;
		int res = fcntl(fd, F_SETFL, flags);
		if(flags < 0 || res < 0) {
#ifdef DEBUG
			fprintf(stderr, "fcntl set O_NONBLOCK failed for %d, %m\n", fd);
#endif
			exit(EXIT_FAILURE);
		}
	}

	uint32_t get_rfc4251_u32(const unsigned char *data) {
		return htonl(*reinterpret_cast<const uint32_t*>(data));
	}

	uint32_t consume_rfc4251_u32(const unsigned char *&data, size_t &length, bool &ok) {
		if(length >= 4) {
			length -= 4;
			data += 4;
			return get_rfc4251_u32(data - 4);
		}
		else {
			ok = false;
			return 0;
		}
	}

	// rvalue refs in case we don't want the lengths back
	uint32_t consume_rfc4251_u32(const unsigned char *&&data, size_t &&length, bool &ok) {
		return consume_rfc4251_u32(data, length, ok);
	}

	std::pair<const unsigned char *, const unsigned char *> consume_rfc4251_string_generic(const unsigned char *&data, size_t &length, bool &ok) {
		uint32_t string_length = consume_rfc4251_u32(data, length, ok);
		if(ok) {
			if(length >= string_length) {
				length -= string_length;
				data += string_length;
				return std::make_pair(data - string_length, data);
			}
		}
		ok = false;
		return std::make_pair(data, data);
	}

	std::string consume_rfc4251_string(const unsigned char *&data, size_t &length, bool &ok) {
		auto pair = consume_rfc4251_string_generic(data, length, ok);
		return std::string(pair.first, pair.second);
	}

	std::string consume_rfc4251_string(const unsigned char *&&data, size_t &&length, bool &ok) {
		return consume_rfc4251_string(data, length, ok);
	}

	std::vector<unsigned char> consume_rfc4251_string_v(const unsigned char *&data, size_t &length, bool &ok) {
		auto pair = consume_rfc4251_string_generic(data, length, ok);
		return std::vector<unsigned char>(pair.first, pair.second);
	}

	std::vector<unsigned char> consume_rfc4251_string_v(const unsigned char *&&data, size_t &&length, bool &ok) {
		return consume_rfc4251_string_v(data, length, ok);
	}

	// returns true if valid, or if 0 length
	bool validate_rfc4251_string_sequence(const unsigned char *data, size_t length) {
		if(!length) return true;
		if(!data) return false;

		while(length) {
			if(length < 4) return false;
			size_t stringlength = get_rfc4251_u32(data);
			data += 4;
			length -= 4;
			if(length < stringlength) return false;
			data += stringlength;
			length -= stringlength;
		}
		return true;
	}

	void serialise_rfc4251_u32(std::vector<unsigned char> &out, uint32_t value) {
		out.push_back((value >> 24) & 0xFF);
		out.push_back((value >> 16) & 0xFF);
		out.push_back((value >> 8) & 0xFF);
		out.push_back((value >> 0) & 0xFF);
	}

	void serialise_rfc4251_string(std::vector<unsigned char> &out, const unsigned char *start, size_t length) {
		serialise_rfc4251_u32(out, length);
		out.insert(out.end(), start, start + length);
	}

	std::string get_env_agent_sock_name() {
		const char *agent_sock_str = getenv("SSH_AUTH_SOCK");
		if(!agent_sock_str || *agent_sock_str == 0) {
			return "";
		}
		else return std::string(agent_sock_str);
	}

	std::string get_env_agent_sock_name_or_die() {
		std::string result = get_env_agent_sock_name();
		if(result.empty()) {
			fprintf(stderr, "No SSH_AUTH_SOCK environment variable\n");
			exit(EXIT_FAILURE);
		}
		return result;
	}

	// Return if lockfile not present
	// Otherwise call cleanup then exit()
	static void single_instance_check_lockfile(std::function<void()> cleanup) {
		auto cleanup_exit = [&](int status) {
			cleanup();
			exit(status);
		};

		int fd = open(lockfile.c_str(), O_RDONLY);
		if(fd == -1) {
			return;
		}

		int result = flock(fd, LOCK_EX | LOCK_NB);
		if(result == 0) {
			// We are the exclusive owner of the existing lockfile
			// This is bad news, as it means that the lockfile is stale
			// Unlink it and make our own
			unlink(lockfile.c_str());
			close(fd);
			return;
		}
		else if(result == -1 && errno == EWOULDBLOCK) {
			// Someone else owns the lockfile
			// This means that another instance is up and alive
			// Use that, print contents of lockfile to STDOUT

			std::vector<unsigned char> buffer;
			if(!slurp_file(fd, buffer)) cleanup_exit(EXIT_FAILURE);
			if(!unslurp_file(STDOUT_FILENO, buffer)) cleanup_exit(EXIT_FAILURE);
			cleanup_exit(EXIT_SUCCESS);
		}
		else {
			// Something unexpected, give up
			cleanup_exit(EXIT_FAILURE);
		}
	}

	// Return if lockfile not present
	// Otherwise call cleanup then exit()
	void single_instance_check(const std::string &agent_env, std::string base_template, std::function<void()> cleanup) {
		base64::encoder b64e;
		std::istringstream ins(agent_env);
		std::ostringstream ss;
		b64e.encode(ins, ss);

		lockfile = base_template + "-";
		std::string b64 = ss.str();
		std::remove_copy(b64.begin(), b64.end(), std::back_inserter(lockfile), '\n'); // Append the base64 representation of the real agent sock, minus any annoying newlines

		single_instance_check_lockfile(cleanup);
	}

	// Return if lockfile not present, and is now created
	// Otherwise call cleanup then exit()
	void single_instance_check_and_create_lockfile(const std::string &our_sock, std::function<void()> cleanup) {
		auto cleanup_exit = [&](int status) {
			cleanup();
			exit(status);
		};

		std::string lockfile_tmp = lockfile + "-XXXXXX";
		int temp_fd = mkstemp((char *) lockfile_tmp.c_str());
		if(temp_fd == -1) exit(EXIT_FAILURE);

		// If we can't write to the new temp file, give up
		if(!unslurp_file(temp_fd, our_sock)) cleanup_exit(EXIT_FAILURE);

		// No-one else should have the temp file, if locking fails give up
		if(flock(temp_fd, LOCK_EX | LOCK_NB) != 0) cleanup_exit(EXIT_FAILURE);

		// Not that critical if this somehow fails
		int flags = fcntl(temp_fd, F_GETFL, 0);
		flags |= O_CLOEXEC;
		fcntl(temp_fd, F_SETFL, flags);

		fchmod(temp_fd, 0400);

		int link_result = link(lockfile_tmp.c_str(), lockfile.c_str());
		int link_errno = errno;
		unlink(lockfile_tmp.c_str());
		if(link_result == 0) {
			// All OK
			single_lock_path = lockfile;
		}
		else if(link_result == -1 && link_errno == EEXIST) {
			// Someone sniped us, retry
			close(temp_fd);
			single_instance_check_lockfile(cleanup);
			single_instance_check_and_create_lockfile(our_sock, cleanup);
			return;
		}
		else cleanup_exit(EXIT_FAILURE);

		// Do not close temp_fd
	}

	sau_state::sau_state() { }

	sau_state::~sau_state() {
		remove_sigchld_pending_ops(*this);
		cleanup();
	}

	// This function must be idempotent
	void sau_state::cleanup() {
		if(should_unlink_listen_sock) {
			unlink(our_sock_name.c_str());
			should_unlink_listen_sock = false;
		}
		if(!tempdir.empty()) {
			rmdir(tempdir.c_str());
			tempdir = "";
		}
		if(!single_lock_path.empty()) {
			unlink(single_lock_path.c_str());
			single_lock_path = "";
		}
	}

	void sau_state::addpollfd(int fd, short events, FDTYPE type) {
		if(fdinfos.size() <= (size_t) fd) fdinfos.resize(fd + 1);
		if(fdinfos[fd].type != FDTYPE::NONE) {
#ifdef DEBUG
			fprintf(stderr, "addpollfd: invalid addition attempt: %d\n", fd);
#endif
			exit(EXIT_FAILURE);
		}
		fdinfos[fd].type = type;
		fdinfos[fd].pollfd_offset = pollfds.size();

		pollfds.push_back({ fd, events, 0 });
	}

	void sau_state::delpollfd(int fd) {
		if((size_t) fd >= fdinfos.size() || fdinfos[fd].type == FDTYPE::NONE) {
#ifdef DEBUG
			fprintf(stderr, "delpollfd: invalid removal attempt: %d\n", fd);
#endif
			exit(EXIT_FAILURE);
		}

		size_t offset = fdinfos[fd].pollfd_offset;
		//offset is poll slot of fd currently being removed

		//if slot is not the last one, move the last one in to fill empty slot
		if(offset < pollfds.size() - 1) {
			pollfds[offset] = std::move(pollfds.back());
			int new_fd_in_slot = pollfds[offset].fd;
			fdinfos[new_fd_in_slot].pollfd_offset = offset;
		}
		pollfds.pop_back();

		// Restore to initial state
		fdinfos[fd] = fdinfo();
	}

	void sau_state::setpollfdevents(int fd, short events) {
		size_t offset = fdinfos[fd].pollfd_offset;
		pollfds[offset].events = events;
	}

	int sau_state::make_listen_sock() {
		auto fail = [&]() {
	#ifdef DEBUG
			fprintf(stderr, "make_listen_sock failed to create %s, %m\n", our_sock_name.c_str());
	#endif
			exit(EXIT_FAILURE);
		};

		mode_t oldmask = umask(0177);

		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if(sock == -1) {
			fail();
		}
		struct sockaddr_un my_addr;
		memset(&my_addr, 0, sizeof(my_addr));
		my_addr.sun_family = AF_UNIX;
		size_t maxlen = sizeof(my_addr.sun_path) - 1;
		if(our_sock_name.size() > maxlen) {
			fail();
		}
		strncpy(my_addr.sun_path, our_sock_name.c_str(), maxlen);

		if(bind(sock, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) {
			fail();
		}

		should_unlink_listen_sock = true;

		if(listen(sock, 64) == -1) {
			fail();
		}

		umask(oldmask);

		setnonblock(sock);
		addpollfd(sock, POLLIN | POLLERR, FDTYPE::LISTENER);
		return sock;
	}

	int sau_state::make_agent_sock() {
		struct sockaddr_un my_addr;
		size_t maxlen = sizeof(my_addr.sun_path) - 1;
		memset(&my_addr, 0, sizeof(my_addr));
		my_addr.sun_family = AF_UNIX;
		if(agent_sock_name.size() > maxlen) {
			return -1;
		}
		strncpy(my_addr.sun_path, agent_sock_name.c_str(), maxlen);

		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if(sock == -1) return -1;

		int flags = fcntl(sock, F_GETFL, 0);
		int res = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
		if(flags < 0 || res < 0) {
			close(sock);
			return -1;
		}

		setnonblock(sock);

		if(connect(sock, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) {
			if(errno == EINPROGRESS) {
				addpollfd(sock, POLLOUT | POLLERR, FDTYPE::AGENT);
				fdinfos[sock].waiting_for_connect = true;
				return sock;
			}
			else {
				close(sock);
				return -1;
			}
		}
		else {
			addpollfd(sock, POLLIN | POLLERR, FDTYPE::AGENT);
			return sock;
		}
	}

	void sau_state::set_output_block_state(int fd, bool blocked) {
		fdinfos[fd].output_blocked = blocked;
		set_connection_poll_events(fd);
	}

	void sau_state::set_connection_poll_events(int fd) {
		fdinfo &info = fdinfos[fd];
		short events = POLLERR;
		if(info.waiting_for_connect) events |= POLLOUT;
		else {
			events |= POLLIN;
			if(!info.output_blocked && !info.out_buffers.empty()) events |= POLLOUT;
		}
		setpollfdevents(fd, events);
	}

	void sau_state::write_message(int fd, const unsigned char *d, size_t l) {
		if(fd != -1) {
			fdinfo &oinfo = fdinfos[fd];
			oinfo.out_buffers.emplace_back();
			auto &buffer = oinfo.out_buffers.back();
			buffer.reserve(l + 4);
			buffer.push_back((l >> 24) & 0xFF);
			buffer.push_back((l >> 16) & 0xFF);
			buffer.push_back((l >> 8) & 0xFF);
			buffer.push_back((l >> 0) & 0xFF);
			buffer.insert(buffer.end(), d, d + l);
			set_connection_poll_events(fd);
		}
	};

	void sau_state::process_message(int fd, unsigned char *data, size_t length) {
		fdinfo &info = fdinfos[fd];

		if(msg_handler) {
			msg_handler(*this, info.type, fd, info.other_fd, data, length);
		}
	}

	void sau_state::poll_loop() {
		while(true) {
			sigset_t mask;
			sigemptyset(&mask);
			int n = ppoll(pollfds.data(), pollfds.size(), nullptr, &mask);
			if(force_exit) {
#ifdef DEBUG
				fprintf(stderr, "Signal handler set force_exit\n");
#endif
				break;
			}
			if(n < 0) {
				if(errno == EINTR) continue;
				else break;
			}

			bool continue_flag = true;

			for(size_t i = 0; i < pollfds.size() && continue_flag; i++) {
				if(!pollfds[i].revents) continue;
				int fd = pollfds[i].fd;
				switch(fdinfos[fd].type) {
					case FDTYPE::NONE:
						exit(EXIT_FAILURE);
					case FDTYPE::LISTENER: {
						int newsock = accept(fd, 0, 0);
						if(newsock == -1) {
#ifdef DEBUG
							fprintf(stderr, "new client accept failed for %d: %m\n", fd);
#endif
							break;
						}

#ifdef DEBUG
						fprintf(stderr, "new client socket: %d\n", newsock);
#endif

						setnonblock(newsock);

						int agent_sock = make_agent_sock();
						if(agent_sock == -1) {
							// Can't contact real agent
#ifdef DEBUG
							fprintf(stderr, "Can't contact real agent: %s, %m\n", agent_sock_name.c_str());
#endif
							shutdown(newsock, SHUT_RDWR);
							close(newsock);
							break;
						}

						addpollfd(newsock, POLLIN | POLLERR, FDTYPE::CLIENT);
						fdinfos[newsock].other_fd = agent_sock;
						fdinfos[agent_sock].other_fd = newsock;

						if(new_connection_notification) {
							new_connection_notification(*this, agent_sock, newsock);
						}
						break;
					}
					case FDTYPE::AGENT:
					case FDTYPE::CLIENT:
						handle_fd(fd, pollfds[i].revents, continue_flag);
						break;
				}
			}
		}
	}

	void sau_state::handle_fd(int fd, short revents, bool &continue_flag) {
		fdinfo &info = fdinfos[fd];
		auto kill_fd = [&]() {
			if(closed_connection_notification) {
				int agent_fd = fd;
				int client_fd = info.other_fd;
				if(info.type == FDTYPE::CLIENT) std::swap(agent_fd, client_fd);
				closed_connection_notification(*this, agent_fd, client_fd);
			}

#ifdef DEBUG
			fprintf(stderr, "handle_fd: killing fd: %d\n", fd);
#endif

			if(info.other_fd != -1) {
#ifdef DEBUG
				fprintf(stderr, "handle_fd: killing other fd: %d\n", info.other_fd);
#endif

				// If the other end is open, kill that too
				shutdown(info.other_fd, SHUT_RDWR);
				close(info.other_fd);
				delpollfd(info.other_fd);
			}

			shutdown(fd, SHUT_RDWR);
			close(fd);
			delpollfd(fd);
			continue_flag = false;
		};

		if(revents & POLLERR) {
			kill_fd();
			return;
		}

		if(info.waiting_for_connect) {
			int sock_err;
			socklen_t sock_err_size = sizeof(sock_err);
			int res = getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_size);
			if(res != 0 || sock_err != 0) {
				// Connection failed
				kill_fd();
				return;
			}
			info.waiting_for_connect = false;
		}
		else {
			// Check I/O here
			if(revents & POLLOUT) {
				while(!info.out_buffers.empty()) {
					auto &buffer = info.out_buffers.front();
					ssize_t result = write(fd, buffer.data(), buffer.size());
					if(result < 0) {
						if(errno == EAGAIN || errno == EWOULDBLOCK) {
							// poll() before trying again
							break;
						}
						else {
							// Give up
							kill_fd();
							return;
						}
					}
					else if(result < (ssize_t) buffer.size()) {
						// Shift the buffer up
						buffer.erase(buffer.begin(), buffer.begin() + result);
						break;
					}
					else {
						// Buffer can now be got rid of
						info.out_buffers.pop_front();
					}
				}
			}
			if(revents & POLLIN) {
				size_t insize = info.in_buffer.size();
				info.in_buffer.resize(insize + read_size);
				ssize_t result = read(fd, info.in_buffer.data() + insize, read_size);
				if(result < 0) {
					if(errno != EAGAIN && errno != EWOULDBLOCK) {
						// Give up
						kill_fd();
						return;
					}
				}
				else if(result == 0) {
					kill_fd();
					return;
				}
				else {
					info.in_buffer.resize(insize + result);
				}

				insize = info.in_buffer.size();

				if(insize >= 4) {
					size_t length = get_rfc4251_u32(info.in_buffer.data());
					if(insize >= length + 4) {
						process_message(fd, info.in_buffer.data() + 4, length);
						info.in_buffer.erase(info.in_buffer.begin(), info.in_buffer.begin() + length + 4);
					}
				}
			}
		}

		set_connection_poll_events(fd);
	}

	void sau_state::set_signal_handlers() {
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, SIGTERM);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGHUP);
		sigaddset(&mask, SIGCHLD);
		sigprocmask(SIG_SETMASK, &mask, nullptr);

		struct sigaction new_action;
		memset(&new_action, 0, sizeof(new_action));
		new_action.sa_handler = sighandler;
		sigaction(SIGINT, &new_action, 0);
		sigaction(SIGHUP, &new_action, 0);
		sigaction(SIGTERM, &new_action, 0);
		new_action.sa_handler = sigchld_handler;
		sigaction(SIGCHLD, &new_action, 0);
		new_action.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &new_action, 0);
	}

	void sau_state::add_sigchld_handler(pid_t pid, std::function<void(sau_state &, pid_t, int /* wait status */)> handler) {
		sigchld_ops.emplace_back(*this, pid, std::move(handler));
	}

	bool sau_state::set_sock_temp_dir_if(const char *dir_template, const char *agent_basename) {
		if(our_sock_name.empty()) {
			tempdir = string_format("%s-XXXXXX", dir_template);
			if(!mkdtemp((char *) tempdir.c_str())) exit(EXIT_FAILURE);
			our_sock_name = string_format("%s/%s.%d", tempdir.c_str(), agent_basename, (int) getpid());
			return true;
		}
		else return false;
	}

	// This checks for an existing lockfile, but doesn't try to create one as we're not ready yet
	// If another instance already exists, execution stops here
	void sau_state::single_instance_precheck_if(std::string base_template) {
		if(single_instance) {
			single_instance_check(agent_sock_name, base_template, [&]() {
				cleanup();
			});
		}
	}

	// If another instance already exists, execution stops here
	void sau_state::single_instance_check_and_create_lockfile_if() {
		if(single_instance) {
			single_instance_check_and_create_lockfile(our_sock_name, [&]() {
				cleanup();
			});
		}
	}

	bool keydata::operator==(const keydata &other) const {
		return data.size() == other.data.size() && std::equal(data.begin(), data.end(), other.data.begin());
	}

	// Note that loading a public key is blocking
	// Returns true on success
	bool load_pubkey_file(const std::string &filename, pubkey_file &key) {
		int fd = open(filename.c_str(), O_RDONLY);

		auto bad_key = [&]() -> bool {
			// reset the key
			key = pubkey_file();
			if(fd != -1) close(fd);
			return false;
		};

		auto good_key = [&]() -> bool {
			if(fd != -1) close(fd);
			return true;
		};

		struct stat s;
		int stat_result = fstat(fd, &s);
		if(stat_result < 0) return bad_key();

		if(key.modified != 0) {
			//we have this key already, don't bother loading it again unless it's new

			if(s.st_mtime == key.modified) {
				// Key has same time, don't reparse
				return good_key();
			}
		}

		key.modified = s.st_mtime;

		std::vector<unsigned char> filedata;
		filedata.reserve(s.st_size + 1);                            // +1 for null-terminator
		if(!slurp_file(fd, filedata, s.st_size)) return bad_key();  // read failed
		if(filedata.size() != (size_t) s.st_size) return bad_key(); // size not as expected

		filedata.resize(filedata.size() + 1);                       // filedata is now null-terminated

		char *token = std::strtok((char *) filedata.data(), " ");
		if(token) key.type = token;
		else return bad_key();

		std::string b64_data;
		token = std::strtok(nullptr, " ");
		if(token) b64_data = token;
		else return bad_key();

		token = std::strtok(NULL,"\n");
		if(token) key.comment = token;

		key.data.resize(b64_data.size()); // over-estimate size
		base64::decoder b64d;
		int output = b64d.decode(b64_data.data(), b64_data.size(), (char *) key.data.data());
		key.data.resize(output);

		// Validate that it looks sensible
		if(!validate_rfc4251_string_sequence(key.data.data(), key.data.size())) return bad_key();

		// Check if type field matches
		bool ok = true;
		std::string type = consume_rfc4251_string(key.data.data(), key.data.size(), ok);
		if(!ok || type != key.type) return bad_key();

		// Hooray, key looks valid

		return good_key();
	}

	bool identities_answer::parse(const unsigned char *d, size_t l) {
		if(l < 5) return false;
		if(d[0] != SSH2_AGENT_IDENTITIES_ANSWER) return false;
		d++;
		l--;

		bool ok = true;
		size_t count = consume_rfc4251_u32(d, l, ok);

		if(!ok) return false;

		// don't reserve based on count, check that keys actually exist first

		for(size_t i = 0; i < count && ok; i++) {
			keys.emplace_back();
			keydata &k = keys.back();

			k.data = consume_rfc4251_string_v(d, l, ok);
			k.comment = consume_rfc4251_string(d, l, ok);
		}
		if(l) ok = false;

#ifdef DEBUG
		if(ok) {
			fprintf(stderr, "SSH2_AGENT_IDENTITIES_ANSWER: found %u keys\n", (unsigned int) count);
			for(auto &k : keys) {
				fprintf(stderr, "Key of length: %u, comment: %s\n", (unsigned int) k.data.size(), k.comment.c_str());
			}
		}
#endif

		return ok;
	}

	void identities_answer::serialise(std::vector<unsigned char> &out) {
		out.push_back(SSH2_AGENT_IDENTITIES_ANSWER);
		serialise_rfc4251_u32(out, keys.size());
		for(auto &k : keys) {
			serialise_rfc4251_string(out, k.data.data(), k.data.size());
			serialise_rfc4251_string(out, (const unsigned char*) k.comment.data(), k.comment.size());
		}
	}

	bool sign_request::parse(const unsigned char *d, size_t l) {
		if(l < 1) return false;
		if(d[0] != SSH2_AGENTC_SIGN_REQUEST) return false;
		d++;
		l--;

		bool ok = true;
		pubkey.data = consume_rfc4251_string_v(d, l, ok);
		data = consume_rfc4251_string_v(d, l, ok);
		flags = consume_rfc4251_u32(d, l, ok);

		if(l) ok = false;

#ifdef DEBUG
		if(ok) {
			fprintf(stderr, "SSH2_AGENTC_SIGN_REQUEST found\n");
		}
#endif

		return ok;
	}

	bool slurp_file(int fd, std::vector<unsigned char> &output, size_t read_hint) {
		output.resize(0);
		size_t real_size = 0;

		if(!read_hint) read_hint = read_size;
		while(true) {
			output.resize(real_size + read_hint);
			ssize_t result = read(fd, output.data() + real_size, read_hint);
			if(result < 0) {
				output.resize(real_size);
				return false;
			}
			else if(result == 0) {
				output.resize(real_size);
				return true;
			}
			else {
				real_size += result;
				read_hint = read_size;
			}
		}
	}

	bool unslurp_file(int fd, const unsigned char *data, size_t size) {
		while(size) {
			ssize_t wrote = write(fd, data, size);
			if(wrote <= 0) return false;
			data += wrote;
			size -= wrote;
		}
		return true;
	}

	// This function is from http://stackoverflow.com/a/8098080
	// Author: Erik Aronesty, CC by-sa
	std::string string_format(const std::string &fmt, ...) {
		int size = 100;
		std::string str;
		va_list ap;
		while (1) {
			str.resize(size);
			va_start(ap, fmt);
			int n = vsnprintf((char *)str.c_str(), size, fmt.c_str(), ap);
			va_end(ap);
			if (n > -1 && n < size) {
				str.resize(n);
				return str;
			}
			if (n > -1)
				size = n + 1;
			else
				size *= 2;
		}
		return str;
	}
}
