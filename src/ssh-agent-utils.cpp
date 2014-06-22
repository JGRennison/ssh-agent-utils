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
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <b64/encode.h>
#include <b64/decode.h>
#include <mhash.h>

#include <cstring>
#include <sstream>
#include <algorithm>

#include "ssh-agent-utils.h"
#include "utils.h"

namespace SSHAgentUtils {

	bool force_exit = false;
	int signal_forward_pid_instead = 0;

	void sighandler(int sig) {
		if(signal_forward_pid_instead) {
			kill(signal_forward_pid_instead, sig);
		}
		else {
			force_exit = true;
		}
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
		std::function<void()> single_lock_cleanup_handler;
		std::function<void(std::string, pid_t)> single_lock_already_exists_handler;
	};

	// This handler must only get called when signals are unblocked during ppoll
	void sigchld_handler(int sig) {
		while(true) {
			int status;
			pid_t pid = waitpid(-1, &status, WNOHANG);
			if(pid <= 0) return;

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

	static bool slurp_parse_lockfile_fd(int fd, pid_t &agent_pid, std::string &agent_sock) {
		std::vector<unsigned char> buffer;
		if(!slurp_file(fd, buffer)) return false;

		// This extracts the info from the lockfile, which is in rfc4251 format
		bool ok = true;
		const unsigned char *d = buffer.data();
		size_t l = buffer.size();
		agent_pid = consume_rfc4251_u32(d, l, ok);
		agent_sock = consume_rfc4251_string(d, l, ok);
		return ok && !l;
	}

	static bool unslurp_serialise_lockfile_fd(int fd, pid_t pid, const std::string &sock) {
		std::vector<unsigned char> data;
		serialise_rfc4251_u32(data, pid);
		serialise_rfc4251_string(data, sock);
		return unslurp_file(fd, data);
	}

	// Calls already_exists and exits if lockfile exists
	// Just returns if lockfile does not exist
	// Calls cleanup and exit if something went wrong
	static void single_instance_check_lockfile() {
		auto cleanup_exit = [&](int status) {
			single_lock_cleanup_handler();
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

			pid_t agent_pid;
			std::string agent_sock;
			if(!slurp_parse_lockfile_fd(fd, agent_pid, agent_sock)) cleanup_exit(EXIT_FAILURE);

			single_lock_already_exists_handler(agent_sock, agent_pid);
			cleanup_exit(EXIT_SUCCESS);
		}
		else {
			// Something unexpected, give up
			cleanup_exit(EXIT_FAILURE);
		}
	}

	// Calls already_exists and exits if lockfile exists
	// Just returns if lockfile does not exist
	// Calls cleanup and exit if something went wrong
	void single_instance_check(const std::vector<unsigned char> &single_instance_opt_str, std::string base_template, std::function<void()> cleanup, std::function<void(std::string, pid_t)> already_exists) {
		unsigned char hash[16];

		MHASH td = mhash_init(MHASH_MD5);
		if(td == MHASH_FAILED) {
			cleanup();
			exit(EXIT_FAILURE);
		}

		mhash(td, single_instance_opt_str.data(), single_instance_opt_str.size());
		mhash_deinit(td, hash);

		generic_streambuf_wrapper<unsigned char> hash_stream(hash, hash + 16);
		std::istream ins(&hash_stream);
		std::ostringstream ss;
		base64::encoder b64e;
		b64e.encode(ins, ss);

		lockfile = base_template + "-";
		std::string b64 = ss.str();
		std::remove_copy(b64.begin(), b64.end(), std::back_inserter(lockfile), '\n'); // Append the base64 representation of the real agent sock, minus any annoying newlines

		single_lock_cleanup_handler = std::move(cleanup);
		single_lock_already_exists_handler = std::move(already_exists);

		single_instance_check_lockfile();
	}

	// Calls already_exists and exits if lockfile exists
	// Just returns if lockfile does not exist
	// Calls cleanup and exit if something went wrong
	void single_instance_check_and_create_lockfile(const std::string &our_sock) {
		auto cleanup_exit = [&](int status) {
			single_lock_cleanup_handler();
			exit(status);
		};

		std::string lockfile_tmp = lockfile + "-XXXXXX";
		int temp_fd = mkstemp((char *) lockfile_tmp.c_str());
		if(temp_fd == -1) exit(EXIT_FAILURE);

		// If we can't write to the new temp file, give up
		if(!unslurp_serialise_lockfile_fd(temp_fd, getpid(), our_sock)) cleanup_exit(EXIT_FAILURE);

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
			single_instance_check_lockfile();
			single_instance_check_and_create_lockfile(our_sock);
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
		our_sock_pid = getpid();

		if(listen(sock, 64) == -1) {
			fail();
		}

		umask(oldmask);

		setnonblock(sock);
		addpollfd(sock, POLLIN | POLLERR, FDTYPE::LISTENER);

		check_print_sock_name(STDOUT_FILENO, our_sock_name, our_sock_pid);

		if(!exec_cmd.empty()) {
			int pid = fork();
			if(pid < 0) exit(EXIT_FAILURE);
			else if(pid == 0) do_exec(our_sock_name, our_sock_pid);
			else {
				signal_forward_pid_instead = pid;
				add_sigchld_handler(pid, [](sau_state &ss, pid_t pid, int status) {
					force_exit = true;

					// See this thread for the rationale behind this
					// http://stackoverflow.com/questions/18640737/why-arent-i-picking-up-the-exit-status-from-my-child-process
					ss.exit_code = ((status & 0x7F) ? (status | 0x80) : (status >> 8)) & 0xFF;
				});
			}
		}

		return sock;
	}

	void sau_state::daemonise_if() {
		if(daemonise) {
			if(!exec_cmd.empty()) {
				int pipefds[2];
				if(pipe(pipefds) == -1) exit(EXIT_FAILURE);

				int pid = fork();
				if(pid < 0) exit(EXIT_FAILURE);
				else if(pid == 0) {
					// child, will become a daemon
					close(pipefds[0]);
					print_sock_pipe = pipefds[1];

					exec_cmd = ""; // don't try to exec again
				}
				else {
					// parent: this will be the exec'd cmd
					close(pipefds[1]);

					// Prevent the temporary child zombifying
					wait(nullptr);

					pid_t agent_pid;
					std::string agent_sock;
					if(!slurp_parse_lockfile_fd(pipefds[0], agent_pid, agent_sock)) exit(EXIT_FAILURE);
					close(pipefds[0]);

					do_exec(agent_sock, agent_pid);
				}
			}
			int pid = fork();
			if(pid < 0) exit(EXIT_FAILURE);
			else if(pid == 0) {
				// child
				setsid();
				if(chdir("/") == -1) exit(EXIT_FAILURE);
				int nullfd = open("/dev/null", O_RDWR);
				dup2(nullfd, STDOUT_FILENO);
				dup2(nullfd, STDIN_FILENO);
#ifndef DEBUG
				dup2(nullfd, STDERR_FILENO);
#endif
				close(nullfd);
			}
			else {
				// parent

				// Don't want each child having their own copy of this
				if(print_sock_pipe != -1) close(print_sock_pipe);
				exit(EXIT_SUCCESS);
			}

			pid = fork();
			if(pid < 0) exit(EXIT_FAILURE);
			else if(pid > 0) {
				// parent

				// Don't want each child having their own copy of this
				if(print_sock_pipe != -1) close(print_sock_pipe);
				exit(EXIT_SUCCESS);
			}
		}
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
	void sau_state::single_instance_precheck_if(std::string base_template, std::string dir_template) {
		auto already_exists = [&](std::string agent_sock, pid_t agent_pid) {
			check_print_sock_name(STDOUT_FILENO, agent_sock, agent_pid);
			if(!exec_cmd.empty()) {
				cleanup();
				do_exec(agent_sock, agent_pid);
			}
		};

		if(no_recurse && !dir_template.empty()) {
			if(agent_sock_name.find(dir_template) == 0) {
				int agent_pid = -1;
				const char *agent_pid_env = getenv("SSH_AGENT_PID");
				if(agent_pid_env) agent_pid = std::stoi(agent_pid_env);

#ifdef DEBUG
				fprintf(stderr, "No recurse: sock: %s, pid: %d, looks like another sshod\n", agent_sock_name.c_str(), agent_pid);
#endif

				already_exists(agent_sock_name, agent_pid);
				cleanup();
				exit(EXIT_SUCCESS);
			}
		}

		if(single_instance) {
			serialise_rfc4251_string(single_instance_opt_str, agent_sock_name);
			single_instance_check(single_instance_opt_str, base_template, [&]() {
				cleanup();
			}, already_exists);
		}
	}

	void sau_state::single_instance_add_checked_option(const std::string &str) {
		serialise_rfc4251_string(single_instance_opt_str, str);
	}

	// If another instance already exists, execution stops here
	void sau_state::single_instance_check_and_create_lockfile_if() {
		if(single_instance) {
			single_instance_check_and_create_lockfile(our_sock_name);
		}
	}

	void sau_state::check_print_sock_name(int fd, std::string sock, pid_t pid) {
		if(print_sock_name) {
			std::string str;
			if(print_sock_bourne) {
				str = string_format("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=%d; export SSH_AGENT_PID;\necho On demand agent proxy pid %d;\n",
						sock.c_str(), pid, pid);
			}
			else {
				str = sock;
			}
			if(!unslurp_file(fd, str)) {
				cleanup();
				exit(EXIT_FAILURE);
			}
		}
		if(print_sock_pipe != -1) {
			if(!unslurp_serialise_lockfile_fd(print_sock_pipe, pid, sock)) exit(EXIT_FAILURE);
			close(print_sock_pipe);
			print_sock_pipe = -1;
		}
	}

	void sau_state::do_exec(std::string sock, pid_t pid) {
		std::string authenv = string_format("SSH_AUTH_SOCK=%s", sock.c_str());
		std::string pidenv = string_format("SSH_AGENT_PID=%d", pid);
		putenv((char *) authenv.c_str());
		putenv((char *) pidenv.c_str());

		std::vector<char *> exec_argv;
		exec_argv.push_back((char *) exec_cmd.c_str());
		for(auto &it : exec_array) exec_argv.push_back((char *) it.c_str());
		exec_argv.push_back(nullptr);
		execvp(exec_cmd.c_str(), exec_argv.data());

		fprintf(stderr, "execvp '%s' failed: %m\n", exec_cmd.c_str());
		exit(EXIT_FAILURE);
	}

	bool keydata::operator==(const keydata &other) const {
		return data.size() == other.data.size() && std::equal(data.begin(), data.end(), other.data.begin());
	}

	// Note that loading a public key is blocking
	// Returns true on success
	bool load_pubkey_file(const std::string &filename, pubkey_file &key) {
		int fd = -1;

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

		fd = open(filename.c_str(), O_RDONLY);
		if(fd == -1) return bad_key();

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
}
