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
#include <arpa/inet.h>

#include "ssh-agent-utils.h"

namespace SSHAgentUtils {

	const size_t read_size = 8192;

	bool force_exit = false;

	void sighandler(int sig) {
		force_exit = true;
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

	sau_state::sau_state(std::string agent, std::string our)
			: agent_sock_name(std::move(agent)), our_sock_name(std::move(our)) { }

	sau_state::~sau_state() {
		unlink(our_sock_name.c_str());
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
		fdinfos[fd].~fdinfo();
		new (&fdinfos[fd]) fdinfo();
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

		if(listen(sock, 64) == -1) {
			fail();
		}

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

	void sau_state::set_connection_poll_events(int fd) {
		fdinfo &info = fdinfos[fd];
		short events = POLLERR;
		if(info.waiting_for_connect) events |= POLLOUT;
		else {
			events |= POLLIN;
			if(!info.out_buffers.empty()) events |= POLLOUT;
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
					size_t length = htonl(*reinterpret_cast<uint32_t*>(info.in_buffer.data()));
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
		sigprocmask(SIG_SETMASK, &mask, nullptr);

		struct sigaction new_action;
		memset(&new_action, 0, sizeof(new_action));
		new_action.sa_handler = sighandler;
		sigaction(SIGINT, &new_action, 0);
		sigaction(SIGHUP, &new_action, 0);
		sigaction(SIGTERM, &new_action, 0);
		new_action.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &new_action, 0);
	}

}
