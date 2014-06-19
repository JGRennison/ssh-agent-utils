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

#ifndef SSH_AGENT_UTILS_H
#define SSH_AGENT_UTILS_H

#include <unistd.h>
#include <poll.h>

#include <vector>
#include <deque>
#include <string>
#include <functional>

namespace SSHAgentUtils {

	enum class FDTYPE {
		NONE,
		AGENT,
		CLIENT,
		LISTENER,
	};

	void setnonblock(int fd, bool setcloexec = true);

	std::string get_env_agent_sock_name();
	std::string get_env_agent_sock_name_or_die();

	class sau_state {
		struct fdinfo {
			FDTYPE type = FDTYPE::NONE;
			unsigned int pollfd_offset;
			std::deque<std::vector<unsigned char> > out_buffers;
			size_t buffered_data = 0;
			bool waiting_for_connect = false;
			std::vector<unsigned char> in_buffer;
			int other_fd = -1;
		};

		std::vector<struct pollfd> pollfds;
		std::deque<struct fdinfo> fdinfos;

		std::string agent_sock_name;
		std::string our_sock_name;

	public:
		sau_state(std::string agent, std::string our);
		~sau_state();

		void addpollfd(int fd, short events, FDTYPE type);
		void delpollfd(int fd);
		void setpollfdevents(int fd, short events);
		int make_listen_sock();
		int make_agent_sock();
		void write_message(int fd, const unsigned char *d, size_t l);
		void process_message(int fd, unsigned char *data, size_t length);
		void set_connection_poll_events(int fd);
		void poll_loop();
		void handle_fd(int fd, short revents, bool &continue_flag);
		void set_signal_handlers();

		// Caller should set this
		std::function<void(sau_state &, FDTYPE, int, int, const unsigned char *, size_t)> msg_handler;   // src fd, other fd
		std::function<void(sau_state &, int, int)> new_connection_notification;    // agent fd, client fd
		std::function<void(sau_state &, int, int)> closed_connection_notification; // agent fd, client fd
	};


	struct pubkey {
		std::string type;
		std::vector<unsigned char> data;
		std::string comment;
		time_t modified = 0;
	};

	bool load_pubkey_file(const std::string &filename, pubkey &key);

	enum {
		SSH2_AGENT_IDENTITIES_ANSWER = 12,
	};

	struct identities_answer {
		struct identity {
			std::vector<unsigned char> pubkey;
			std::string comment;
		};
		std::vector<identity> keys;

		bool parse(const unsigned char *d, size_t l);
		void serialise(std::vector<unsigned char> &out);
	};

	std::string string_format(const std::string &fmt, ...);
};

#endif
