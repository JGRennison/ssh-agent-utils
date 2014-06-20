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
			bool output_blocked = false;
		};

		std::vector<struct pollfd> pollfds;
		std::deque<struct fdinfo> fdinfos;

		std::string tempdir;
		bool should_unlink_listen_sock = false;

		void do_exec(std::string sock, pid_t pid);

	public:
		std::string agent_sock_name;
		std::string our_sock_name;
		int our_sock_pid = -1;
		bool single_instance = false;
		bool print_sock_name = false;
		bool print_sock_bourne = false;
		char *exec_cmd = nullptr;
		std::vector<char *> exec_array;

		int exit_code = 0;

		sau_state();
		~sau_state();

		void cleanup();
		void addpollfd(int fd, short events, FDTYPE type);
		void delpollfd(int fd);
		void setpollfdevents(int fd, short events);
		int make_listen_sock();
		int make_agent_sock();
		void write_message(int fd, const unsigned char *d, size_t l);
		void process_message(int fd, unsigned char *data, size_t length);
		void set_output_block_state(int fd, bool blocked);
		void set_connection_poll_events(int fd);
		void poll_loop();
		void handle_fd(int fd, short revents, bool &continue_flag);
		void set_signal_handlers();
		void add_sigchld_handler(pid_t pid, std::function<void(sau_state &, pid_t, int /* wait status */)> handler);
		bool set_sock_temp_dir_if(const char *dir_template, const char *agent_basename);
		void single_instance_precheck_if(std::string base_template);
		void single_instance_check_and_create_lockfile_if();
		void check_print_sock_name(int fd, std::string sock, pid_t pid);

		// Caller should set this
		std::function<void(sau_state &, FDTYPE, int, int, const unsigned char *, size_t)> msg_handler;   // src fd, other fd
		std::function<void(sau_state &, int, int)> new_connection_notification;    // agent fd, client fd
		std::function<void(sau_state &, int, int)> closed_connection_notification; // agent fd, client fd
	};

	struct keydata {
		std::vector<unsigned char> data;
		std::string comment;

		bool operator==(const keydata &other) const;
		bool operator!=(const keydata &other) const {
			return !(*this == other);
		}
	};

	struct pubkey_file : public keydata {
		std::string type;
		time_t modified = 0;
	};

	bool load_pubkey_file(const std::string &filename, pubkey_file &key);

	enum {
		SSH2_AGENT_IDENTITIES_ANSWER = 12,
		SSH2_AGENTC_SIGN_REQUEST = 13,
	};

	struct identities_answer {
		std::vector<keydata> keys;

		bool parse(const unsigned char *d, size_t l);
		void serialise(std::vector<unsigned char> &out);
	};

	struct sign_request {
		keydata pubkey;
		std::vector<unsigned char> data;
		uint32_t flags;

		bool parse(const unsigned char *d, size_t l);
	};

	bool slurp_file(int fd, std::vector<unsigned char> &output, size_t read_hint = 0);
	bool unslurp_file(int fd, const unsigned char *data, size_t size);

	inline bool unslurp_file(int fd, const std::vector<unsigned char> &buffer) {
		return unslurp_file(fd, buffer.data(), buffer.size());
	}

	inline bool unslurp_file(int fd, const std::string &buffer) {
		return unslurp_file(fd, (unsigned char *) buffer.data(), buffer.size());
	}

	std::string string_format(const std::string &fmt, ...);
};

#endif
