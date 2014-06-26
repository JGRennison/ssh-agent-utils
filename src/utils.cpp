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

#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "utils.h"

namespace SSHAgentUtils {

	const size_t read_size = 8192;

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

	std::vector<unsigned char> consume_rfc4251_string_v(const unsigned char *&data, size_t &length, bool &ok) {
		auto pair = consume_rfc4251_string_generic(data, length, ok);
		return std::vector<unsigned char>(pair.first, pair.second);
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
		if(access(agent_sock_str, R_OK | W_OK) != 0) {
			fprintf(stderr, "Warning: SSH_AUTH_SOCK: '%s', appears to be invalid\n", agent_sock_str);
		}
		return std::string(agent_sock_str);
	}

	std::string get_env_agent_sock_name_or_die() {
		std::string result = get_env_agent_sock_name();
		if(result.empty()) {
			fprintf(stderr, "No SSH_AUTH_SOCK environment variable\n");
			exit(EXIT_FAILURE);
		}
		return result;
	}

	bool slurp_file(int fd, std::vector<unsigned char> &output, size_t read_hint) {
		output.resize(0);
		size_t real_size = 0;
		size_t next_read_hint = 0;

		if(!read_hint) read_hint = read_size;
		else next_read_hint = 16;
		while(true) {
			output.resize(real_size + read_hint + next_read_hint);
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
				read_hint = next_read_hint ? next_read_hint : read_size;
				next_read_hint = 0;
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

};
