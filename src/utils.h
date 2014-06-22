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

#ifndef UTILS_H
#define UTILS_H

#include <unistd.h>

#include <string>
#include <vector>
#include <algorithm>
#include <streambuf>

#define OBJ_EXTERN(obj) \
	extern "C" char extern_##obj##_start[] asm("_binary_" #obj "_start"); \
	extern "C" char extern_##obj##_end[] asm("_binary_" #obj "_end");

#define EXTERN_STRING(obj) \
	std::string( extern_##obj##_start , extern_##obj##_end )

namespace SSHAgentUtils {

	extern const size_t read_size;

	void setnonblock(int fd, bool setcloexec = true);

	uint32_t get_rfc4251_u32(const unsigned char *data) ;
	uint32_t consume_rfc4251_u32(const unsigned char *&data, size_t &length, bool &ok);
	inline uint32_t consume_rfc4251_u32(const unsigned char *&&data, size_t &&length, bool &ok) {
		return consume_rfc4251_u32(data, length, ok);
	}

	std::string consume_rfc4251_string(const unsigned char *&data, size_t &length, bool &ok);
	inline std::string consume_rfc4251_string(const unsigned char *&&data, size_t &&length, bool &ok) {
		return consume_rfc4251_string(data, length, ok);
	}

	std::vector<unsigned char> consume_rfc4251_string_v(const unsigned char *&data, size_t &length, bool &ok);
	inline std::vector<unsigned char> consume_rfc4251_string_v(const unsigned char *&&data, size_t &&length, bool &ok) {
		return consume_rfc4251_string_v(data, length, ok);
	}

	// returns true if valid, or if 0 length
	bool validate_rfc4251_string_sequence(const unsigned char *data, size_t length);

	void serialise_rfc4251_u32(std::vector<unsigned char> &out, uint32_t value);
	void serialise_rfc4251_string(std::vector<unsigned char> &out, const unsigned char *start, size_t length);

	inline void serialise_rfc4251_string(std::vector<unsigned char> &out, const std::string &str) {
		serialise_rfc4251_string(out, (const unsigned char*) str.data(), str.size());
	}

	std::string get_env_agent_sock_name();
	std::string get_env_agent_sock_name_or_die();


	bool slurp_file(int fd, std::vector<unsigned char> &output, size_t read_hint = 0);
	bool unslurp_file(int fd, const unsigned char *data, size_t size);

	inline bool unslurp_file(int fd, const std::vector<unsigned char> &buffer) {
		return unslurp_file(fd, buffer.data(), buffer.size());
	}

	inline bool unslurp_file(int fd, const std::string &buffer) {
		return unslurp_file(fd, (unsigned char *) buffer.data(), buffer.size());
	}

	std::string string_format(const std::string &fmt, ...);

	struct uchar_vector_streambuf : public std::streambuf {
		uchar_vector_streambuf(const std::vector<unsigned char> &vec) {
			this->setg((char *) vec.data(), (char *) vec.data(), (char *) vec.data() + vec.size());
		}
	};

	template <typename C> struct generic_streambuf_wrapper : public std::streambuf {
		generic_streambuf_wrapper(C *start, C *end) {
			this->setg(reinterpret_cast<char*>(start), reinterpret_cast<char*>(start), reinterpret_cast<char*>(end));
		}
	};


	// These are from http://stackoverflow.com/a/217605
	// Author: Evan Teran

	// trim from start
	static inline std::string &ltrim(std::string &s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
		return s;
	}

	// trim from end
	static inline std::string &rtrim(std::string &s) {
		s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
		return s;
	}

	// trim from both ends
	static inline std::string &trim(std::string &s) {
		return ltrim(rtrim(s));
	}
};

#endif
