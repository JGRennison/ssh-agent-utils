//  ssh-agent-passthrough
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

#include "ssh-agent-utils.h"

using namespace SSHAgentUtils;

int main(int argc, char **argv) {
	sau_state s(get_env_agent_sock_name_or_die(), "ssh-agent-passthrough-sock");

	s.set_signal_handlers();
	s.make_listen_sock();
	s.msg_handler = [](sau_state &ss, FDTYPE type, int this_fd, int other_fd, const unsigned char *d, size_t l) {
		ss.write_message(other_fd, d, l);
	};
	s.poll_loop();

	return 0;
}
