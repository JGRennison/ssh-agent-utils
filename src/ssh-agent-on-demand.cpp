//  ssh-agent-on-demand
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

#include <algorithm>

#include "ssh-agent-utils.h"

using namespace SSHAgentUtils;

struct on_demand_key {
	std::string filename;
	pubkey key;

	on_demand_key(std::string f) : filename(f) { }
};

std::vector<on_demand_key> on_demand_keys;

int main(int argc, char **argv) {
	sau_state s(get_env_agent_sock_name_or_die(), "ssh-agent-on-demand-sock");

	s.set_signal_handlers();
	s.make_listen_sock();
	s.msg_handler = [](sau_state &ss, FDTYPE type, int this_fd, int other_fd, const unsigned char *d, size_t l) {
		if(type == FDTYPE::AGENT && l > 0 && d[0] == SSH2_AGENT_IDENTITIES_ANSWER) {
			// The agent is supplying a list of identities, possibly add our own here

			identities_answer ans;
			if(!ans.parse(d, l)) {
				// parse failed
				return;
			}

			for(auto &k : on_demand_keys) {
				if(load_pubkey_file(k.filename, k.key)) {
					auto it = std::find_if(ans.keys.begin(), ans.keys.end(), [&](const identities_answer::identity &id) {
						return id.pubkey.size() == k.key.data.size() && std::equal(id.pubkey.begin(), id.pubkey.end(), k.key.data.begin());
					});
					if(it == ans.keys.end()) {
						// no such key, add it now
						ans.keys.emplace_back();
						identities_answer::identity &id = ans.keys.back();
						id.pubkey = k.key.data;
						id.comment = k.filename + " (" + k.key.comment + ") [On Demand]";
					}
				}
			}
			std::vector<unsigned char> out;
			ans.serialise(out);
			ss.write_message(other_fd, out.data(), out.size());
		}
		else {
			ss.write_message(other_fd, d, l);
		}
	};
	s.poll_loop();

	return 0;
}
