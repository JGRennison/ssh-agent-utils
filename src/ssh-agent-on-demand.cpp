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

#include <getopt.h>

#include <algorithm>

#include "ssh-agent-utils.h"

using namespace SSHAgentUtils;

struct on_demand_key {
	std::string filename;
	pubkey_file key;
	std::vector<int> client_fds;        // List of client fds we have sent an on-demand key to

	on_demand_key(std::string f) : filename(f) { }
};

std::vector<on_demand_key> on_demand_keys;

static struct option options[] = {
	{ "help",          no_argument,        NULL, 'h' },
	{ "socket-path",   required_argument,  NULL, 's' },
	{ NULL, 0, 0, 0 }
};

std::string sock_path;
std::string tempdir;

void show_usage() {
	fprintf(stderr,
			"Usage: ssh-agent-on-demand [options] pubkeyfiles ...\n"
			"\tAn SSH agent proxy which adds public keys to identity lists.\n"
			"\tIf such a public key is requested, the corresponding private key\n"
			"\tis added on-demand using ssh-add.\n"
			"Options:\n"
			"-h, --help\n"
			"\tShow this help\n"
			"-s, --socket-path PATH\n"
			"\tCreate the listener socket at PATH\n"
			"\tDefaults to a path of the form /tmp/sshod-XXXXXX/agentod.pid\n"
	);
}

int main(int argc, char **argv) {
	int n = 0;
	while (n >= 0) {
		n = getopt_long(argc, argv, "hs:", options, NULL);
		if (n < 0) continue;
		switch (n) {
		case 's':
			sock_path = optarg;
			break;
		case '?':
		case 'h':
			show_usage();
			exit(1);
		}
	}

	while(optind < argc) {
		on_demand_keys.emplace_back(argv[optind++]);
	}

	std::string agent_env = get_env_agent_sock_name_or_die();

	if(sock_path.empty()) {
		char tmp[] = "/tmp/sshod-XXXXXX";
		if(!mkdtemp(tmp)) exit(EXIT_FAILURE);
		tempdir = tmp;
		sock_path = string_format("%s/agentod.%d", tmp, (int) getpid());
	}

	sau_state s(agent_env, sock_path);

	s.set_signal_handlers();

	s.msg_handler = [](sau_state &ss, FDTYPE type, int this_fd, int other_fd, const unsigned char *d, size_t l) {
		if(type == FDTYPE::AGENT && l > 0 && d[0] == SSH2_AGENT_IDENTITIES_ANSWER) {
			// The agent is supplying a list of identities, possibly add our own here

			identities_answer ans;
			if(!ans.parse(d, l)) {
				// parse failed
				return;
			}

			for(auto &k : on_demand_keys) {
				// If this client fd is already listed, remove it
				k.client_fds.erase(std::remove(k.client_fds.begin(), k.client_fds.end(), other_fd), k.client_fds.end());

				if(load_pubkey_file(k.filename, k.key)) {
					auto it = std::find_if(ans.keys.begin(), ans.keys.end(), [&](const keydata &id) {
						return id == k.key;
					});
					if(it == ans.keys.end()) {
						// no such key, add it now
						ans.keys.emplace_back();
						keydata &id = ans.keys.back();
						id.data = k.key.data;
						id.comment = k.filename + " (" + k.key.comment + ") [On Demand]";

						// Add this client fd to list
						k.client_fds.push_back(other_fd);
#ifdef DEBUG
						fprintf(stderr, "Adding on-demand key of length: %u, comment: %s\n", (unsigned int) id.data.size(), id.comment.c_str());
#endif
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

	s.closed_connection_notification = [](sau_state &ss, int agent_fd, int client_fd) {
		for(auto &k : on_demand_keys) {
			// If this client fd is listed, remove it
			k.client_fds.erase(std::remove(k.client_fds.begin(), k.client_fds.end(), client_fd), k.client_fds.end());
		}
	};
	s.poll_loop();

	if(!tempdir.empty()) {
		rmdir(tempdir.c_str());
	}

	return 0;
}
