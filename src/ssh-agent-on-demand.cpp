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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <algorithm>

#include "ssh-agent-utils.h"

using namespace SSHAgentUtils;

struct ssh_add_options {
	std::vector<std::string> args;
};

ssh_add_options global_options;

struct on_demand_key {
	std::string filename;
	pubkey_file key;
	std::vector<int> client_fds;        // List of client fds we have sent an on-demand key to
	ssh_add_options options;

	on_demand_key(std::string f) : filename(f) {
		// Start by duplicating global_options
		options = global_options;
	}
};

std::vector<on_demand_key> on_demand_keys;

ssh_add_options &get_current_options() {
	if(on_demand_keys.empty()) return global_options;
	else return on_demand_keys.back().options;
}

struct ssh_add_operation {
	pid_t pid = 0;
	keydata pubkey;
	std::vector<int> unblock_agent_fds; // List of agent fds to unblock when ssh-add is complete
};

std::vector<ssh_add_operation> ssh_add_ops;

static struct option options[] = {
	{ "help",          no_argument,        NULL, 'h' },
	{ "socket-path",   required_argument,  NULL, 's' },
	{ NULL, 0, 0, 0 }
};

std::string sock_path;
std::string tempdir;

void show_usage() {
	fprintf(stderr,
			"Usage: ssh-agent-on-demand [options] [pubkeyfiles]\n"
			"\tAn SSH agent proxy which adds public keys to the list of agent keys.\n"
			"\tIf a client requests that the agent sign with an added key, the\n"
			"\tcorresponding private key is added on-demand using ssh-add.\n"
			"\tThe path to the listener socket is printed to STDOUT.\n"
			"\n"
			"Options which refer to the previous public key on the command line\n"
			"If specified at the beginning, these apply to all keys on the command line\n"
			"-c\n"
			"\tPassed verbatim to ssh-add\n"
			"\tRequire confirmation to sign using identities\n"
			"-t life\n"
			"\tPassed verbatim to ssh-add\n"
			"\tSet lifetime (in seconds) when adding identities\n"
			"\n"
			"General Options:\n"
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
		n = getopt_long(argc, argv, "-s:ct:h", options, NULL);
		if (n < 0) continue;
		switch (n) {
		case 's':
			sock_path = optarg;
			break;
		case 'c':
			get_current_options().args.push_back("-c");
			break;
		case 't': {
			ssh_add_options &options = get_current_options();
			options.args.push_back("-t");
			options.args.push_back(optarg);
			break;
		}
		case 1:
			on_demand_keys.emplace_back(optarg);
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

	fprintf(stdout, "%s\n", sock_path.c_str());

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
		else if(type == FDTYPE::CLIENT && l > 0 && d[0] == SSH2_AGENTC_SIGN_REQUEST) {
			sign_request sr;
			if(!sr.parse(d, l)) {
				// parse failed
				return;
			}

			for(auto &k : on_demand_keys) {
				if(std::find(k.client_fds.begin(), k.client_fds.end(), this_fd) == k.client_fds.end()) continue;
				// We sent this client this on-demand key

				if(k.key != sr.pubkey) continue;
				// This is the right key

				auto it = std::find_if(ssh_add_ops.begin(), ssh_add_ops.end(), [&](const ssh_add_operation &op) {
					return op.pubkey == k.key;
				});
				if(it == ssh_add_ops.end()) {
					// Don't have an existing ssh-add request for this key, make new one
					ssh_add_ops.emplace_back();
					it = ssh_add_ops.end() - 1;
					it->pubkey = k.key;

					int child_pid = fork();
					if(child_pid < -1) {
						// failed: give up
						ssh_add_ops.pop_back();
						break;
					}
					else if(child_pid == 0) {
						// child
						// close stdout and stdin
						int nullfd = open("/dev/null", O_RDWR);
						dup2(nullfd, STDOUT_FILENO);
						dup2(nullfd, STDIN_FILENO);
						close(nullfd);

						std::vector<char*> args;
						std::string priv_filename = k.filename;
						if(priv_filename.size() > 4 && priv_filename.substr(priv_filename.size() - 4, 4) == ".pub") {
							// snip off .pub
							priv_filename.resize(priv_filename.size() - 4);
						}
						args.push_back((char *) "ssh-add");
						for(auto &it : k.options.args) {
							args.push_back((char *) it.c_str());
						}
						args.push_back((char *) priv_filename.c_str());
						args.push_back(nullptr);

						execvp("ssh-add", args.data());

						fprintf(stderr, "ssh-add execvp failed: %m\n");
						exit(EXIT_FAILURE);
					}
					else {
						// parent
						it->pid = child_pid;

						// NB: this will be called from SIGCHLD handler
						ss.add_sigchld_handler(child_pid, [](sau_state &ss, pid_t pid, int status) {
							auto it = std::find_if(ssh_add_ops.begin(), ssh_add_ops.end(), [&](const ssh_add_operation &op) {
								return op.pid == pid;
							});
							if(it != ssh_add_ops.end()) {
								// Found op
								for(int fd : it->unblock_agent_fds) {
									ss.set_output_block_state(fd, false);
								}

								for(on_demand_key &k : on_demand_keys) {
									if(k.key == it->pubkey) {
										// If we previously advertised to a client that we have this key on demand,
										// now forget that we did so. This is as the real agent now nominally has
										// this key and so we do not need to call ssh-add for it again
										k.client_fds.resize(0);
									}
								}

								ssh_add_ops.erase(it);
							}
						});
					}

				}
				it->unblock_agent_fds.push_back(other_fd);
				ss.set_output_block_state(other_fd, true);
				break;
			}

			// If calling ssh-add, this message will be held in agent output queue, until agent output unblocked
			ss.write_message(other_fd, d, l);
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

		for(auto &o : ssh_add_ops) {
			// If agent fd is listed, remove it
			o.unblock_agent_fds.erase(std::remove(o.unblock_agent_fds.begin(), o.unblock_agent_fds.end(), agent_fd), o.unblock_agent_fds.end());
		}
	};

	s.poll_loop();

	if(!tempdir.empty()) {
		rmdir(tempdir.c_str());
	}

	return 0;
}
