bin/ssh-agent-on-demand: ssh-agent-on-demand.cpp | bin
	g++ ssh-agent-on-demand.cpp -Wall --std=gnu++0x -O3 -g -o bin/ssh-agent-on-demand

bin:
	mkdir bin

.PHONY: install

install: bin/ssh-agent-on-demand
	cp bin/ssh-agent-on-demand /usr/local/bin/
