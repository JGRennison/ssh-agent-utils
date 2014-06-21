CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter -O3
LDFLAGS ?=
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CXXFLAGS += -std=c++11
LDLIBS = -lb64 -lmhash

ifndef debug
BIN = bin
OBJ = obj
else
BIN = bin_debug
OBJ = obj_debug
CXXFLAGS += -g
LDFLAGS += -g
CPPFLAGS += -DDEBUG
endif
MANDIR = man1

.PHONY: install all
.SECONDARY:

all: $(BIN)/ssh-agent-passthrough $(BIN)/ssh-agent-on-demand

VERSION_STRING := $(shell git describe --always --dirty=-m 2>/dev/null || date "+%F %T %z" 2>/dev/null)
ifdef VERSION_STRING
CVFLAGS := -DVERSION_STRING='"${VERSION_STRING}"'
endif

$(BIN)/%: $(OBJ)/%.o $(OBJ)/ssh-agent-utils.o | $(BIN)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< $(OBJ)/ssh-agent-utils.o $(LOADLIBES) $(LDLIBS)

$(OBJ)/%.o: src/%.cpp src/ssh-agent-utils.h | $(OBJ)
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $(CVFLAGS) $< -o $@

$(BIN):
	mkdir $(BIN)

$(OBJ):
	mkdir $(OBJ)

$(MANDIR):
	mkdir $(MANDIR)

clean:
	rm -f $(OBJ)/* $(BIN)/* $(MANDIR)/*

install: bin/ssh-agent-on-demand
	cp bin/ssh-agent-on-demand /usr/local/bin/

HELP2MANOK := $(shell help2man --version 2>/dev/null)
ifdef HELP2MANOK
all: $(MANDIR)/ssh-agent-on-demand.1

$(MANDIR)/ssh-agent-on-demand.1: $(BIN)/ssh-agent-on-demand | $(MANDIR)
	help2man -s 1 -N $(BIN)/ssh-agent-on-demand -n "SSH-Agent On Demand" -o $(MANDIR)/ssh-agent-on-demand.1

install: install-man

.PHONY: install-man

install-man: $(MANDIR)/ssh-agent-on-demand.1
	cp $(MANDIR)/ssh-agent-on-demand.1 /usr/local/share/man/man1/
	-mandb -pq

else
$(shell echo "Install help2man for man page generation" >&2)
endif
