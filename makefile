CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter -O3
LDFLAGS ?=
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CXXFLAGS += -std=c++11
LDLIBS = -lb64 -lmhash

OBJCOPY = objcopy

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

.PHONY: install uninstall all
.SECONDARY:

all: $(BIN)/ssh-agent-passthrough $(BIN)/ssh-agent-on-demand

VERSION_STRING := $(shell git describe --always --dirty=-m 2>/dev/null || date "+%F %T %z" 2>/dev/null)
ifdef VERSION_STRING
CVFLAGS := -DVERSION_STRING='"${VERSION_STRING}"'
endif

$(BIN)/ssh-agent-on-demand: $(OBJ)/ssh-agent-on-demand_help.o

$(BIN)/%: $(OBJ)/%.o $(OBJ)/ssh-agent-utils.o | $(BIN)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)

$(OBJ)/%.o: src/%.cpp src/ssh-agent-utils.h | $(OBJ)
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $(CVFLAGS) $< -o $@

$(OBJ)/%_help.o: %_help.txt | $(OBJ)
	$(LD) -r -b binary $< -o $@
	-$(OBJCOPY) --rename-section .data=.rodata,alloc,load,readonly,data,contents $@ $@

$(BIN):
	mkdir $(BIN)

$(OBJ):
	mkdir $(OBJ)

$(MANDIR):
	mkdir $(MANDIR)

clean:
	rm -f $(OBJ)/* $(BIN)/* $(MANDIR)/*

install: bin/ssh-agent-on-demand
	install -m 755 bin/ssh-agent-on-demand /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/ssh-agent-on-demand /usr/local/share/man/man1/ssh-agent-on-demand.1
	-mandb -q

HELP2MANOK := $(shell help2man --version 2>/dev/null)
ifdef HELP2MANOK
all: $(MANDIR)/ssh-agent-on-demand.1

$(MANDIR)/ssh-agent-on-demand.1: $(BIN)/ssh-agent-on-demand | $(MANDIR)
	help2man -s 1 -N $(BIN)/ssh-agent-on-demand -n "SSH-Agent On Demand" -o $(MANDIR)/ssh-agent-on-demand.1

install: install-man

.PHONY: install-man

install-man: $(MANDIR)/ssh-agent-on-demand.1
	install -m 644 $(MANDIR)/ssh-agent-on-demand.1 /usr/local/share/man/man1/
	-mandb -pq

else
$(shell echo "Install help2man for man page generation" >&2)
endif
