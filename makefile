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
VERDIR = version

.PHONY: install uninstall all
.SECONDARY:

all: $(BIN)/ssh-agent-passthrough $(BIN)/ssh-agent-on-demand

VERSION_STRING := $(shell git describe --always --dirty=-m 2>/dev/null || date "+%F %T %z" 2>/dev/null || echo "Unknown version")

-include $(OBJ)/*.d

MAKEDEPS = -MMD -MP -MT '$@ $(patsubst %.o,%.d,$@)'

$(BIN)/ssh-agent-on-demand: $(OBJ)/ssh-agent-on-demand_help.o $(OBJ)/ssh-agent-on-demand_more_help.o $(OBJ)/ssh-agent-on-demand_version.o

$(BIN)/%: $(OBJ)/%.o $(OBJ)/ssh-agent-utils.o $(OBJ)/utils.o | $(BIN)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)

$(OBJ)/%.o: src/%.cpp | $(OBJ)
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $(MAKEDEPS) $< -o $@

$(OBJ)/%_help.o: %_help.txt | $(OBJ)
	$(LD) -r -b binary $< -o $@
	-$(OBJCOPY) --rename-section .data=.rodata,alloc,load,readonly,data,contents $@ $@

$(OBJ)/%_version.o: $(VERDIR)/%_version.txt | $(OBJ)
	$(LD) -r -b binary $< -o $@
	-$(OBJCOPY) --rename-section .data=.rodata,alloc,load,readonly,data,contents $@ $@

$(VERDIR)/%_version.txt: src/*.cpp src/*.h *_help.txt authors.txt makefile | $(VERDIR) # Rebuild version string whenever any source changes
	echo '$* $(VERSION_STRING)' > $@
	echo '' >> $@
	cat authors.txt >> $@

BUILDDIRS := $(BIN) $(OBJ) $(MANDIR) $(VERDIR)

$(BUILDDIRS):
	mkdir $@

# This is deliberately non-recursive to prevent accidents
clean:
	rm -f $(addsuffix /*,$(BUILDDIRS))
	rm -f -d $(BUILDDIRS)

install: bin/ssh-agent-on-demand
	install -m 755 bin/ssh-agent-on-demand /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/ssh-agent-on-demand /usr/local/share/man/man1/ssh-agent-on-demand.1
	-mandb -q

HELP2MANOK := $(shell help2man --version 2>/dev/null)
ifdef HELP2MANOK
all: $(MANDIR)/ssh-agent-on-demand.1

$(MANDIR)/ssh-agent-on-demand.1.txt: ssh-agent-on-demand_help.txt ssh-agent-on-demand_more_help.txt | $(MANDIR)
	sed -s -e '$$G' $^ > $@

$(MANDIR)/ssh-agent-on-demand.1: $(MANDIR)/ssh-agent-on-demand.1.txt $(VERDIR)/ssh-agent-on-demand_version.txt | $(MANDIR)
	help2man -s 1 -N cat -h $(MANDIR)/ssh-agent-on-demand.1.txt -v $(VERDIR)/ssh-agent-on-demand_version.txt -n "SSH-Agent On Demand" -o $(MANDIR)/ssh-agent-on-demand.1

install: install-man

.PHONY: install-man

install-man: $(MANDIR)/ssh-agent-on-demand.1
	install -m 644 $(MANDIR)/ssh-agent-on-demand.1 /usr/local/share/man/man1/
	-mandb -pq

else
$(shell echo "Install help2man for man page generation" >&2)
endif
