# Install directories
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
datarootdir = $(prefix)/share
mandir = $(datarootdir)/man
man1dir = $(mandir)/man1
# end

DEFAULTTARG = all
INSTALLTARG = install-all

-include makefile.local

CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter -O3
LDFLAGS ?=
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CXXFLAGS += -std=c++11
LDLIBS += -lb64 -lmhash

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
MAN1 = man1
VER = ver

$(DEFAULTTARG):
install: $(INSTALLTARG)

.PHONY: install install-all uninstall all dumpversion
.PHONY: ssh-agent-on-demand install-ssh-agent-on-demand uninstall-ssh-agent-on-demand
.SECONDARY:

all: $(BIN)/ssh-agent-passthrough ssh-agent-on-demand

VERSION_STRING := $(shell cat version 2>/dev/null || git describe --tags --always --dirty=-m 2>/dev/null || date "+%F %T %z" 2>/dev/null || echo "Unknown version")

dumpversion:
	@echo $(VERSION_STRING)

-include $(OBJ)/*.d

MAKEDEPS = -MMD -MP -MT '$@ $(patsubst %.o,%.d,$@)'

ssh-agent-on-demand: $(BIN)/ssh-agent-on-demand

$(BIN)/ssh-agent-on-demand: $(OBJ)/ssh-agent-on-demand_help.o $(OBJ)/ssh-agent-on-demand_more_help.o $(OBJ)/ssh-agent-on-demand_version.o

$(BIN)/%: $(OBJ)/%.o $(OBJ)/ssh-agent-utils.o $(OBJ)/utils.o | $(BIN)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)

$(OBJ)/%.o: src/%.cpp | $(OBJ)
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $(MAKEDEPS) $< -o $@

$(OBJ)/%_help.o: %_help.txt | $(OBJ)
	$(LD) -r -b binary $< -o $@
	-$(OBJCOPY) --rename-section .data=.rodata,alloc,load,readonly,data,contents $@ $@

$(OBJ)/%_version.o: $(VER)/%_version.txt | $(OBJ)
	$(LD) -r -b binary $< -o $@
	-$(OBJCOPY) --rename-section .data=.rodata,alloc,load,readonly,data,contents $@ $@

$(VER)/%_version.txt: src/*.cpp src/*.h *_help.txt authors.txt makefile | $(VER) # Rebuild version string whenever any source changes
	echo '$* $(VERSION_STRING)' > $@
	echo '' >> $@
	cat authors.txt >> $@

BUILDDIRS := $(BIN) $(OBJ) $(MAN1) $(VER)

$(BUILDDIRS):
	mkdir $@

# This is deliberately non-recursive to prevent accidents
clean:
	rm -f $(addsuffix /*,$(BUILDDIRS))
	rm -f -d $(BUILDDIRS)

install-all: install-ssh-agent-on-demand

install-ssh-agent-on-demand: $(BIN)/ssh-agent-on-demand
	install -D -m 755 $(BIN)/ssh-agent-on-demand $(DESTDIR)$(bindir)/ssh-agent-on-demand

uninstall: uninstall-ssh-agent-on-demand

uninstall-ssh-agent-on-demand:
	rm -f $(DESTDIR)$(bindir)/ssh-agent-on-demand $(DESTDIR)$(man1dir)/ssh-agent-on-demand.1
	-mandb -q

HELP2MANOK := $(shell help2man --version 2>/dev/null)
ifdef HELP2MANOK
ssh-agent-on-demand: $(MAN1)/ssh-agent-on-demand.1

$(MAN1)/ssh-agent-on-demand.1.txt: ssh-agent-on-demand_help.txt ssh-agent-on-demand_more_help.txt | $(MAN1)
	sed -s -e '$$G' $^ > $@

$(MAN1)/ssh-agent-on-demand.1: $(MAN1)/ssh-agent-on-demand.1.txt $(VER)/ssh-agent-on-demand_version.txt | $(MAN1)
	help2man -s 1 -N cat -h $(MAN1)/ssh-agent-on-demand.1.txt -v $(VER)/ssh-agent-on-demand_version.txt -n "SSH-Agent On Demand" -o $(MAN1)/ssh-agent-on-demand.1

install-ssh-agent-on-demand: install-ssh-agent-on-demand-man

.PHONY: install-ssh-agent-on-demand-man

install-ssh-agent-on-demand-man: $(MAN1)/ssh-agent-on-demand.1
	install -D -m 644 $(MAN1)/ssh-agent-on-demand.1 $(DESTDIR)$(man1dir)/ssh-agent-on-demand.1
	-mandb -pq

else
$(shell echo "Install help2man for man page generation" >&2)
endif
