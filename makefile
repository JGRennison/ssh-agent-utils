BIN=bin
OBJ=obj

CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter --std=c++11 -O3 -g
LDFLAGS ?= -g
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CXXFLAGS += -std=c++11

.PHONY: install all
.SECONDARY:

all: $(BIN)/ssh-agent-passthrough

$(BIN)/%: $(OBJ)/%.o $(OBJ)/ssh-agent-utils.o | $(BIN)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< $(OBJ)/ssh-agent-utils.o $(LOADLIBES) $(LDLIBS)

$(OBJ)/%.o: %.cpp ssh-agent-utils.h
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

$(BIN):
	mkdir $(BIN)

$(OBJ):
	mkdir $(OBJ)

install: bin/ssh-agent-on-demand
	cp bin/ssh-agent-on-demand /usr/local/bin/
