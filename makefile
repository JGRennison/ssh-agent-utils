CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter -O3
LDFLAGS ?=
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CXXFLAGS += -std=c++11
LDLIBS = -lb64

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

.PHONY: install all
.SECONDARY:

all: $(BIN)/ssh-agent-passthrough $(BIN)/ssh-agent-on-demand

$(BIN)/%: $(OBJ)/%.o $(OBJ)/ssh-agent-utils.o | $(BIN)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< $(OBJ)/ssh-agent-utils.o $(LOADLIBES) $(LDLIBS)

$(OBJ)/%.o: src/%.cpp src/ssh-agent-utils.h | $(OBJ)
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

$(BIN):
	mkdir $(BIN)

$(OBJ):
	mkdir $(OBJ)

clean:
	rm -f $(OBJ)/* $(BIN)/*

install: bin/ssh-agent-on-demand
	cp bin/ssh-agent-on-demand /usr/local/bin/
