CC      ?= gcc
CXX     ?= g++
CFLAGS  ?= -O2 -g -fPIC -std=c11 -Wall -Wextra
CXXFLAGS?= -O2 -g -fPIC -std=c++17 -Wall -Wextra
LDFLAGS ?=

BUILD   := build
INCLUDES:= -Iinclude -Isrc/common

SERVER_OBJS := $(BUILD)/hook_engine.o $(BUILD)/trampoline.o $(BUILD)/server.o
ALL_TARGETS := $(BUILD)/ihook.so $(BUILD)/ihook-cli $(BUILD)/libdemo.so $(BUILD)/demo

.PHONY: all clean test demo server cli
all: $(ALL_TARGETS)

server: $(BUILD)/ihook.so
cli: $(BUILD)/ihook-cli
demo: $(BUILD)/libdemo.so $(BUILD)/demo

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/hook_engine.o: src/server/hook_engine.c include/ihook_engine.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD)/trampoline.o: src/server/trampoline.S | $(BUILD)
	$(CC) -fPIC -c $< -o $@

$(BUILD)/server.o: src/server/server.cpp src/common/json.hpp include/ihook_engine.h | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD)/ihook.so: $(SERVER_OBJS)
	$(CXX) -shared -o $@ $(SERVER_OBJS) -ldl -lpthread -Wl,-z,relro,-z,now

$(BUILD)/ihook-cli: src/cli/ihook_cli.cpp src/common/json.hpp include/ihook_engine.h | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@

$(BUILD)/libdemo.so: demo/libdemo.cpp demo/libdemo.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -shared -Wl,-soname,libdemo.so -o $@ demo/libdemo.cpp

$(BUILD)/demo: demo/demo_main.cpp demo/libdemo.h $(BUILD)/libdemo.so | $(BUILD)
	$(CXX) $(CXXFLAGS) demo/demo_main.cpp -o $@ -L$(BUILD) -ldemo \
		-Wl,-rpath,'$$ORIGIN' -pthread

test: all
	./tests/smoke.sh

clean:
	rm -f $(BUILD)/*.o $(ALL_TARGETS)
