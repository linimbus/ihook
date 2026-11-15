CC      ?= gcc
CXX     ?= g++
CFLAGS  ?= -O2 -g -fPIC -std=c11 -Wall -Wextra
CXXFLAGS?= -O2 -g -fPIC -std=c++17 -Wall -Wextra
LDFLAGS ?=

BUILD   := build
INCLUDES:= -Iinclude -Isrc/common

SERVER_OBJS := $(BUILD)/hook_engine.o $(BUILD)/trampoline.o $(BUILD)/server.o
ALL_TARGETS := $(BUILD)/ihook.so $(BUILD)/ihook-cli $(BUILD)/libdemo.so $(BUILD)/demo

UNIT_ENGINE := $(BUILD)/libihook_engine.so
UNIT_TARGET := $(BUILD)/libunittest_target.so
UNIT_LAZY   := $(BUILD)/libunit_lazy.so
UNIT_PLUGIN := $(BUILD)/libunit_plugin.so
UNIT_INTERNAL := $(BUILD)/test_engine_internal
UNIT_API      := $(BUILD)/test_engine_api
UNIT_TARGETS  := $(UNIT_ENGINE) $(UNIT_TARGET) $(UNIT_LAZY) $(UNIT_PLUGIN) \
                 $(UNIT_INTERNAL) $(UNIT_API)

.PHONY: all clean test test-unit unit server cli demo
all: $(ALL_TARGETS)

server: $(BUILD)/ihook.so
cli: $(BUILD)/ihook-cli
demo: $(BUILD)/libdemo.so $(BUILD)/demo
unit: $(UNIT_TARGETS)

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

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

$(UNIT_ENGINE): $(BUILD)/hook_engine.o $(BUILD)/trampoline.o
	$(CC) -shared -o $@ $(BUILD)/hook_engine.o $(BUILD)/trampoline.o \
		-ldl -lpthread -Wl,-z,relro,-z,now

$(UNIT_TARGET): tests/unit/unit_target.cpp tests/unit/unit_target.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -shared -Wl,-soname,libunittest_target.so \
		-o $@ tests/unit/unit_target.cpp

$(UNIT_LAZY): tests/unit/unit_lazy.c | $(BUILD)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libunit_lazy.so -Wl,-z,lazy \
		-o $@ tests/unit/unit_lazy.c

$(UNIT_PLUGIN): tests/unit/unit_plugin.c $(UNIT_TARGET) | $(BUILD)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libunit_plugin.so \
		-o $@ tests/unit/unit_plugin.c -L$(BUILD) -lunittest_target \
		-Wl,-rpath,'$$ORIGIN'

$(UNIT_INTERNAL): tests/unit/test_engine_internal.c \
                  src/server/hook_engine.c include/ihook_engine.h \
                  $(BUILD)/trampoline.o | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) -Isrc/server tests/unit/test_engine_internal.c \
		$(BUILD)/trampoline.o -o $@ -ldl -lpthread

$(UNIT_API): tests/unit/test_engine_api.cpp tests/unit/unit_target.h \
             $(UNIT_ENGINE) $(UNIT_TARGET) $(UNIT_LAZY) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -Itests/unit tests/unit/test_engine_api.cpp \
		-o $@ -L$(BUILD) -lihook_engine -lunittest_target -lunit_lazy \
		-Wl,-rpath,'$$ORIGIN' -Wl,-z,lazy -ldl -lpthread

test-unit: unit
	./$(UNIT_INTERNAL)
	./$(UNIT_API)

test: all unit
	./tests/smoke.sh
	./$(UNIT_INTERNAL)
	./$(UNIT_API)

clean:
	rm -f $(BUILD)/*.o $(ALL_TARGETS) $(UNIT_TARGETS)
