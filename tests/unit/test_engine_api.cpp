// Public-API unit/integration tests for the ihook engine.
//
// The engine is linked as build/libihook_engine.so (not build/ihook.so), so
// there is no control socket.  The test executable and its helper libraries
// are ordinary ELF objects whose GOT/PLT relocations the engine scans.
#include "ihook_engine.h"
#include "unit_target.h"

#include <atomic>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" int lazy_add(int value);

namespace {

int g_failures;
std::string g_dir;
std::string g_log_path;
std::string g_log2_path;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "    CHECK failed at %s:%d: %s\n", __FILE__, \
                   __LINE__, #cond);                                    \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

#define REQUIRE(cond)                                                   \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "    REQUIRE failed at %s:%d: %s\n",         \
                   __FILE__, __LINE__, #cond);                          \
      ++g_failures;                                                     \
      return;                                                           \
    }                                                                   \
  } while (0)

#define RUN(fn)                                                         \
  do {                                                                  \
    std::printf("[ RUN ] %s\n", #fn);                                   \
    int before = g_failures;                                            \
    fn();                                                               \
    std::printf(g_failures == before ? "[ OK  ] %s\n" : "[FAIL ] %s\n", \
                #fn);                                                   \
  } while (0)

std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::string();
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

std::string executable_dir() {
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return std::string(".");
  buf[n] = '\0';
  std::string path(buf);
  size_t slash = path.find_last_of('/');
  return slash == std::string::npos ? std::string(".") : path.substr(0, slash);
}

bool find_slot(const char* symbol, const char* module_part,
               ihook_slot_info* out) {
  ihook_engine_info info;
  ihook_engine_get_info(&info);
  for (int i = 0; i < info.slot_count; ++i) {
    ihook_slot_info si;
    if (ihook_engine_get_slot(i, &si) != 0) continue;
    if (!si.current) continue;
    if (std::strcmp(si.symbol, symbol) != 0) continue;
    if (module_part && *module_part &&
        std::strstr(si.module, module_part) == nullptr) {
      continue;
    }
    if (out) *out = si;
    return true;
  }
  return false;
}

bool find_hook_by_id(int id, ihook_hook_info* out) {
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    ihook_hook_info hi;
    if (ihook_engine_get_hook(i, &hi) != 0) continue;
    if (hi.id != id) continue;
    if (out) *out = hi;
    return true;
  }
  return false;
}


int hook_symbol(const char* symbol, const char* module, int mode, int* hook_id,
                int* slot_count, int* failed_slots, std::string* error) {
  int id = -1;
  int slots = 0;
  int failed = 0;
  char err[IHOOK_MSG_MAX] = {0};
  char msg[IHOOK_MSG_MAX] = {0};
  int rc = ihook_engine_hook(symbol, module ? module : "", mode, err,
                             sizeof(err), msg, sizeof(msg), &id, &slots,
                             &failed);
  if (hook_id) *hook_id = id;
  if (slot_count) *slot_count = slots;
  if (failed_slots) *failed_slots = failed;
  if (error) *error = err;
  return rc;
}

int unhook_symbol(const char* symbol, const char* module, int* restored,
                  int* failed_slots, std::string* error) {
  int r = 0;
  int f = 0;
  char err[IHOOK_MSG_MAX] = {0};
  char msg[IHOOK_MSG_MAX] = {0};
  int rc = ihook_engine_unhook(symbol, module ? module : "", err, sizeof(err),
                               msg, sizeof(msg), &r, &f);
  if (restored) *restored = r;
  if (failed_slots) *failed_slots = f;
  if (error) *error = err;
  return rc;
}

void cleanup_hooks() {
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    ihook_hook_info hi;
    if (ihook_engine_get_hook(i, &hi) != 0) continue;
    if (!hi.active) continue;
    char err[IHOOK_MSG_MAX] = {0};
    char msg[IHOOK_MSG_MAX] = {0};
    int restored = 0;
    int failed = 0;
    ihook_engine_unhook(hi.symbol, hi.module_filter, err, sizeof(err), msg,
                        sizeof(msg), &restored, &failed);
  }
}

std::string plugin_path() {
  return executable_dir() + "/libunit_plugin.so";
}

void test_init_and_refresh() {
  char err[IHOOK_MSG_MAX] = {0};
  REQUIRE(ihook_engine_refresh(err, sizeof(err)) == 0);

  ihook_engine_info info;
  ihook_engine_get_info(&info);
  CHECK(info.pid == (int)getpid());
  CHECK(info.enabled == 1);
  CHECK(info.slot_count > 0);
  CHECK(info.module_count > 0);
  CHECK(info.log_path[0] != '\0');
  CHECK(std::strstr(info.self_path, "libihook_engine") != nullptr);
  CHECK(std::strstr(info.log_path, "engine.jsonl") != nullptr);

  int before = info.slot_count;
  for (int i = 0; i < 3; ++i) {
    CHECK(ihook_engine_refresh(err, sizeof(err)) == 0);
  }
  ihook_engine_get_info(&info);
  CHECK(info.slot_count == before);

  ihook_slot_info si;
  CHECK(find_slot("unit_add", "", &si));
  CHECK(si.current);
  CHECK(!si.active);
  CHECK(si.slot_addr != 0);

  CHECK(find_slot("unit_scale", "", &si));
  CHECK(find_slot("unit_call_puts", "", &si));
}

void test_enter_mode_and_unhook() {
  cleanup_hooks();
  int id = -1;
  int slots = 0;
  int failed = 0;
  std::string err;
  REQUIRE(hook_symbol("unit_add", "", IHOOK_MODE_ENTER, &id, &slots, &failed,
                      &err) == 0);
  CHECK(id > 0);
  CHECK(slots >= 1);
  CHECK(failed == 0);

  CHECK(unit_add(2, 3) == 5);
  CHECK(unit_add(10, 20) == 30);

  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 2);
  CHECK(hi.returns == 0);

  uint64_t calls_before_unhook = hi.calls;
  CHECK(unhook_symbol("unit_add", "", nullptr, nullptr, &err) == 0);
  CHECK(unit_add(1, 1) == 2);
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.active == 0);
  CHECK(hi.calls == calls_before_unhook);
}

void test_enter_exit_mode() {
  cleanup_hooks();
  int id = -1;
  int slots = 0;
  int failed = 0;
  std::string err;
  REQUIRE(hook_symbol("unit_add", "", IHOOK_MODE_ENTER_EXIT, &id, &slots,
                      &failed, &err) == 0);
  for (int i = 0; i < 100; ++i) {
    CHECK(unit_add(i, 1) == i + 1);
  }
  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 100);
  CHECK(hi.returns == 100);
  CHECK(hi.cycles > 0);
  CHECK(hi.errors == 0);
  CHECK(unhook_symbol("unit_add", "", nullptr, nullptr, &err) == 0);
}

void test_double_and_variadic_returns() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;

  REQUIRE(hook_symbol("unit_scale", "", IHOOK_MODE_ENTER_EXIT, &id, &slots,
                      &failed, &err) == 0);
  CHECK(unit_scale(2.0) == 5.0);
  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 1);
  CHECK(hi.returns == 1);
  CHECK(unhook_symbol("unit_scale", "", nullptr, nullptr, &err) == 0);

  REQUIRE(hook_symbol("unit_variadic", "", IHOOK_MODE_ENTER_EXIT, &id, &slots,
                      &failed, &err) == 0);
  CHECK(unit_variadic(4, 1, 2.5, 3, 4.5) == 11.0);
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 1);
  CHECK(hi.returns == 1);
  CHECK(unhook_symbol("unit_variadic", "", nullptr, nullptr, &err) == 0);
}

void test_cpp_method_symbol() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;
  const char* mangled = "_ZN4unit7Counter3addEi";

  ihook_slot_info si;
  REQUIRE(find_slot(mangled, "", &si));
  REQUIRE(hook_symbol(mangled, "", IHOOK_MODE_ENTER, &id, &slots, &failed,
                      &err) == 0);

  unit::Counter counter(10);
  counter.add(5);
  CHECK(counter.value() == 15);

  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 1);
  CHECK(unhook_symbol(mangled, "", nullptr, nullptr, &err) == 0);
}

void test_module_filter() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;
  REQUIRE(hook_symbol("puts", "libunittest_target.so", IHOOK_MODE_ENTER, &id,
                      &slots, &failed, &err) == 0);
  CHECK(slots == 1);

  unit_call_puts("unit-target-puts-1");
  unit_call_puts("unit-target-puts-2");
  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 2);

  // The test executable's own puts slot is not patched because of the module
  // filter, so this call must not increment the counter.
  puts("unit-direct-puts");
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 2);
  CHECK(unhook_symbol("puts", "libunittest_target.so", nullptr, nullptr,
                      &err) == 0);
}

void test_duplicate_and_missing() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;
  REQUIRE(hook_symbol("unit_add", "", IHOOK_MODE_ENTER, &id, &slots, &failed,
                      &err) == 0);

  std::string duplicate_err;
  int dup_id = -1;
  CHECK(hook_symbol("unit_add", "", IHOOK_MODE_ENTER, &dup_id, nullptr,
                    nullptr, &duplicate_err) == -1);
  CHECK(duplicate_err == "already_hooked");

  CHECK(unhook_symbol("unit_add", "", nullptr, nullptr, &err) == 0);
  std::string second_unhook_err;
  CHECK(unhook_symbol("unit_add", "", nullptr, nullptr, &second_unhook_err) ==
        -1);
  CHECK(second_unhook_err == "not_hooked");

  std::string missing_err;
  CHECK(hook_symbol("definitely_missing_unit_symbol", "", IHOOK_MODE_ENTER,
                    nullptr, nullptr, nullptr, &missing_err) == -1);
  CHECK(missing_err == "symbol_not_found");
}

void test_thread_safety() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;
  REQUIRE(hook_symbol("unit_add", "", IHOOK_MODE_ENTER_EXIT, &id, &slots,
                      &failed, &err) == 0);

  constexpr int kThreads = 4;
  constexpr int kIterations = 5000;
  std::atomic<long long> total{0};
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&total, t] {
      long long local = 0;
      for (int i = 0; i < kIterations; ++i) {
        local += unit_add(i, t + 1);
      }
      total.fetch_add(local, std::memory_order_relaxed);
    });
  }
  for (auto& th : threads) th.join();

  long long expected = 0;
  for (int t = 0; t < kThreads; ++t) {
    for (int i = 0; i < kIterations; ++i) expected += i + t + 1;
  }
  CHECK(total.load() == expected);

  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == (uint64_t)kThreads * kIterations);
  CHECK(hi.returns == (uint64_t)kThreads * kIterations);
  CHECK(hi.errors == 0);
  CHECK(unhook_symbol("unit_add", "", nullptr, nullptr, &err) == 0);
}

void test_lazy_binding() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;

  // lazy_add is linked with -z lazy and is not called before this point.
  REQUIRE(hook_symbol("lazy_add", "", IHOOK_MODE_ENTER_EXIT, &id, &slots,
                      &failed, &err) == 0);
  ihook_slot_info si;
  REQUIRE(find_slot("lazy_add", "", &si));
  CHECK(si.lazy == 1);

  CHECK(lazy_add(41) == 42);
  ihook_hook_info hi;
  REQUIRE(find_hook_by_id(id, &hi));
  CHECK(hi.calls == 1);
  CHECK(hi.returns == 1);
  CHECK(unhook_symbol("lazy_add", "", nullptr, nullptr, &err) == 0);
}

void test_dlopen_deactivation_and_extension() {
  cleanup_hooks();
  std::string err;
  int id = -1;
  int slots = 0;
  int failed = 0;
  REQUIRE(hook_symbol("unit_add", "", IHOOK_MODE_ENTER, &id, &slots, &failed,
                      &err) == 0);

  ihook_hook_info before;
  REQUIRE(find_hook_by_id(id, &before));
  uint64_t initial_slots = (uint64_t)before.slot_count;
  uint64_t initial_calls = before.calls;

  std::string path = plugin_path();
  void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    std::fprintf(stderr, "    dlopen(%s): %s\n", path.c_str(), dlerror());
  }
  REQUIRE(handle != nullptr);

  CHECK(ihook_engine_refresh(nullptr, 0) == 0);
  ihook_hook_info extended;
  REQUIRE(find_hook_by_id(id, &extended));
  CHECK(extended.slot_count > before.slot_count);

  using PluginFn = int (*)(int);
  PluginFn plugin_call = (PluginFn)dlsym(handle, "plugin_call");
  REQUIRE(plugin_call != nullptr);
  CHECK(plugin_call(5) == 105);

  ihook_hook_info after_call;
  REQUIRE(find_hook_by_id(id, &after_call));
  CHECK(after_call.calls == initial_calls + 1);

  CHECK(dlclose(handle) == 0);
  CHECK(ihook_engine_refresh(nullptr, 0) == 0);
  ihook_hook_info after_close;
  REQUIRE(find_hook_by_id(id, &after_close));
  CHECK(after_close.active == 1);
  CHECK(after_close.slot_count == (int)initial_slots);
  CHECK(after_close.calls == after_call.calls);

  CHECK(unhook_symbol("unit_add", "", nullptr, nullptr, &err) == 0);
  // Keep the compiler from optimizing the initial-slot variable away.
  CHECK(initial_slots >= 1);
}

void test_log_switch() {
  char err[IHOOK_MSG_MAX] = {0};
  CHECK(ihook_engine_set_log_path(g_log2_path.c_str(), err, sizeof(err)) == 0);
  ihook_engine_flush_log(1);
  CHECK(ihook_engine_set_log_path(g_log_path.c_str(), err, sizeof(err)) == 0);

  std::string switched = read_file(g_log2_path);
  CHECK(switched.find("\"event\":\"log_path\"") != std::string::npos);

  char bad_err[IHOOK_MSG_MAX] = {0};
  CHECK(ihook_engine_set_log_path("/no/such/ihook-directory/log.jsonl",
                                  bad_err, sizeof(bad_err)) == -1);
  CHECK(bad_err[0] != '\0');
}

void test_log_contents() {
  cleanup_hooks();
  ihook_engine_flush_log(1);
  ihook_engine_shutdown();

  std::string log = read_file(g_log_path);
  CHECK(log.find("\"event\":\"start\"") != std::string::npos);
  CHECK(log.find("\"event\":\"hook\"") != std::string::npos);
  CHECK(log.find("\"event\":\"unhook\"") != std::string::npos);
  CHECK(log.find("\"event\":\"error\"") != std::string::npos);
  CHECK(log.find("symbol_not_found") != std::string::npos);
  CHECK(log.find("\"event\":\"stats\"") != std::string::npos);
  CHECK(log.find("\"event\":\"exit\"") != std::string::npos);
  CHECK(log.find("\"symbol\":\"unit_add\"") != std::string::npos);
}

}  // namespace

int main() {
  char tmpl[] = "/tmp/ihook-unit-api-XXXXXX";
  char* dir = mkdtemp(tmpl);
  if (!dir) {
    std::perror("mkdtemp");
    return 1;
  }
  g_dir = dir;
  g_log_path = g_dir + "/engine.jsonl";
  g_log2_path = g_dir + "/switched.jsonl";

  setenv("IHOOK_LOG", g_log_path.c_str(), 1);
  setenv("IHOOK_RUNDIR", g_dir.c_str(), 1);
  unsetenv("IHOOK_DISABLE");

  std::printf("ihook public API unit tests (log dir: %s)\n", g_dir.c_str());
  if (ihook_engine_init() != 0) {
    std::fprintf(stderr, "ihook_engine_init failed\n");
    return 1;
  }
  ihook_engine_log_start("/tmp/ihook-unit-api.sock");

  RUN(test_init_and_refresh);
  RUN(test_enter_mode_and_unhook);
  RUN(test_enter_exit_mode);
  RUN(test_double_and_variadic_returns);
  RUN(test_cpp_method_symbol);
  RUN(test_module_filter);
  RUN(test_duplicate_and_missing);
  RUN(test_thread_safety);
  RUN(test_lazy_binding);
  RUN(test_dlopen_deactivation_and_extension);
  RUN(test_log_switch);
  RUN(test_log_contents);

  if (g_failures) {
    std::printf("FAILED: %d check(s); logs kept in %s\n", g_failures,
                g_dir.c_str());
    return 1;
  }

  unlink(g_log_path.c_str());
  unlink(g_log2_path.c_str());
  rmdir(g_dir.c_str());
  std::printf("PASS: public API engine unit tests\n");
  return 0;
}
