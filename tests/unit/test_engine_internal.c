/*
 * White-box unit tests for the core hook engine.
 *
 * The engine source is included directly so the test can exercise static
 * helpers and the synthetic-slot trampoline path without a real GOT patch.
 * Link with build/trampoline.o.
 */
#include "../../src/server/hook_engine.c"

#include <math.h>
#include <stdarg.h>
#include <sys/wait.h>

static int g_failures;

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) {                                                        \
      fprintf(stderr, "    CHECK failed at %s:%d: %s\n", __FILE__,   \
                   __LINE__, #cond);                                      \
      ++g_failures;                                                       \
    }                                                                     \
  } while (0)

#define RUN(fn)                                                           \
  do {                                                                    \
    printf("[ RUN ] %s\n", #fn);                                     \
    int before = g_failures;                                              \
    fn();                                                                 \
    printf(g_failures == before ? "[ OK  ] %s\n" : "[FAIL ] %s\n",   \
                #fn);                                                     \
  } while (0)

static void reset_state(void) {
  g_slot_count = 0;
  for (int i = 0; i < 8; ++i) {
    memset(&g_slots[i], 0, sizeof(g_slots[i]));
  }
  for (int i = 0; i < 8; ++i) {
    memset(&g_hooks[i], 0, sizeof(g_hooks[i]));
  }
  g_hook_seq = 0;
  tls_depth = 0;
  tls_in_handler = 0;
  g_stats_dirty = 0;
}

static void prepare_slot(void* original, int mode) {
  reset_state();
  g_slot_count = 1;
  g_slots[0].id = 0;
  g_slots[0].orig_addr = (uintptr_t)original;
  g_slots[0].active = 1;
  g_slots[0].hook_idx = 0;
  g_hooks[0].id = 1;
  g_hooks[0].active = 1;
  g_hooks[0].mode = mode;
  strcpy(g_hooks[0].symbol, "unit_test_symbol");
}

__attribute__((noinline)) static int orig_add(int a, int b) { return a + b; }

__attribute__((noinline)) static double orig_scale(double value) {
  return value * 2.5;
}

__attribute__((noinline)) static double orig_variadic(int count, ...) {
  va_list ap;
  va_start(ap, count);
  double sum = 0.0;
  for (int i = 0; i < count; ++i) {
    if ((i & 1) == 0) {
      sum += (double)va_arg(ap, int);
    } else {
      sum += va_arg(ap, double);
    }
  }
  va_end(ap);
  return sum;
}

__attribute__((noinline)) static long orig_sum8(long a, long b, long c, long d,
                                                long e, long f, long g, long h) {
  return a + b + c + d + e + f + g + h;
}

static void test_module_matching(void) {
  CHECK(module_match("/opt/app/libdemo.so", "") == 1);
  CHECK(module_match("/opt/app/libdemo.so", "libdemo.so") == 1);
  CHECK(module_match("/opt/app/libdemo.so", "libdemo*") == 1);
  CHECK(module_match("/opt/app/libdemo.so", "/opt/app/libdemo.so") == 1);
  CHECK(module_match("/opt/app/libdemo.so", "libc.so.6") == 0);

  CHECK(same_module_path("/opt/app/libdemo.so", "libdemo.so") == 1);
  CHECK(same_module_path("/opt/app/libdemo.so", "/opt/app/libdemo.so") == 1);
  CHECK(same_module_path("/opt/a.so", "/opt/b.so") == 0);
  CHECK(same_module_path(NULL, "x") == 0);
}

static void test_lazy_detection(void) {
  unsigned char classic[8] = {0x68, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00};
  CHECK(looks_lazy((uintptr_t)classic, "unit-test") == 1);

  unsigned char cet[8] = {0x68, 0x00, 0x00, 0x00, 0x00, 0xF2, 0xE9, 0x00};
  CHECK(looks_lazy((uintptr_t)cet, "unit-test") == 1);

  unsigned char not_stub[8] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                               0x90};
  CHECK(looks_lazy((uintptr_t)not_stub, "unit-test") == 0);
  CHECK(looks_lazy(0, "unit-test") == 1);
}

static void test_got_patch(void) {
  void* page = mmap(NULL, g_page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(page != MAP_FAILED);
  if (page == MAP_FAILED) return;

  uintptr_t* slot = (uintptr_t*)page;
  *slot = 0x1111;
  CHECK(mprotect(page, g_page_size, PROT_READ) == 0);

  CHECK(patch_got((uintptr_t)slot, 0x2222) == 0);
  CHECK(*slot == 0x2222);

  int prot = 0;
  CHECK(addr_prot((uintptr_t)slot, &prot) == 0);
  CHECK((prot & PROT_WRITE) == 0);

  CHECK(mprotect(page, g_page_size, PROT_READ | PROT_WRITE) == 0);
  CHECK(munmap(page, g_page_size) == 0);

  /* Unmapped address: addr_prot() must fail cleanly. */
  CHECK(patch_got((uintptr_t)0x1, 0x2222) == -1);
}

static void test_hash_table(void) {
  reset_state();
  memset(g_slot_hash, 0, sizeof(g_slot_hash));
  g_slot_count = 3;
  g_slots[0].slot_addr = 0x1000;
  g_slots[1].slot_addr = 0x2000;
  g_slots[2].slot_addr = 0x3000;
  for (int i = 0; i < 3; ++i) hash_insert(i);
  CHECK(hash_find(0x1000) == 0);
  CHECK(hash_find(0x2000) == 1);
  CHECK(hash_find(0x3000) == 2);
  CHECK(hash_find(0x4000) == -1);
}

static void test_trampoline_enter(void) {
  prepare_slot((void*)&orig_add, IHOOK_MODE_ENTER);
  void* tr = make_trampoline(0);
  CHECK(tr != NULL);
  if (!tr) return;

  int (*fn)(int, int) = (int (*)(int, int))(uintptr_t)tr;
  CHECK(fn(2, 3) == 5);
  CHECK(g_hooks[0].calls == 1);
  CHECK(g_slots[0].calls == 1);
  CHECK(g_hooks[0].returns == 0);
  CHECK(tls_depth == 0);
  munmap(tr, g_page_size);
}

static void test_trampoline_enter_exit(void) {
  prepare_slot((void*)&orig_add, IHOOK_MODE_ENTER_EXIT);
  void* tr = make_trampoline(0);
  CHECK(tr != NULL);
  if (!tr) return;

  int (*fn)(int, int) = (int (*)(int, int))(uintptr_t)tr;
  for (int i = 0; i < 100; ++i) {
    CHECK(fn(i, 1) == i + 1);
  }
  CHECK(g_hooks[0].calls == 100);
  CHECK(g_hooks[0].returns == 100);
  CHECK(g_hooks[0].cycles > 0);
  CHECK(g_hooks[0].errors == 0);
  CHECK(tls_depth == 0);
  munmap(tr, g_page_size);
}

static void test_trampoline_double_return(void) {
  prepare_slot((void*)&orig_scale, IHOOK_MODE_ENTER_EXIT);
  void* tr = make_trampoline(0);
  CHECK(tr != NULL);
  if (!tr) return;

  double (*fn)(double) = (double (*)(double))(uintptr_t)tr;
  CHECK(fn(4.0) == 10.0);
  CHECK(g_hooks[0].calls == 1);
  CHECK(g_hooks[0].returns == 1);
  munmap(tr, g_page_size);
}

static void test_trampoline_variadic(void) {
  prepare_slot((void*)&orig_variadic, IHOOK_MODE_ENTER_EXIT);
  void* tr = make_trampoline(0);
  CHECK(tr != NULL);
  if (!tr) return;

  double (*fn)(int, ...) = (double (*)(int, ...))(uintptr_t)tr;
  CHECK(fn(4, 1, 2.5, 3, 4.5) == 11.0);
  CHECK(g_hooks[0].returns == 1);
  munmap(tr, g_page_size);
}

static void test_trampoline_stack_args(void) {
  prepare_slot((void*)&orig_sum8, IHOOK_MODE_ENTER_EXIT);
  void* tr = make_trampoline(0);
  CHECK(tr != NULL);
  if (!tr) return;

  long (*fn)(long, long, long, long, long, long, long, long) =
      (long (*)(long, long, long, long, long, long, long, long))(uintptr_t)tr;
  CHECK(fn(1, 2, 3, 4, 5, 6, 7, 8) == 36);
  CHECK(g_hooks[0].returns == 1);
  munmap(tr, g_page_size);
}

static void test_frame_overflow(void) {
  prepare_slot((void*)&orig_add, IHOOK_MODE_ENTER_EXIT);
  void* tr = make_trampoline(0);
  CHECK(tr != NULL);
  if (!tr) return;

  tls_depth = IHOOK_TLS_FRAMES;
  int (*fn)(int, int) = (int (*)(int, int))(uintptr_t)tr;
  CHECK(fn(7, 8) == 15);
  CHECK(g_hooks[0].calls == 1);
  CHECK(g_hooks[0].returns == 0);
  CHECK(g_hooks[0].errors == 1);
  tls_depth = 0;
  munmap(tr, g_page_size);
}

static void test_invalid_slot_id(void) {
  reset_state();
  uintptr_t result = ihook_on_enter(12345, NULL);
  CHECK(result == (uintptr_t)&ihook_bad_exit);
}

static void test_log_json(void) {
  char path[] = "/tmp/ihook-unit-log-XXXXXX";
  int fd = mkstemp(path);
  CHECK(fd >= 0);
  if (fd < 0) return;

  g_log_fd = fd;
  g_pid = (int)getpid();
  reset_state();
  g_hooks[0].id = 7;
  g_hooks[0].active = 1;
  g_hooks[0].mode = IHOOK_MODE_ENTER_EXIT;
  g_hooks[0].slot_count = 2;
  g_hooks[0].calls = 7;
  g_hooks[0].returns = 3;
  g_hooks[0].errors = 1;
  strcpy(g_hooks[0].symbol, "ev\"il\\sym");

  log_event_hook(7, "sym\"x\\y", "mod", IHOOK_MODE_ENTER_EXIT, 2, 1, "ok",
                 NULL);
  log_event_error("hook", "missing", "", "symbol_not_found", "bad\\path");
  log_stats_locked(1);

  char buf[32768];
  ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
  CHECK(n > 0);
  if (n > 0) {
    buf[n] = '\0';
    CHECK(strstr(buf, "\"event\":\"hook\"") != NULL);
    CHECK(strstr(buf, "\"event\":\"error\"") != NULL);
    CHECK(strstr(buf, "\"event\":\"stats\"") != NULL);
    CHECK(strstr(buf, "sym\\\"x\\\\y") != NULL);
    CHECK(strstr(buf, "symbol_not_found") != NULL);
    CHECK(strstr(buf, "\"calls\":7") != NULL);
    CHECK(strstr(buf, "\"total_calls\":7") != NULL);
  }

  close(fd);
  unlink(path);
  g_log_fd = -1;
}

static void test_exit_underflow(void) {
  pid_t pid = fork();
  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, 2);
      close(devnull);
    }
    tls_depth = 0;
    ihook_on_exit();  /* must terminate with status 127 */
    _exit(0);
  }
  CHECK(pid > 0);
  if (pid <= 0) return;
  int status = 0;
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 127);
}

int main(void) {
  long ps = sysconf(_SC_PAGESIZE);
  g_page_size = ps > 0 ? (size_t)ps : 4096;

  printf("ihook internal engine unit tests\n");
  RUN(test_module_matching);
  RUN(test_lazy_detection);
  RUN(test_got_patch);
  RUN(test_hash_table);
  RUN(test_trampoline_enter);
  RUN(test_trampoline_enter_exit);
  RUN(test_trampoline_double_return);
  RUN(test_trampoline_variadic);
  RUN(test_trampoline_stack_args);
  RUN(test_frame_overflow);
  RUN(test_invalid_slot_id);
  RUN(test_log_json);
  RUN(test_exit_underflow);

  if (g_failures) {
    printf("FAILED: %d check(s)\n", g_failures);
    return 1;
  }
  printf("PASS: internal engine unit tests\n");
  return 0;
}
