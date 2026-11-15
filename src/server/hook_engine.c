/*
 * ihook_engine.c - GOT/PLT instrumentation engine.
 *
 * Lifecycle:
 *   - constructed by ihook.so (LD_PRELOAD), started from server.cpp
 *   - scans the loaded ELF objects with dl_iterate_phdr
 *   - records every .rela.plt JUMP_SLOT (and function GLOB_DAT) in a
 *     persistent slot table
 *   - writes a per-slot executable trampoline into a private page
 *   - patches the GOT entry with an 8-byte atomic store
 *
 * The hot path (ihook_on_enter / ihook_on_exit) allocates nothing, takes no
 * locks, and performs no I/O.  Statistics are written to the log file by a
 * separate flusher thread using raw syscalls.
 */
#define _GNU_SOURCE
#include "ihook_engine.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

#define IHOOK_HASH_SIZE 32768u
#define IHOOK_TLS_FRAMES 256u
#define IHOOK_LOG_BUF_SIZE (512u * 1024u)

typedef struct IHookSlot {
  uint32_t id;
  int active;
  int hook_idx;
  int lazy;
  int failed_hook_idx;
  uintptr_t slot_addr;
  uintptr_t raw_addr;
  uintptr_t orig_addr;
  uintptr_t local_addr;
  void* trampoline;
  uint64_t calls;
  uint64_t errors;
  uint32_t last_seen;
  char symbol[IHOOK_NAME_MAX];
  char module[IHOOK_PATH_MAX];
} IHookSlot;

typedef struct IHookHook {
  int id;
  int active;
  int mode;
  int slot_count;
  int failed_slots;
  char symbol[IHOOK_NAME_MAX];
  char module_filter[IHOOK_PATH_MAX];
  uint64_t calls;
  uint64_t returns;
  uint64_t cycles;
  uint64_t errors;
  uint64_t created_ms;
} IHookHook;

typedef struct IHookFrame {
  uintptr_t retaddr;
  uint32_t slot_id;
  uint32_t pad;
  uint64_t tsc;
} IHookFrame;

static IHookSlot g_slots[IHOOK_MAX_SLOTS];
static int g_slot_count;
static uint32_t g_slot_hash[IHOOK_HASH_SIZE];

static IHookHook g_hooks[IHOOK_MAX_HOOKS];
static int g_hook_seq;

static uint32_t g_refresh_gen = 1;
static int g_module_count;
static size_t g_page_size = 4096;

static int g_initialized;
static int g_enabled = 1;
static int g_shutdown_done;
static int g_pid;
static uint64_t g_start_ms;
static uint64_t g_next_stats_ms;

static char g_main_path[IHOOK_PATH_MAX];
static char g_self_path[IHOOK_PATH_MAX];
static uintptr_t g_self_base;
static char g_socket_path[IHOOK_PATH_MAX];
static char g_log_path[IHOOK_PATH_MAX];
static int g_log_fd = -1;
static int g_stats_dirty;

static pthread_mutex_t g_engine_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* Assembly entry points                                              */
/* ------------------------------------------------------------------ */

extern void ihook_common_entry(void);
extern void ihook_exit_stub(void);

uintptr_t ihook_on_enter(uint32_t slot_id, uintptr_t* ret_slot);
uintptr_t ihook_on_exit(void);
void ihook_bad_exit(void) __attribute__((noreturn));

static inline uint64_t rdtsc(void) {
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void) {
  struct timespec ts;
  if (syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts) != 0) return 0;
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

static void str_copy(char* dst, size_t cap, const char* src) {
  if (!cap) return;
  if (!src) src = "";
  size_t n = strlen(src);
  if (n >= cap) n = cap - 1;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

static int env_truthy(const char* name) {
  const char* v = getenv(name);
  if (!v || !*v) return 0;
  if (!strcmp(v, "0") || !strcmp(v, "off") || !strcmp(v, "false") ||
      !strcmp(v, "no")) {
    return 0;
  }
  return 1;
}

static const char* rundir(void) {
  const char* d = getenv("IHOOK_RUNDIR");
  if (!d || !*d) d = "/tmp/ihook";
  return d;
}

static void get_main_path(void) {
  ssize_t n = readlink("/proc/self/exe", g_main_path, sizeof(g_main_path) - 1);
  if (n > 0) {
    g_main_path[n] = '\0';
  } else {
    str_copy(g_main_path, sizeof(g_main_path), "<main>");
  }
}

static int same_module_path(const char* a, const char* b) {
  if (!a || !b) return 0;
  if (!strcmp(a, b)) return 1;
  const char* ba = strrchr(a, '/');
  const char* bb = strrchr(b, '/');
  ba = ba ? ba + 1 : a;
  bb = bb ? bb + 1 : b;
  return !strcmp(ba, bb);
}

static int module_match(const char* path, const char* pattern) {
  if (!pattern || !*pattern) return 1;
  if (fnmatch(pattern, path, 0) == 0) return 1;
  const char* base = strrchr(path, '/');
  if (base && fnmatch(pattern, base + 1, 0) == 0) return 1;
  return 0;
}

/* Parse /proc/self/maps for the protection bits of addr. */
static int addr_prot(uintptr_t addr, int* out_prot) {
  FILE* f = fopen("/proc/self/maps", "r");
  if (!f) return -1;
  char line[1024];
  int rc = -1;
  while (fgets(line, sizeof(line), f)) {
    unsigned long start = 0, end = 0;
    char perms[8];
    if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
    if (addr >= (uintptr_t)start && addr < (uintptr_t)end) {
      int p = 0;
      if (perms[0] == 'r') p |= PROT_READ;
      if (perms[1] == 'w') p |= PROT_WRITE;
      if (perms[2] == 'x') p |= PROT_EXEC;
      *out_prot = p;
      rc = 0;
      break;
    }
  }
  fclose(f);
  return rc;
}

static int addr_mapped(uintptr_t addr) {
  int prot = 0;
  if (addr_prot(addr, &prot) != 0) return 0;
  return (prot & PROT_READ) != 0;
}

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

typedef struct SBuf {
  char* p;
  size_t cap;
  size_t len;
  int truncated;
} SBuf;

static void sb_init(SBuf* b, char* p, size_t cap) {
  b->p = p;
  b->cap = cap;
  b->len = 0;
  b->truncated = 0;
  if (cap) p[0] = '\0';
}

static void sb_reserve(SBuf* b, size_t n) {
  if (b->len + n + 1 > b->cap) {
    b->truncated = 1;
    return;
  }
}

static void sb_putc(SBuf* b, char c) {
  if (b->len + 2 > b->cap) {
    b->truncated = 1;
    return;
  }
  b->p[b->len++] = c;
  b->p[b->len] = '\0';
}

static void sb_puts(SBuf* b, const char* s) {
  if (!s) s = "";
  size_t n = strlen(s);
  sb_reserve(b, n);
  if (b->truncated) return;
  memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = '\0';
}

static void sb_putu(SBuf* b, uint64_t v) {
  char tmp[32];
  size_t n = 0;
  if (v == 0) {
    sb_putc(b, '0');
    return;
  }
  while (v && n < sizeof(tmp)) {
    tmp[n++] = (char)('0' + (v % 10));
    v /= 10;
  }
  while (n) sb_putc(b, tmp[--n]);
}

static void sb_puti(SBuf* b, int64_t v) {
  if (v < 0) {
    sb_putc(b, '-');
    sb_putu(b, (uint64_t)(-(v + 1)) + 1);
  } else {
    sb_putu(b, (uint64_t)v);
  }
}

static void sb_put_hex(SBuf* b, uintptr_t v) {
  static const char hex[] = "0123456789abcdef";
  char tmp[2 * sizeof(uintptr_t) + 1];
  size_t n = 0;
  if (!v) {
    sb_putc(b, '0');
    return;
  }
  while (v && n < sizeof(tmp)) {
    tmp[n++] = hex[v & 0xF];
    v >>= 4;
  }
  while (n) sb_putc(b, tmp[--n]);
}

static void sb_json_str(SBuf* b, const char* s) {
  static const char hex[] = "0123456789abcdef";
  sb_putc(b, '"');
  if (!s) s = "";
  for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
    unsigned char c = *p;
    switch (c) {
      case '"': sb_puts(b, "\\\""); break;
      case '\\': sb_puts(b, "\\\\"); break;
      case '\b': sb_puts(b, "\\b"); break;
      case '\f': sb_puts(b, "\\f"); break;
      case '\n': sb_puts(b, "\\n"); break;
      case '\r': sb_puts(b, "\\r"); break;
      case '\t': sb_puts(b, "\\t"); break;
      default:
        if (c < 0x20) {
          sb_puts(b, "\\u00");
          sb_putc(b, hex[(c >> 4) & 0xF]);
          sb_putc(b, hex[c & 0xF]);
        } else {
          sb_putc(b, (char)c);
        }
    }
  }
  sb_putc(b, '"');
}

static void log_write_locked(const char* data, size_t len) {
  if (g_log_fd < 0 || !data || !len) return;
  size_t off = 0;
  while (off < len) {
    ssize_t n = syscall(SYS_write, g_log_fd, data + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;
    off += (size_t)n;
  }
}

static void log_line_locked(const char* line) {
  if (!line) return;
  log_write_locked(line, strlen(line));
}

static int open_log_path(const char* path) {
  if (!path || !*path || !strcmp(path, "off") || !strcmp(path, "none")) {
    return -1;
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  return fd;
}

static void log_stats_locked(int force) {
  if (g_log_fd < 0) return;
  uint64_t now = now_ms();
  if (!force && !__atomic_load_n(&g_stats_dirty, __ATOMIC_RELAXED)) return;
  if (!force && now < g_next_stats_ms) return;
  g_next_stats_ms = now + 900;
  __atomic_store_n(&g_stats_dirty, 0, __ATOMIC_RELAXED);

  static char buf[IHOOK_LOG_BUF_SIZE];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now);
  sb_puts(&b, ",\"event\":\"stats\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"hooks\":[");
  int first = 1;
  uint64_t total_calls = 0;
  uint64_t total_errors = 0;
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    IHookHook* h = &g_hooks[i];
    if (!__atomic_load_n(&h->active, __ATOMIC_ACQUIRE)) continue;
    if (!first) sb_putc(&b, ',');
    first = 0;
    uint64_t calls = __atomic_load_n(&h->calls, __ATOMIC_RELAXED);
    uint64_t returns = __atomic_load_n(&h->returns, __ATOMIC_RELAXED);
    uint64_t cycles = __atomic_load_n(&h->cycles, __ATOMIC_RELAXED);
    uint64_t errors = __atomic_load_n(&h->errors, __ATOMIC_RELAXED);
    total_calls += calls;
    total_errors += errors;
    sb_puts(&b, "{\"id\":");
    sb_puti(&b, h->id);
    sb_puts(&b, ",\"symbol\":");
    sb_json_str(&b, h->symbol);
    sb_puts(&b, ",\"mode\":");
    sb_json_str(&b, h->mode == IHOOK_MODE_ENTER_EXIT ? "enter_exit" : "enter");
    sb_puts(&b, ",\"slots\":");
    sb_puti(&b, h->slot_count);
    sb_puts(&b, ",\"calls\":");
    sb_putu(&b, calls);
    sb_puts(&b, ",\"returns\":");
    sb_putu(&b, returns);
    sb_puts(&b, ",\"cycles\":");
    sb_putu(&b, cycles);
    sb_puts(&b, ",\"errors\":");
    sb_putu(&b, errors);
    sb_putc(&b, '}');
  }
  sb_puts(&b, "],\"total_calls\":");
  sb_putu(&b, total_calls);
  sb_puts(&b, ",\"total_errors\":");
  sb_putu(&b, total_errors);
  sb_puts(&b, "}\n");
  if (!b.truncated) log_write_locked(b.p, b.len);
}

static void log_event_hook(int hook_id, const char* symbol,
                           const char* module_filter, int mode, int slots,
                           int failed, const char* result,
                           const char* reason) {
  char buf[4096];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now_ms());
  sb_puts(&b, ",\"event\":\"hook\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"hook_id\":");
  sb_puti(&b, hook_id);
  sb_puts(&b, ",\"symbol\":");
  sb_json_str(&b, symbol);
  sb_puts(&b, ",\"module\":");
  sb_json_str(&b, module_filter);
  sb_puts(&b, ",\"mode\":");
  sb_json_str(&b, mode == IHOOK_MODE_ENTER_EXIT ? "enter_exit" : "enter");
  sb_puts(&b, ",\"slots\":");
  sb_puti(&b, slots);
  sb_puts(&b, ",\"failed_slots\":");
  sb_puti(&b, failed);
  sb_puts(&b, ",\"result\":");
  sb_json_str(&b, result);
  if (reason && *reason) {
    sb_puts(&b, ",\"reason\":");
    sb_json_str(&b, reason);
  }
  sb_puts(&b, "}\n");
  if (b.truncated) return;
  pthread_mutex_lock(&g_log_mutex);
  log_line_locked(b.p);
  pthread_mutex_unlock(&g_log_mutex);
}

static void log_event_unhook(const char* symbol, const char* module_filter,
                             int restored, int failed, const char* result) {
  char buf[4096];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now_ms());
  sb_puts(&b, ",\"event\":\"unhook\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"symbol\":");
  sb_json_str(&b, symbol);
  sb_puts(&b, ",\"module\":");
  sb_json_str(&b, module_filter);
  sb_puts(&b, ",\"restored\":");
  sb_puti(&b, restored);
  sb_puts(&b, ",\"failed\":");
  sb_puti(&b, failed);
  sb_puts(&b, ",\"result\":");
  sb_json_str(&b, result);
  sb_puts(&b, "}\n");
  if (b.truncated) return;
  pthread_mutex_lock(&g_log_mutex);
  log_line_locked(b.p);
  pthread_mutex_unlock(&g_log_mutex);
}

static void log_event_error(const char* op, const char* symbol,
                            const char* module_filter, const char* reason,
                            const char* message) {
  char buf[4096];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now_ms());
  sb_puts(&b, ",\"event\":\"error\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"op\":");
  sb_json_str(&b, op);
  sb_puts(&b, ",\"symbol\":");
  sb_json_str(&b, symbol);
  sb_puts(&b, ",\"module\":");
  sb_json_str(&b, module_filter);
  sb_puts(&b, ",\"reason\":");
  sb_json_str(&b, reason);
  sb_puts(&b, ",\"message\":");
  sb_json_str(&b, message);
  sb_puts(&b, "}\n");
  if (b.truncated) return;
  pthread_mutex_lock(&g_log_mutex);
  log_line_locked(b.p);
  pthread_mutex_unlock(&g_log_mutex);
}

static void log_event_slot_error(const char* symbol, const char* module,
                                 uintptr_t slot_addr, const char* reason) {
  char buf[4096];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now_ms());
  sb_puts(&b, ",\"event\":\"slot_error\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"symbol\":");
  sb_json_str(&b, symbol);
  sb_puts(&b, ",\"module\":");
  sb_json_str(&b, module);
  sb_puts(&b, ",\"slot\":\"0x");
  sb_put_hex(&b, slot_addr);
  sb_puts(&b, "\",\"reason\":");
  sb_json_str(&b, reason);
  sb_puts(&b, "}\n");
  if (b.truncated) return;
  pthread_mutex_lock(&g_log_mutex);
  log_line_locked(b.p);
  pthread_mutex_unlock(&g_log_mutex);
}

/* ------------------------------------------------------------------ */
/* Hot path                                                           */
/* ------------------------------------------------------------------ */

static __thread IHookFrame tls_frames[IHOOK_TLS_FRAMES];
static __thread uint32_t tls_depth;
static __thread int tls_in_handler;

__attribute__((visibility("default"))) uintptr_t ihook_on_enter(
    uint32_t slot_id, uintptr_t* ret_slot) {
  if (slot_id >= (uint32_t)g_slot_count) {
    return (uintptr_t)&ihook_bad_exit;
  }
  IHookSlot* s = &g_slots[slot_id];
  if (!__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) {
    return __atomic_load_n(&s->orig_addr, __ATOMIC_RELAXED);
  }
  uintptr_t orig = __atomic_load_n(&s->orig_addr, __ATOMIC_RELAXED);

  int hi = __atomic_load_n(&s->hook_idx, __ATOMIC_RELAXED);
  if (hi < 0 || hi >= IHOOK_MAX_HOOKS) return orig;
  IHookHook* h = &g_hooks[hi];

  __atomic_fetch_add(&s->calls, 1, __ATOMIC_RELAXED);
  __atomic_fetch_add(&h->calls, 1, __ATOMIC_RELAXED);
  if (__atomic_load_n(&g_stats_dirty, __ATOMIC_RELAXED) == 0) {
    __atomic_store_n(&g_stats_dirty, 1, __ATOMIC_RELAXED);
  }

  if (h->mode == IHOOK_MODE_ENTER_EXIT) {
    if (!tls_in_handler && tls_depth < IHOOK_TLS_FRAMES) {
      IHookFrame* f = &tls_frames[tls_depth++];
      f->retaddr = *ret_slot;
      f->slot_id = slot_id;
      f->pad = 0;
      f->tsc = rdtsc();
      tls_in_handler = 1;
      *ret_slot = (uintptr_t)&ihook_exit_stub;
      tls_in_handler = 0;
    } else {
      __atomic_fetch_add(&h->errors, 1, __ATOMIC_RELAXED);
      __atomic_fetch_add(&s->errors, 1, __ATOMIC_RELAXED);
      __atomic_store_n(&g_stats_dirty, 1, __ATOMIC_RELAXED);
    }
  }
  return orig;
}

__attribute__((visibility("default"))) uintptr_t ihook_on_exit(void) {
  if (tls_depth == 0) ihook_bad_exit();
  IHookFrame* f = &tls_frames[--tls_depth];
  IHookSlot* s = &g_slots[f->slot_id];
  if (__atomic_load_n(&s->active, __ATOMIC_ACQUIRE) && s->hook_idx >= 0 &&
      s->hook_idx < IHOOK_MAX_HOOKS) {
    IHookHook* h = &g_hooks[s->hook_idx];
    __atomic_fetch_add(&h->returns, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->cycles, rdtsc() - f->tsc, __ATOMIC_RELAXED);
  }
  return f->retaddr;
}

__attribute__((visibility("default"))) void ihook_bad_exit(void) {
  static const char msg[] = "ihook: fatal: unbalanced exit trampoline\n";
  syscall(SYS_write, 2, msg, sizeof(msg) - 1);
  syscall(SYS_exit_group, 127);
  __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* GOT patching                                                       */
/* ------------------------------------------------------------------ */

static int patch_got(uintptr_t addr, uintptr_t value) {
  uintptr_t first = addr & ~(uintptr_t)(g_page_size - 1);
  uintptr_t last = (addr + sizeof(uintptr_t) - 1) &
                   ~(uintptr_t)(g_page_size - 1);
  int prot_first = 0;
  if (addr_prot(addr, &prot_first) != 0) return -1;

  if (first == last) {
    if (mprotect((void*)first, g_page_size, prot_first | PROT_WRITE) != 0) {
      return -1;
    }
    __atomic_store_n((uintptr_t*)addr, value, __ATOMIC_RELEASE);
    __builtin___clear_cache((char*)addr, (char*)addr + sizeof(uintptr_t));
    if (mprotect((void*)first, g_page_size, prot_first) != 0) {
      /* The write succeeded; keep the hook functional. */
    }
    return 0;
  }

  int prot_last = 0;
  if (addr_prot(last, &prot_last) != 0) return -1;
  if (mprotect((void*)first, g_page_size, prot_first | PROT_WRITE) != 0) {
    return -1;
  }
  if (mprotect((void*)last, g_page_size, prot_last | PROT_WRITE) != 0) {
    mprotect((void*)first, g_page_size, prot_first);
    return -1;
  }
  __atomic_store_n((uintptr_t*)addr, value, __ATOMIC_RELEASE);
  __builtin___clear_cache((char*)addr, (char*)addr + sizeof(uintptr_t));
  mprotect((void*)last, g_page_size, prot_last);
  mprotect((void*)first, g_page_size, prot_first);
  return 0;
}

static void* make_trampoline(uint32_t slot_id) {
  uint8_t* p = (uint8_t*)mmap(NULL, g_page_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;

  size_t o = 0;
  /* endbr64 - safe NOP when CET IBT is not enforced, required when it is. */
  p[o++] = 0xF3;
  p[o++] = 0x0F;
  p[o++] = 0x1E;
  p[o++] = 0xFA;
  /* mov r11d, slot_id */
  p[o++] = 0x41;
  p[o++] = 0xBB;
  memcpy(p + o, &slot_id, sizeof(slot_id));
  o += sizeof(slot_id);
  /* movabs r10, ihook_common_entry */
  p[o++] = 0x49;
  p[o++] = 0xBA;
  uint64_t entry = (uintptr_t)&ihook_common_entry;
  memcpy(p + o, &entry, sizeof(entry));
  o += sizeof(entry);
  /* jmp r10 */
  p[o++] = 0x41;
  p[o++] = 0xFF;
  p[o++] = 0xE2;

  __builtin___clear_cache((char*)p, (char*)p + o);
  if (mprotect(p, g_page_size, PROT_READ | PROT_EXEC) != 0) {
    munmap(p, g_page_size);
    return NULL;
  }
  return p;
}

static int looks_lazy(uintptr_t addr, const char* module) {
  if (!addr) return 1;
  if (!addr_mapped(addr)) return 1;

  const unsigned char* p = (const unsigned char*)addr;
  /* Classic lazy PLT stub starts at "push $index".  With CET the following
     jump is prefixed by 0xf2 (bnd). */
  if (p[0] == 0x68) {
    if (p[5] == 0xE9) return 1;
    if (p[5] == 0xF2 && p[6] == 0xE9) return 1;
  }

  Dl_info di;
  memset(&di, 0, sizeof(di));
  if (dladdr((void*)addr, &di) && di.dli_fname && !di.dli_sname &&
      same_module_path(di.dli_fname, module)) {
    return 1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Slot table                                                         */
/* ------------------------------------------------------------------ */

static uint32_t hash_addr(uintptr_t addr) {
  uint64_t v = (uint64_t)(addr >> 3);
  v *= 11400714819323198485ull;
  return (uint32_t)(v >> 40) & (IHOOK_HASH_SIZE - 1);
}

static int hash_find(uintptr_t addr) {
  uint32_t h = hash_addr(addr);
  for (uint32_t i = 0; i < IHOOK_HASH_SIZE; ++i) {
    uint32_t slot = g_slot_hash[(h + i) & (IHOOK_HASH_SIZE - 1)];
    if (slot == 0) return -1;
    int idx = (int)slot - 1;
    if (idx >= 0 && idx < g_slot_count && g_slots[idx].slot_addr == addr) {
      return idx;
    }
  }
  return -1;
}

static void hash_insert(int idx) {
  uintptr_t addr = g_slots[idx].slot_addr;
  uint32_t h = hash_addr(addr);
  for (uint32_t i = 0; i < IHOOK_HASH_SIZE; ++i) {
    uint32_t* ent = &g_slot_hash[(h + i) & (IHOOK_HASH_SIZE - 1)];
    if (*ent == 0) {
      *ent = (uint32_t)(idx + 1);
      return;
    }
    int other = (int)*ent - 1;
    if (other >= 0 && other < g_slot_count &&
        g_slots[other].slot_addr == addr) {
      *ent = (uint32_t)(idx + 1);
      return;
    }
  }
}

typedef struct RefreshCtx {
  uint32_t gen;
} RefreshCtx;

static int addr_in_writable_load(uintptr_t base, const ElfW(Phdr) * phdr,
                                 int phnum, uintptr_t addr) {
  for (int i = 0; i < phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD) continue;
    if (!(phdr[i].p_flags & PF_W)) continue;
    uintptr_t start = base + (uintptr_t)phdr[i].p_vaddr;
    uintptr_t end = start + (uintptr_t)phdr[i].p_memsz;
    if (addr >= start && addr + sizeof(uintptr_t) <= end) return 1;
  }
  return 0;
}

static void process_relocations(RefreshCtx* ctx, const char* module,
                                uintptr_t base, const ElfW(Phdr) * phdr,
                                int phnum, const ElfW(Sym) * symtab,
                                const char* strtab, const void* relocs,
                                size_t reloc_size, int is_plt, int is_rela) {
  if (!symtab || !strtab || !relocs) return;
  if (is_rela) {
    const ElfW(Rela)* r = (const ElfW(Rela)*)relocs;
    size_t count = reloc_size / sizeof(ElfW(Rela));
    for (size_t i = 0; i < count; ++i) {
      unsigned type = (unsigned)ELF64_R_TYPE(r[i].r_info);
      int ok_type = 0;
      if (is_plt) {
        ok_type = (type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT);
      } else {
        ok_type = (type == R_X86_64_GLOB_DAT);
      }
      if (!ok_type) continue;

      size_t symidx = (size_t)ELF64_R_SYM(r[i].r_info);
      const ElfW(Sym)* sym = &symtab[symidx];
      if (!sym->st_name) continue;
      const char* name = strtab + sym->st_name;
      if (!name || !*name) continue;

      unsigned stype = ELF64_ST_TYPE(sym->st_info);
      if (!is_plt && stype != STT_FUNC && stype != STT_GNU_IFUNC) continue;
      if (stype == STT_TLS) continue;

      uintptr_t addr = base + (uintptr_t)r[i].r_offset;
      if (addr % sizeof(uintptr_t) != 0) continue;
      if (!addr_in_writable_load(base, phdr, phnum, addr)) continue;
      if (strlen(name) >= IHOOK_NAME_MAX || strlen(module) >= IHOOK_PATH_MAX) {
        continue;
      }

      int idx = hash_find(addr);
      if (idx >= 0) {
        IHookSlot* s = &g_slots[idx];
        if (strcmp(s->symbol, name) != 0 ||
            strcmp(s->module, module) != 0) {
          /* The address was reused by a newly loaded object. */
          if (__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&s->active, 0, __ATOMIC_RELEASE);
            s->hook_idx = -1;
          }
          memset(s, 0, sizeof(*s));
          s->id = (uint32_t)idx;
          s->slot_addr = addr;
          s->hook_idx = -1;
          s->failed_hook_idx = -1;
          s->trampoline = NULL;
          str_copy(s->symbol, sizeof(s->symbol), name);
          str_copy(s->module, sizeof(s->module), module);
          s->raw_addr =
              __atomic_load_n((uintptr_t*)addr, __ATOMIC_ACQUIRE);
        }
        s->last_seen = ctx->gen;
        if (!__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) {
          s->raw_addr =
              __atomic_load_n((uintptr_t*)addr, __ATOMIC_ACQUIRE);
        }
        continue;
      }

      if (g_slot_count >= IHOOK_MAX_SLOTS) continue;
      int new_idx = g_slot_count++;
      IHookSlot* s = &g_slots[new_idx];
      memset(s, 0, sizeof(*s));
      s->id = (uint32_t)new_idx;
      s->slot_addr = addr;
      s->hook_idx = -1;
      s->failed_hook_idx = -1;
      s->last_seen = ctx->gen;
      str_copy(s->symbol, sizeof(s->symbol), name);
      str_copy(s->module, sizeof(s->module), module);
      s->raw_addr = __atomic_load_n((uintptr_t*)addr, __ATOMIC_ACQUIRE);

      /* Remember a local definition as a last-resort original for symbols
         whose lazy PLT entry cannot be resolved with dlsym. */
      if (sym->st_shndx != SHN_UNDEF && sym->st_value != 0 &&
          ELF64_ST_TYPE(sym->st_info) != STT_GNU_IFUNC) {
        s->local_addr = base + (uintptr_t)sym->st_value;
      }
      hash_insert(new_idx);
    }
  } else {
    const ElfW(Rel)* r = (const ElfW(Rel)*)relocs;
    size_t count = reloc_size / sizeof(ElfW(Rel));
    for (size_t i = 0; i < count; ++i) {
      unsigned type = (unsigned)ELF64_R_TYPE(r[i].r_info);
      int ok_type = is_plt
                        ? (type == R_X86_64_JUMP_SLOT ||
                           type == R_X86_64_GLOB_DAT)
                        : (type == R_X86_64_GLOB_DAT);
      if (!ok_type) continue;
      size_t symidx = (size_t)ELF64_R_SYM(r[i].r_info);
      const ElfW(Sym)* sym = &symtab[symidx];
      if (!sym->st_name) continue;
      const char* name = strtab + sym->st_name;
      if (!name || !*name) continue;
      unsigned stype = ELF64_ST_TYPE(sym->st_info);
      if (!is_plt && stype != STT_FUNC && stype != STT_GNU_IFUNC) continue;
      if (stype == STT_TLS) continue;
      uintptr_t addr = base + (uintptr_t)r[i].r_offset;
      if (addr % sizeof(uintptr_t) != 0) continue;
      if (!addr_in_writable_load(base, phdr, phnum, addr)) continue;
      if (strlen(name) >= IHOOK_NAME_MAX || strlen(module) >= IHOOK_PATH_MAX) {
        continue;
      }
      int idx = hash_find(addr);
      if (idx >= 0) {
        g_slots[idx].last_seen = ctx->gen;
        continue;
      }
      if (g_slot_count >= IHOOK_MAX_SLOTS) continue;
      int new_idx = g_slot_count++;
      IHookSlot* s = &g_slots[new_idx];
      memset(s, 0, sizeof(*s));
      s->id = (uint32_t)new_idx;
      s->slot_addr = addr;
      s->hook_idx = -1;
      s->failed_hook_idx = -1;
      s->last_seen = ctx->gen;
      str_copy(s->symbol, sizeof(s->symbol), name);
      str_copy(s->module, sizeof(s->module), module);
      s->raw_addr = __atomic_load_n((uintptr_t*)addr, __ATOMIC_ACQUIRE);
      if (sym->st_shndx != SHN_UNDEF && sym->st_value != 0 &&
          ELF64_ST_TYPE(sym->st_info) != STT_GNU_IFUNC) {
        s->local_addr = base + (uintptr_t)sym->st_value;
      }
      hash_insert(new_idx);
    }
  }
}


/* Dynamic entries are stored as addresses.  glibc adjusts d_ptr to an
 * absolute address in memory; musl and some other loaders leave it relative
 * to the load bias.  Accept both forms by checking the module's PT_LOAD
 * ranges first. */
static uintptr_t dyn_ptr_abs(uintptr_t base, uintptr_t ptr,
                             const ElfW(Phdr)* phdr, int phnum) {
  if (!ptr) return 0;
  for (int i = 0; i < phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD) continue;
    uintptr_t start = base + (uintptr_t)phdr[i].p_vaddr;
    uintptr_t end = start + (uintptr_t)phdr[i].p_memsz;
    if (ptr >= start && ptr < end) return ptr;
  }
  return base + ptr;
}

static int phdr_callback(struct dl_phdr_info* info, size_t size, void* data) {
  (void)size;
  RefreshCtx* ctx = (RefreshCtx*)data;

  uintptr_t base = (uintptr_t)info->dlpi_addr;
  if (base == g_self_base) return 0;

  const char* module =
      (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : g_main_path;
  if (!module || !*module) module = "<main>";
  if (strstr(module, "linux-vdso") || strstr(module, "ld-linux") ||
      strstr(module, "/ld.so") || same_module_path(module, g_self_path)) {
    return 0;
  }

  const ElfW(Dyn)* dyn = NULL;
  for (int i = 0; i < info->dlpi_phnum; ++i) {
    if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
      dyn = (const ElfW(Dyn)*)(base + (uintptr_t)info->dlpi_phdr[i].p_vaddr);
      break;
    }
  }
  if (!dyn) return 0;

  const ElfW(Sym)* symtab = NULL;
  const char* strtab = NULL;
  const void* jmprel = NULL;
  size_t pltrelsz = 0;
  int pltrel = DT_RELA;
  const void* reladyn = NULL;
  size_t relasz = 0;
  const void* reldyn = NULL;
  size_t relsz = 0;

  for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
    switch (d->d_tag) {
      case DT_STRTAB:
        strtab = (const char*)dyn_ptr_abs(base, (uintptr_t)d->d_un.d_ptr,
                                           info->dlpi_phdr, info->dlpi_phnum);
        break;
      case DT_SYMTAB:
        symtab = (const ElfW(Sym)*)dyn_ptr_abs(
            base, (uintptr_t)d->d_un.d_ptr, info->dlpi_phdr,
            info->dlpi_phnum);
        break;
      case DT_JMPREL:
        jmprel = (const void*)dyn_ptr_abs(base, (uintptr_t)d->d_un.d_ptr,
                                            info->dlpi_phdr, info->dlpi_phnum);
        break;
      case DT_PLTRELSZ:
        pltrelsz = (size_t)d->d_un.d_val;
        break;
      case DT_PLTREL:
        pltrel = (int)d->d_un.d_val;
        break;
      case DT_RELA:
        reladyn = (const void*)dyn_ptr_abs(
            base, (uintptr_t)d->d_un.d_ptr, info->dlpi_phdr,
            info->dlpi_phnum);
        break;
      case DT_RELASZ:
        relasz = (size_t)d->d_un.d_val;
        break;
      case DT_REL:
        reldyn = (const void*)dyn_ptr_abs(
            base, (uintptr_t)d->d_un.d_ptr, info->dlpi_phdr,
            info->dlpi_phnum);
        break;
      case DT_RELSZ:
        relsz = (size_t)d->d_un.d_val;
        break;
      default:
        break;
    }
  }
  if (!symtab || !strtab) return 0;

  g_module_count++;

  if (jmprel && pltrelsz) {
    if (pltrel == DT_RELA) {
      process_relocations(ctx, module, base, info->dlpi_phdr,
                          info->dlpi_phnum, symtab, strtab, jmprel, pltrelsz,
                          1, 1);
    } else if (pltrel == DT_REL) {
      process_relocations(ctx, module, base, info->dlpi_phdr,
                          info->dlpi_phnum, symtab, strtab, jmprel, pltrelsz,
                          1, 0);
    }
  }

  if (reladyn && relasz) {
    process_relocations(ctx, module, base, info->dlpi_phdr, info->dlpi_phnum,
                        symtab, strtab, reladyn, relasz, 0, 1);
  }
  if (reldyn && relsz) {
    process_relocations(ctx, module, base, info->dlpi_phdr, info->dlpi_phnum,
                        symtab, strtab, reldyn, relsz, 0, 0);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Install / uninstall                                                */
/* ------------------------------------------------------------------ */

static const char* failure_reason(const char* err) {
  return err && *err ? err : "hook_failed";
}

static int install_slot_locked(int hi, int si, char* reason,
                               size_t reasonsz, char* message,
                               size_t messagesz) {
  IHookSlot* s = &g_slots[si];
  if (reason && reasonsz) reason[0] = '\0';
  if (message && messagesz) message[0] = '\0';

  if (__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) {
    if (reason) str_copy(reason, reasonsz, "slot_already_hooked");
    if (message) {
      snprintf(message, messagesz, "slot 0x%lx in %s is already hooked",
               (unsigned long)s->slot_addr, s->module);
    }
    return -1;
  }
  if (!addr_mapped(s->slot_addr)) {
    if (reason) str_copy(reason, reasonsz, "slot_unmapped");
    if (message) {
      snprintf(message, messagesz, "GOT slot 0x%lx is no longer mapped",
               (unsigned long)s->slot_addr);
    }
    return -1;
  }

  uintptr_t cur =
      __atomic_load_n((uintptr_t*)s->slot_addr, __ATOMIC_ACQUIRE);
  uintptr_t raw = cur;
  int lazy = 0;
  uintptr_t orig = 0;

  if (s->trampoline && cur == (uintptr_t)s->trampoline && s->orig_addr) {
    /* A previous unhook could not restore the GOT slot (for example the page
       became read-only again while another thread raced us).  Reuse the
       saved original rather than treating our own trampoline as the target. */
    raw = s->raw_addr;
    lazy = s->lazy;
    orig = s->orig_addr;
  } else {
    lazy = looks_lazy(cur, s->module);
    orig = cur;
    if (lazy) {
      dlerror();
      void* p = dlsym(RTLD_DEFAULT, s->symbol);
      const char* de = dlerror();
      if (p) {
        orig = (uintptr_t)p;
      } else if (s->local_addr) {
        orig = s->local_addr;
      } else {
        if (reason) str_copy(reason, reasonsz, "unresolved_symbol");
        if (message) {
          snprintf(message, messagesz,
                   "cannot resolve original '%s' (%s); lazy PLT slot and "
                   "dlsym failed%s%s",
                   s->symbol, s->module, de ? ": " : "", de ? de : "");
        }
        return -1;
      }
    }
  }
  if (!orig) {
    if (reason) str_copy(reason, reasonsz, "null_original");
    if (message) {
      snprintf(message, messagesz, "original address for '%s' is NULL",
               s->symbol);
    }
    return -1;
  }

  if (!s->trampoline) {
    s->trampoline = make_trampoline(s->id);
    if (!s->trampoline) {
      if (reason) str_copy(reason, reasonsz, "trampoline_alloc_failed");
      if (message) {
        snprintf(message, messagesz,
                 "failed to allocate executable trampoline for '%s'",
                 s->symbol);
      }
      return -1;
    }
  }

  s->raw_addr = raw;
  s->orig_addr = orig;
  s->lazy = lazy;
  s->hook_idx = hi;
  s->failed_hook_idx = -1;
  s->calls = 0;
  s->errors = 0;
  __atomic_store_n(&s->active, 1, __ATOMIC_RELEASE);

  if (patch_got(s->slot_addr, (uintptr_t)s->trampoline) != 0) {
    __atomic_store_n(&s->active, 0, __ATOMIC_RELEASE);
    s->hook_idx = -1;
    if (reason) str_copy(reason, reasonsz, "patch_failed");
    if (message) {
      snprintf(message, messagesz, "mprotect/write failed for GOT slot 0x%lx",
               (unsigned long)s->slot_addr);
    }
    return -1;
  }

  /* A thread may have raced the lazy resolver between our read and write.
     Put the trampoline back once; a second overwrite is extremely unlikely. */
  if (__atomic_load_n((uintptr_t*)s->slot_addr, __ATOMIC_ACQUIRE) !=
      (uintptr_t)s->trampoline) {
    if (patch_got(s->slot_addr, (uintptr_t)s->trampoline) != 0) {
      __atomic_store_n(&s->active, 0, __ATOMIC_RELEASE);
      s->hook_idx = -1;
      if (reason) str_copy(reason, reasonsz, "patch_race");
      if (message) {
        snprintf(message, messagesz,
                 "GOT slot 0x%lx was overwritten by the lazy resolver",
                 (unsigned long)s->slot_addr);
      }
      return -1;
    }
  }
  return 0;
}

static void apply_active_hooks_locked(int log_errors) {
  for (int hi = 0; hi < IHOOK_MAX_HOOKS; ++hi) {
    IHookHook* h = &g_hooks[hi];
    if (!__atomic_load_n(&h->active, __ATOMIC_ACQUIRE)) continue;
    for (int si = 0; si < g_slot_count; ++si) {
      IHookSlot* s = &g_slots[si];
      if (s->last_seen != g_refresh_gen) continue;
      if (__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) continue;
      if (strcmp(s->symbol, h->symbol) != 0) continue;
      if (!module_match(s->module, h->module_filter)) continue;
      if (!addr_mapped(s->slot_addr)) continue;

      uintptr_t cur =
          __atomic_load_n((uintptr_t*)s->slot_addr, __ATOMIC_ACQUIRE);
      if (s->failed_hook_idx == hi && s->raw_addr == cur) continue;

      char reason[64];
      char message[IHOOK_MSG_MAX];
      if (install_slot_locked(hi, si, reason, sizeof(reason), message,
                              sizeof(message)) == 0) {
        h->slot_count++;
        if (log_errors) {
          log_event_hook(h->id, h->symbol, h->module_filter, h->mode,
                         h->slot_count, h->failed_slots, "extended",
                         "new GOT slot discovered");
        }
      } else {
        s->failed_hook_idx = hi;
        s->raw_addr = cur;
        h->errors++;
        h->failed_slots++;
        if (log_errors) {
          log_event_slot_error(h->symbol, s->module, s->slot_addr, reason);
          log_event_error("hook", h->symbol, h->module_filter,
                          failure_reason(reason), message);
        }
      }
    }
  }
}

static int refresh_locked(char* err, size_t errsz) {
  g_refresh_gen++;
  if (g_refresh_gen == 0) {
    g_refresh_gen = 1;
    for (int i = 0; i < g_slot_count; ++i) g_slots[i].last_seen = 0;
  }
  g_module_count = 0;
  RefreshCtx ctx;
  ctx.gen = g_refresh_gen;
  int rc = dl_iterate_phdr(phdr_callback, &ctx);
  if (rc != 0) {
    if (err && errsz) snprintf(err, errsz, "dl_iterate_phdr failed");
    return -1;
  }

  /* Objects can be unloaded with dlclose().  Do not leave a slot marked
     active: its GOT page may be unmapped, and the address can be reused by a
     different object.  Any later address reuse is treated as a fresh slot. */
  for (int i = 0; i < g_slot_count; ++i) {
    IHookSlot* s = &g_slots[i];
    if (s->last_seen == g_refresh_gen) continue;
    int hi = s->hook_idx;
    if (__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) {
      __atomic_store_n(&s->active, 0, __ATOMIC_RELEASE);
      if (hi >= 0 && hi < IHOOK_MAX_HOOKS &&
          __atomic_load_n(&g_hooks[hi].active, __ATOMIC_ACQUIRE) &&
          g_hooks[hi].slot_count > 0) {
        g_hooks[hi].slot_count--;
      }
    }
    s->hook_idx = -1;
    s->failed_hook_idx = -1;
  }

  apply_active_hooks_locked(1);
  return 0;
}

static int hook_matches(const IHookHook* h, const char* symbol,
                        const char* module_filter) {
  if (strcmp(h->symbol, symbol) != 0) return 0;
  if (!module_filter || !*module_filter) return 1;
  if (!h->module_filter[0]) return 1;
  if (!strcmp(h->module_filter, module_filter)) return 1;
  if (fnmatch(module_filter, h->module_filter, 0) == 0) return 1;
  const char* base = strrchr(h->module_filter, '/');
  if (base && fnmatch(module_filter, base + 1, 0) == 0) return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int ihook_engine_init(void) {
  if (g_initialized) return 0;
  g_initialized = 1;
  g_pid = (int)getpid();
  g_start_ms = now_ms();
  long ps = sysconf(_SC_PAGESIZE);
  if (ps > 0) g_page_size = (size_t)ps;
  get_main_path();

  Dl_info di;
  memset(&di, 0, sizeof(di));
  if (dladdr((void*)&ihook_engine_init, &di)) {
    g_self_base = (uintptr_t)di.dli_fbase;
    if (di.dli_fname) str_copy(g_self_path, sizeof(g_self_path), di.dli_fname);
  }
  if (!g_self_path[0]) str_copy(g_self_path, sizeof(g_self_path), "ihook.so");

  if (env_truthy("IHOOK_DISABLE")) g_enabled = 0;
  if (!g_enabled) return 0;

  mkdir(rundir(), 0700);

  const char* logenv = getenv("IHOOK_LOG");
  if (logenv && (!strcmp(logenv, "off") || !strcmp(logenv, "none") ||
                 !strcmp(logenv, "0"))) {
    g_log_path[0] = '\0';
  } else if (logenv && *logenv) {
    str_copy(g_log_path, sizeof(g_log_path), logenv);
  } else {
    snprintf(g_log_path, sizeof(g_log_path), "%s/ihook-%d.log", rundir(),
             g_pid);
  }
  if (g_log_path[0]) {
    int fd = open_log_path(g_log_path);
    if (fd >= 0) {
      g_log_fd = fd;
    } else {
      static const char warn[] =
          "ihook: cannot open log file; file logging disabled\n";
      syscall(SYS_write, 2, warn, sizeof(warn) - 1);
      g_log_path[0] = '\0';
    }
  }
  atexit((void (*)(void))ihook_engine_shutdown);
  return 0;
}

void ihook_engine_set_socket_path(const char* path) {
  str_copy(g_socket_path, sizeof(g_socket_path), path ? path : "");
}

int ihook_engine_refresh(char* err, size_t errsz) {
  if (err && errsz) err[0] = '\0';
  if (!g_initialized) ihook_engine_init();
  if (!g_enabled) {
    if (err && errsz) str_copy(err, errsz, "engine_disabled");
    return -1;
  }
  pthread_mutex_lock(&g_engine_mutex);
  int rc = refresh_locked(err, errsz);
  pthread_mutex_unlock(&g_engine_mutex);
  return rc;
}

int ihook_engine_hook(const char* mangled_symbol, const char* module_filter,
                      int mode, char* err, size_t errsz, char* msg,
                      size_t msgsz, int* out_hook_id, int* out_slots,
                      int* out_failed) {
  if (err && errsz) err[0] = '\0';
  if (msg && msgsz) msg[0] = '\0';
  if (out_hook_id) *out_hook_id = -1;
  if (out_slots) *out_slots = 0;
  if (out_failed) *out_failed = 0;
  if (!mangled_symbol || !*mangled_symbol) {
    if (err) str_copy(err, errsz, "invalid_symbol");
    if (msg) str_copy(msg, msgsz, "empty symbol name");
    return -1;
  }
  if (mode != IHOOK_MODE_ENTER && mode != IHOOK_MODE_ENTER_EXIT) {
    if (err) str_copy(err, errsz, "invalid_mode");
    if (msg) str_copy(msg, msgsz, "mode must be enter or enter_exit");
    return -1;
  }
  if (!g_initialized) ihook_engine_init();
  if (!g_enabled) {
    if (err) str_copy(err, errsz, "engine_disabled");
    if (msg) str_copy(msg, msgsz, "ihook is disabled");
    return -1;
  }

  pthread_mutex_lock(&g_engine_mutex);
  char rerr[IHOOK_MSG_MAX];
  if (refresh_locked(rerr, sizeof(rerr)) != 0) {
    pthread_mutex_unlock(&g_engine_mutex);
    if (err) str_copy(err, errsz, "refresh_failed");
    if (msg) str_copy(msg, msgsz, rerr);
    return -1;
  }

  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    IHookHook* h = &g_hooks[i];
    if (!__atomic_load_n(&h->active, __ATOMIC_ACQUIRE)) continue;
    if (hook_matches(h, mangled_symbol,
                     module_filter ? module_filter : "")) {
      pthread_mutex_unlock(&g_engine_mutex);
      if (err) str_copy(err, errsz, "already_hooked");
      if (msg) {
        snprintf(msg, msgsz,
                 "'%s' is already hooked (hook id %d); unhook it first",
                 mangled_symbol, h->id);
      }
      return -1;
    }
  }

  int hi = -1;
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    if (!__atomic_load_n(&g_hooks[i].active, __ATOMIC_ACQUIRE)) {
      hi = i;
      break;
    }
  }
  if (hi < 0) {
    pthread_mutex_unlock(&g_engine_mutex);
    if (err) str_copy(err, errsz, "too_many_hooks");
    if (msg) {
      snprintf(msg, msgsz, "hook table is full (%d entries)",
               IHOOK_MAX_HOOKS);
    }
    return -1;
  }

  IHookHook* h = &g_hooks[hi];
  memset(h, 0, sizeof(*h));
  h->id = ++g_hook_seq;
  h->mode = mode;
  h->created_ms = now_ms();
  str_copy(h->symbol, sizeof(h->symbol), mangled_symbol);
  str_copy(h->module_filter, sizeof(h->module_filter),
           module_filter ? module_filter : "");
  __atomic_store_n(&h->active, 1, __ATOMIC_RELEASE);

  int matched = 0;
  int patched = 0;
  int failed = 0;
  int logged = 0;
  char first_reason[64] = "";
  char first_message[IHOOK_MSG_MAX] = "";

  for (int si = 0; si < g_slot_count; ++si) {
    IHookSlot* s = &g_slots[si];
    if (s->last_seen != g_refresh_gen) continue;
    if (strcmp(s->symbol, mangled_symbol) != 0) continue;
    if (!module_match(s->module, module_filter ? module_filter : "")) {
      continue;
    }
    matched++;

    char reason[64];
    char smsg[IHOOK_MSG_MAX];
    if (install_slot_locked(hi, si, reason, sizeof(reason), smsg,
                            sizeof(smsg)) == 0) {
      patched++;
      h->slot_count++;
    } else {
      failed++;
      h->failed_slots++;
      h->errors++;
      s->failed_hook_idx = hi;
      if (!first_reason[0]) str_copy(first_reason, sizeof(first_reason), reason);
      if (!first_message[0]) str_copy(first_message, sizeof(first_message), smsg);
      if (logged < 16) {
        log_event_slot_error(mangled_symbol, s->module, s->slot_addr, reason);
        logged++;
      }
    }
  }

  if (patched == 0) {
    __atomic_store_n(&h->active, 0, __ATOMIC_RELEASE);
    const char* reason = "symbol_not_found";
    if (matched > 0) reason = first_reason[0] ? first_reason : "patch_failed";
    if (err) str_copy(err, errsz, reason);
    if (msg) {
      if (matched == 0) {
        snprintf(msg, msgsz,
                 "no GOT/PLT slot for '%s' in the selected module(s)",
                 mangled_symbol);
      } else {
        snprintf(msg, msgsz, "%s (%d slot(s), %d failed%s%s)", first_message,
                 matched, failed, first_reason[0] ? ", first error: " : "",
                 first_reason);
      }
    }
    log_event_hook(-1, mangled_symbol, module_filter ? module_filter : "",
                   mode, 0, failed, "failed", reason);
    log_event_error("hook", mangled_symbol, module_filter ? module_filter : "",
                    reason, msg ? msg : first_message);
    pthread_mutex_unlock(&g_engine_mutex);
    return -1;
  }

  if (out_hook_id) *out_hook_id = h->id;
  if (out_slots) *out_slots = patched;
  if (out_failed) *out_failed = failed;
  if (msg) {
    if (failed) {
      snprintf(msg, msgsz, "installed %d slot(s), %d slot(s) failed", patched,
               failed);
    } else {
      snprintf(msg, msgsz, "installed %d slot(s)", patched);
    }
  }
  log_event_hook(h->id, mangled_symbol, module_filter ? module_filter : "",
                 mode, patched, failed, failed ? "partial" : "ok",
                 first_reason);
  if (failed) {
    log_event_error("hook", mangled_symbol, module_filter ? module_filter : "",
                    first_reason, first_message);
  }
  pthread_mutex_unlock(&g_engine_mutex);
  return 0;
}

int ihook_engine_unhook(const char* mangled_symbol, const char* module_filter,
                        char* err, size_t errsz, char* msg, size_t msgsz,
                        int* out_restored, int* out_failed) {
  if (err && errsz) err[0] = '\0';
  if (msg && msgsz) msg[0] = '\0';
  if (out_restored) *out_restored = 0;
  if (out_failed) *out_failed = 0;
  if (!mangled_symbol || !*mangled_symbol) {
    if (err) str_copy(err, errsz, "invalid_symbol");
    if (msg) str_copy(msg, msgsz, "empty symbol name");
    return -1;
  }
  if (!g_initialized) ihook_engine_init();
  if (!g_enabled) {
    if (err) str_copy(err, errsz, "engine_disabled");
    return -1;
  }

  pthread_mutex_lock(&g_engine_mutex);
  char rerr[IHOOK_MSG_MAX];
  if (refresh_locked(rerr, sizeof(rerr)) != 0) {
    pthread_mutex_unlock(&g_engine_mutex);
    if (err) str_copy(err, errsz, "refresh_failed");
    if (msg) str_copy(msg, msgsz, rerr);
    return -1;
  }

  int found = 0;
  int restored = 0;
  int failed = 0;
  for (int hi = 0; hi < IHOOK_MAX_HOOKS; ++hi) {
    IHookHook* h = &g_hooks[hi];
    if (!__atomic_load_n(&h->active, __ATOMIC_ACQUIRE)) continue;
    if (!hook_matches(h, mangled_symbol, module_filter ? module_filter : "")) {
      continue;
    }
    found = 1;
    h->failed_slots = 0;
    for (int si = 0; si < g_slot_count; ++si) {
      IHookSlot* s = &g_slots[si];
      if (!__atomic_load_n(&s->active, __ATOMIC_ACQUIRE)) continue;
      if (s->hook_idx != hi) continue;

      __atomic_store_n(&s->active, 0, __ATOMIC_RELEASE);
      if (addr_mapped(s->slot_addr)) {
        if (patch_got(s->slot_addr, s->raw_addr) == 0) {
          restored++;
        } else {
          failed++;
          h->failed_slots++;
          h->errors++;
        }
      } else {
        failed++;
        h->failed_slots++;
        h->errors++;
      }
      s->hook_idx = -1;
      s->failed_hook_idx = -1;
    }
    /* Persist the final counters even if the hook lived for less than one
       flusher interval. */
    pthread_mutex_lock(&g_log_mutex);
    log_stats_locked(1);
    pthread_mutex_unlock(&g_log_mutex);
    __atomic_store_n(&h->active, 0, __ATOMIC_RELEASE);
    log_event_unhook(h->symbol, h->module_filter, restored, failed,
                     failed ? "partial" : "ok");
  }

  if (!found) {
    if (err) str_copy(err, errsz, "not_hooked");
    if (msg) {
      snprintf(msg, msgsz, "'%s' is not currently hooked", mangled_symbol);
    }
    log_event_error("unhook", mangled_symbol,
                    module_filter ? module_filter : "", "not_hooked",
                    msg ? msg : "");
    pthread_mutex_unlock(&g_engine_mutex);
    return -1;
  }

  if (out_restored) *out_restored = restored;
  if (out_failed) *out_failed = failed;
  if (msg) {
    if (failed) {
      snprintf(msg, msgsz, "restored %d slot(s), %d slot(s) failed", restored,
               failed);
    } else {
      snprintf(msg, msgsz, "restored %d slot(s)", restored);
    }
  }
  pthread_mutex_unlock(&g_engine_mutex);
  return 0;
}

int ihook_engine_get_hook(int index, ihook_hook_info* out) {
  if (!out || index < 0 || index >= IHOOK_MAX_HOOKS) return -1;
  pthread_mutex_lock(&g_engine_mutex);
  IHookHook* h = &g_hooks[index];
  memset(out, 0, sizeof(*out));
  out->id = h->id;
  out->mode = h->mode;
  out->active = __atomic_load_n(&h->active, __ATOMIC_ACQUIRE);
  out->slot_count = h->slot_count;
  out->failed_slots = h->failed_slots;
  out->calls = __atomic_load_n(&h->calls, __ATOMIC_RELAXED);
  out->returns = __atomic_load_n(&h->returns, __ATOMIC_RELAXED);
  out->cycles = __atomic_load_n(&h->cycles, __ATOMIC_RELAXED);
  out->errors = __atomic_load_n(&h->errors, __ATOMIC_RELAXED);
  out->created_ms = h->created_ms;
  str_copy(out->symbol, sizeof(out->symbol), h->symbol);
  str_copy(out->module_filter, sizeof(out->module_filter), h->module_filter);
  pthread_mutex_unlock(&g_engine_mutex);
  return 0;
}

int ihook_engine_get_slot(int index, ihook_slot_info* out) {
  if (!out || index < 0) return -1;
  pthread_mutex_lock(&g_engine_mutex);
  if (index >= g_slot_count) {
    pthread_mutex_unlock(&g_engine_mutex);
    return -1;
  }
  IHookSlot* s = &g_slots[index];
  memset(out, 0, sizeof(*out));
  out->id = s->id;
  out->slot_addr = (uint64_t)s->slot_addr;
  out->original_addr = (uint64_t)s->orig_addr;
  out->raw_addr = (uint64_t)s->raw_addr;
  out->lazy = s->lazy;
  out->active = __atomic_load_n(&s->active, __ATOMIC_ACQUIRE);
  out->current = (s->last_seen == g_refresh_gen);
  out->hook_id = -1;
  if (out->active && s->hook_idx >= 0 && s->hook_idx < IHOOK_MAX_HOOKS) {
    out->hook_id = g_hooks[s->hook_idx].id;
  }
  out->calls = __atomic_load_n(&s->calls, __ATOMIC_RELAXED);
  out->errors = __atomic_load_n(&s->errors, __ATOMIC_RELAXED);
  str_copy(out->symbol, sizeof(out->symbol), s->symbol);
  str_copy(out->module, sizeof(out->module), s->module);
  pthread_mutex_unlock(&g_engine_mutex);
  return 0;
}

void ihook_engine_get_info(ihook_engine_info* out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&g_engine_mutex);
  out->pid = g_pid;
  out->enabled = g_enabled;
  out->slot_count = g_slot_count;
  out->module_count = g_module_count;
  out->uptime_ms = now_ms() - g_start_ms;
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    if (__atomic_load_n(&g_hooks[i].active, __ATOMIC_ACQUIRE)) {
      out->hook_count++;
    }
  }
  str_copy(out->socket_path, sizeof(out->socket_path), g_socket_path);
  str_copy(out->log_path, sizeof(out->log_path), g_log_path);
  str_copy(out->self_path, sizeof(out->self_path), g_self_path);
  pthread_mutex_unlock(&g_engine_mutex);
}

int ihook_engine_set_log_path(const char* path, char* err, size_t errsz) {
  if (err && errsz) err[0] = '\0';
  if (!path) path = "";
  int fd = -1;
  if (*path && strcmp(path, "off") && strcmp(path, "none")) {
    fd = open_log_path(path);
    if (fd < 0) {
      if (err) {
        snprintf(err, errsz, "cannot open log '%s': %s", path,
                 strerror(errno));
      }
      return -1;
    }
  }

  pthread_mutex_lock(&g_log_mutex);
  int old_fd = g_log_fd;
  g_log_fd = fd;
  if (fd >= 0) {
    str_copy(g_log_path, sizeof(g_log_path), path);
  } else {
    g_log_path[0] = '\0';
  }
  if (old_fd >= 0) close(old_fd);
  if (fd >= 0) {
    SBuf b;
    static char buf[2048];
    sb_init(&b, buf, sizeof(buf));
    sb_puts(&b, "{\"ts_ms\":");
    sb_putu(&b, now_ms());
    sb_puts(&b, ",\"event\":\"log_path\",\"pid\":");
    sb_puti(&b, g_pid);
    sb_puts(&b, ",\"path\":");
    sb_json_str(&b, path);
    sb_puts(&b, "}\n");
    if (!b.truncated) log_line_locked(b.p);
  }
  pthread_mutex_unlock(&g_log_mutex);
  return 0;
}

void ihook_engine_flush_log(int force) {
  if (!g_initialized) return;
  pthread_mutex_lock(&g_engine_mutex);
  pthread_mutex_lock(&g_log_mutex);
  log_stats_locked(force);
  pthread_mutex_unlock(&g_log_mutex);
  pthread_mutex_unlock(&g_engine_mutex);
}

void ihook_engine_log_failure(const char* op, const char* symbol,
                              const char* module_filter, const char* reason,
                              const char* message) {
  log_event_error(op ? op : "control", symbol ? symbol : "",
                  module_filter ? module_filter : "", reason ? reason : "",
                  message ? message : "");
}

void ihook_engine_log_start(const char* socket_path) {
  static char buf[4096];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now_ms());
  sb_puts(&b, ",\"event\":\"start\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"socket\":");
  sb_json_str(&b, socket_path ? socket_path : g_socket_path);
  sb_puts(&b, ",\"log\":");
  sb_json_str(&b, g_log_path);
  sb_puts(&b, ",\"self\":");
  sb_json_str(&b, g_self_path);
  sb_puts(&b, ",\"version\":");
  sb_json_str(&b, IHOOK_VERSION);
  sb_puts(&b, "}\n");
  if (b.truncated) return;
  pthread_mutex_lock(&g_log_mutex);
  log_line_locked(b.p);
  pthread_mutex_unlock(&g_log_mutex);
}

void ihook_engine_shutdown(void) {
  if (__atomic_exchange_n(&g_shutdown_done, 1, __ATOMIC_ACQ_REL)) return;
  ihook_engine_flush_log(1);

  static char buf[2048];
  SBuf b;
  sb_init(&b, buf, sizeof(buf));
  sb_puts(&b, "{\"ts_ms\":");
  sb_putu(&b, now_ms());
  sb_puts(&b, ",\"event\":\"exit\",\"pid\":");
  sb_puti(&b, g_pid);
  sb_puts(&b, ",\"uptime_ms\":");
  sb_putu(&b, now_ms() - g_start_ms);
  sb_puts(&b, "}\n");

  pthread_mutex_lock(&g_log_mutex);
  if (!b.truncated) log_line_locked(b.p);
  if (g_log_fd >= 0) {
    close(g_log_fd);
    g_log_fd = -1;
  }
  pthread_mutex_unlock(&g_log_mutex);
}
