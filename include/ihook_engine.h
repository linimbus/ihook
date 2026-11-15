/*
 * ihook engine - public C interface used by the socket server.
 *
 * The engine is deliberately written in C and never calls into libc from the
 * hot path (the generated trampolines).  The socket server is C++17.
 */
#ifndef IHOOK_ENGINE_H
#define IHOOK_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IHOOK_VERSION "1.0.0"

#define IHOOK_MODE_ENTER 0
#define IHOOK_MODE_ENTER_EXIT 1

#define IHOOK_NAME_MAX 512
#define IHOOK_PATH_MAX 512
#define IHOOK_MSG_MAX 1024

#define IHOOK_MAX_SLOTS 16384
#define IHOOK_MAX_HOOKS 512

typedef struct ihook_hook_info {
  int id;
  char symbol[IHOOK_NAME_MAX];        /* mangled name used in the GOT/PLT */
  char module_filter[IHOOK_PATH_MAX]; /* empty means every module */
  int mode;                           /* IHOOK_MODE_* */
  int active;
  int slot_count;
  int failed_slots;
  uint64_t calls;
  uint64_t returns;
  uint64_t cycles;
  uint64_t errors;
  uint64_t created_ms;
} ihook_hook_info;

typedef struct ihook_slot_info {
  uint32_t id;
  char symbol[IHOOK_NAME_MAX];
  char module[IHOOK_PATH_MAX];
  uint64_t slot_addr;
  uint64_t original_addr;
  uint64_t raw_addr;
  int lazy;
  int active;
  int hook_id;
  int current;
  uint64_t calls;
  uint64_t errors;
} ihook_slot_info;

typedef struct ihook_engine_info {
  int pid;
  int enabled;
  int hook_count;
  int slot_count;
  int module_count;
  uint64_t uptime_ms;
  char socket_path[IHOOK_PATH_MAX];
  char log_path[IHOOK_PATH_MAX];
  char self_path[IHOOK_PATH_MAX];
} ihook_engine_info;

/* Returns 0 on success, -1 on failure.  Safe to call more than once. */
int ihook_engine_init(void);

/* Scan all currently loaded ELF objects and add any unseen GOT/PLT slots. */
int ihook_engine_refresh(char* err, size_t errsz);

void ihook_engine_set_socket_path(const char* path);

void ihook_engine_get_info(ihook_engine_info* out);

/*
 * Install a hook.  `mangled_symbol` must be the exact dynamic symbol name as
 * it appears in the GOT/PLT.  `module_filter` may be empty, a basename, or a
 * glob pattern (fnmatch).  Returns 0 when at least one slot was patched.
 */
int ihook_engine_hook(const char* mangled_symbol, const char* module_filter,
                      int mode, char* err, size_t errsz, char* msg,
                      size_t msgsz, int* out_hook_id, int* out_slots,
                      int* out_failed);

int ihook_engine_unhook(const char* mangled_symbol, const char* module_filter,
                        char* err, size_t errsz, char* msg, size_t msgsz,
                        int* out_restored, int* out_failed);

int ihook_engine_get_hook(int index, ihook_hook_info* out);
int ihook_engine_get_slot(int index, ihook_slot_info* out);

/* path may be "" / "off" / "none" to disable file logging. */
int ihook_engine_set_log_path(const char* path, char* err, size_t errsz);

void ihook_engine_flush_log(int force);

void ihook_engine_log_start(const char* socket_path);
void ihook_engine_log_failure(const char* op, const char* symbol,
                              const char* module_filter, const char* reason,
                              const char* message);
void ihook_engine_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* IHOOK_ENGINE_H */
