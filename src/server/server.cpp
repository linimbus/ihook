/*
 * ihook.so server: Unix-domain socket + line-delimited JSON control plane.
 *
 * This file is C++17; the hook engine itself is C plus a small x86-64
 * assembly trampoline.  The constructor starts the listener and a flusher
 * thread; both are detached so the target program is never kept alive by us.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ihook_engine.h"
#include "json.hpp"

#include <cxxabi.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using ijson::Value;

namespace {

constexpr const char* kEngineName = "ihook";
constexpr size_t kMaxRequest = 8u * 1024u * 1024u;

int g_listen_fd = -1;
std::atomic<bool> g_stop{false};
char g_rundir[IHOOK_PATH_MAX];
char g_socket_path[IHOOK_PATH_MAX];
pthread_t g_server_tid{};
pthread_t g_flusher_tid{};
bool g_threads_started = false;

std::mutex g_demangle_mutex;
std::unordered_map<std::string, std::string> g_demangle_cache;

/* ------------------------------------------------------------------ */
/* Generic helpers                                                    */
/* ------------------------------------------------------------------ */

bool env_is_set(const char* name) {
  const char* v = getenv(name);
  if (!v || !*v) return false;
  return !(!strcmp(v, "0") || !strcmp(v, "off") || !strcmp(v, "false") ||
           !strcmp(v, "no"));
}

void copy_path(char* dst, size_t cap, const std::string& src) {
  if (!cap) return;
  size_t n = src.size();
  if (n >= cap) n = cap - 1;
  memcpy(dst, src.data(), n);
  dst[n] = '\0';
}

std::string demangle(const std::string& symbol) {
  {
    std::lock_guard<std::mutex> lock(g_demangle_mutex);
    auto it = g_demangle_cache.find(symbol);
    if (it != g_demangle_cache.end()) return it->second;
  }
  int status = 0;
  char* p = abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status);
  std::string result = symbol;
  if (status == 0 && p) {
    result.assign(p);
  }
  std::free(p);
  {
    std::lock_guard<std::mutex> lock(g_demangle_mutex);
    g_demangle_cache.emplace(symbol, result);
  }
  return result;
}

std::string hex_string(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx",
                static_cast<unsigned long long>(v));
  return buf;
}

const char* mode_name(int mode) {
  return mode == IHOOK_MODE_ENTER_EXIT ? "enter_exit" : "enter";
}

bool module_matches(const std::string& path, const std::string& pattern) {
  if (pattern.empty()) return true;
  if (fnmatch(pattern.c_str(), path.c_str(), 0) == 0) return true;
  size_t slash = path.find_last_of('/');
  if (slash != std::string::npos) {
    if (fnmatch(pattern.c_str(), path.c_str() + slash + 1, 0) == 0) return true;
  }
  return false;
}

std::string lower_copy(const std::string& s) {
  std::string out = s;
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string get_string(const Value& req, const char* key,
                       const std::string& fallback = std::string()) {
  return req.get_string(key, fallback);
}

Value make_response(const Value* id) {
  Value r = Value::object();
  if (id) {
    r.set("id", *id);
  } else {
    r.set("id", Value::null());
  }
  return r;
}

std::string ok_response(const Value* id, Value data) {
  Value r = make_response(id);
  r.set("ok", Value::boolean(true));
  r.set("data", std::move(data));
  return r.dump();
}

std::string error_response(const Value* id, const std::string& code,
                           const std::string& message,
                           Value data = Value::null()) {
  Value r = make_response(id);
  r.set("ok", Value::boolean(false));
  r.set("error", Value::string(code));
  r.set("message", Value::string(message));
  if (!data.is_null()) r.set("data", std::move(data));
  return r.dump();
}

void engine_refresh_quiet() {
  char err[IHOOK_MSG_MAX];
  ihook_engine_refresh(err, sizeof(err));
}

/* Build the current symbol universe from live slots.  `active_hooks_only`
 * restricts the result to symbols with an active hook (used by unhook). */
struct SymbolEntry {
  std::string symbol;
  std::string demangled;
  int slots = 0;
  int active_slots = 0;
  std::set<std::string> modules;
};

std::vector<SymbolEntry> collect_symbols(const std::string& module_filter,
                                         bool hooks_only) {
  std::map<std::string, SymbolEntry> map;
  if (!hooks_only) {
    int total = 0;
    ihook_engine_info info;
    ihook_engine_get_info(&info);
    total = info.slot_count;
    for (int i = 0; i < total; ++i) {
      ihook_slot_info si;
      if (ihook_engine_get_slot(i, &si) != 0) continue;
      if (!si.current) continue;
      if (!module_matches(si.module, module_filter)) continue;
      SymbolEntry& e = map[si.symbol];
      e.symbol = si.symbol;
      e.slots++;
      if (si.active) e.active_slots++;
      e.modules.insert(si.module);
    }
  } else {
    for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
      ihook_hook_info hi;
      if (ihook_engine_get_hook(i, &hi) != 0) continue;
      if (hi.id == 0 || !hi.active) continue;
      if (!module_filter.empty() && hi.module_filter[0] &&
          !module_matches(hi.module_filter, module_filter)) {
        continue;
      }
      SymbolEntry& e = map[hi.symbol];
      e.symbol = hi.symbol;
      e.slots += hi.slot_count;
      e.active_slots += hi.slot_count;
      if (hi.module_filter[0]) e.modules.insert(hi.module_filter);
    }
  }

  std::vector<SymbolEntry> out;
  out.reserve(map.size());
  for (auto& kv : map) {
    kv.second.demangled = demangle(kv.second.symbol);
    out.push_back(std::move(kv.second));
  }
  std::sort(out.begin(), out.end(), [](const SymbolEntry& a,
                                       const SymbolEntry& b) {
    if (a.demangled != b.demangled) return a.demangled < b.demangled;
    return a.symbol < b.symbol;
  });
  return out;
}

struct ResolveResult {
  bool found = false;
  bool ambiguous = false;
  std::string demangled_query;
  std::vector<std::string> symbols;  // mangled names
  std::vector<SymbolEntry> suggestions;
};

ResolveResult resolve_symbol(const std::string& query,
                             const std::string& module_filter,
                             bool hooks_only) {
  ResolveResult rr;
  if (query.empty()) return rr;

  std::vector<SymbolEntry> universe = collect_symbols(module_filter, hooks_only);
  if (universe.empty()) return rr;

  // Exact mangled match is unambiguous and cheapest.
  for (const auto& e : universe) {
    if (e.symbol == query) {
      rr.found = true;
      rr.symbols.push_back(e.symbol);
      rr.demangled_query = e.demangled;
      return rr;
    }
  }

  // Exact demangled match, then a prefix match for users who omit arguments.
  for (const auto& e : universe) {
    if (e.demangled == query) {
      rr.symbols.push_back(e.symbol);
      rr.demangled_query = e.demangled;
    }
  }
  if (rr.symbols.empty() && query.find('(') == std::string::npos) {
    for (const auto& e : universe) {
      if (e.demangled.rfind(query, 0) != 0) continue;
      if (e.demangled.size() == query.size() ||
          e.demangled[query.size()] == '(' ||
          e.demangled[query.size()] == '<') {
        rr.symbols.push_back(e.symbol);
        if (rr.demangled_query.empty()) rr.demangled_query = e.demangled;
      }
    }
  }

  if (!rr.symbols.empty()) {
    std::sort(rr.symbols.begin(), rr.symbols.end());
    rr.symbols.erase(std::unique(rr.symbols.begin(), rr.symbols.end()),
                     rr.symbols.end());
    rr.found = true;
    if (rr.symbols.size() > 32) {
      rr.symbols.resize(32);
      rr.ambiguous = true;
    }
    return rr;
  }

  // Suggestions: case-insensitive substring on mangled or demangled name.
  std::string needle = lower_copy(query);
  for (const auto& e : universe) {
    std::string hay = lower_copy(e.demangled + " " + e.symbol);
    if (hay.find(needle) != std::string::npos) {
      rr.suggestions.push_back(e);
      if (rr.suggestions.size() >= 12) break;
    }
  }
  return rr;
}

Value suggestions_value(const std::vector<SymbolEntry>& suggestions) {
  Value arr = Value::array();
  for (const auto& e : suggestions) {
    Value item = Value::object();
    item.set("symbol", Value::string(e.symbol));
    item.set("demangled", Value::string(e.demangled));
    item.set("slots", Value::number(e.slots));
    arr.push(std::move(item));
  }
  return arr;
}

/* ------------------------------------------------------------------ */
/* Commands                                                           */
/* ------------------------------------------------------------------ */

std::string cmd_ping(const Value* id) {
  Value data = Value::object();
  data.set("pong", Value::boolean(true));
  data.set("engine", Value::string(kEngineName));
  data.set("version", Value::string(IHOOK_VERSION));
  data.set("pid", Value::number(static_cast<long long>(getpid())));
  return ok_response(id, std::move(data));
}

std::string cmd_info(const Value* id) {
  engine_refresh_quiet();
  ihook_engine_info info;
  ihook_engine_get_info(&info);

  Value data = Value::object();
  data.set("engine", Value::string(kEngineName));
  data.set("version", Value::string(IHOOK_VERSION));
  data.set("pid", Value::number(info.pid));
  data.set("uid", Value::number(static_cast<long long>(getuid())));
  data.set("enabled", Value::boolean(info.enabled != 0));
  data.set("socket", Value::string(info.socket_path));
  data.set("log", Value::string(info.log_path));
  data.set("log_enabled", Value::boolean(info.log_path[0] != '\0'));
  data.set("self", Value::string(info.self_path));
  data.set("hooks", Value::number(info.hook_count));
  data.set("slots", Value::number(info.slot_count));
  data.set("modules", Value::number(info.module_count));
  data.set(
      "uptime_ms",
      Value::number_u(static_cast<unsigned long long>(info.uptime_ms)));
  Value modes = Value::array();
  modes.push(Value::string("enter"));
  modes.push(Value::string("enter_exit"));
  data.set("modes", std::move(modes));
  data.set("protocol", Value::string("line-delimited JSON over AF_UNIX"));
  return ok_response(id, std::move(data));
}

std::string cmd_symbols(const Value& req, const Value* id) {
  engine_refresh_quiet();
  std::string pattern = get_string(req, "pattern");
  std::string module_filter = get_string(req, "module");
  long long limit = req.get_i64("limit", 300);
  if (limit <= 0) limit = 300;
  if (limit > 5000) limit = 5000;

  std::vector<SymbolEntry> universe = collect_symbols(module_filter, false);
  std::string needle = lower_copy(pattern);
  std::vector<SymbolEntry> filtered;
  for (auto& e : universe) {
    if (!needle.empty()) {
      std::string hay = lower_copy(e.demangled + " " + e.symbol);
      if (hay.find(needle) == std::string::npos) continue;
    }
    filtered.push_back(std::move(e));
  }

  size_t total = filtered.size();
  if (filtered.size() > static_cast<size_t>(limit)) {
    filtered.resize(static_cast<size_t>(limit));
  }

  Value arr = Value::array();
  for (const auto& e : filtered) {
    Value item = Value::object();
    item.set("symbol", Value::string(e.symbol));
    item.set("demangled", Value::string(e.demangled));
    item.set("slots", Value::number(e.slots));
    item.set("active_slots", Value::number(e.active_slots));
    Value mods = Value::array();
    for (const auto& m : e.modules) mods.push(Value::string(m));
    item.set("modules", std::move(mods));
    arr.push(std::move(item));
  }

  Value data = Value::object();
  data.set("pattern", Value::string(pattern));
  data.set("total", Value::number_u(total));
  data.set("returned", Value::number(static_cast<long long>(filtered.size())));
  data.set("symbols", std::move(arr));
  data.set("note",
           Value::string("only symbols present in loaded GOT/PLT relocations "
                         "are listed"));
  return ok_response(id, std::move(data));
}

std::string cmd_slots(const Value& req, const Value* id) {
  engine_refresh_quiet();
  std::string symbol = get_string(req, "symbol");
  std::string module_filter = get_string(req, "module");
  long long limit = req.get_i64("limit", 300);
  if (limit <= 0) limit = 300;
  if (limit > 5000) limit = 5000;

  ResolveResult resolved;
  if (!symbol.empty()) {
    resolved = resolve_symbol(symbol, module_filter, false);
  }

  ihook_engine_info info;
  ihook_engine_get_info(&info);

  Value arr = Value::array();
  size_t total = 0;
  for (int i = 0; i < info.slot_count; ++i) {
    ihook_slot_info si;
    if (ihook_engine_get_slot(i, &si) != 0) continue;
    if (!si.current) continue;
    if (!module_matches(si.module, module_filter)) continue;
    if (!symbol.empty()) {
      bool match = (si.symbol == symbol);
      if (!match && resolved.found) {
        match = std::find(resolved.symbols.begin(), resolved.symbols.end(),
                          si.symbol) != resolved.symbols.end();
      }
      if (!match) continue;
    }
    total++;
    if (arr.items.size() >= static_cast<size_t>(limit)) continue;

    std::string dm = demangle(si.symbol);
    Value item = Value::object();
    item.set("id", Value::number(static_cast<long long>(si.id)));
    item.set("symbol", Value::string(si.symbol));
    item.set("demangled", Value::string(dm));
    item.set("module", Value::string(si.module));
    item.set("slot", Value::string(hex_string(si.slot_addr)));
    item.set("original", Value::string(hex_string(si.original_addr)));
    item.set("raw", Value::string(hex_string(si.raw_addr)));
    item.set("lazy", Value::boolean(si.lazy != 0));
    item.set("active", Value::boolean(si.active != 0));
    item.set("hook_id", Value::number(si.hook_id));
    item.set("calls", Value::number_u(si.calls));
    item.set("errors", Value::number_u(si.errors));
    arr.push(std::move(item));
  }

  Value data = Value::object();
  data.set("total", Value::number_u(total));
  data.set("returned", Value::number(static_cast<long long>(arr.items.size())));
  data.set("slots", std::move(arr));
  return ok_response(id, std::move(data));
}

std::string cmd_hook(const Value& req, const Value* id) {
  engine_refresh_quiet();
  std::string query = get_string(req, "symbol");
  if (query.empty()) {
    return error_response(id, "invalid_request",
                          "hook requires a non-empty 'symbol' field");
  }
  std::string module_filter = get_string(req, "module");
  std::string mode_str = get_string(req, "mode", "enter");
  int mode = IHOOK_MODE_ENTER;
  if (mode_str == "enter") {
    mode = IHOOK_MODE_ENTER;
  } else if (mode_str == "enter_exit" || mode_str == "enter-exit") {
    mode = IHOOK_MODE_ENTER_EXIT;
  } else {
    return error_response(id, "invalid_mode",
                          "mode must be 'enter' or 'enter_exit'");
  }

  std::string log_path = get_string(req, "log");
  if (!log_path.empty()) {
    char lerr[IHOOK_MSG_MAX];
    if (ihook_engine_set_log_path(log_path.c_str(), lerr, sizeof(lerr)) != 0) {
      ihook_engine_log_failure("hook", query.c_str(), module_filter.c_str(),
                               "log_open_failed", lerr);
      return error_response(id, "log_open_failed", lerr);
    }
  }

  ResolveResult rr = resolve_symbol(query, module_filter, false);
  if (!rr.found) {
    Value data = Value::object();
    data.set("query", Value::string(query));
    data.set("module", Value::string(module_filter));
    data.set("suggestions", suggestions_value(rr.suggestions));
    std::string msg =
        "symbol '" + query +
        "' was not found in any loaded GOT/PLT relocation; use the "
        "'symbols' command to inspect available symbols";
    if (rr.suggestions.empty()) {
      msg += " (the target may be statically linked, stripped, or the symbol "
             "may never be called through the PLT)";
    }
    ihook_engine_log_failure("hook", query.c_str(), module_filter.c_str(),
                             "symbol_not_found", msg.c_str());
    return error_response(id, "symbol_not_found", msg, std::move(data));
  }
  if (rr.ambiguous) {
    Value data = Value::object();
    data.set("query", Value::string(query));
    Value matches = Value::array();
    for (const auto& sym : rr.symbols) {
      Value item = Value::object();
      item.set("symbol", Value::string(sym));
      item.set("demangled", Value::string(demangle(sym)));
      matches.push(std::move(item));
    }
    data.set("matches", std::move(matches));
    std::string msg =
        "query matches more than 32 symbols; use a mangled or more specific "
        "name";
    ihook_engine_log_failure("hook", query.c_str(), module_filter.c_str(),
                             "ambiguous_symbol", msg.c_str());
    return error_response(id, "ambiguous_symbol", msg, std::move(data));
  }

  Value results = Value::array();
  int installed = 0;
  int total_slots = 0;
  int total_failed = 0;
  std::string first_error;
  std::string first_message;

  for (const auto& sym : rr.symbols) {
    int hook_id = -1;
    int slots = 0;
    int failed = 0;
    char err[IHOOK_MSG_MAX];
    char msg[IHOOK_MSG_MAX];
    int rc = ihook_engine_hook(sym.c_str(), module_filter.c_str(), mode, err,
                               sizeof(err), msg, sizeof(msg), &hook_id, &slots,
                               &failed);
    Value item = Value::object();
    item.set("symbol", Value::string(sym));
    item.set("demangled", Value::string(demangle(sym)));
    item.set("ok", Value::boolean(rc == 0));
    item.set("hook_id", Value::number(hook_id));
    item.set("slots", Value::number(slots));
    item.set("failed_slots", Value::number(failed));
    if (rc == 0) {
      installed++;
      total_slots += slots;
      total_failed += failed;
      item.set("message", Value::string(msg));
    } else {
      item.set("error", Value::string(err));
      item.set("message", Value::string(msg));
      if (first_error.empty()) {
        first_error = err;
        first_message = msg;
      }
    }
    results.push(std::move(item));
  }

  Value data = Value::object();
  data.set("requested", Value::string(query));
  data.set("module", Value::string(module_filter));
  data.set("mode", Value::string(mode_name(mode)));
  data.set("resolved_query", Value::string(rr.demangled_query));
  data.set("hooks_installed", Value::number(installed));
  data.set("total_slots", Value::number(total_slots));
  data.set("total_failed_slots", Value::number(total_failed));
  data.set("results", std::move(results));

  if (installed == 0) {
    if (first_error.empty()) first_error = "hook_failed";
    if (first_message.empty()) first_message = "no hook was installed";
    ihook_engine_log_failure("hook", query.c_str(), module_filter.c_str(),
                             first_error.c_str(), first_message.c_str());
    return error_response(id, first_error, first_message, std::move(data));
  }
  if (total_failed > 0) {
    data.set("warning", Value::string("some GOT/PLT slots could not be "
                                      "instrumented; see results and log"));
  }
  return ok_response(id, std::move(data));
}

std::string cmd_unhook(const Value& req, const Value* id) {
  engine_refresh_quiet();
  std::string query = get_string(req, "symbol");
  if (query.empty()) {
    return error_response(id, "invalid_request",
                          "unhook requires a non-empty 'symbol' field");
  }
  std::string module_filter = get_string(req, "module");

  ResolveResult rr = resolve_symbol(query, module_filter, true);
  if (!rr.found) {
    // Give the user the actual active-hook names as suggestions.
    std::vector<SymbolEntry> active = collect_symbols("", true);
    std::string needle = lower_copy(query);
    std::vector<SymbolEntry> hints;
    for (auto& e : active) {
      std::string hay = lower_copy(e.demangled + " " + e.symbol);
      if (needle.empty() || hay.find(needle) != std::string::npos) {
        hints.push_back(std::move(e));
      }
      if (hints.size() >= 12) break;
    }
    Value data = Value::object();
    data.set("query", Value::string(query));
    data.set("active_hooks", Value::number(static_cast<long long>(active.size())));
    data.set("suggestions", suggestions_value(hints));
    std::string msg =
        "no active hook matches '" + query + "'; use 'list' to see hooks";
    ihook_engine_log_failure("unhook", query.c_str(), module_filter.c_str(),
                             "not_hooked", msg.c_str());
    return error_response(id, "not_hooked", msg, std::move(data));
  }

  Value results = Value::array();
  int unhooked = 0;
  int total_restored = 0;
  int total_failed = 0;
  std::string first_error;
  std::string first_message;

  for (const auto& sym : rr.symbols) {
    int restored = 0;
    int failed = 0;
    char err[IHOOK_MSG_MAX];
    char msg[IHOOK_MSG_MAX];
    int rc = ihook_engine_unhook(sym.c_str(), module_filter.c_str(), err,
                                 sizeof(err), msg, sizeof(msg), &restored,
                                 &failed);
    Value item = Value::object();
    item.set("symbol", Value::string(sym));
    item.set("demangled", Value::string(demangle(sym)));
    item.set("ok", Value::boolean(rc == 0));
    item.set("restored_slots", Value::number(restored));
    item.set("failed_slots", Value::number(failed));
    if (rc == 0) {
      unhooked++;
      total_restored += restored;
      total_failed += failed;
      item.set("message", Value::string(msg));
    } else {
      item.set("error", Value::string(err));
      item.set("message", Value::string(msg));
      if (first_error.empty()) {
        first_error = err;
        first_message = msg;
      }
    }
    results.push(std::move(item));
  }

  Value data = Value::object();
  data.set("requested", Value::string(query));
  data.set("module", Value::string(module_filter));
  data.set("unhooked", Value::number(unhooked));
  data.set("total_restored_slots", Value::number(total_restored));
  data.set("total_failed_slots", Value::number(total_failed));
  data.set("results", std::move(results));

  if (unhooked == 0) {
    if (first_error.empty()) first_error = "not_hooked";
    if (first_message.empty()) first_message = "no hook was removed";
    return error_response(id, first_error, first_message, std::move(data));
  }
  if (total_failed > 0) {
    data.set("warning", Value::string("some slots could not be restored"));
  }
  return ok_response(id, std::move(data));
}

std::string cmd_list(const Value& req, const Value* id) {
  bool include_inactive = req.get_bool("all", false);
  Value arr = Value::array();
  int active_count = 0;
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    ihook_hook_info hi;
    if (ihook_engine_get_hook(i, &hi) != 0) continue;
    if (hi.id == 0) continue;
    if (!hi.active) {
      if (!include_inactive) continue;
    } else {
      active_count++;
    }
    Value item = Value::object();
    item.set("id", Value::number(hi.id));
    item.set("symbol", Value::string(hi.symbol));
    item.set("demangled", Value::string(demangle(hi.symbol)));
    item.set("mode", Value::string(mode_name(hi.mode)));
    item.set("active", Value::boolean(hi.active != 0));
    item.set("module", Value::string(hi.module_filter));
    item.set("slots", Value::number(hi.slot_count));
    item.set("failed_slots", Value::number(hi.failed_slots));
    item.set("calls", Value::number_u(hi.calls));
    item.set("returns", Value::number_u(hi.returns));
    item.set("errors", Value::number_u(hi.errors));
    item.set("cycles", Value::number_u(hi.cycles));
    item.set("created_ms", Value::number_u(hi.created_ms));
    arr.push(std::move(item));
  }
  Value data = Value::object();
  data.set("active_hooks", Value::number(active_count));
  data.set("hooks", std::move(arr));
  return ok_response(id, std::move(data));
}

std::string cmd_stats(const Value& req, const Value* id) {
  (void)req;
  engine_refresh_quiet();
  ihook_engine_info info;
  ihook_engine_get_info(&info);

  Value arr = Value::array();
  uint64_t total_calls = 0;
  uint64_t total_returns = 0;
  uint64_t total_errors = 0;
  for (int i = 0; i < IHOOK_MAX_HOOKS; ++i) {
    ihook_hook_info hi;
    if (ihook_engine_get_hook(i, &hi) != 0) continue;
    if (hi.id == 0 || !hi.active) continue;
    total_calls += hi.calls;
    total_returns += hi.returns;
    total_errors += hi.errors;
    Value item = Value::object();
    item.set("id", Value::number(hi.id));
    item.set("symbol", Value::string(hi.symbol));
    item.set("demangled", Value::string(demangle(hi.symbol)));
    item.set("mode", Value::string(mode_name(hi.mode)));
    item.set("module", Value::string(hi.module_filter));
    item.set("slots", Value::number(hi.slot_count));
    item.set("failed_slots", Value::number(hi.failed_slots));
    item.set("calls", Value::number_u(hi.calls));
    item.set("returns", Value::number_u(hi.returns));
    item.set("cycles", Value::number_u(hi.cycles));
    item.set("errors", Value::number_u(hi.errors));
    if (hi.returns) {
      item.set("avg_cycles",
               Value::number_u(static_cast<unsigned long long>(
                   hi.cycles / hi.returns)));
    } else {
      item.set("avg_cycles", Value::number(0));
    }
    arr.push(std::move(item));
  }

  Value data = Value::object();
  data.set("pid", Value::number(info.pid));
  data.set("uptime_ms",
           Value::number_u(static_cast<unsigned long long>(info.uptime_ms)));
  data.set("log", Value::string(info.log_path));
  data.set("active_hooks", Value::number(info.hook_count));
  data.set("slots", Value::number(info.slot_count));
  data.set("modules", Value::number(info.module_count));
  data.set("total_calls", Value::number_u(total_calls));
  data.set("total_returns", Value::number_u(total_returns));
  data.set("total_errors", Value::number_u(total_errors));
  data.set("hooks", std::move(arr));
  return ok_response(id, std::move(data));
}

std::string cmd_setlog(const Value& req, const Value* id) {
  std::string path = get_string(req, "path");
  if (path.empty()) path = get_string(req, "log");
  if (path.empty()) {
    return error_response(id, "invalid_request",
                          "setlog requires a non-empty 'path' field "
                          "(use 'off' to disable)");
  }
  char err[IHOOK_MSG_MAX];
  if (ihook_engine_set_log_path(path.c_str(), err, sizeof(err)) != 0) {
    return error_response(id, "log_open_failed", err);
  }
  Value data = Value::object();
  bool disabled = (path == "off" || path == "none");
  data.set("log", Value::string(disabled ? "off" : path));
  data.set("enabled", Value::boolean(!disabled));
  return ok_response(id, std::move(data));
}

std::string cmd_flush(const Value&, const Value* id) {
  ihook_engine_flush_log(1);
  ihook_engine_info info;
  ihook_engine_get_info(&info);
  Value data = Value::object();
  data.set("flushed", Value::boolean(true));
  data.set("log", Value::string(info.log_path));
  return ok_response(id, std::move(data));
}

std::string dispatch(const Value& req, const Value* id) {
  std::string cmd = get_string(req, "cmd");
  if (cmd.empty()) {
    return error_response(id, "invalid_request", "missing 'cmd' field");
  }
  if (cmd == "ping") return cmd_ping(id);
  if (cmd == "info") return cmd_info(id);
  if (cmd == "symbols") return cmd_symbols(req, id);
  if (cmd == "slots") return cmd_slots(req, id);
  if (cmd == "hook") return cmd_hook(req, id);
  if (cmd == "unhook") return cmd_unhook(req, id);
  if (cmd == "list") return cmd_list(req, id);
  if (cmd == "stats") return cmd_stats(req, id);
  if (cmd == "setlog") return cmd_setlog(req, id);
  if (cmd == "flush") return cmd_flush(req, id);
  return error_response(id, "unknown_command", "unknown command '" + cmd + "'");
}

std::string handle_line(const std::string& line) {
  std::string parse_error;
  Value req = Value::parse(line, parse_error);
  if (!parse_error.empty()) {
    return error_response(nullptr, "bad_json", parse_error);
  }
  if (!req.is_object()) {
    return error_response(nullptr, "bad_json",
                          "top-level JSON value must be an object");
  }
  const Value* id = req.find("id");
  try {
    return dispatch(req, id);
  } catch (const std::exception& e) {
    return error_response(id, "internal_error", e.what());
  } catch (...) {
    return error_response(id, "internal_error", "unknown C++ exception");
  }
}

/* ------------------------------------------------------------------ */
/* Socket plumbing                                                    */
/* ------------------------------------------------------------------ */

bool send_all(int fd, const char* data, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

void handle_client(int fd) {
  struct ucred cred {};
  socklen_t cred_len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0) {
    close(fd);
    return;
  }
  if (cred.uid != getuid() && cred.uid != 0) {
    close(fd);
    return;
  }

  struct timeval tv {};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  std::string buffer;
  char tmp[8192];
  while (!g_stop.load()) {
    ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;
    buffer.append(tmp, static_cast<size_t>(n));
    if (buffer.size() > kMaxRequest) {
      std::string resp =
          error_response(nullptr, "request_too_large",
                         "request exceeds the 8 MiB line limit");
      resp.push_back('\n');
      send_all(fd, resp.data(), resp.size());
      break;
    }
    size_t pos;
    while ((pos = buffer.find('\n')) != std::string::npos) {
      std::string line = buffer.substr(0, pos);
      buffer.erase(0, pos + 1);
      if (line.empty()) continue;
      std::string resp = handle_line(line);
      resp.push_back('\n');
      if (!send_all(fd, resp.data(), resp.size())) break;
    }
  }
  if (!buffer.empty()) {
    std::string resp = handle_line(buffer);
    resp.push_back('\n');
    send_all(fd, resp.data(), resp.size());
  }
  close(fd);
}

void* server_thread(void*) {
  pthread_setname_np(pthread_self(), "ihook-server");
  while (!g_stop.load()) {
    struct pollfd pfd {};
    pfd.fd = g_listen_fd;
    pfd.events = POLLIN;
    int rc = poll(&pfd, 1, 1000);
    if (rc < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (rc == 0) continue;
    if (!(pfd.revents & POLLIN)) continue;
    int cfd = accept4(g_listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      continue;
    }
    handle_client(cfd);
  }
  return nullptr;
}

void* flusher_thread(void*) {
  pthread_setname_np(pthread_self(), "ihook-flush");
  while (!g_stop.load()) {
    struct timespec ts {};
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &ts, nullptr);
    ihook_engine_flush_log(0);
  }
  return nullptr;
}

bool start_server() {
  const char* socket_env = getenv("IHOOK_SOCKET");
  std::string path;
  if (socket_env && *socket_env) {
    path = socket_env;
  } else {
    const char* rd = getenv("IHOOK_RUNDIR");
    if (!rd || !*rd) rd = "/tmp/ihook";
    copy_path(g_rundir, sizeof(g_rundir), rd);
    mkdir(g_rundir, 0700);
    path = std::string(g_rundir) + "/ihook-" +
           std::to_string(static_cast<long long>(getpid())) + ".sock";
  }
  if (path.size() + 1 > sizeof(((sockaddr_un*)nullptr)->sun_path)) {
    std::fprintf(stderr, "ihook: socket path too long: %s\n", path.c_str());
    return false;
  }
  copy_path(g_socket_path, sizeof(g_socket_path), path);

  struct stat st {};
  if (lstat(g_socket_path, &st) == 0) {
    if (S_ISSOCK(st.st_mode)) {
      unlink(g_socket_path);
    } else {
      std::fprintf(stderr,
                   "ihook: refusing to remove non-socket path %s\n",
                   g_socket_path);
      return false;
    }
  }

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    std::fprintf(stderr, "ihook: socket() failed: %s\n", strerror(errno));
    return false;
  }

  sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  size_t path_len = std::strlen(g_socket_path);
  if (path_len >= sizeof(addr.sun_path)) {
    close(fd);
    return false;
  }
  std::memcpy(addr.sun_path, g_socket_path, path_len + 1);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::fprintf(stderr, "ihook: bind(%s) failed: %s\n", g_socket_path,
                 strerror(errno));
    close(fd);
    return false;
  }
  chmod(g_socket_path, 0600);
  if (listen(fd, 16) != 0) {
    std::fprintf(stderr, "ihook: listen() failed: %s\n", strerror(errno));
    close(fd);
    unlink(g_socket_path);
    return false;
  }
  g_listen_fd = fd;
  ihook_engine_set_socket_path(g_socket_path);
  ihook_engine_log_start(g_socket_path);

  if (pthread_create(&g_server_tid, nullptr, server_thread, nullptr) != 0) {
    std::fprintf(stderr, "ihook: cannot start server thread\n");
    close(g_listen_fd);
    g_listen_fd = -1;
    unlink(g_socket_path);
    return false;
  }
  pthread_detach(g_server_tid);
  return true;
}

void start_flusher() {
  if (pthread_create(&g_flusher_tid, nullptr, flusher_thread, nullptr) != 0) {
    return;
  }
  pthread_detach(g_flusher_tid);
}

__attribute__((constructor)) void ihook_constructor() {
  if (env_is_set("IHOOK_DISABLE")) return;
  if (ihook_engine_init() != 0) return;
  g_stop.store(false);
  start_flusher();
  g_threads_started = start_server();
  if (!g_threads_started) {
    std::fprintf(stderr,
                 "ihook: control socket unavailable; target continues "
                 "uninstrumented\n");
  }
}

__attribute__((destructor)) void ihook_destructor() {
  if (env_is_set("IHOOK_DISABLE")) return;
  g_stop.store(true);
  if (g_listen_fd >= 0) {
    close(g_listen_fd);
    g_listen_fd = -1;
  }
  if (g_socket_path[0]) {
    unlink(g_socket_path);
  }
  ihook_engine_shutdown();
}

}  // namespace
