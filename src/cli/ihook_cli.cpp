// ihook-cli - C++17 control client for the ihook LD_PRELOAD server.
#include "ihook_engine.h"
#include "json.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <algorithm>
#include <vector>

using ijson::Value;

namespace {

struct Options {
  long long pid = -1;
  std::string socket_path;
  std::string rundir;
  std::string command;
  std::vector<std::string> positional;
  std::string module;
  std::string mode = "enter";
  std::string log_path;
  std::string pattern;
  std::string symbol;
  std::string path;
  long long limit = 300;
  long long timeout_ms = 5000;
  bool raw_json = false;
  bool list_sockets = false;
  bool all = false;
  bool help = false;
  bool version = false;
};

void print_usage(std::ostream& out) {
  out << "ihook-cli - dynamic GOT/PLT instrumentation client\n"
         "\n"
         "Usage:\n"
         "  ihook-cli --pid PID [--json] <command> [arguments]\n"
         "  ihook-cli --socket PATH <command> [arguments]\n"
         "  ihook-cli --list\n"
         "\n"
         "Global options:\n"
         "  --pid PID          target process id (socket path is derived)\n"
         "  --socket PATH      exact Unix socket path\n"
         "  --rundir DIR       socket directory (default /tmp/ihook,\n"
         "                     or $IHOOK_RUNDIR)\n"
         "  --timeout MS       socket timeout in milliseconds (default 5000)\n"
         "  --json             print the raw JSON response, pretty-printed\n"
         "  --list             list available ihook sockets and exit\n"
         "  -h, --help         show this help\n"
         "  --version          show the client version\n"
         "\n"
         "Commands:\n"
         "  ping\n"
         "  info\n"
         "  symbols [PATTERN] [--module GLOB] [--limit N]\n"
         "  slots [SYMBOL] [--module GLOB] [--limit N]\n"
         "  hook SYMBOL [--module GLOB] [--mode enter|enter_exit] [--log FILE]\n"
         "  unhook SYMBOL [--module GLOB]\n"
         "  list [--all]\n"
         "  stats\n"
         "  setlog PATH        (PATH may be 'off' to disable file logging)\n"
         "  flush\n"
         "\n"
         "SYMBOL may be a mangled ELF name or a demangled C++ name, for example\n"
         "  _ZN4demo7Account7depositEl\n"
         "  'demo::Account::deposit(long)'\n"
         "\n"
         "Examples:\n"
         "  ihook-cli --pid 1234 symbols demo\n"
         "  ihook-cli --pid 1234 hook demo_add --mode enter_exit\n"
         "  ihook-cli --pid 1234 hook 'demo::Account::deposit(long)' --log /tmp/a.log\n"
         "  ihook-cli --pid 1234 stats\n"
         "  ihook-cli --pid 1234 unhook demo_add\n";
}

bool parse_number(const std::string& s, long long* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  errno = 0;
  long long v = std::strtoll(s.c_str(), &end, 10);
  if (errno || !end || *end != '\0') return false;
  *out = v;
  return true;
}

bool take_value(int argc, char** argv, int* i, const char* name,
                std::string* out, std::string* err) {
  std::string arg = argv[*i];
  std::string prefix = std::string(name) + "=";
  if (arg.rfind(prefix, 0) == 0) {
    *out = arg.substr(prefix.size());
    return true;
  }
  if (arg == name) {
    if (*i + 1 >= argc) {
      *err = std::string("missing value for ") + name;
      return false;
    }
    *out = argv[++(*i)];
    return true;
  }
  return false;
}

Options parse_args(int argc, char** argv) {
  Options o;
  bool seen_command = false;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    std::string value;
    std::string err;

    if (arg == "-h" || arg == "--help") {
      o.help = true;
      continue;
    }
    if (arg == "--version") {
      o.version = true;
      continue;
    }
    if (arg == "--json") {
      o.raw_json = true;
      continue;
    }
    if (arg == "--list") {
      o.list_sockets = true;
      continue;
    }
    if (arg == "--all") {
      o.all = true;
      continue;
    }
    if (take_value(argc, argv, &i, "--pid", &value, &err)) {
      if (!parse_number(value, &o.pid)) {
        std::cerr << "ihook-cli: invalid --pid: " << value << "\n";
        std::exit(2);
      }
      continue;
    }
    if (!err.empty()) {
      std::cerr << "ihook-cli: " << err << "\n";
      std::exit(2);
    }
    if (take_value(argc, argv, &i, "--socket", &value, &err)) {
      o.socket_path = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--rundir", &value, &err)) {
      o.rundir = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--timeout", &value, &err)) {
      if (!parse_number(value, &o.timeout_ms) || o.timeout_ms <= 0) {
        std::cerr << "ihook-cli: invalid --timeout: " << value << "\n";
        std::exit(2);
      }
      continue;
    }
    if (take_value(argc, argv, &i, "--module", &value, &err)) {
      o.module = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--mode", &value, &err)) {
      o.mode = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--log", &value, &err)) {
      o.log_path = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--limit", &value, &err)) {
      if (!parse_number(value, &o.limit) || o.limit <= 0) {
        std::cerr << "ihook-cli: invalid --limit: " << value << "\n";
        std::exit(2);
      }
      continue;
    }
    if (take_value(argc, argv, &i, "--pattern", &value, &err)) {
      o.pattern = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--symbol", &value, &err)) {
      o.symbol = value;
      continue;
    }
    if (take_value(argc, argv, &i, "--path", &value, &err)) {
      o.path = value;
      continue;
    }
    if (!err.empty()) {
      std::cerr << "ihook-cli: " << err << "\n";
      std::exit(2);
    }
    if (!arg.empty() && arg[0] == '-') {
      std::cerr << "ihook-cli: unknown option: " << arg << "\n";
      std::exit(2);
    }
    if (!seen_command) {
      o.command = arg;
      seen_command = true;
    } else {
      o.positional.push_back(arg);
    }
  }
  return o;
}

std::string default_rundir(const Options& o) {
  if (!o.rundir.empty()) return o.rundir;
  const char* env = std::getenv("IHOOK_RUNDIR");
  if (env && *env) return env;
  return "/tmp/ihook";
}

std::string resolve_socket(const Options& o) {
  if (!o.socket_path.empty()) return o.socket_path;
  const char* env_sock = std::getenv("IHOOK_SOCKET");
  if (env_sock && *env_sock) return env_sock;
  if (o.pid <= 0) return "";
  return default_rundir(o) + "/ihook-" + std::to_string(o.pid) + ".sock";
}

int connect_socket(const std::string& path, long long timeout_ms) {
  if (path.size() + 1 > sizeof(((sockaddr_un*)nullptr)->sun_path)) {
    std::cerr << "ihook-cli: socket path too long: " << path << "\n";
    return -1;
  }
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    std::perror("ihook-cli: socket");
    return -1;
  }
  struct timeval tv {};
  tv.tv_sec = static_cast<time_t>(timeout_ms / 1000);
  tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::cerr << "ihook-cli: connect(" << path << ") failed: "
              << std::strerror(errno) << "\n";
    ::close(fd);
    return -1;
  }
  return fd;
}

bool send_all(int fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

bool read_line(int fd, std::string* out) {
  out->clear();
  char buf[8192];
  while (out->size() < 16u * 1024u * 1024u) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::cerr << "ihook-cli: recv failed: " << std::strerror(errno) << "\n";
      return false;
    }
    if (n == 0) return !out->empty();
    out->append(buf, static_cast<size_t>(n));
    if (out->find('\n') != std::string::npos) {
      out->resize(out->find('\n'));
      return true;
    }
  }
  std::cerr << "ihook-cli: response too large\n";
  return false;
}

std::string basename_of(const std::string& path) {
  size_t slash = path.find_last_of('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string shorten(const std::string& s, size_t n) {
  if (s.size() <= n) return s;
  if (n <= 3) return s.substr(0, n);
  return s.substr(0, n - 3) + "...";
}


void print_suggestions(const Value& data) {
  const Value* suggestions = data.find("suggestions");
  if (!suggestions || !suggestions->is_array() || suggestions->items.empty()) {
    return;
  }
  std::cerr << "did you mean:\n";
  for (const auto& item : suggestions->items) {
    std::string dm = item.get_string("demangled");
    std::string sym = item.get_string("symbol");
    if (dm.empty()) dm = sym;
    std::cerr << "  " << dm;
    if (!sym.empty() && sym != dm) std::cerr << "  [" << sym << "]";
    std::cerr << "\n";
  }
}

void print_results(const Value& data, const char* ok_verb, const char* fail_verb) {
  const Value* results = data.find("results");
  if (!results || !results->is_array()) return;
  for (const auto& item : results->items) {
    std::string sym = item.get_string("symbol");
    std::string dm = item.get_string("demangled");
    if (dm.empty()) dm = sym;
    bool ok = item.get_bool("ok", false);
    if (ok) {
      std::cout << ok_verb << " " << dm << "\n";
      if (sym != dm) std::cout << "  " << sym << "\n";
      long long hook_id = item.get_i64("hook_id", -1);
      long long slots = item.get_i64("slots", item.get_i64("restored_slots", 0));
      long long failed = item.get_i64("failed_slots", 0);
      if (hook_id >= 0) std::cout << "  id=" << hook_id << " ";
      else std::cout << "  ";
      std::cout << "slots=" << slots;
      if (failed) std::cout << " failed_slots=" << failed;
      std::cout << "\n";
    } else {
      std::cout << fail_verb << " " << dm << ": "
                << item.get_string("error") << " - "
                << item.get_string("message") << "\n";
    }
  }
}

void print_hooks_table(const Value& data, bool stats_mode) {
  const Value* hooks = data.find("hooks");
  if (!hooks || !hooks->is_array() || hooks->items.empty()) {
    std::cout << "no hooks\n";
    return;
  }
  std::cout << std::left << std::setw(4) << "ID" << std::setw(12) << "MODE"
            << std::setw(7) << "SLOTS" << std::setw(7) << "FAIL"
            << std::setw(12) << "CALLS" << std::setw(12) << "RETURNS"
            << std::setw(10) << "ERRORS";
  if (stats_mode) std::cout << std::setw(12) << "AVG_CYC";
  std::cout << "SYMBOL\n";
  std::cout << std::string(stats_mode ? 100 : 88, '-') << "\n";
  for (const auto& item : hooks->items) {
    std::string dm = item.get_string("demangled");
    if (dm.empty()) dm = item.get_string("symbol");
    std::cout << std::left << std::setw(4) << item.get_i64("id", 0)
              << std::setw(12) << item.get_string("mode")
              << std::setw(7) << item.get_i64("slots", 0)
              << std::setw(7) << item.get_i64("failed_slots", 0)
              << std::setw(12) << item.get_i64("calls", 0)
              << std::setw(12) << item.get_i64("returns", 0)
              << std::setw(10) << item.get_i64("errors", 0);
    if (stats_mode) {
      std::cout << std::setw(12) << item.get_i64("avg_cycles", 0);
    }
    std::cout << shorten(dm, 64) << "\n";
  }
}

void print_symbols(const Value& data) {
  std::cout << "symbols: total=" << data.get_i64("total", 0)
            << " returned=" << data.get_i64("returned", 0) << "\n";
  const Value* symbols = data.find("symbols");
  if (!symbols || !symbols->is_array()) return;
  for (const auto& item : symbols->items) {
    std::string dm = item.get_string("demangled");
    std::string sym = item.get_string("symbol");
    if (dm.empty()) dm = sym;
    std::cout << dm << "\n";
    std::cout << "  " << sym << "  slots=" << item.get_i64("slots", 0)
              << " active=" << item.get_i64("active_slots", 0) << "\n";
  }
}

void print_slots(const Value& data) {
  const Value* slots = data.find("slots");
  std::cout << "slots: total=" << data.get_i64("total", 0)
            << " returned=" << data.get_i64("returned", 0) << "\n";
  if (!slots || !slots->is_array() || slots->items.empty()) return;
  std::cout << std::left << std::setw(18) << "SLOT" << std::setw(34) << "MODULE"
            << std::setw(6) << "LAZY" << std::setw(7) << "ACTIVE"
            << std::setw(8) << "HOOK" << std::setw(12) << "CALLS"
            << "SYMBOL\n";
  std::cout << std::string(120, '-') << "\n";
  for (const auto& item : slots->items) {
    std::string dm = item.get_string("demangled");
    if (dm.empty()) dm = item.get_string("symbol");
    std::cout << std::left << std::setw(18) << item.get_string("slot")
              << std::setw(34)
              << shorten(basename_of(item.get_string("module")), 32)
              << std::setw(6) << (item.get_bool("lazy") ? "yes" : "no")
              << std::setw(7) << (item.get_bool("active") ? "yes" : "no")
              << std::setw(8) << item.get_i64("hook_id", -1)
              << std::setw(12) << item.get_i64("calls", 0)
              << shorten(dm, 60) << "\n";
  }
}

void print_info(const Value& data) {
  auto line = [](const char* key, const std::string& value) {
    std::cout << std::left << std::setw(14) << key << value << "\n";
  };
  line("engine", data.get_string("engine") + " " + data.get_string("version"));
  line("pid", std::to_string(data.get_i64("pid", 0)));
  line("uid", std::to_string(data.get_i64("uid", 0)));
  line("enabled", data.get_bool("enabled") ? "yes" : "no");
  line("socket", data.get_string("socket"));
  line("log", data.get_bool("log_enabled") ? data.get_string("log")
                                           : "off");
  line("hooks", std::to_string(data.get_i64("hooks", 0)));
  line("slots", std::to_string(data.get_i64("slots", 0)));
  line("modules", std::to_string(data.get_i64("modules", 0)));
  line("uptime_ms", std::to_string(data.get_i64("uptime_ms", 0)));
  line("self", data.get_string("self"));
  line("protocol", data.get_string("protocol"));
}

int list_sockets(const Options& o, bool raw_json) {
  std::string dir = default_rundir(o);
  DIR* d = opendir(dir.c_str());
  if (!d) {
    std::cerr << "ihook-cli: cannot open " << dir << ": "
              << std::strerror(errno) << "\n";
    return 3;
  }
  std::vector<std::string> paths;
  while (struct dirent* ent = readdir(d)) {
    std::string name = ent->d_name;
    if (name.size() > 5 && name.compare(name.size() - 5, 5, ".sock") == 0) {
      paths.push_back(dir + "/" + name);
    }
  }
  closedir(d);
  std::sort(paths.begin(), paths.end());
  if (raw_json) {
    Value out = Value::object();
    out.set("ok", Value::boolean(true));
    Value data = Value::object();
    data.set("rundir", Value::string(dir));
    Value arr = Value::array();
    for (const auto& p : paths) arr.push(Value::string(p));
    data.set("sockets", std::move(arr));
    out.set("data", std::move(data));
    std::cout << out.dump(2) << "\n";
  } else {
    for (const auto& p : paths) std::cout << p << "\n";
    if (paths.empty()) std::cout << "no sockets in " << dir << "\n";
  }
  return 0;
}

std::string make_request(const Options& o, const std::string& symbol) {
  Value req = Value::object();
  req.set("id", Value::number(1));
  req.set("cmd", Value::string(o.command));
  if (o.command == "hook") {
    req.set("symbol", Value::string(symbol));
    if (!o.module.empty()) req.set("module", Value::string(o.module));
    req.set("mode", Value::string(o.mode));
    if (!o.log_path.empty()) req.set("log", Value::string(o.log_path));
  } else if (o.command == "unhook") {
    req.set("symbol", Value::string(symbol));
    if (!o.module.empty()) req.set("module", Value::string(o.module));
  } else if (o.command == "symbols") {
    if (!o.pattern.empty()) req.set("pattern", Value::string(o.pattern));
    if (!o.module.empty()) req.set("module", Value::string(o.module));
    req.set("limit", Value::number(o.limit));
  } else if (o.command == "slots") {
    if (!symbol.empty()) req.set("symbol", Value::string(symbol));
    if (!o.module.empty()) req.set("module", Value::string(o.module));
    req.set("limit", Value::number(o.limit));
  } else if (o.command == "list") {
    req.set("all", Value::boolean(o.all));
  } else if (o.command == "setlog") {
    req.set("path", Value::string(o.path));
  }
  return req.dump();
}

}  // namespace

int main(int argc, char** argv) {
  Options o = parse_args(argc, argv);
  if (o.help) {
    print_usage(std::cout);
    return 0;
  }
  if (o.version) {
    std::cout << IHOOK_VERSION << "\n";
    return 0;
  }
  if (o.list_sockets) {
    return list_sockets(o, o.raw_json);
  }
  if (o.command.empty()) {
    print_usage(std::cerr);
    return 2;
  }

  auto need_positional = [&](size_t index) -> std::string {
    if (o.positional.size() > index) return o.positional[index];
    return std::string();
  };

  std::string symbol;
  if (o.command == "hook") {
    symbol = !o.symbol.empty() ? o.symbol : need_positional(0);
    if (symbol.empty()) {
      std::cerr << "ihook-cli: hook requires a SYMBOL\n";
      return 2;
    }
    if (o.positional.size() > (o.symbol.empty() ? 1u : 0u)) {
      std::cerr << "ihook-cli: too many positional arguments\n";
      return 2;
    }
  } else if (o.command == "unhook") {
    symbol = !o.symbol.empty() ? o.symbol : need_positional(0);
    if (symbol.empty()) {
      std::cerr << "ihook-cli: unhook requires a SYMBOL\n";
      return 2;
    }
    if (o.positional.size() > (o.symbol.empty() ? 1u : 0u)) {
      std::cerr << "ihook-cli: too many positional arguments\n";
      return 2;
    }
  } else if (o.command == "symbols") {
    if (o.pattern.empty()) o.pattern = need_positional(0);
  } else if (o.command == "slots") {
    if (o.symbol.empty()) o.symbol = need_positional(0);
    symbol = o.symbol;
  } else if (o.command == "setlog") {
    if (o.path.empty()) o.path = need_positional(0);
    if (o.path.empty()) {
      std::cerr << "ihook-cli: setlog requires a PATH\n";
      return 2;
    }
  } else if (o.command == "ping" || o.command == "info" ||
             o.command == "list" || o.command == "stats" ||
             o.command == "flush") {
    if (!o.positional.empty()) {
      std::cerr << "ihook-cli: " << o.command
                << " takes no positional arguments\n";
      return 2;
    }
  } else {
    std::cerr << "ihook-cli: unknown command: " << o.command << "\n";
    print_usage(std::cerr);
    return 2;
  }

  std::string path = resolve_socket(o);
  if (path.empty()) {
    std::cerr << "ihook-cli: specify --pid PID or --socket PATH\n";
    return 2;
  }
  int fd = connect_socket(path, o.timeout_ms);
  if (fd < 0) return 3;

  std::string request = make_request(o, symbol);
  request.push_back('\n');
  if (!send_all(fd, request)) {
    std::cerr << "ihook-cli: send failed: " << std::strerror(errno) << "\n";
    ::close(fd);
    return 3;
  }
  std::string response;
  bool got = read_line(fd, &response);
  ::close(fd);
  if (!got) {
    std::cerr << "ihook-cli: no response from " << path << "\n";
    return 3;
  }

  std::string parse_error;
  Value resp = Value::parse(response, parse_error);
  if (!parse_error.empty()) {
    std::cerr << "ihook-cli: invalid JSON response: " << parse_error << "\n";
    std::cerr << response << "\n";
    return 3;
  }
  if (o.raw_json) std::cout << resp.dump(2) << "\n";

  bool ok = resp.get_bool("ok", false);
  const Value* data_ptr = resp.find("data");
  Value empty = Value::object();
  const Value& data = data_ptr ? *data_ptr : empty;

  if (!ok) {
    if (!o.raw_json) {
      std::cerr << "error: " << resp.get_string("error") << ": "
                << resp.get_string("message") << "\n";
      print_suggestions(data);
      if (data.find("results")) {
        print_results(data, "hooked", "failed");
      }
    }
    return 1;
  }

  if (!o.raw_json) {
    if (o.command == "ping") {
      std::cout << "pong: pid=" << data.get_i64("pid", 0)
                << " engine=" << data.get_string("engine") << " "
                << data.get_string("version") << "\n";
    } else if (o.command == "info") {
      print_info(data);
    } else if (o.command == "symbols") {
      print_symbols(data);
    } else if (o.command == "slots") {
      print_slots(data);
    } else if (o.command == "hook") {
      print_results(data, "hooked", "failed");
      std::cout << "installed=" << data.get_i64("hooks_installed", 0)
                << " slots=" << data.get_i64("total_slots", 0)
                << " failed_slots=" << data.get_i64("total_failed_slots", 0)
                << "\n";
      std::string warning = data.get_string("warning");
      if (!warning.empty()) std::cerr << "warning: " << warning << "\n";
    } else if (o.command == "unhook") {
      print_results(data, "unhooked", "failed");
      std::cout << "unhooked=" << data.get_i64("unhooked", 0)
                << " restored_slots=" << data.get_i64("total_restored_slots", 0)
                << " failed_slots=" << data.get_i64("total_failed_slots", 0)
                << "\n";
    } else if (o.command == "list") {
      print_hooks_table(data, false);
    } else if (o.command == "stats") {
      std::cout << "pid=" << data.get_i64("pid", 0)
                << " active_hooks=" << data.get_i64("active_hooks", 0)
                << " slots=" << data.get_i64("slots", 0)
                << " modules=" << data.get_i64("modules", 0)
                << " total_calls=" << data.get_i64("total_calls", 0)
                << " total_errors=" << data.get_i64("total_errors", 0)
                << " log=" << data.get_string("log") << "\n";
      print_hooks_table(data, true);
    } else if (o.command == "setlog") {
      std::cout << "log=" << data.get_string("log") << "\n";
    } else if (o.command == "flush") {
      std::cout << "flushed log=" << data.get_string("log") << "\n";
    }
  }
  return 0;
}
