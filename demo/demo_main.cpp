#include "libdemo.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

namespace {

void usage(const char* argv0) {
  std::cout << "Usage: " << argv0
            << " [--seconds N] [--threads N] [--iterations N]\n"
               "\n"
               "The process prints its pid and keeps exercising the demo\n"
               "classes so the ihook CLI can attach and instrument symbols.\n";
}

}  // namespace

int main(int argc, char** argv) {
  int seconds = 20;
  int threads = 3;
  int iterations = 0;
  for (int i = 1; i < argc; ++i) {
    if (!std::strcmp(argv[i], "--help") || !std::strcmp(argv[i], "-h")) {
      usage(argv[0]);
      return 0;
    }
    if (!std::strcmp(argv[i], "--seconds") && i + 1 < argc) {
      seconds = std::atoi(argv[++i]);
    } else if (!std::strcmp(argv[i], "--threads") && i + 1 < argc) {
      threads = std::atoi(argv[++i]);
    } else if (!std::strcmp(argv[i], "--iterations") && i + 1 < argc) {
      iterations = std::atoi(argv[++i]);
    } else {
      std::cerr << "unknown argument: " << argv[i] << "\n";
      usage(argv[0]);
      return 2;
    }
  }
  if (seconds <= 0) seconds = 20;
  if (threads <= 0) threads = 1;
  if (threads > 16) threads = 16;

  std::cout << std::unitbuf;
  demo::Account account(1000);
  demo::Circle circle(2.5);
  demo::Rectangle rectangle(3.0, 4.0);
  demo::EventLog log;

  const char* rundir_env = std::getenv("IHOOK_RUNDIR");
  const char* socket_env = std::getenv("IHOOK_SOCKET");
  std::string socket_hint;
  if (socket_env && *socket_env) {
    socket_hint = socket_env;
  } else {
    std::string rundir =
        (rundir_env && *rundir_env) ? rundir_env : "/tmp/ihook";
    socket_hint = rundir + "/ihook-" +
                  std::to_string(static_cast<long long>(getpid())) + ".sock";
  }
  std::cout << "ihook demo pid=" << static_cast<long long>(getpid())
            << " version=" << demo::version() << " threads=" << threads
            << " seconds=" << seconds << "\n";
  std::cout << "  socket: " << socket_hint << "\n";
  std::cout << "  hint: build/ihook-cli --pid "
            << static_cast<long long>(getpid()) << " symbols demo\n";

  std::atomic<bool> stop{false};
  std::vector<std::thread> workers;
  workers.reserve(static_cast<size_t>(threads));
  for (int i = 0; i < threads; ++i) {
    workers.emplace_back([&, i] {
      demo::Worker worker(i, account, log, (i % 2) ? static_cast<demo::Shape&>(circle)
                                                   : static_cast<demo::Shape&>(rectangle));
      worker.run(stop, iterations);
    });
  }

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  while (std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  stop.store(true, std::memory_order_relaxed);
  for (auto& t : workers) t.join();

  std::cout << "ihook demo done: balance=" << account.balance()
            << " deposits=" << account.deposit_count()
            << " events=" << log.size() << "\n"
            << "  last=" << log.last() << "\n";
  return 0;
}
