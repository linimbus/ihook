#include "libdemo.h"

#include <chrono>
#include <cmath>
#include <cstring>
#include <thread>

namespace demo {

Account::Account(std::int64_t initial_balance) : balance_(initial_balance) {}

void Account::deposit(std::int64_t amount) {
  std::lock_guard<std::mutex> lock(mutex_);
  balance_ += amount;
  ++deposit_count_;
}

bool Account::withdraw(std::int64_t amount) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (amount > balance_) return false;
  balance_ -= amount;
  return true;
}

std::int64_t Account::balance() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return balance_;
}

std::int64_t Account::deposit_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return deposit_count_;
}

Circle::Circle(double radius) : radius_(radius) {}

const char* Circle::name() const { return "circle"; }
double Circle::area() const { return 3.141592653589793 * radius_ * radius_; }
double Circle::perimeter() const { return 2.0 * 3.141592653589793 * radius_; }

double Shape::scaled_area(double factor) const { return area() * factor; }

Rectangle::Rectangle(double width, double height)
    : width_(width), height_(height) {}

const char* Rectangle::name() const { return "rectangle"; }
double Rectangle::area() const { return width_ * height_; }
double Rectangle::perimeter() const { return 2.0 * (width_ + height_); }

void EventLog::record(const std::string& event) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (events_.size() >= 4096) events_.erase(events_.begin());
  events_.push_back(event);
}

std::size_t EventLog::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return events_.size();
}

std::string EventLog::last() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return events_.empty() ? std::string() : events_.back();
}

Worker::Worker(int id, Account& account, EventLog& log, Shape& shape)
    : id_(id), account_(account), log_(log), shape_(shape) {}

void Worker::run(std::atomic<bool>& stop, int iterations_hint) {
  long n = 0;
  while (!stop.load(std::memory_order_relaxed)) {
    account_.deposit(10 + (n % 7));
    if ((n % 9) == 0) account_.withdraw(3);
    const double area = shape_.area();
    const double perimeter = shape_.perimeter();
    const double scaled = shape_.scaled_area(1.5);
    const long sum = demo_add(n, 17);
    const std::size_t checksum = demo_checksum("ihook-demo-thread");
    const std::string event =
        "worker=" + std::to_string(id_) + " n=" + std::to_string(n) +
        " area=" + std::to_string(area) +
        " perimeter=" + std::to_string(perimeter) +
        " scaled=" + std::to_string(scaled) +
        " sum=" + std::to_string(sum) +
        " checksum=" + std::to_string(checksum);
    log_.record(event);
    ++n;
    if (iterations_hint > 0 && n >= iterations_hint) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

std::string version() { return "demo-1.0"; }

}  // namespace demo

extern "C" long demo_add(long a, long b) { return a + b; }

extern "C" std::size_t demo_checksum(const char* text) {
  if (!text) return 0;
  const std::size_t len = std::strlen(text);
  std::size_t sum = len;
  for (std::size_t i = 0; i < len; ++i) {
    sum = sum * 131u + static_cast<unsigned char>(text[i]);
  }
  return sum;
}
