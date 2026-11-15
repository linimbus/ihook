#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace demo {

class Account {
 public:
  explicit Account(std::int64_t initial_balance);
  void deposit(std::int64_t amount);
  bool withdraw(std::int64_t amount);
  std::int64_t balance() const;
  std::int64_t deposit_count() const;

 private:
  mutable std::mutex mutex_;
  std::int64_t balance_;
  std::int64_t deposit_count_ = 0;
};

class Shape {
 public:
  virtual ~Shape() = default;
  virtual const char* name() const = 0;
  virtual double area() const = 0;
  virtual double perimeter() const = 0;

  // Non-virtual helper: gives the demo a normal (PLT-visible) C++ method with
  // a floating-point return value that the instrumentation can hook.
  double scaled_area(double factor) const;
};

class Circle final : public Shape {
 public:
  explicit Circle(double radius);
  const char* name() const override;
  double area() const override;
  double perimeter() const override;

 private:
  double radius_;
};

class Rectangle final : public Shape {
 public:
  Rectangle(double width, double height);
  const char* name() const override;
  double area() const override;
  double perimeter() const override;

 private:
  double width_;
  double height_;
};

class EventLog {
 public:
  void record(const std::string& event);
  std::size_t size() const;
  std::string last() const;

 private:
  mutable std::mutex mutex_;
  std::vector<std::string> events_;
};

class Worker {
 public:
  Worker(int id, Account& account, EventLog& log, Shape& shape);
  void run(std::atomic<bool>& stop, int iterations_hint = 0);

 private:
  int id_;
  Account& account_;
  EventLog& log_;
  Shape& shape_;
};

std::string version();

}  // namespace demo

extern "C" {
long demo_add(long a, long b);
std::size_t demo_checksum(const char* text);
}
