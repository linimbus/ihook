#pragma once

namespace unit {

// Non-virtual class with out-of-line methods: callers go through the PLT and
// the mangled symbol is visible in the GOT.
class Counter {
 public:
  explicit Counter(int start);
  void add(int amount);
  int value() const;

 private:
  int value_;
};

}  // namespace unit

extern "C" {
int unit_add(int a, int b);
double unit_scale(double value);
double unit_variadic(int count, ...);
int unit_call_puts(const char* text);
}
