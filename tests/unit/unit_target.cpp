#include "unit_target.h"

#include <cstdarg>
#include <cstdio>

namespace unit {

Counter::Counter(int start) : value_(start) {}

void Counter::add(int amount) { value_ += amount; }

int Counter::value() const { return value_; }

}  // namespace unit

extern "C" int unit_add(int a, int b) { return a + b; }

extern "C" double unit_scale(double value) { return value * 2.5; }

extern "C" double unit_variadic(int count, ...) {
  va_list ap;
  va_start(ap, count);
  double sum = 0.0;
  for (int i = 0; i < count; ++i) {
    if ((i & 1) == 0) {
      sum += static_cast<double>(va_arg(ap, int));
    } else {
      sum += va_arg(ap, double);
    }
  }
  va_end(ap);
  return sum;
}

extern "C" int unit_call_puts(const char* text) {
  return std::puts(text) >= 0 ? 1 : 0;
}
