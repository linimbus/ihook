// Built with -Wl,-z,lazy.  The unit API test hooks lazy_add before its first
// call, exercising the lazy GOT resolution path.
int lazy_add(int value) { return value + 1; }
