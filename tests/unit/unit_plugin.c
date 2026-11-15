// Loaded with dlopen() by the engine API test.  The call to unit_add goes
// through the plugin's own GOT and creates a new slot that the engine must
// discover and extend an already-installed hook onto.
extern int unit_add(int a, int b);

int plugin_call(int value) { return unit_add(value, 100); }
