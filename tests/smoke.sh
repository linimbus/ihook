#!/usr/bin/env bash
# End-to-end smoke test for ihook.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x build/ihook.so || ! -x build/ihook-cli || ! -x build/demo ]]; then
  make -j"$(nproc)"
fi

TMPDIR_TEST="$(mktemp -d /tmp/ihook-smoke.XXXXXX)"
SOCKDIR="$TMPDIR_TEST/run"
LOG="$TMPDIR_TEST/ihook.jsonl"
OUT="$TMPDIR_TEST/demo.out"
ERR="$TMPDIR_TEST/demo.err"
SWITCHED_LOG="$TMPDIR_TEST/switched.jsonl"
DEMO_PID=""
cleanup() {
  if [[ -n "$DEMO_PID" ]] && kill -0 "$DEMO_PID" 2>/dev/null; then
    kill "$DEMO_PID" 2>/dev/null || true
    wait "$DEMO_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

mkdir -p "$SOCKDIR"
export IHOOK_RUNDIR="$SOCKDIR"

LD_PRELOAD="$ROOT/build/ihook.so" IHOOK_LOG="$LOG" \
  ./build/demo --seconds 30 --threads 2 >"$OUT" 2>"$ERR" &
DEMO_PID=$!

SOCK="$SOCKDIR/ihook-$DEMO_PID.sock"
for _ in $(seq 1 100); do
  if [[ -S "$SOCK" ]]; then break; fi
  if ! kill -0 "$DEMO_PID" 2>/dev/null; then
    echo "FAIL: demo exited before creating its socket" >&2
    cat "$ERR" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$SOCK" ]]; then
  echo "FAIL: socket $SOCK was not created" >&2
  cat "$ERR" >&2
  exit 1
fi

CLI=("./build/ihook-cli" --pid "$DEMO_PID" --timeout 3000)
PY=(python3 python/ihook_cli.py --pid "$DEMO_PID" --timeout 3)

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "[1] ping/info"
"${CLI[@]}" ping | grep >/dev/null "pong: pid=$DEMO_PID" || fail "ping"
"${CLI[@]}" info | grep >/dev/null "socket.*$SOCK" || fail "info socket"
"${CLI[@]}" info | grep >/dev/null "slots" || fail "info slots"

echo "[2] symbol discovery"
"${CLI[@]}" symbols demo --limit 100 >"$TMPDIR_TEST/symbols.txt"
grep -q "demo::Account::deposit(long)" "$TMPDIR_TEST/symbols.txt" ||
  fail "demangled Account::deposit missing"
grep -q "_ZN4demo7Account7depositEl" "$TMPDIR_TEST/symbols.txt" ||
  fail "mangled Account::deposit missing"
"${CLI[@]}" slots demo_add | grep >/dev/null "demo_add" || fail "slots demo_add"

echo "[3] direct C hook (enter_exit)"
"${CLI[@]}" hook demo_add --mode enter_exit | grep >/dev/null "hooked demo_add" ||
  fail "hook demo_add"
sleep 1.5
"${CLI[@]}" stats >"$TMPDIR_TEST/stats1.txt"
grep -q "demo_add" "$TMPDIR_TEST/stats1.txt" || fail "stats missing demo_add"
grep -q "enter_exit" "$TMPDIR_TEST/stats1.txt" || fail "stats mode"
"${CLI[@]}" list | grep >/dev/null "demo_add" || fail "list missing demo_add"

echo "[4] demangled C++ method hook"
"${CLI[@]}" hook 'demo::Account::deposit(long)' --mode enter |
  grep -q "hooked demo::Account::deposit(long)" || fail "hook C++ method"
sleep 1.2
"${CLI[@]}" stats >"$TMPDIR_TEST/stats2.txt"
grep -q "demo::Account::deposit(long)" "$TMPDIR_TEST/stats2.txt" ||
  fail "stats missing C++ method"

echo "[5] unhook restores the GOT"
"${CLI[@]}" unhook demo_add | grep >/dev/null "unhooked demo_add" || fail "unhook"
"${CLI[@]}" unhook 'demo::Account::deposit(long)' | grep >/dev/null "unhooked" ||
  fail "unhook C++ method"
"${CLI[@]}" list | grep >/dev/null "no hooks" || fail "hooks remain after unhook"

echo "[6] missing symbol is reported by the CLI and recorded in the log"
if "${CLI[@]}" hook definitely_missing_symbol >"$TMPDIR_TEST/missing.out" 2>&1; then
  fail "missing symbol unexpectedly hooked"
fi
grep -q "symbol_not_found" "$TMPDIR_TEST/missing.out" ||
  fail "CLI did not report symbol_not_found"
sleep 0.3
grep -q '"reason":"symbol_not_found"' "$LOG" ||
  fail "failure was not recorded in the log"

echo "[7] Python client"
"${PY[@]}" ping | grep >/dev/null "pong: pid=$DEMO_PID" || fail "python ping"
"${PY[@]}" hook demo_add --mode enter | grep >/dev/null "hooked demo_add" ||
  fail "python hook"
sleep 1.0
"${PY[@]}" stats | grep >/dev/null "demo_add" || fail "python stats"
"${PY[@]}" unhook demo_add | grep >/dev/null "unhooked demo_add" || fail "python unhook"

echo "[8] log switching / flush"
"${CLI[@]}" setlog "$SWITCHED_LOG" | grep >/dev/null "log=$SWITCHED_LOG" ||
  fail "setlog"
"${CLI[@]}" hook demo_add | grep >/dev/null "hooked demo_add" || fail "rehook"
sleep 1.0
"${CLI[@]}" flush | grep >/dev/null "flushed" || fail "flush"
"${CLI[@]}" unhook demo_add >/dev/null || fail "final unhook"
grep -q '"event":"hook"' "$SWITCHED_LOG" || fail "hook event missing in new log"
grep -q '"event":"stats"' "$SWITCHED_LOG" || fail "stats event missing in new log"

echo "[9] log contents"
grep -q '"event":"start"' "$LOG" || fail "start event missing"
grep -q '"event":"hook"' "$LOG" || fail "hook event missing"
grep -q '"event":"stats"' "$LOG" || fail "stats event missing"
grep -q '"symbol":"demo_add"' "$LOG" || fail "demo_add missing from log"


echo "[10] lazy binding resolution"
kill "$DEMO_PID" 2>/dev/null || true
wait "$DEMO_PID" 2>/dev/null || true
DEMO_PID=""

cat >"$TMPDIR_TEST/liblate.c" <<'CEOF'
#include <stddef.h>
#include <string.h>
int late_function(int x) { return x + 1; }
size_t late_strlen(const char* s) { return strlen(s); }
CEOF
cat >"$TMPDIR_TEST/late_main.c" <<'CEOF'
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
extern int late_function(int);
extern size_t late_strlen(const char*);
int main(void) {
  printf("lazy pid=%d\n", (int)getpid());
  fflush(stdout);
  sleep(4);
  printf("lazy result=%d len=%zu\n", late_function(41), late_strlen("lazy"));
  fflush(stdout);
  sleep(2);
  return 0;
}
CEOF
gcc -O2 -fPIC -shared -Wl,-z,lazy -o "$TMPDIR_TEST/liblate.so" \
  "$TMPDIR_TEST/liblate.c"
gcc -O2 -Wl,-z,lazy -o "$TMPDIR_TEST/late_main" "$TMPDIR_TEST/late_main.c" \
  -L"$TMPDIR_TEST" -llate -Wl,-rpath,"$TMPDIR_TEST"

mkdir -p "$TMPDIR_TEST/run2"
LD_PRELOAD="$ROOT/build/ihook.so" IHOOK_RUNDIR="$TMPDIR_TEST/run2" \
  IHOOK_LOG="$TMPDIR_TEST/lazy.jsonl" \
  "$TMPDIR_TEST/late_main" >"$TMPDIR_TEST/late.out" 2>"$TMPDIR_TEST/late.err" &
DEMO_PID=$!
SOCK2="$TMPDIR_TEST/run2/ihook-$DEMO_PID.sock"
for _ in $(seq 1 100); do
  [[ -S "$SOCK2" ]] && break
  kill -0 "$DEMO_PID" 2>/dev/null || fail "lazy target exited early"
  sleep 0.1
done
[[ -S "$SOCK2" ]] || fail "lazy target socket missing"

CLI2=("./build/ihook-cli" --pid "$DEMO_PID" --rundir "$TMPDIR_TEST/run2")
"${CLI2[@]}" slots late_function | grep >/dev/null "no" ||
  fail "lazy slot was not unresolved before hook"
"${CLI2[@]}" hook late_function --mode enter_exit |
  grep >/dev/null "hooked late_function" || fail "lazy hook install"
"${CLI2[@]}" slots late_function | grep >/dev/null "yes.*late_function" ||
  fail "slot was not resolved as lazy"
sleep 5
grep -q "lazy result=42" "$TMPDIR_TEST/late.out" ||
  fail "lazy original returned the wrong value"
"${CLI2[@]}" stats | grep >/dev/null "late_function" ||
  fail "lazy hook produced no statistics"
"${CLI2[@]}" unhook late_function >/dev/null || fail "lazy unhook"

echo "PASS: all ihook smoke tests"
