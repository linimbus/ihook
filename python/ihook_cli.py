#!/usr/bin/env python3
"""ihook Python client.

Speaks the same line-delimited JSON protocol as build/ihook-cli over the
per-process Unix domain socket created by the LD_PRELOAD server.
"""

import argparse
import glob
import json
import os
import socket
import sys

VERSION = "1.0.0"


def default_rundir(args):
    return args.rundir or os.environ.get("IHOOK_RUNDIR") or "/tmp/ihook"


def resolve_socket(args):
    if args.socket:
        return args.socket
    env = os.environ.get("IHOOK_SOCKET")
    if env:
        return env
    if args.pid is None:
        return ""
    return os.path.join(default_rundir(args), f"ihook-{args.pid}.sock")


def connect(path, timeout):
    if not path:
        print("ihook-py: specify --pid PID or --socket PATH", file=sys.stderr)
        raise SystemExit(2)
    if len(path.encode()) + 1 > 108:
        print(f"ihook-py: socket path too long: {path}", file=sys.stderr)
        raise SystemExit(2)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except OSError as exc:
        print(f"ihook-py: connect({path}) failed: {exc}", file=sys.stderr)
        sock.close()
        raise SystemExit(3)
    return sock


def send_request(sock, payload):
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    try:
        sock.sendall(data)
    except OSError as exc:
        print(f"ihook-py: send failed: {exc}", file=sys.stderr)
        raise SystemExit(3)
    buf = bytearray()
    try:
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > 16 * 1024 * 1024:
                print("ihook-py: response too large", file=sys.stderr)
                raise SystemExit(3)
    except OSError as exc:
        print(f"ihook-py: recv failed: {exc}", file=sys.stderr)
        raise SystemExit(3)
    finally:
        sock.close()
    if not buf:
        print("ihook-py: empty response", file=sys.stderr)
        raise SystemExit(3)
    text = bytes(buf).split(b"\n", 1)[0].decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"ihook-py: invalid JSON response: {exc}", file=sys.stderr)
        print(text, file=sys.stderr)
        raise SystemExit(3)


def shorten(text, width):
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def basename(path):
    return path.rsplit("/", 1)[-1] if "/" in path else path


def print_suggestions(data):
    suggestions = data.get("suggestions") or []
    if not suggestions:
        return
    print("did you mean:", file=sys.stderr)
    for item in suggestions:
        demangled = item.get("demangled") or item.get("symbol", "")
        symbol = item.get("symbol", "")
        extra = f"  [{symbol}]" if symbol and symbol != demangled else ""
        print(f"  {demangled}{extra}", file=sys.stderr)


def print_results(data, ok_verb="hooked"):
    for item in data.get("results") or []:
        demangled = item.get("demangled") or item.get("symbol", "")
        symbol = item.get("symbol", "")
        if item.get("ok"):
            print(f"{ok_verb} {demangled}")
            if symbol != demangled:
                print(f"  {symbol}")
            hook_id = item.get("hook_id")
            slots = item.get("slots", item.get("restored_slots", 0))
            failed = item.get("failed_slots", 0)
            prefix = f"  id={hook_id} " if hook_id is not None and hook_id >= 0 else "  "
            suffix = f" failed_slots={failed}" if failed else ""
            print(f"{prefix}slots={slots}{suffix}")
        else:
            print(
                f"failed {demangled}: {item.get('error', '')} - "
                f"{item.get('message', '')}"
            )


def print_hooks(data, stats_mode=False):
    hooks = data.get("hooks") or []
    if not hooks:
        print("no hooks")
        return
    if stats_mode:
        print(
            f"{'ID':<4}{'MODE':<12}{'SLOTS':<7}{'FAIL':<7}{'CALLS':<12}"
            f"{'RETURNS':<12}{'ERRORS':<10}{'AVG_CYC':<12}SYMBOL"
        )
        print("-" * 100)
    else:
        print(
            f"{'ID':<4}{'MODE':<12}{'SLOTS':<7}{'FAIL':<7}{'CALLS':<12}"
            f"{'RETURNS':<12}{'ERRORS':<10}SYMBOL"
        )
        print("-" * 88)
    for item in hooks:
        symbol = item.get("demangled") or item.get("symbol", "")
        line = (
            f"{item.get('id', 0):<4}{item.get('mode', ''):<12}"
            f"{item.get('slots', 0):<7}{item.get('failed_slots', 0):<7}"
            f"{item.get('calls', 0):<12}{item.get('returns', 0):<12}"
            f"{item.get('errors', 0):<10}"
        )
        if stats_mode:
            line += f"{item.get('avg_cycles', 0):<12}"
        print(line + shorten(symbol, 64))


def print_symbols(data):
    print(
        f"symbols: total={data.get('total', 0)} "
        f"returned={data.get('returned', 0)}"
    )
    for item in data.get("symbols") or []:
        demangled = item.get("demangled") or item.get("symbol", "")
        print(demangled)
        print(
            f"  {item.get('symbol', '')}  slots={item.get('slots', 0)} "
            f"active={item.get('active_slots', 0)}"
        )


def print_slots(data):
    print(f"slots: total={data.get('total', 0)} returned={data.get('returned', 0)}")
    slots = data.get("slots") or []
    if not slots:
        return
    print(
        f"{'SLOT':<18}{'MODULE':<34}{'LAZY':<6}{'ACTIVE':<7}{'HOOK':<8}"
        f"{'CALLS':<12}SYMBOL"
    )
    print("-" * 120)
    for item in slots:
        demangled = item.get("demangled") or item.get("symbol", "")
        print(
            f"{item.get('slot', ''):<18}"
            f"{shorten(basename(item.get('module', '')), 32):<34}"
            f"{'yes' if item.get('lazy') else 'no':<6}"
            f"{'yes' if item.get('active') else 'no':<7}"
            f"{item.get('hook_id', -1):<8}{item.get('calls', 0):<12}"
            f"{shorten(demangled, 60)}"
        )


def print_info(data):
    fields = [
        ("engine", f"{data.get('engine', '')} {data.get('version', '')}"),
        ("pid", data.get("pid", 0)),
        ("uid", data.get("uid", 0)),
        ("enabled", "yes" if data.get("enabled") else "no"),
        ("socket", data.get("socket", "")),
        ("log", data.get("log", "") if data.get("log_enabled") else "off"),
        ("hooks", data.get("hooks", 0)),
        ("slots", data.get("slots", 0)),
        ("modules", data.get("modules", 0)),
        ("uptime_ms", data.get("uptime_ms", 0)),
        ("self", data.get("self", "")),
        ("protocol", data.get("protocol", "")),
    ]
    for key, value in fields:
        print(f"{key:<14}{value}")


def list_sockets(args):
    directory = default_rundir(args)
    paths = sorted(glob.glob(os.path.join(directory, "*.sock")))
    if args.json:
        print(json.dumps({"ok": True, "data": {"rundir": directory, "sockets": paths}}, indent=2))
        return 0
    for path in paths:
        print(path)
    if not paths:
        print(f"no sockets in {directory}")
    return 0


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--pid", type=int, help="target process id")
    common.add_argument("--socket", help="exact Unix socket path")
    common.add_argument("--rundir", help="socket directory (default /tmp/ihook)")
    common.add_argument("--timeout", type=float, default=5.0,
                        help="socket timeout in seconds (default 5)")
    common.add_argument("--json", action="store_true",
                        help="print the raw JSON response")
    common.add_argument("--version", action="version",
                        version=f"ihook-py {VERSION}")

    # Subparsers must not reset options supplied before the command word, so
    # their defaults are SUPPRESS (unset options leave the main namespace
    # untouched).
    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("--pid", type=int, default=argparse.SUPPRESS,
                            help="target process id")
    sub_common.add_argument("--socket", default=argparse.SUPPRESS,
                            help="exact Unix socket path")
    sub_common.add_argument("--rundir", default=argparse.SUPPRESS,
                            help="socket directory (default /tmp/ihook)")
    sub_common.add_argument("--timeout", type=float, default=argparse.SUPPRESS,
                            help="socket timeout in seconds (default 5)")
    sub_common.add_argument("--json", action="store_true",
                            default=argparse.SUPPRESS,
                            help="print the raw JSON response")
    sub_common.add_argument("--version", action="version",
                            version=f"ihook-py {VERSION}")

    parser = argparse.ArgumentParser(
        description="ihook Python client for the GOT/PLT instrumentation server",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ping", parents=[sub_common], help="check the server")
    sub.add_parser("info", parents=[sub_common], help="server and target info")
    sub.add_parser("stats", parents=[sub_common], help="hook hit statistics")
    sub.add_parser("flush", parents=[sub_common], help="flush statistics to the log")

    p = sub.add_parser("symbols", parents=[sub_common], help="list GOT/PLT symbols")
    p.add_argument("pattern", nargs="?", default="", help="substring filter")
    p.add_argument("--module", default="", help="module basename or glob")
    p.add_argument("--limit", type=int, default=300)

    p = sub.add_parser("slots", parents=[sub_common], help="inspect GOT slots")
    p.add_argument("symbol", nargs="?", default="", help="mangled or demangled symbol")
    p.add_argument("--module", default="", help="module basename or glob")
    p.add_argument("--limit", type=int, default=300)

    p = sub.add_parser("hook", parents=[sub_common], help="install a hook")
    p.add_argument("symbol", help="mangled or demangled symbol")
    p.add_argument("--module", default="", help="module basename or glob")
    p.add_argument("--mode", choices=["enter", "enter_exit"], default="enter")
    p.add_argument("--log", default="", help="switch the JSONL log to this path")

    p = sub.add_parser("unhook", parents=[sub_common], help="remove a hook")
    p.add_argument("symbol", help="mangled or demangled symbol")
    p.add_argument("--module", default="", help="module basename or glob")

    p = sub.add_parser("list", parents=[sub_common], help="list active hooks")
    p.add_argument("--all", action="store_true", help="include inactive records")

    p = sub.add_parser("setlog", parents=[sub_common], help="set the JSONL log path")
    p.add_argument("path", help="log path, or 'off'")

    sub.add_parser("sockets", parents=[sub_common], help="list available sockets")
    return parser


def make_payload(args):
    payload = {"id": 1, "cmd": args.command}
    if args.command == "hook":
        payload["symbol"] = args.symbol
        payload["mode"] = args.mode
        if args.module:
            payload["module"] = args.module
        if args.log:
            payload["log"] = args.log
    elif args.command == "unhook":
        payload["symbol"] = args.symbol
        if args.module:
            payload["module"] = args.module
    elif args.command == "symbols":
        if args.pattern:
            payload["pattern"] = args.pattern
        if args.module:
            payload["module"] = args.module
        payload["limit"] = args.limit
    elif args.command == "slots":
        if args.symbol:
            payload["symbol"] = args.symbol
        if args.module:
            payload["module"] = args.module
        payload["limit"] = args.limit
    elif args.command == "list":
        payload["all"] = bool(args.all)
    elif args.command == "setlog":
        payload["path"] = args.path
    return payload


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "sockets":
        return list_sockets(args)

    socket_path = resolve_socket(args)
    sock = connect(socket_path, args.timeout)
    response = send_request(sock, make_payload(args))

    if args.json:
        print(json.dumps(response, indent=2))

    if not response.get("ok"):
        data = response.get("data") or {}
        if not args.json:
            print(
                f"error: {response.get('error')}: {response.get('message')}",
                file=sys.stderr,
            )
            print_suggestions(data)
            if data.get("results"):
                print_results(data)
        return 1

    if not args.json:
        data = response.get("data") or {}
        if args.command == "ping":
            print(
                f"pong: pid={data.get('pid')} engine={data.get('engine')} "
                f"{data.get('version')}"
            )
        elif args.command == "info":
            print_info(data)
        elif args.command == "symbols":
            print_symbols(data)
        elif args.command == "slots":
            print_slots(data)
        elif args.command == "hook":
            print_results(data)
            print(
                f"installed={data.get('hooks_installed', 0)} "
                f"slots={data.get('total_slots', 0)} "
                f"failed_slots={data.get('total_failed_slots', 0)}"
            )
            warning = data.get("warning")
            if warning:
                print(f"warning: {warning}", file=sys.stderr)
        elif args.command == "unhook":
            print_results(data, ok_verb="unhooked")
            print(
                f"unhooked={data.get('unhooked', 0)} "
                f"restored_slots={data.get('total_restored_slots', 0)} "
                f"failed_slots={data.get('total_failed_slots', 0)}"
            )
        elif args.command == "list":
            print_hooks(data, stats_mode=False)
        elif args.command == "stats":
            print(
                f"pid={data.get('pid')} active_hooks={data.get('active_hooks')} "
                f"slots={data.get('slots')} modules={data.get('modules')} "
                f"total_calls={data.get('total_calls')} "
                f"total_errors={data.get('total_errors')} "
                f"log={data.get('log')}"
            )
            print_hooks(data, stats_mode=True)
        elif args.command == "setlog":
            print(f"log={data.get('log')}")
        elif args.command == "flush":
            print(f"flushed log={data.get('log')}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # A pipe consumer such as `grep -q` may close early; not an error.
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)
