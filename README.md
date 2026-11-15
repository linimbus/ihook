# ihook — 基于 GOT/PLT 的动态插桩框架

`ihook` 是一个 Linux x86-64 用户态动态插桩框架：

- **服务端**：`build/ihook.so`，通过 `LD_PRELOAD` 装入目标进程，启动一个子线程监听 Unix Domain Socket。
- **客户端**：C++17 CLI（`build/ihook-cli`）和 Python CLI（`python/ihook_cli.py`）。
- **协议**：Unix Socket 上按行传输 JSON（line-delimited JSON）。
- **插桩**：扫描目标进程已加载 ELF 的 GOT/PLT 重定位，把目标符号的 GOT 槽原子替换为 trampoline，支持任意动态符号的安装与卸载。
- **记录**：每次插桩、去插桩、失败、命中次数/返回次数/耗时都会写入 JSONL 日志；也可通过 CLI 实时查询。
- **被测试程序**：`demo/` 下提供多类、多线程的 C++17 Demo。

> 当前实现聚焦 **GOT/PLT 调用点**：直接调用、跨模块调用、`-fno-plt` 的 GOT 调用会被覆盖；虚函数表调用、内联函数、静态链接函数不在覆盖范围内（详见“限制”）。

---

## 1. 目录结构

```
.
├── Makefile
├── README.md
├── include/
│   └── ihook_engine.h          # 服务端 C 接口
├── src/
│   ├── common/
│   │   └── json.hpp            # 无第三方依赖的 JSON 解析/序列化
│   ├── server/
│   │   ├── hook_engine.c       # GOT/PLT 扫描、补丁、统计、日志
│   │   ├── trampoline.S        # x86-64 入口/出口 trampoline
│   │   └── server.cpp          # C++17 Unix Socket + JSON 控制面
│   └── cli/
│       └── ihook_cli.cpp       # C++17 CLI
├── python/
│   └── ihook_cli.py            # Python CLI
├── demo/
│   ├── libdemo.h
│   ├── libdemo.cpp             # 多类共享库（Account/Shape/Circle/...）
│   └── demo_main.cpp           # 多线程测试驱动
└── tests/
    └── smoke.sh                # 端到端测试
```

构建产物：

| 文件 | 说明 |
| --- | --- |
| `build/ihook.so` | 注入目标进程的服务端 |
| `build/ihook-cli` | C++17 客户端 |
| `build/libdemo.so` | Demo 共享库 |
| `build/demo` | Demo 主程序 |

---

## 2. 构建

依赖：Linux x86-64、GCC/Clang、GNU Make、pthread、libdl、libstdc++。不需要任何第三方库。

```bash
make            # 构建全部
make server     # 仅构建 ihook.so
make cli        # 仅构建 ihook-cli
make demo       # 仅构建 demo/libdemo
make test       # 端到端 smoke test
make clean
```

---

## 3. 快速开始

### 3.1 启动被插桩进程

```bash
# 终端 1：让 demo 运行 60 秒
LD_PRELOAD=$PWD/build/ihook.so \
IHOOK_LOG=/tmp/ihook-demo.jsonl \
./build/demo --seconds 60 --threads 3
```

输出示例：

```
ihook demo pid=12345 version=demo-1.0 threads=3 seconds=60
  socket: /tmp/ihook/ihook-12345.sock
  hint: build/ihook-cli --pid 12345 symbols demo
```

服务端构造时会：

1. 初始化插桩引擎；
2. 创建 `/tmp/ihook/ihook-<pid>.sock`（权限 `0600`）；
3. 启动 socket 服务线程和日志刷新线程；
4. 打开 `IHOOK_LOG` 指定的 JSONL 日志。

### 3.2 查看符号

```bash
./build/ihook-cli --pid 12345 info
./build/ihook-cli --pid 12345 symbols demo
```

`symbols` 会同时显示 mangled 名称和 demangle 后的 C++ 名称：

```
demo::Account::deposit(long)
  _ZN4demo7Account7depositEl  slots=1 active=0
demo::Shape::scaled_area(double) const
  _ZNK4demo5Shape11scaled_areaEd  slots=1 active=0
```

### 3.3 安装插桩

```bash
# 直接 C 符号，enter_exit：统计进入、返回和 TSC 周期
./build/ihook-cli --pid 12345 hook demo_add --mode enter_exit

# C++ 方法：可直接写 demangle 后的名字
./build/ihook-cli --pid 12345 hook 'demo::Account::deposit(long)' --mode enter

# 只插桩某个模块
./build/ihook-cli --pid 12345 hook malloc --module libc.so.6 --mode enter
```

### 3.4 查看统计

```bash
./build/ihook-cli --pid 12345 stats
./build/ihook-cli --pid 12345 list
```

示例：

```
pid=12345 active_hooks=2 slots=1386 modules=6 total_calls=1200 total_errors=0 log=/tmp/ihook-demo.jsonl
ID  MODE        SLOTS  FAIL   CALLS       RETURNS     ERRORS    AVG_CYC     SYMBOL
----------------------------------------------------------------------------------------------------
1   enter_exit  1      0      900         900         0         469         demo_add
2   enter       1      0      300         0           0         0           demo::Account::deposit(long)
```

### 3.5 去插桩

```bash
./build/ihook-cli --pid 12345 unhook demo_add
./build/ihook-cli --pid 12345 unhook 'demo::Account::deposit(long)'
./build/ihook-cli --pid 12345 list
```

### 3.6 日志切换 / 刷新

```bash
./build/ihook-cli --pid 12345 setlog /tmp/another.jsonl
./build/ihook-cli --pid 12345 flush
./build/ihook-cli --pid 12345 setlog off
```

### 3.7 Python 客户端

```bash
python3 python/ihook_cli.py --pid 12345 ping
python3 python/ihook_cli.py --pid 12345 info
python3 python/ihook_cli.py --pid 12345 symbols demo
python3 python/ihook_cli.py --pid 12345 hook 'demo::Account::deposit(long)' --mode enter_exit
python3 python/ihook_cli.py --pid 12345 stats
python3 python/ihook_cli.py --pid 12345 unhook 'demo::Account::deposit(long)'
```

### 3.8 发现可用 socket

```bash
./build/ihook-cli --list
python3 python/ihook_cli.py sockets
```

---

## 4. 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `IHOOK_RUNDIR` | `/tmp/ihook` | socket 与默认日志目录 |
| `IHOOK_SOCKET` | 空 | 指定完整 socket 路径，优先级最高 |
| `IHOOK_LOG` | `<rundir>/ihook-<pid>.log` | JSONL 日志路径；`off`/`none`/`0` 关闭 |
| `IHOOK_DISABLE` | 空 | 非空且非 `0/off/false/no` 时完全禁用服务端 |
| `LD_PRELOAD` | — | 必须指向 `build/ihook.so` |

默认路径规则：

```
socket: <IHOOK_RUNDIR 或 /tmp/ihook>/ihook-<pid>.sock
log:    <IHOOK_LOG，或 <rundir>/ihook-<pid>.log>
```

---

## 5. CLI 命令参考

```
ihook-cli --pid PID [--json] [--timeout MS] <command> [args]
ihook-cli --socket PATH <command> [args]
ihook-cli --list
```

| 命令 | 说明 |
| --- | --- |
| `ping` | 探活，返回 pid/engine/version |
| `info` | socket、日志、模块数、GOT 槽数量、hook 数、运行时间 |
| `symbols [PATTERN] [--module GLOB] [--limit N]` | 列出当前已加载 GOT/PLT 中的符号，支持 demangle |
| `slots [SYMBOL] [--module GLOB] [--limit N]` | 查看具体 GOT 槽：地址、模块、lazy、active、命中次数 |
| `hook SYMBOL [--module GLOB] [--mode enter\|enter_exit] [--log FILE]` | 安装插桩；SYMBOL 可为 mangled 或 demangled |
| `unhook SYMBOL [--module GLOB]` | 卸载插桩并恢复 GOT |
| `list [--all]` | 当前活跃 hook；`--all` 包含已卸载记录 |
| `stats` | 命中/返回/错误/TSC 周期统计 |
| `setlog PATH` | 切换日志；`off` 关闭 |
| `flush` | 立即写一次统计快照 |

全局参数：

- `--pid`：根据 PID 推导 socket 路径。
- `--socket`：直接指定 socket。
- `--rundir`：覆盖目录。
- `--timeout`：socket 超时，C++ CLI 单位为毫秒，Python CLI 单位为秒。
- `--json`：打印完整 JSON 响应。

`hook` 的 `--mode`：

- `enter`（默认）：只统计进入次数，最安全；不改写返回地址。
- `enter_exit`：额外统计返回次数和 TSC 周期，会临时改写函数返回地址。

---

## 6. JSON 协议

传输方式：`AF_UNIX` + `SOCK_STREAM`，每个请求/响应一行 JSON，以 `\n` 结尾。一个连接可以发送多条请求；CLI 通常每次连接发送一条。

### 6.1 请求

```json
{"id":1,"cmd":"ping"}
{"id":1,"cmd":"info"}
{"id":1,"cmd":"symbols","pattern":"demo","module":"","limit":300}
{"id":1,"cmd":"slots","symbol":"demo_add","limit":100}
{"id":1,"cmd":"hook","symbol":"demo_add","mode":"enter_exit","module":""}
{"id":1,"cmd":"hook","symbol":"demo::Account::deposit(long)","mode":"enter"}
{"id":1,"cmd":"unhook","symbol":"demo_add"}
{"id":1,"cmd":"list","all":false}
{"id":1,"cmd":"stats"}
{"id":1,"cmd":"setlog","path":"/tmp/ihook.jsonl"}
{"id":1,"cmd":"flush"}
```

`id` 会原样回显，可为任意 JSON 值。

### 6.2 成功响应

```json
{
  "id": 1,
  "ok": true,
  "data": {
    "requested": "demo_add",
    "hooks_installed": 1,
    "total_slots": 1,
    "total_failed_slots": 0,
    "results": [
      {
        "symbol": "demo_add",
        "demangled": "demo_add",
        "ok": true,
        "hook_id": 1,
        "slots": 1,
        "failed_slots": 0
      }
    ]
  }
}
```

### 6.3 失败响应

```json
{
  "id": 1,
  "ok": false,
  "error": "symbol_not_found",
  "message": "symbol 'foo' was not found in any loaded GOT/PLT relocation; ...",
  "data": {
    "suggestions": [
      {"symbol": "_Z...", "demangled": "demo::...", "slots": 1}
    ]
  }
}
```

常见错误码：

| error | 含义 |
| --- | --- |
| `symbol_not_found` | 目标不在任何已加载 GOT/PLT 中，或用 `--module` 过滤后为空 |
| `already_hooked` | 同一符号（且模块过滤条件匹配）已安装 |
| `not_hooked` | `unhook` 时没有匹配的活跃 hook |
| `unresolved_symbol` | lazy GOT 槽无法通过 `dlsym`/本地符号解析原始地址 |
| `patch_failed` | `mprotect` 或 GOT 写入失败 |
| `invalid_mode` / `invalid_request` | 参数错误 |
| `bad_json` | 请求不是合法 JSON |
| `unknown_command` | 未知命令 |
| `log_open_failed` | 日志路径无法打开 |

### 6.4 符号解析顺序

1. 先按 **mangled** 名称精确匹配；
2. 再按 **demangled** 名称精确匹配；
3. 若查询不含 `(`，按 demangled 前缀匹配（例如 `demo::Account::deposit` 可命中所有重载）；
4. 都失败时返回 `symbol_not_found` 和最多 12 条建议。

C++ 名称由 `abi::__cxa_demangle` 生成。对于构造函数等一个 demangled 名称对应多个 mangled 名称的情况，会依次尝试多个符号。

---

## 7. 日志格式

日志是 JSONL（每行一个 JSON 对象），由服务端在独立线程中周期性写入，并在 hook/unhook/错误发生时立即写入。

启动：

```json
{"ts_ms":1794700804131,"event":"start","pid":12345,"socket":"/tmp/ihook/ihook-12345.sock","log":"/tmp/ihook-demo.jsonl","self":"/root/agent/build/ihook.so","version":"1.0.0"}
```

安装：

```json
{"ts_ms":1794700845742,"event":"hook","pid":12345,"hook_id":1,"symbol":"demo_add","module":"","mode":"enter","slots":1,"failed_slots":0,"result":"ok"}
```

失败（符号不存在、部分槽失败等）：

```json
{"ts_ms":1794701049596,"event":"error","pid":12345,"op":"hook","symbol":"definitely_not_here","module":"","reason":"symbol_not_found","message":"..."}
{"ts_ms":1794700845742,"event":"slot_error","pid":12345,"symbol":"foo","module":"/lib/x86_64-linux-gnu/libc.so.6","slot":"0x7f...","reason":"unresolved_symbol"}
```

周期统计：

```json
{"ts_ms":1794700850796,"event":"stats","pid":12345,"hooks":[{"id":1,"symbol":"demo_add","mode":"enter_exit","slots":1,"calls":210,"returns":210,"cycles":129964,"errors":0}],"total_calls":210,"total_errors":0}
```

去插桩：

```json
{"ts_ms":1794700849382,"event":"unhook","pid":12345,"symbol":"demo_add","module":"","restored":1,"failed":0,"result":"ok"}
```

退出：

```json
{"ts_ms":1794700957824,"event":"exit","pid":12345,"uptime_ms":10001}
```

说明：

- `calls`：进入 trampoline 的次数。
- `returns`：`enter_exit` 模式下 exit trampoline 执行的次数。
- `cycles`：`rdtsc` 差值累加（不是纳秒，适合相对比较）。
- `errors`：槽安装失败、TLS frame 溢出等错误累计。
- `failed_slots`：安装时失败的 GOT 槽数量。

---

## 8. 架构与实现

### 8.1 启动流程

```
目标进程 exec
  └─ ld.so 加载 LD_PRELOAD=ihook.so
      └─ __attribute__((constructor)) server.cpp:ihook_constructor
          ├─ ihook_engine_init()        # 初始化路径、日志、mutex
          ├─ start_flusher()            # 1s 周期写统计
          └─ start_server()
              ├─ /tmp/ihook/ihook-<pid>.sock  (0600)
              ├─ listen + pthread
              └─ ihook_engine_log_start()
```

服务端线程只负责控制面；目标程序的业务线程不会因为 socket I/O 阻塞。

### 8.2 GOT/PLT 扫描

`hook_engine.c` 使用 `dl_iterate_phdr` 遍历所有已加载 ELF：

1. 从 `PT_DYNAMIC` 读取 `DT_SYMTAB`、`DT_STRTAB`、`DT_JMPREL`、`DT_PLTRELSZ`、`DT_PLTREL`，以及 `.rela.dyn` 的 `DT_RELA/DT_RELASZ`。
2. 遍历 `R_X86_64_JUMP_SLOT` 和函数类型的 `R_X86_64_GLOB_DAT`。
3. 用 `base + r_offset` 得到 GOT 槽地址。
4. 只接受位于可写 `PT_LOAD` 段内的槽，避免读到未映射地址。
5. 用地址哈希表去重，把槽信息持久化在 `g_slots[]` 中。
6. 跳过：
   - 自身 `ihook.so`（避免插桩库递归插桩自己）；
   - `ld-linux` / `ld.so`；
   - `linux-vdso`。

### 8.3 GOT 补丁

对每个匹配槽：

```
原值 raw = GOT[slot]
if raw 是 lazy PLT stub:
    original = dlsym(RTLD_DEFAULT, symbol)
             或模块内本地定义地址
else:
    original = raw

trampoline = 每槽独立 mmap 页（可执行）
mprotect(GOT 页, 原权限 | PROT_WRITE)
atomic store GOT[slot] = trampoline
mprotect(GOT 页, 原权限)
```

- 使用原权限恢复，兼容 RELRO（GOT 页通常只读）。
- 8 字节对齐原子写，目标线程可以继续执行。
- 每个槽有独立 trampoline 页，避免在“运行时切换页面 W/X”导致并发执行崩溃。
- 去插桩时把 `raw` 写回，保留 lazy 绑定语义。

### 8.4 lazy binding

经典 x86-64 PLT lazy 槽的初始 GOT 值指向 `push $index; jmp plt0`。检测方式：

1. 读取 `GOT[slot]` 指向的机器码；
2. 若为 `0x68`（push imm32）后接 `e9` 或 CET 的 `f2 e9`，判定为 lazy；
3. 再结合 `dladdr`：地址在同一模块且没有符号名，也视为 lazy；
4. 用 `dlsym(RTLD_DEFAULT, symbol)` 解析真实函数；失败时回退到该槽所属模块的本地 `st_value`（仅对非 IFUNC）。

这样即使槽尚未触发首次绑定，也能安全调用原函数。详见“限制”中的竞态说明。

### 8.5 trampoline

`src/server/trampoline.S` 生成每槽入口：

```
endbr64
mov r11d, <slot_id>
movabs r10, ihook_common_entry
jmp r10
```

`ihook_common_entry`：

1. 保存 `rax`（可变参数向量个数 `%al`）、`rdi/rsi/rdx/rcx/r8/r9`、`xmm0..xmm7`；
2. 调用 `ihook_on_enter(slot_id, &return_address_slot)`；
3. C 函数累加命中计数，并（`enter_exit` 模式）在 TLS 中压入返回帧；
4. 恢复寄存器和 `%rax`；
5. `jmp` 到原始函数，保持原调用栈不变。

`enter_exit` 模式：

- C 函数把栈上的返回地址替换为 `ihook_exit_stub`；
- 原返回地址保存在线程局部 `IHookFrame` 栈中；
- 原函数 `ret` 后执行 exit stub，保存 `rax/rdx/xmm0/xmm1`；
- 调用 `ihook_on_exit()` 弹出 TLS 帧、累加返回次数和 `rdtsc` 差值；
- 恢复返回值寄存器，跳回真实调用者。

### 8.6 统计与日志

- 命中路径只做 `__atomic_fetch_add` 和 TLS 操作，不加锁、不分配、不做 I/O。
- 日志刷新线程每 1 秒调用一次；仅当计数变化时写 `stats` 行。
- 失败事件立即写入日志。
- `unhook` 前会强制写一次最终统计，避免短生命周期 hook 的计数丢失。
- 日志写入使用原始 `write` 系统调用，避免 hook 到 `write/printf` 时递归。

---

## 9. Demo 程序

`build/demo` 链接 `build/libdemo.so`，包含多个类：

| 类 | 方法 |
| --- | --- |
| `demo::Account` | `deposit`、`withdraw`、`balance`、`deposit_count` |
| `demo::Shape` | 虚接口 + 非虚 `scaled_area` |
| `demo::Circle` | `area`、`perimeter` |
| `demo::Rectangle` | `area`、`perimeter` |
| `demo::EventLog` | `record`、`size`、`last` |
| `demo::Worker` | 多线程循环调用上面这些 API |

另外导出：

```c
long demo_add(long a, long b);
size_t demo_checksum(const char* text);
```

Demo 默认 20 秒、3 线程，可用 `--seconds`、`--threads`、`--iterations` 调整。

推荐演示流程：

```bash
# 终端 1
LD_PRELOAD=$PWD/build/ihook.so IHOOK_LOG=/tmp/demo.jsonl ./build/demo --seconds 120

# 终端 2
./build/ihook-cli --pid <pid> symbols demo
./build/ihook-cli --pid <pid> hook 'demo::Account::deposit(long)' --mode enter_exit
./build/ihook-cli --pid <pid> hook demo_add --mode enter_exit
sleep 3
./build/ihook-cli --pid <pid> stats
./build/ihook-cli --pid <pid> slots 'demo::Account::deposit(long)'
./build/ihook-cli --pid <pid> unhook 'demo::Account::deposit(long)'
```

`Account::deposit` 是普通成员函数，通过 PLT 调用，适合演示；`Shape::area` 是虚函数，通过 vtable 调用，不会出现在 GOT/PLT 中（见限制）。

---

## 10. 测试

```bash
make test
```

`tests/smoke.sh` 会：

1. 以 `LD_PRELOAD` 启动 demo；
2. 校验 ping/info/symbols/slots；
3. 安装 `demo_add` 的 `enter_exit` hook 并检查统计；
4. 用 demangled 名称安装 C++ 方法 hook；
5. 卸载并确认 GOT 恢复；
6. 检查不存在符号的 CLI 报错与日志记录；
7. 使用 Python CLI 完成 ping/hook/stats/unhook；
8. 切换日志、flush、检查 JSONL 内容。

测试使用临时 `IHOOK_RUNDIR`，不会污染 `/tmp/ihook`。

---

## 11. 限制与注意事项

### 11.1 只覆盖 GOT/PLT 调用点

- **适合**：跨共享库调用、libc API、编译器生成的 PLT 调用、`-fno-plt` 的 GOT 调用、函数指针槽。
- **不适合**：
  - 虚函数（vtable）；
  - 编译器内联/直接绑定的同模块调用；
  - `static` 函数、隐藏符号、未导出符号；
  - 静态链接程序（没有动态 PLT/GOT）；
  - `dlopen` 后尚未被下一次 `refresh` 扫描到的模块（执行任意命令时会自动 refresh 并补挂已存在的活跃 hook）。

如果符号不在任何 GOT/PLT 中，CLI 会打印 `symbol_not_found`，并在日志记录 `{"event":"error","reason":"symbol_not_found",...}`。这满足“符号表不存在也要通过 CLI 打印出来”的要求。

### 11.2 lazy binding 竞态

如果 hook 安装时另一个线程正好首次调用该 lazy 槽，动态链接器可能在极窄窗口内把 GOT 写回真实地址，覆盖我们的 trampoline。代码会检测并重写一次；但仍建议对生产程序使用：

```bash
LD_BIND_NOW=1 LD_PRELOAD=... ./target
```

或在启动早期安装 hook。

### 11.3 `enter_exit` 的代价

- 会改写函数返回地址，因此：
  - 不要用于依赖 `__builtin_return_address`/`backtrace` 的函数；
  - 不要用于会通过异常、`longjmp`、`setjmp` 跨过该帧的函数；
  - 不要用于 `long double` 返回值（x87 `st0`）或 AVX 向量返回值（YMM 上半部分）——当前保存的是 SysV 整数/SSE 返回寄存器。
- 对大多数 libc API 和普通 C/C++ 函数是安全的。
- 对可能抛异常的 C++ 方法，建议使用默认 `enter` 模式。

### 11.4 符号与模块

- 一个符号同时只建议安装一个 hook；重复安装返回 `already_hooked`。
- `--module` 支持 basename 或 `fnmatch` glob，例如 `libc.so.6`、`libdemo*`、`/lib/x86_64-linux-gnu/libc.so.6`。
- 动态加载/卸载模块时，槽表只增不减；卸载后的槽在写入前会检查 `/proc/self/maps`，避免访问已解除映射的地址。

### 11.5 平台

- 当前 trampoline 是 **x86-64 System V** 汇编；其他架构需要重写 `trampoline.S`。
- 支持 PIE/非 PIE、RELRO、CET IBT 的 `endbr64`。
- 插桩库自身不会被插桩，避免日志/JSON 代码递归。

### 11.6 安全

- socket 目录默认 `0700`（创建时），socket 文件 `0600`。
- 服务端通过 `SO_PEERCRED` 校验：仅允许同 UID 或 root 连接。
- `IHOOK_DISABLE=1` 可完全禁用服务端。

---

## 12. 故障排查

| 现象 | 排查 |
| --- | --- |
| `connect ... No such file or directory` | 确认目标进程仍存活；确认 `/tmp/ihook/ihook-<pid>.sock` 存在；确认 CLI 与目标使用相同 `IHOOK_RUNDIR` |
| `connect ... Connection refused` | socket 文件是残留的；服务端可能已崩溃/退出，重启目标 |
| `symbol_not_found` | 运行 `symbols` 查看实际 GOT/PLT 符号；确认不是虚函数/内联/静态链接；检查 `--module` 过滤 |
| `already_hooked` | 先 `unhook`，或 `list` 查看已有 hook |
| 插桩后目标崩溃 | 尝试 `--mode enter`；避免对 `longjmp`/异常路径使用 `enter_exit`；确认不是对自身/loader 插桩 |
| 日志没有内容 | 检查 `IHOOK_LOG` 路径权限；`info` 中 `log_enabled` 是否为 true；执行 `flush` |
| 统计为 0 | 目标可能没有执行到该调用点；用 `slots` 确认 `active=yes`；某些调用可能被内联或直接绑定 |

---

## 13. 设计要点

- **控制面与数据面分离**：socket/JSON/日志刷新在独立线程；命中路径无锁、无分配、无 I/O。
- **不依赖第三方库**：内置最小 JSON 解析器，便于在任意目标环境中 `LD_PRELOAD`。
- **每槽 trampoline**：避免“一个符号一个全局跳板”在模块绑定不同实现时调用错误的 original。
- **原始保护位恢复**：兼容 RELRO，不长期降低 GOT 页权限。
- **延迟解析 + 本地回退**：覆盖 lazy binding 和部分非导出符号。
- **可观测性**：每次安装/卸载/失败、周期命中统计、最终统计都落在 JSONL 中。
- **可脚本化**：C++17 与 Python 两个客户端共享同一协议。
