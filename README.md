# tylogin-native

江苏电信校园网（天翼校园宽 ESurfing，SSID `@f-Young`，`preportal.go189.cn` 门户）独立登录客户端的C++实现

提取来自Android客户端的libdaproxy.so，内置一个基于 [Unicorn Engine](https://github.com/unicorn-engine/unicorn) 的 AArch64 沙箱模拟器，模拟执行。

```
单文件 ~3.5MB，冷启动 <10ms（含 JNI_OnLoad），峰值内存 ~18MB
可静态链接（musl）
```

## 使用

```bash
./build/tylogin -u 账号 -p 密码            # 一次性登录（默认退出后会话保持在线）
./build/tylogin -u 账号 -p 密码 -l         # 保活模式（心跳 + 探活 + 掉线重连，Ctrl+C 退出时自动下线）
./build/tylogin -d ...                    # 调试日志（协议 + 模拟器）
```

`-u/-p/-l/-d/-h`、退出码（0 成功 / 1 认证失败 / 2 网络不可达）、工作目录 `config` 配置文件（`account=`/`password=`，含别名）。默认（无 `-l`）登录成功后立即退出，会话保留至服务端心跳超时；`-l` 与官方客户端行为一致，Ctrl+C 退出时自动发送下线报文。

环境变量：

| 变量 | 说明 |
| --- | --- |
| `TYLOGIN_HOME` | 模拟器工作目录（默认 `~/.tylogin`） |
| `TY_EMU_TIMEOUT` | 单段模拟执行的看门狗秒数（默认 60，0 关闭） |
| `TY_THREAD_SYNC=1` | 同步执行 so 内创建的线程（调试用，默认跳过） |
| `TY_PORTAL_BASE` | 门户地址覆盖（配合 mock 服务器做联调，勿在生产使用） |

## 构建

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
```

依赖：C++17 编译器、CMake、python3。

### Windows（MSYS2 mingw64）

支持 Windows 原生构建，产物为单文件静态 exe，无需运行时 DLL：

```bash
cmake -B build_win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build_win          # -> build-win/tylogin.exe
```

注意：首次配置 unicorn 时若出现 `failed to create symbolic link ... unicorn.o` 可忽略（仅最后的符号链接步骤需要特权，静态库本身已生成）。

Linux 下源码路径与 Windows 完全共用（`_WIN32` 分支隔离），行为与退出码一致；`HOME` 回退顺序为 `TYLOGIN_HOME` → `USERPROFILE` → 当前目录。

## 自检

```bash
./build/tylogin --selftest                # JNI_OnLoad 冒烟 + 模块失败路径
./build/tylogin --selftest damod.bin      # 用真实 ZSM 模块对拍 aid/key/prev + enc/dec
./build/tylogin --dump-zsm damod.bin      # 校内网抓取一份下发的算法模块
tools/realtest.sh                         # 校内网一键实测（见下）
```

`--selftest damod.bin` 的判定标准（`aid` 前 8 位是服务端下发时间戳、`key` 每次下发都不同，故只校验静态特征）：

```
aid  = 68bdf74c-50fa-11f0-b040-fa163efce7ed   # 静态后缀 -50fa-11f0-b040-fa163efce7ed
key  = <64 hex 会话密钥>
prev = 001
dec roundtrip ok   # 还原出的 XML 含完整 <sysinfo> 注入
```

加密兼容性已用双实现交叉验证：同一模块下，Java/unidbg 与本实现的密文可互相解密且明文逐字节一致（sysinfo 注入内容一致）。

### 模拟环境要点（libdaproxy.so 适配记录）

模块解压后通过 `dlopen/dlsym` 按清单探测约 70 个 libc 符号，任一缺失即放弃装载；探测到的符号会被真实调用。因此 `guestlibc.cpp` 注册了完整的实现集（字符串/内存/时间/locale 属性/socket 桩/pthread 桩/`__android_log_print`），其中：

- `uname`/`__system_property_get`（`gsm.network.type=Unknown`、`ro.build.version.sdk=23` 等）决定 `enc` 注入的 `<sysinfo>` 内容，必须与 unidbg SDK23 镜像取值一致
- `dlopen` 为每个库名返回不同句柄（相同句柄会被判定为篡改）
- socket 组为假成功 + I/O 失败：反向通知通道按协议分析无实际流量

## 校园网实测

`tools/realtest.sh` 一键完成：门户状态检查 → 抓取下发的算法模块 → 模拟器对拍 →（可选）真实登录。

```bash
tools/realtest.sh --wait                  # 当前已在线时轮询等待掉线后自动测试
tools/realtest.sh --login                 # 对拍通过后用 ./config 里的账号真实登录
tools/realtest.sh -u 账号 -p 密码 --login --keep
```

注意：已在线状态下门户不下发算法模块（`check.go189.cn` 返回 200 直接判"已在线"），必须处于未认证状态才能走完整流程。

## 模拟器架构（src/zsm/）

Java 版用 unidbg 完成的事情，这里由四块自研组件承担：

| 组件 | 职责 |
| --- | --- |
| `elfload.cpp` | AArch64 ELF 加载：PT_LOAD 映射 + RELATIVE/ABS64/GLOB_DAT/JUMP_SLOT 四种重定位 |
| `emu.cpp` | Unicorn 运行时：事件驱动主循环、SVC 桩分发、syscall 层（open/read/write/mmap/uname…）、guest 堆分配器 |
| `guestlibc.cpp` | so 的全部 55 个 bionic 导入的原生实现（malloc/memcpy/字符串/stdio/pthread/dl…） |
| `jni.cpp` + `damod.cpp` | 假 JNI 环境（233 槽 JNIEnv 虚表、JavaVM、对象模型、RegisterNatives）+ DaMod 会话封装 |

运行机制：guest 通过 SVC 桩调用宿主（unicorn 在 INTR 钩子中按 PC 定位桩号，停机后由主循环在 `uc_emu_start` 之外执行宿主实现，因此宿主可随意再入 guest——`pthread_once` 回调、`JNI_OnLoad` 等均基于此）。`JNI_OnLoad` 所需的 4 个 Android 调用（`currentPackageName` / `currentApplication` / `getFilesDir` / `getAbsolutePath`）按 unidbg 版同样方式 mock。TLS（`TPIDR_EL0`，bionic 槽位 0/5）在构造时初始化。

`libdaproxy.so` 以字节数组形式嵌入二进制（`resources/`，构建期由 `tools/embed.py` 生成）。

## 测试

```bash
python3 tools/mock_portal.py 8899 &
TY_PORTAL_BASE=http://127.0.0.1:8899 ./build/tylogin -u test -p test -d
```

mock 门户复刻 detect→check→BAS→index.cgi 链路并校验 POST 头（`CDC-Checksum` 与请求体 MD5 一致性）；`tools/mock_portal.py` 也可作为协议参考。

## 已知限制

- 传输层支持 Linux/macOS（POSIX socket）与 Windows（winsock2）
- 门户协议为纯 HTTP，无 TLS
- `libdaproxy.so` 版权归中国电信及其开发方所有，仅收录用于协议兼容研究；仅供个人学习研究

## 部署（systemd）

```ini
# /etc/systemd/system/tylogin.service
[Unit]
Description=Jiangsu ESurfing Campus Portal Client (native)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/tylogin
ExecStart=/opt/tylogin/tylogin -l
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
```

账号密码放 `/opt/tylogin/config`（`account=`/`password=`，`chmod 600`），二进制与 config 同目录即可，无需 JRE。

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now tylogin
journalctl -u tylogin -f
```
