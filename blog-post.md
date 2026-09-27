# 一条命令从标准用户到 SYSTEM：UAC 绕过 + 令牌窃取两级提权的完整分析与教训

> 本文基于本地授权的安全测试，记录一次把 `uacbypass`（UAC 绕过）与 `systembypass`（SYSTEM 令牌窃取）合并成单工具的实践：**一条命令贯通「标准用户 → 管理员 → NT AUTHORITY\SYSTEM」两级提权**。测试环境为 Windows 11 Pro for Workstations `10.0.28000`，账户在本地 `Administrators` 组内，以标准用户令牌（Medium 完整性）启动。
>
> **免责声明**：仅用于本机授权的安全测试与恶意样本行为验证，请勿用于未授权的系统。

---

## 一、整体设计

工具的核心思路是把两级提权拆成两个独立阶段，靠「当前自身权限」自动切换，**不需要任何额外的阶段标记参数**：

```
阶段 0（非管理员时）：UAC 绕过，以管理员身份重启自身
    │
    ▼  提权后的实例发现自己 isElevated() 为真，自动进入阶段 1
阶段 1（已是管理员时）：复制 SYSTEM 进程令牌，以 SYSTEM 身份拉起目标程序
```

这条自动衔接是整个工具最省事的设计：阶段 0 的注册表载荷里直接写「自身完整路径 + 原始参数」，重启后的实例带着 `--verify` 等参数原样继续往下走。

### 阶段 0：ms-settings 注册表劫持 + 自动提权白名单程序

UAC 绕过的原理并不新鲜：

1. 在 `HKCU\Software\Classes\ms-settings\Shell\Open\command` 写入劫持项：
   - `(默认值) = "<自身完整路径>" <原始参数...>`
   - `DelegateExecute = ""`（置空，绕过 COM 委派，迫使系统直接执行默认值）
2. 用 `ShellExecuteEx` 拉起「自动提权白名单」程序，例如 `fodhelper.exe`、`computerdefaults.exe`、`slui.exe` 或 `ms-settings:` 协议 URI。这些程序设计上就会以高完整性运行并触发 `ms-settings` 的 Shell 打开操作——也就是执行我们刚写入的劫持载荷。
3. `RegDeleteTreeA` 清理痕迹。

工具内置了 4 种手法（`--method=` 可选，`auto` 模式依次尝试），对应常见样本家族里 `restart_as_admin_*` 的触发方式。

### 阶段 1：SeDebugPrivilege + 令牌复制

管理员上下文中拿到 SYSTEM 的主路线只有四步：

```
1. AdjustTokenPrivileges 开启 SeDebugPrivilege
2. OpenProcess + OpenProcessToken 定位 winlogon.exe（默认目标）
3. DuplicateTokenEx（SecurityImpersonation → TokenPrimary）
4. CreateProcessWithTokenW 以 SYSTEM 身份拉起目标程序
```

`SeDebugPrivilege` 是管理员令牌的固有部分——这是后文加固讨论的起点。默认策略下先尝试首选进程（`winlogon.exe`，可用 `--target=` 指定），失败则遍历全部进程寻找任意可打开令牌的 SYSTEM 进程。主路线失败时，`--fallback` 会改走 `schtasks /create /ru SYSTEM` 建计划任务的兜底路线（任务计划服务本身以 SYSTEM 运行，但注意任务跑在**会话 0**，没有桌面，交互式窗口不可见）。

### 验证结果

```
PS> .\allbypass.exe --verify
[INFO] 阶段 0:UAC 绕过,以管理员身份重启自身
[INFO] 目标命令: C:\Users\Public\ucbtest\allbypass.exe --verify
[INFO] ---- 手法 fodhelper: Windows 可选功能 ----
[INFO] 已拉起触发程序: C:\Windows\System32\fodhelper.exe
[OK] 阶段 0 完成,提权后的实例已接管后续流程
```

证据文件 `%TEMP%\allbypass_verify_system.txt`：

```
用户名              SID
=================== ========
nt authority\system S-1-5-18
```

| 阶段 | 验证方式 | 结果 |
|---|---|---|
| 阶段 0（→管理员） | `--verify-uac`，查 `S-1-16-12288` | ✅ `High Mandatory Level` + `BUILTIN\Administrators 已启用` |
| 阶段 1（→SYSTEM） | `--verify`，查 `S-1-5-18` | ✅ `nt authority\system` |
| 完整链路 | `--verify` | ✅ 一次运行贯通两级 |

---

## 二、实测发现一：决定令牌能否复制的是令牌 DACL，不是 PPL

这是整个测试中最有价值的发现，也是修正了一个常见误解。

用探测脚本以**高完整性管理员**身份逐个进程实测（`NtQueryInformationProcess(ProcessProtectionInformation)` + 逐项访问权测试）：

| 进程 | 保护级别 | `TOKEN_QUERY` | `TOKEN_DUPLICATE` | 结论 |
|---|---|---|---|---|
| `winlogon.exe` | Type=0 无保护 | ✅ | ✅ | 可复制 |
| `lsass.exe` | **Type=1 PPL, Signer=4 (WinTcb)** | ✅ | ✅ | **PPL 不挡复制** |
| `smss.exe` | **Type=1 PPL, Signer=6 (WinSystem)** | ✅ | ✅ | **PPL 不挡复制** |
| `TrustedInstaller.exe` | Type=0 无保护 | ✅ | ❌ 错误 5 | **令牌 DACL 拒绝** |

注意反直觉的部分：`lsass` 和 `smss` 开着 Type=1 PPL，令牌照样可复制；而没有 PPL 保护的 `TrustedInstaller` 反而拒绝复制。

测试机当时 `RunAsPPL = 2`（LSA 保护已启用、UEFI 锁定），VBS/HVCI 也在运行（`SecurityServicesRunning = 2`），但 `--token=lsass.exe --verify` 依然成功拿到 SYSTEM。结论可以明确表述为：

> **PPL 根本不参与 `OpenProcessToken` 的访问检查。PPL 拦的是进程内存读（`PROCESS_VM_READ`，即凭据转储），不是令牌复制。真正决定能否复制的是令牌对象自身的 DACL。**
>
> **开了 PPL + HVCI ≠ 挡得住「管理员 → SYSTEM」。PPL 保护凭据，不保护 SYSTEM 这个身份。**

### 顺带观察：本机实际可复制的身份范围

工具内置了 `--list-tokens` 枚举本机全部可打开令牌（按 身份+完整性 去重，并单独探测每个令牌是否具备 `TOKEN_DUPLICATE`）。在交互式会话的管理员上下文里，实际可用的只有：

- **NT AUTHORITY\SYSTEM**（可复制）
- **当前用户自己的令牌**（High）

`LOCAL SERVICE` / `NETWORK SERVICE` / `DWM` / `UMFD` 的令牌 DACL 同样不给复制权。

---

## 三、实测发现二：新版 Windows 上 TrustedInstaller 已经「消失」了

`--trustedinstaller`（先启动 TrustedInstaller 服务，再获取 `NT SERVICE\TrustedInstaller` 令牌）在 build 28000 上**失败，但原因不是权限，而是这个身份已经没有任何进程持有**：

```
> sc qc TrustedInstaller
SERVICE_START_NAME : localSystem          <-- 不是 NT SERVICE\TrustedInstaller

> dir /q C:\Windows\System32\ntoskrnl.exe
... NT SERVICE\TrustedInstaller   13,887,008 ntoskrnl.exe
```

- 服务已改为以 **LocalSystem** 运行 → `TrustedInstaller.exe` 进程的令牌身份是 `NT AUTHORITY\SYSTEM`；
- 但系统文件的**属主**仍是 `NT SERVICE\TrustedInstaller` 这个 SID；
- 也就是说，这个身份如今只剩「文件属主」这一个存在形式，**不再有进程持有它的令牌**，自然无令牌可偷。

**实际影响**：在这类系统上，「TrustedInstaller 权限」等价于 SYSTEM 权限——拿到 SYSTEM 后用 `takeown` / `icacls`，或启用 `SeTakeOwnershipPrivilege` / `SeRestorePrivilege`，就能改写这些受保护文件。所以该路线失败时，用默认的 SYSTEM 即可达成同一目的。

一个工程化的细节：工具在按选择器取不到令牌时，会**自动列出本机实际存在的身份**（含「不允许复制」标记），避免继续猜。这类「失败时输出实际状态」的行为对排查同类问题非常有用。

---

## 四、实现中的六个坑

这些坑都直接导致过「功能看起来正常、实际静默失败」，值得单独记录。

### 1. 注册表载荷必须是 ANSI，不能是 UTF-8

劫持注册表项是交给 Windows 命令行解释器执行的，它按**系统代码页**读取 `REG_SZ` 内容。若直接写入 UTF-8，中文用户名下的 `%TEMP%` 路径会变乱码，表现为「命令好像执行了但没有任何产物」。日志可以显示 UTF-8，但写入注册表前必须转 `CP_ACP`。

### 2. 枚举与复制必须用不同权限的令牌句柄，否则会静默失败

`DuplicateTokenEx` 要求**源句柄**具备 `TOKEN_DUPLICATE`。如果为了「最小权限」把枚举用的句柄统一改成只申请 `TOKEN_QUERY`，再复用它去复制，就会得到 `DuplicateTokenEx 失败`。两个用途必须各开各的句柄。这个坑的表象是 winlogon 的令牌「突然全部拿不到」，非常迷惑。

顺带的经验：枚举阶段用最小权限（`PROCESS_QUERY_LIMITED_INFORMATION` + `TOKEN_QUERY`）是对的——受 PPL 保护的进程仍允许查询身份，若枚举就申请大权限，清单里反而会出现「凭空消失」的进程。可复制性应**单独探测一次** `TOKEN_DUPLICATE` 并记入结果。

### 3. 不要猜控制台代码页

早先实现是 `GetConsoleOutputCP()` + 转 GBK，在 GBK 控制台与 UTF-8 终端（`chcp 65001` / Windows Terminal）混用时会输出乱码。正确做法：控制台场景直接 `WriteConsoleW` 喂 UTF-16，由控制台自行渲染；重定向时才原样写 UTF-8 字节。另外刻意**不**调用 `SetConsoleOutputCP` 改全局状态，避免残留给调用方。

### 4. 表格按字节补空格会错位

`printf("%-38s")` 按**字节数**补齐，而中文在 UTF-8 里占 3 字节却只占 2 列，含中文用户名的行整列错位，看起来也像乱码。需要对 CJK 宽字符按**显示宽度**补齐。

### 5. MinGW 的 `swprintf` 里 `%s` 是 `char*`

按 ISO C，宽字符 printf 的 `%s` 指多字节串（宽串要用 `%ls`）。传 `wchar_t*` 会在首个 0 字节处截断，`L"C:\Users\..."` 直接变成 `"C"`。在 MinGW 下拼路径一律改用 `std::wstring` 运算符，不用格式符。

### 6. `AdjustTokenPrivileges` 返回 TRUE 不代表成功

即使特权不在令牌里它也返回 TRUE，必须再查 `GetLastError() == ERROR_SUCCESS` 才算真的成功。这是 Windows API 里著名的「假成功」陷阱之一。

### 附：一个容易被忽略的工程细节

提权后的实例由 `fodhelper` 在**独立控制台**里启动，调用方的终端看不到它的输出，而且那个控制台在进程结束时立刻消失。因此阶段 1 的日志必须**同时落盘**（`%TEMP%\allbypass_stage1.log`），否则出问题完全无从定位。做这类「进程会自我复制并以不同身份重启」的工具时，日志通道要在设计阶段就想清楚。

---

## 五、检测与加固

### 检测点（按攻击链顺序）

1. `HKCU\Software\Classes\ms-settings\Shell\Open\command` 被写入（尤其 `DelegateExecute` 置空）——Sysmon 事件 13（注册表值写入）；
2. 非 `System32` 父进程启动 `fodhelper.exe` / `computerdefaults.exe`，并派生出 `cmd.exe` / `powershell.exe`——审计策略 4688 + Sysmon 事件 1（父子进程关系）；
3. 进程开启 `SeDebugPrivilege` 后 `OpenProcess` 到 `winlogon.exe` / `lsass.exe` 等 SYSTEM 进程——ETW 进程句柄获取（4104/4105）；
4. `CreateProcessWithTokenW` 产生父进程为 `fodhelper.exe` 的 SYSTEM 子进程——进程创建事件里「父进程与令牌身份不匹配」是强特征；
5. `schtasks /create /ru SYSTEM` 后立即 `/run` 并 `/delete`——服务/计划任务事件 + 短生命周期模式。

### 加固（按有效性排序）

1. **日常使用标准用户账户** —— 唯一能 100% 阻断该手法的手段。UAC 绕过要求调用者已在 Administrators 组内；标准用户即使触发绕过也只能拿到 Medium 令牌，阶段 1 的 `SeDebugPrivilege` 根本开不起来。
2. **AppLocker / WDAC** 限制 `fodhelper.exe`、`computerdefaults.exe`、`slui.exe` 的可执行上下文（只允许从 System32 由特定父进程启动）。
3. 限制 `HKCU\Software\Classes` 下 `ms-settings` 的写入（注册表 ACL）。
4. 审计策略 4688 进程创建 + Sysmon 事件 13 指向上述路径，配合 EDR 规则。
5. UAC 调至最高级别——能挡住部分变体，但**挡不住 fodhelper 类**。

> **关键结论**：第 3~5 项都只是提高门槛。**令牌窃取本身在管理员上下文里没有可靠的软件层缓解**——`SeDebugPrivilege` 是管理员令牌的固有部分，PPL 又不覆盖令牌复制。防线必须建在「不要以管理员身份日常使用」这一层。

---

## 六、结语

这次把两条独立的提权链路合并、并系统性实测之后，有三个认识比工具本身更值得带走：

1. **两级提权的自动衔接是可行的**：让阶段 0 的载荷携带原始参数重启自身，阶段判定靠运行时权限检查而非命令行标记，整条链就能「一条命令」贯通。
2. **PPL 常被高估**：它保护的是进程内存（凭据），不是令牌。评估「管理员 → SYSTEM」风险时，PPL/HVCI 不在缓解清单里。
3. **OS 版本演进会悄悄改变攻击面**：TrustedInstaller 从「独立身份的宿主服务」退化成「只剩文件属主的形式」，很多老教程里的路线在新系统上失效的原因不是被修复，而是前提条件消失了。做攻击/防御分析时，先确认「目标身份现在还有谁持有」。

---

### 附录：工具用法速查

```
allbypass.exe [软件 [参数...]] [选项]

选项:
  --method=<名字>    UAC 手法: fodhelper | computerdefaults | slui | ms-settings | auto(默认)
  --list-tokens      列出当前可获取的令牌(账户 / 完整性 / 会话 / 是否可复制 / 来源进程)
  --token=<选择器>   指定要获取的令牌身份, 默认 SYSTEM
                     选择器可为账户名、账户名尾段、SID 或进程名
  --trustedinstaller 便捷写法: 获取 NT SERVICE\TrustedInstaller(新版系统上已无进程持有)
  --start-service=<名> 获取令牌前先启动的服务
  --target=<进程名>  默认策略下的首选 SYSTEM 进程, 默认 winlogon.exe
  --fallback         令牌获取失败时改用 schtasks 兜底
  --force-fallback   强制只走 schtasks 兜底
  --verify           验证启动后的真实身份(与目标令牌 SID 比对)
  --verify-uac       只验证到管理员即停止
  --stop-at-admin    只提到管理员, 不提权到其他身份
  --keep             保留劫持项与计划任务(便于观察/取证)
  --list             列出可用 UAC 手法
  --help             显示帮助
```

```powershell
.\allbypass.exe                                # 一路提到 SYSTEM, 打开 powershell
.\allbypass.exe --verify                       # 一路提到 SYSTEM 并自动验证
.\allbypass.exe --list-tokens                  # 看本机有哪些身份可拿
.\allbypass.exe --token=lsass.exe --verify     # 按进程名指定来源
.\allbypass.exe --stop-at-admin --verify-uac   # 只提到管理员
```

编译（MinGW，注意必须用 `g++` 驱动而非 `gcc`，否则 C++ 运行时链接失败）：

```
g++ -O2 -Wall -Wextra -std=c++17 -o allbypass.exe allbypass.cpp -ladvapi32 -lshell32 -luser32
```
