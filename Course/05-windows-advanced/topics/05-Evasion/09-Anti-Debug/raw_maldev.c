/*
 * Anti-Debug - Detection and evasion of debuggers
 * Patterns from packers, malware samples
 */

#include <windows.h>
#include <intrin.h>

// ============================================================================
// NTAPI TYPEDEFS
// ============================================================================

typedef NTSTATUS (NTAPI *t_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *t_NtSIT)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *t_NtCTE)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// ProcessDebugPort = 7
// ProcessDebugFlags = 0x1F
// ProcessDebugObjectHandle = 0x1E

// ThreadHideFromDebugger = 0x11

// ============================================================================
// PEB CHECKS
// ============================================================================

__forceinline BYTE* GetPEB(void)
{
#ifdef _WIN64
    return (BYTE*)__readgsqword(0x60);
#else
    return (BYTE*)__readfsdword(0x30);
#endif
}

BOOL chk_BeingDebugged(void)
{
    return GetPEB()[2];  // BeingDebugged @ offset 2
}

BOOL chk_NtGlobalFlag(void)
{
#ifdef _WIN64
    DWORD flags = *(DWORD*)(GetPEB() + 0xBC);
#else
    DWORD flags = *(DWORD*)(GetPEB() + 0x68);
#endif
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    return (flags & 0x70) != 0;
}

BOOL chk_HeapFlags(void)
{
#ifdef _WIN64
    BYTE* heap = *(BYTE**)(GetPEB() + 0x30);
    DWORD flags = *(DWORD*)(heap + 0x70);
    DWORD force = *(DWORD*)(heap + 0x74);
#else
    BYTE* heap = *(BYTE**)(GetPEB() + 0x18);
    DWORD flags = *(DWORD*)(heap + 0x40);
    DWORD force = *(DWORD*)(heap + 0x44);
#endif
    return (flags != 2) || (force != 0);
}

// ============================================================================
// API CHECKS
// ============================================================================

BOOL chk_IsDebuggerPresent(void)
{
    return IsDebuggerPresent();
}

BOOL chk_CheckRemoteDebugger(void)
{
    BOOL dbg = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
    return dbg;
}

BOOL chk_DebugPort(void)
{
    t_NtQIP NtQIP = (t_NtQIP)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    DWORD_PTR port = 0;
    NtQIP(GetCurrentProcess(), 7, &port, sizeof(port), 0);

    return port != 0;
}

BOOL chk_DebugFlags(void)
{
    t_NtQIP NtQIP = (t_NtQIP)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    DWORD flags = 0;
    NtQIP(GetCurrentProcess(), 0x1F, &flags, sizeof(flags), 0);

    return flags == 0;  // 0 = being debugged
}

BOOL chk_DebugObject(void)
{
    t_NtQIP NtQIP = (t_NtQIP)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    HANDLE obj = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), 0x1E, &obj, sizeof(obj), 0);

    return (status == 0);  // Success = debug object exists
}

// ============================================================================
// TIMING CHECKS
// ============================================================================

BOOL chk_RDTSC(void)
{
    DWORD64 t1 = __rdtsc();

    volatile int x = 0;
    for(int i = 0; i < 1000; i++) x += i;

    DWORD64 t2 = __rdtsc();

    return (t2 - t1) > 100000;  // Stepping = slow
}

BOOL chk_QueryPerformance(void)
{
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    volatile int x = 0;
    for(int i = 0; i < 1000; i++) x += i;

    QueryPerformanceCounter(&t2);

    DWORD64 us = ((t2.QuadPart - t1.QuadPart) * 1000000) / freq.QuadPart;
    return us > 1000;  // > 1ms is suspicious
}

BOOL chk_GetTickCount(void)
{
    DWORD t1 = GetTickCount();
    Sleep(1);
    DWORD t2 = GetTickCount();

    return (t2 - t1) > 100;
}

// ============================================================================
// EXCEPTION CHECKS
// ============================================================================

BOOL chk_INT3(void)
{
    __try {
        __debugbreak();
        return 1;  // If we get here, debugger handled it
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;  // Exception raised normally
    }
}

BOOL chk_INT2D(void)
{
    __try {
        __asm { int 2dh }
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

BOOL chk_ICE(void)
{
    __try {
        __asm { __emit 0xF1 }  // ICEBP
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

BOOL chk_Trap(void)
{
    __try {
        __asm {
            pushfd
            or dword ptr [esp], 0x100  // Set TF
            popfd
            nop
        }
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// ============================================================================
// HARDWARE BREAKPOINT CHECK
// ============================================================================

BOOL chk_HardwareBP(void)
{
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if(!GetThreadContext(GetCurrentThread(), &ctx))
        return 0;

    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
}

// ============================================================================
// PROCESS/WINDOW CHECKS
// ============================================================================

BOOL chk_DebuggerWindows(void)
{
    char* windows[] = {
        "OLLYDBG", "x64dbg", "x32dbg", "IDA", "WinDbg",
        "Immunity Debugger", "Process Hacker", "Process Monitor",
        "Cheat Engine", "PE-bear", "CFF Explorer",
        0
    };

    for(int i = 0; windows[i]; i++) {
        if(FindWindowA(0, windows[i])) return 1;
        if(FindWindowA(windows[i], 0)) return 1;
    }
    return 0;
}

// ============================================================================
// PARENT PROCESS CHECK
// ============================================================================

BOOL chk_ParentProcess(void)
{
    // Normal parents: explorer.exe, cmd.exe, powershell.exe
    // Suspicious: ida.exe, ollydbg.exe, x64dbg.exe, windbg.exe

    // Would use NtQueryInformationProcess(ProcessBasicInformation)
    // to get parent PID, then check process name
    return 0;
}

// ============================================================================
// EVASION TECHNIQUES
// ============================================================================

void hide_HideFromDebugger(void)
{
    t_NtSIT NtSIT = (t_NtSIT)GetProcAddress(GetModuleHandleA("ntdll"), "NtSetInformationThread");
    NtSIT(GetCurrentThread(), 0x11, 0, 0);  // ThreadHideFromDebugger
}

void hide_PatchDbgBreakPoint(void)
{
    BYTE* p = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll"), "DbgBreakPoint");
    DWORD old;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *p = 0xC3;  // ret
    VirtualProtect(p, 1, old, &old);
}

void hide_PatchDbgUiRemoteBreakin(void)
{
    BYTE* p = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll"), "DbgUiRemoteBreakin");
    DWORD old;
    VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &old);

    // xor eax, eax; ret
    p[0] = 0x31; p[1] = 0xC0; p[2] = 0xC3;

    VirtualProtect(p, 6, old, &old);
}

void hide_BlockInput(void)
{
    // Block mouse/keyboard during critical sections
    BlockInput(TRUE);
    // ... do work
    BlockInput(FALSE);
}

void hide_ClearHardwareBP(void)
{
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
    ctx.Dr6 = ctx.Dr7 = 0;

    SetThreadContext(GetCurrentThread(), &ctx);
}

// ============================================================================
// SELF-DEBUGGING
// ============================================================================

BOOL chk_SelfDebug(void)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    if(!CreateProcessA(0, GetCommandLineA(), 0, 0, 0,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, 0, 0, &si, &pi)) {
        return 1;  // Already being debugged
    }

    DebugActiveProcessStop(pi.dwProcessId);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// ============================================================================
// COMBINED CHECK
// ============================================================================

BOOL is_debugged(void)
{
    if(chk_BeingDebugged())     return 1;
    if(chk_NtGlobalFlag())      return 1;
    if(chk_IsDebuggerPresent()) return 1;
    if(chk_DebugPort())         return 1;
    if(chk_HardwareBP())        return 1;
    if(chk_DebuggerWindows())   return 1;
    return 0;
}

int antidebug_score(void)
{
    int score = 0;

    if(chk_BeingDebugged())        score += 100;
    if(chk_NtGlobalFlag())         score += 50;
    if(chk_HeapFlags())            score += 50;
    if(chk_IsDebuggerPresent())    score += 100;
    if(chk_CheckRemoteDebugger())  score += 100;
    if(chk_DebugPort())            score += 100;
    if(chk_DebugFlags())           score += 75;
    if(chk_HardwareBP())           score += 80;
    if(chk_RDTSC())                score += 30;
    if(chk_DebuggerWindows())      score += 60;

    return score;
}

// ============================================================================
// ANTI-DEBUG LOOP (continuous monitoring)
// ============================================================================

DWORD WINAPI antidebug_thread(LPVOID param)
{
    while(1) {
        if(is_debugged()) {
            // Detected - take action
            ExitProcess(0);
            // Or: corrupt memory, infinite loop, etc.
        }
        Sleep(1000);
    }
    return 0;
}

void start_antidebug(void)
{
    CreateThread(0, 0, antidebug_thread, 0, 0, 0);
}

// ============================================================================
// EOF
// ============================================================================
