/*
 * Pointers - Memory manipulation patterns from shellcode/loaders
 * PE parsing, memory scanning, patching
 */

#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;
typedef void* PVOID;
typedef int BOOL;
#endif

// ============================================================================
// POINTER MACROS - every loader uses these
// ============================================================================

// Dereference at offset
#define DEREF(p)     (*(DWORD_PTR*)(p))
#define DEREF64(p)   (*(QWORD*)(p))
#define DEREF32(p)   (*(DWORD*)(p))
#define DEREF16(p)   (*(WORD*)(p))
#define DEREF8(p)    (*(BYTE*)(p))

// RVA to VA conversion
#define RVA2VA(base, rva) ((PVOID)((BYTE*)(base) + (DWORD)(rva)))

// VA to RVA conversion
#define VA2RVA(base, va)  ((DWORD)((BYTE*)(va) - (BYTE*)(base)))

// Pointer arithmetic
#define PTR_ADD(p, off)  ((PVOID)((BYTE*)(p) + (off)))
#define PTR_SUB(p, off)  ((PVOID)((BYTE*)(p) - (off)))
#define PTR_DIFF(a, b)   ((DWORD_PTR)(a) - (DWORD_PTR)(b))

// ============================================================================
// PE HEADER NAVIGATION
// ============================================================================

// DOS header
#define DOS(m)     ((PIMAGE_DOS_HEADER)(m))

// NT headers
#define NT(m)      ((PIMAGE_NT_HEADERS)RVA2VA(m, DOS(m)->e_lfanew))

// File header
#define FILE_HDR(m) (&NT(m)->FileHeader)

// Optional header
#define OPT(m)     (&NT(m)->OptionalHeader)

// Data directory
#define DIR(m,i)   (&OPT(m)->DataDirectory[i])

// Section headers
#define SEC(m)     ((PIMAGE_SECTION_HEADER)((BYTE*)OPT(m) + FILE_HDR(m)->SizeOfOptionalHeader))

// Export directory
#define EXP(m)     ((PIMAGE_EXPORT_DIRECTORY)RVA2VA(m, DIR(m,0)->VirtualAddress))

// Import directory
#define IMP(m)     ((PIMAGE_IMPORT_DESCRIPTOR)RVA2VA(m, DIR(m,1)->VirtualAddress))

// ============================================================================
// MEMORY COPY PATTERNS
// ============================================================================

// Basic memcpy (no libc)
void cpy(BYTE* d, BYTE* s, DWORD n)
{
    while(n--) *d++ = *s++;
}

// Backward copy (for overlapping regions)
void cpy_back(BYTE* d, BYTE* s, DWORD n)
{
    d += n; s += n;
    while(n--) *--d = *--s;
}

// DWORD aligned copy
void cpy32(DWORD* d, DWORD* s, DWORD count)
{
    while(count--) *d++ = *s++;
}

// REP MOVSB (Windows intrinsic)
#ifdef _WIN32
#define MOVSB(d,s,n) __movsb((BYTE*)(d), (BYTE*)(s), (n))
#else
#define MOVSB(d,s,n) cpy((BYTE*)(d), (BYTE*)(s), (n))
#endif

// ============================================================================
// MEMORY SCAN PATTERNS
// ============================================================================

// Find byte in range
BYTE* scan_byte(BYTE* start, BYTE* end, BYTE val)
{
    while(start < end) {
        if(*start == val) return start;
        start++;
    }
    return 0;
}

// Find pattern (exact match)
BYTE* scan_pattern(BYTE* mem, DWORD sz, BYTE* pat, DWORD plen)
{
    BYTE* end = mem + sz - plen;
    while(mem <= end) {
        DWORD i;
        for(i = 0; i < plen && mem[i] == pat[i]; i++);
        if(i == plen) return mem;
        mem++;
    }
    return 0;
}

// Find pattern with mask (FF=match, 00=wildcard)
BYTE* scan_mask(BYTE* mem, DWORD sz, BYTE* pat, BYTE* mask, DWORD plen)
{
    BYTE* end = mem + sz - plen;
    while(mem <= end) {
        DWORD i;
        for(i = 0; i < plen; i++) {
            if((mem[i] & mask[i]) != (pat[i] & mask[i]))
                break;
        }
        if(i == plen) return mem;
        mem++;
    }
    return 0;
}

// Find MZ header
BYTE* find_mz(BYTE* start, BYTE* end)
{
    while(start < end - 2) {
        if(start[0] == 'M' && start[1] == 'Z')
            return start;
        start++;
    }
    return 0;
}

// ============================================================================
// MEMORY PATCHING
// ============================================================================

// Simple patch
void patch(BYTE* target, BYTE* bytes, DWORD len)
{
    while(len--) *target++ = *bytes++;
}

// Patch with protection change
BOOL patch_safe(BYTE* target, BYTE* bytes, DWORD len)
{
    DWORD old;
    if(!VirtualProtect(target, len, 0x40, &old))
        return 0;
    patch(target, bytes, len);
    VirtualProtect(target, len, old, &old);
    return 1;
}

// NOP out code
void nop_out(BYTE* target, DWORD len)
{
    DWORD old;
    VirtualProtect(target, len, 0x40, &old);
    while(len--) *target++ = 0x90;
    VirtualProtect(target - len, len, old, &old);
}

// Patch JE to JMP (bypass check)
void patch_je_jmp(BYTE* target)
{
    // 74 XX (JE) -> EB XX (JMP)
    if(*target == 0x74) {
        DWORD old;
        VirtualProtect(target, 1, 0x40, &old);
        *target = 0xEB;
        VirtualProtect(target, 1, old, &old);
    }
}

// ============================================================================
// HOOK INSTALLATION
// ============================================================================

// x86 relative JMP (5 bytes)
void write_jmp32(BYTE* from, BYTE* to)
{
    DWORD old;
    VirtualProtect(from, 5, 0x40, &old);
    from[0] = 0xE9;
    *(DWORD*)(from + 1) = (DWORD)(to - from - 5);
    VirtualProtect(from, 5, old, &old);
}

// x64 absolute JMP (12 bytes)
void write_jmp64(BYTE* from, BYTE* to)
{
    DWORD old;
    VirtualProtect(from, 12, 0x40, &old);
    // mov rax, addr
    from[0] = 0x48;
    from[1] = 0xB8;
    *(QWORD*)(from + 2) = (QWORD)to;
    // jmp rax
    from[10] = 0xFF;
    from[11] = 0xE0;
    VirtualProtect(from, 12, old, &old);
}

// ============================================================================
// POINTER CASTING PATTERNS
// ============================================================================

// Cast buffer to function and call
#define EXEC(p) ((void(*)())(p))()

// With return value
#define CALL(p,t) ((t(*)())(p))()

// Type punning via pointer
typedef union {
    DWORD dw;
    BYTE  b[4];
    WORD  w[2];
    float f;
} PTYPE;

// View DWORD as bytes
#define AS_BYTES(dw) ((BYTE*)&(dw))

// ============================================================================
// DOUBLE POINTER PATTERNS
// ============================================================================

// Output parameter (Windows API style)
// e.g., VirtualAllocEx(h, &base, ...)
typedef PVOID* PPVOID;

// Allocate and return via pointer
BOOL alloc_out(PPVOID out, DWORD size)
{
    *out = VirtualAlloc(0, size, 0x3000, 0x04);
    return *out != 0;
}

// Chain of pointers (PEB walking)
// fs:[0x30] -> PEB -> Ldr -> InLoadOrderModuleList -> ...

// ============================================================================
// PE PARSING HELPERS
// ============================================================================

// Get module size from PE headers
DWORD get_image_size(PVOID base)
{
    if(DEREF16(base) != 0x5A4D) return 0;  // MZ check

    DWORD pe_off = DEREF32((BYTE*)base + 0x3C);
    if(DEREF32((BYTE*)base + pe_off) != 0x4550) return 0;  // PE check

    return DEREF32((BYTE*)base + pe_off + 0x50);  // SizeOfImage
}

// Get entry point
PVOID get_entry_point(PVOID base)
{
    if(DEREF16(base) != 0x5A4D) return 0;

    DWORD pe_off = DEREF32((BYTE*)base + 0x3C);
    DWORD ep_rva = DEREF32((BYTE*)base + pe_off + 0x28);

    return RVA2VA(base, ep_rva);
}

// Find export by name
PVOID get_export(PVOID base, char* name)
{
    DWORD pe_off = DEREF32((BYTE*)base + 0x3C);
    DWORD exp_rva = DEREF32((BYTE*)base + pe_off + 0x78);
    if(!exp_rva) return 0;

    BYTE* exp = (BYTE*)base + exp_rva;
    DWORD nNames = DEREF32(exp + 0x18);
    DWORD* names = (DWORD*)RVA2VA(base, DEREF32(exp + 0x20));
    WORD*  ords  = (WORD*)RVA2VA(base, DEREF32(exp + 0x24));
    DWORD* funcs = (DWORD*)RVA2VA(base, DEREF32(exp + 0x1C));

    for(DWORD i = 0; i < nNames; i++) {
        char* fn = (char*)RVA2VA(base, names[i]);
        // strcmp
        char* a = fn; char* b = name;
        while(*a && *a == *b) { a++; b++; }
        if(*a == *b)
            return RVA2VA(base, funcs[ords[i]]);
    }
    return 0;
}

// ============================================================================
// GHIDRA-STYLE DECOMPILED CODE
// ============================================================================

// What Ghidra shows - unnamed variables
DWORD FUN_00401234(PVOID param_1, DWORD param_2)
{
    BYTE* pbVar1;
    DWORD uVar2;
    DWORD uVar3;

    pbVar1 = (BYTE*)param_1;
    uVar2 = 0;
    uVar3 = 0;

    while(uVar2 < param_2) {
        uVar3 = uVar3 + pbVar1[uVar2];
        uVar2++;
    }
    return uVar3;
}

// Same thing recovered
DWORD checksum(BYTE* data, DWORD len)
{
    DWORD sum = 0;
    for(DWORD i = 0; i < len; i++)
        sum += data[i];
    return sum;
}

// ============================================================================
// EOF
// ============================================================================
