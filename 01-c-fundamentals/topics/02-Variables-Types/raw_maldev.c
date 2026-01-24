/*
 * Types - What you actually see in decompiled samples
 * Ghidra output style, real implant patterns
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
// GHIDRA OUTPUT STYLE - unnamed vars, cryptic casts
// ============================================================================

// What Ghidra gives you when analyzing malware
typedef struct _UNK_STRUCT_0x18 {
    DWORD dw0;
    DWORD dw4;
    PVOID p8;
    DWORD dwC;
    DWORD dw10;
    WORD  w14;
    BYTE  b16;
    BYTE  pad17;
} UNK_STRUCT, *PUNK_STRUCT;

// Recovered after analysis - Cobalt Strike beacon config
#pragma pack(push,1)
typedef struct {
    WORD  wVer;           // +0x00
    WORD  wPayloadType;   // +0x02
    DWORD dwPort;         // +0x04
    DWORD dwSleepTime;    // +0x08
    DWORD dwMaxGetSize;   // +0x0C
    DWORD dwJitter;       // +0x10
    DWORD dwMaxDNS;       // +0x14
    BYTE  bPublicKey[16]; // +0x18
    BYTE  bC2Server[256]; // +0x28
} BEACON_CFG;
#pragma pack(pop)

// ============================================================================
// POINTER ARITHMETIC MACROS - seen in every loader
// ============================================================================

#define RVA2VA(base, rva)    ((PVOID)((DWORD_PTR)(base) + (DWORD)(rva)))
#define DEREF(p)             (*(DWORD_PTR*)(p))
#define DEREF32(p)           (*(DWORD*)(p))
#define DEREF16(p)           (*(WORD*)(p))
#define DEREF8(p)            (*(BYTE*)(p))

// PE header navigation - every shellcode uses this
#define DOS(m)  ((PIMAGE_DOS_HEADER)(m))
#define NT(m)   ((PIMAGE_NT_HEADERS)RVA2VA(m, DOS(m)->e_lfanew))
#define OPT(m)  (&NT(m)->OptionalHeader)
#define DIR(m,i) (&OPT(m)->DataDirectory[i])

// ============================================================================
// TYPE PUNNING - reading PE headers, parsing configs
// ============================================================================

// What you see decompiled - no variable names
DWORD FUN_00401000(PVOID param_1)
{
    WORD uVar1;
    DWORD uVar2;
    BYTE *pbVar3;

    uVar1 = DEREF16(param_1);
    if (uVar1 != 0x5a4d) {  // MZ check
        return 0;
    }
    pbVar3 = (BYTE*)param_1 + DEREF32((BYTE*)param_1 + 0x3c);
    uVar2 = DEREF32(pbVar3);
    if (uVar2 != 0x4550) {  // PE check
        return 0;
    }
    return DEREF32(pbVar3 + 0x50);  // SizeOfImage
}

// Same thing, slightly recovered
DWORD GetImageSize(PVOID pBase)
{
    if(DEREF16(pBase) != 0x5A4D) return 0;
    BYTE* pNT = (BYTE*)pBase + DEREF32((BYTE*)pBase + 0x3C);
    if(DEREF32(pNT) != 0x4550) return 0;
    return DEREF32(pNT + 0x50);
}

// ============================================================================
// UNION OVERLAY - config parsing, protocol parsing
// ============================================================================

// Seen in: Emotet, Dridex, TrickBot config decryption
typedef union {
    BYTE  b[8];
    WORD  w[4];
    DWORD d[2];
    QWORD q;
} CRYPTO_BLOCK;

// XOR key extraction pattern
void decrypt_block(CRYPTO_BLOCK* blk, DWORD key)
{
    blk->d[0] ^= key;
    blk->d[1] ^= key;
}

// ============================================================================
// BITFIELD STRUCTURES - PE section characteristics
// ============================================================================

typedef struct {
    DWORD type_offset : 12;
    DWORD type        : 4;
    DWORD reserved    : 16;
} RELOC_ENTRY;  // PE relocation entry

typedef struct {
    unsigned r : 1;
    unsigned w : 1;
    unsigned x : 1;
    unsigned s : 1;  // shared
    unsigned : 28;
} MEM_PROT;

// ============================================================================
// FUNCTION POINTER TYPEDEFS - API resolution
// ============================================================================

// Standard patterns from shellcode
typedef PVOID  (WINAPI *t_VirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *t_VirtualProtect)(PVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *t_CreateThread)(PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);
typedef HMODULE(WINAPI *t_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *t_GetProcAddress)(HMODULE, LPCSTR);
typedef PVOID  (WINAPI *t_RtlMoveMemory)(PVOID, PVOID, SIZE_T);

// Compact - what you see in stagers
typedef PVOID  (WINAPI *fnAlloc)(PVOID,SIZE_T,DWORD,DWORD);
typedef HANDLE (WINAPI *fnThread)(PVOID,SIZE_T,PVOID,PVOID,DWORD,PDWORD);

// ============================================================================
// PACKED CONFIG STRUCTURES - real implant configs
// ============================================================================

// Metasploit stager config
#pragma pack(push,1)
typedef struct {
    DWORD dwXorKey;
    WORD  wPort;
    DWORD dwHost;     // inet_addr format
    DWORD dwExitFunc; // hash
} MSF_CFG;
#pragma pack(pop)

// Generic implant config pattern
#pragma pack(push,1)
typedef struct {
    BYTE  magic[4];        // "CFG\x00"
    DWORD dwVersion;
    DWORD dwFlags;
    BYTE  bKey[32];
    DWORD cbC2;
    // BYTE  bC2Data[];     // Variable length
} IMPLANT_CFG;
#pragma pack(pop)

// ============================================================================
// INTEGER TRAPS - exploitation primitives
// ============================================================================

// Integer overflow -> heap overflow
// Seen in: CVE-2021-21224 (Chrome V8)
DWORD calc_size_vuln(DWORD count, DWORD elem_sz)
{
    return count * elem_sz;  // No overflow check
}

// Safe version pattern
int calc_size_safe(DWORD count, DWORD elem_sz, DWORD* out)
{
    QWORD sz = (QWORD)count * elem_sz;
    if(sz > 0xFFFFFFFF) return 0;
    *out = (DWORD)sz;
    return 1;
}

// Sign comparison bypass
// if(user_len > MAX_LEN) return ERR;  // -1 passes as 0xFFFFFFFF
int check_len_vuln(int user_len, unsigned int max_len)
{
    if((unsigned int)user_len > max_len) return 0;
    return 1;
}

// ============================================================================
// MEMORY LAYOUT PATTERNS
// ============================================================================

// Stack string - avoid .rodata detection
// Seen in: APT29, Lazarus, most advanced malware
void get_kernel32(char* out)
{
    out[0]='k'; out[1]='e'; out[2]='r'; out[3]='n';
    out[4]='e'; out[5]='l'; out[6]='3'; out[7]='2';
    out[8]='.'; out[9]='d'; out[10]='l'; out[11]='l';
    out[12]=0;
}

// Compact stack string
#define STR_K32 {'k','e','r','n','e','l','3','2','.','d','l','l',0}

// ============================================================================
// TYPE CASTING PATTERNS - shellcode exec
// ============================================================================

// Classic shellcode execution cast
#define EXEC(p) ((void(*)())(p))()

// With parameter
#define EXEC1(p,a) ((void(*)(PVOID))(p))(a)

// Return value
#define CALL(p,r) ((r(*)())(p))()

// Full pattern from decompiled loader
void run_payload(BYTE* sc, DWORD len)
{
    PVOID p;
    DWORD old;

    p = VirtualAlloc(0, len, 0x3000, 0x04);  // RW first
    __movsb(p, sc, len);                      // intrinsic copy
    VirtualProtect(p, len, 0x20, &old);       // RX
    ((void(*)())p)();
}

// ============================================================================
// SAMPLE PATTERNS - real decompiled code
// ============================================================================

/*
 * Pattern: Cobalt Strike beacon XOR decode
 * Sample: Various CS beacons
 *
 * void decode(BYTE* data, DWORD len, BYTE key) {
 *     for(DWORD i=0; i<len; i++)
 *         data[i] ^= key;
 * }
 */
#define XOR(b,l,k) do{BYTE*_=(BYTE*)(b);DWORD n=(l);while(n--)*_++^=(k);}while(0)

/*
 * Pattern: Config extraction from .data section
 * Seen in: TrickBot, Emotet, QakBot
 */
IMPLANT_CFG* find_cfg(PVOID pBase)
{
    BYTE* p = (BYTE*)pBase;
    DWORD sz = GetImageSize(pBase);

    for(DWORD i=0; i<sz-sizeof(IMPLANT_CFG); i++) {
        if(p[i]=='C' && p[i+1]=='F' && p[i+2]=='G' && p[i+3]==0) {
            return (IMPLANT_CFG*)(p+i);
        }
    }
    return 0;
}

/*
 * Pattern: Hash-based string comparison
 * Avoids string literals in binary
 */
#define H_KERNEL32 0x6A4ABC5B
#define H_NTDLL    0x3CFA685D

DWORD djb2(char* str)
{
    DWORD h = 5381;
    int c;
    while((c = *str++))
        h = ((h << 5) + h) + c;
    return h;
}

// ============================================================================
// EOF
// ============================================================================
