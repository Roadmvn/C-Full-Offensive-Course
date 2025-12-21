/*
 * Arrays - Shellcode buffers, lookup tables, encrypted strings
 * Patterns from loaders, droppers, implants
 */

#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef void* PVOID;
#endif

// ============================================================================
// SHELLCODE BUFFERS - every dropper has these
// ============================================================================

// Inline shellcode (lives in .data section)
// Pattern: Metasploit payload
BYTE sc_meterpreter[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
    0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    // ... truncated for example
};

// As DWORDs - evades some string detection
// Pattern: Seen in packed samples
DWORD sc_dwords[] = {
    0xe48348fc, 0xc0e8f0e8, 0x51410000, 0x51524150
};

// XOR encoded - most common
// Pattern: Cobalt Strike default
BYTE sc_xor[] = {
    0xbd, 0x09, 0xc2, 0xa5, 0xb1, 0xa9, 0x81, 0x41,
    0x41, 0x41, 0x00, 0x10, 0x00, 0x11, 0x13, 0x10
};

// UUID encoded - bypass technique
// Pattern: Seen in UrSnif, Lazarus
char* sc_uuid[] = {
    "e48348fc-e8f0-00c0-0041-514150525156",
    "d2654856-8b48-4852-608b-525e488b5218",
    NULL
};

// ============================================================================
// LOOKUP TABLES - crypto, encoding
// ============================================================================

// RC4 S-box (initialized at runtime)
BYTE g_sbox[256];

// Base64 alphabet
static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 decode table
static const BYTE b64_dec[256] = {
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64, 0,64,64,
    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
    // ... rest are 64 (invalid)
};

// CRC32 table (precomputed)
static const DWORD crc32_tab[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    // ... truncated
};

// ============================================================================
// ENCRYPTED STRING TABLES
// ============================================================================

// XOR encrypted strings table
// Pattern: APT samples, avoid static strings
BYTE enc_strings[][32] = {
    // "kernel32.dll" ^ 0x42
    {0x29,0x27,0x30,0x2c,0x27,0x2e,0x71,0x70,0x0c,0x26,0x2e,0x2e,0x00},
    // "ntdll.dll" ^ 0x42
    {0x2c,0x36,0x26,0x2e,0x2e,0x0c,0x26,0x2e,0x2e,0x00},
    // "VirtualAlloc" ^ 0x42
    {0x14,0x2b,0x30,0x36,0x37,0x23,0x2e,0x03,0x2e,0x2e,0x2d,0x25,0x00},
    {0x00} // terminator
};

// Stack strings - built at runtime
// Pattern: Every advanced malware
#define STR_K32 {'k','e','r','n','e','l','3','2','.','d','l','l',0}
#define STR_NTDLL {'n','t','d','l','l','.','d','l','l',0}
#define STR_VA {'V','i','r','t','u','a','l','A','l','l','o','c',0}

// ============================================================================
// API HASH TABLES
// ============================================================================

// Precomputed DJB2 hashes
static const DWORD api_hashes[] = {
    0x91AFCA54, // VirtualAlloc
    0x7946C61B, // VirtualProtect
    0x0726774C, // LoadLibraryA
    0x7C0DFCAA, // GetProcAddress
    0xCA2BD06B, // CreateThread
    0x00000000  // terminator
};

// Hash + offset pairs (for faster lookup)
typedef struct { DWORD hash; WORD offset; } HASH_ENTRY;
static const HASH_ENTRY export_cache[] = {
    {0x91AFCA54, 0x1234},
    {0x7946C61B, 0x2345},
    {0x00000000, 0x0000}
};

// ============================================================================
// PE SECTION TABLES
// ============================================================================

#pragma pack(push,1)
typedef struct {
    char  Name[8];
    DWORD VSize;
    DWORD VAddr;
    DWORD RawSize;
    DWORD RawAddr;
    DWORD Chars;
} SEC_HDR;
#pragma pack(pop)

// Section table (parsed from PE)
SEC_HDR g_sections[16];
WORD g_nsections = 0;

// ============================================================================
// RELOCATION TABLES
// ============================================================================

typedef struct {
    DWORD PageRVA;
    DWORD BlockSize;
    // WORD Entries[];
} RELOC_BLOCK;

// Process relocation block
void apply_relocs(BYTE* base, RELOC_BLOCK* blk, DWORD delta)
{
    WORD* entries = (WORD*)((BYTE*)blk + 8);
    DWORD count = (blk->BlockSize - 8) / 2;

    for(DWORD i = 0; i < count; i++) {
        WORD e = entries[i];
        BYTE type = e >> 12;
        WORD off = e & 0xFFF;

        if(type == 3) {  // IMAGE_REL_BASED_HIGHLOW
            DWORD* ptr = (DWORD*)(base + blk->PageRVA + off);
            *ptr += delta;
        }
        else if(type == 10) {  // IMAGE_REL_BASED_DIR64
            QWORD* ptr = (QWORD*)(base + blk->PageRVA + off);
            *ptr += delta;
        }
    }
}

// ============================================================================
// IMPORT TABLES
// ============================================================================

typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMP_DESC;

// Walk import table
void resolve_imports(BYTE* base, IMP_DESC* imp)
{
    while(imp->Name) {
        char* dll = (char*)(base + imp->Name);
        // HMODULE h = LoadLibraryA(dll);

        DWORD* thunk = (DWORD*)(base + imp->FirstThunk);
        DWORD* orig = imp->OriginalFirstThunk ?
                      (DWORD*)(base + imp->OriginalFirstThunk) : thunk;

        while(*orig) {
            // char* name = (char*)(base + *orig + 2);  // skip hint
            // *thunk = GetProcAddress(h, name);
            thunk++;
            orig++;
        }
        imp++;
    }
}

// ============================================================================
// BEACON CONFIG ARRAY
// ============================================================================

// Cobalt Strike malleable profile settings
#pragma pack(push,1)
typedef struct {
    WORD  id;
    WORD  len;
    BYTE  data[];
} CFG_ENTRY;
#pragma pack(pop)

// Config blob (decrypted)
BYTE g_config[4096];

CFG_ENTRY* get_cfg_entry(WORD id)
{
    BYTE* p = g_config;
    while(p < g_config + sizeof(g_config)) {
        CFG_ENTRY* e = (CFG_ENTRY*)p;
        if(e->id == 0) break;
        if(e->id == id) return e;
        p += 4 + e->len;
    }
    return 0;
}

// ============================================================================
// NOP SLED / SHELLCODE LAYOUT
// ============================================================================

// Build exploit payload
// [nops][shellcode][padding][ret_addr]
void build_exploit(BYTE* buf, DWORD sz, BYTE* sc, DWORD sclen, DWORD ret)
{
    DWORD nops = sz - sclen - 8;

    // NOP sled
    for(DWORD i = 0; i < nops; i++)
        buf[i] = 0x90;

    // Shellcode
    for(DWORD i = 0; i < sclen; i++)
        buf[nops + i] = sc[i];

    // Padding
    for(DWORD i = 0; i < 4; i++)
        buf[nops + sclen + i] = 'A';

    // Return address (little-endian)
    *(DWORD*)(buf + nops + sclen + 4) = ret;
}

// ============================================================================
// DECODE HELPERS
// ============================================================================

// XOR decode string from table
char* dec_str(DWORD idx, BYTE key)
{
    static char buf[64];
    BYTE* src = enc_strings[idx];
    DWORD i = 0;

    while(src[i]) {
        buf[i] = src[i] ^ key;
        i++;
    }
    buf[i] = 0;
    return buf;
}

// UUID to bytes
void uuid_to_bytes(char* uuid, BYTE* out)
{
    // Skip dashes, convert hex pairs
    int j = 0;
    for(int i = 0; uuid[i] && j < 16; i++) {
        if(uuid[i] == '-') continue;
        char hex[3] = {uuid[i], uuid[i+1], 0};
        out[j++] = (BYTE)strtol(hex, 0, 16);
        i++;
    }
}

// RC4 init
void rc4_init(BYTE* key, DWORD klen)
{
    for(int i = 0; i < 256; i++) g_sbox[i] = i;
    for(int i = 0, j = 0; i < 256; i++) {
        j = (j + g_sbox[i] + key[i % klen]) & 0xFF;
        BYTE t = g_sbox[i];
        g_sbox[i] = g_sbox[j];
        g_sbox[j] = t;
    }
}

// ============================================================================
// EOF
// ============================================================================
