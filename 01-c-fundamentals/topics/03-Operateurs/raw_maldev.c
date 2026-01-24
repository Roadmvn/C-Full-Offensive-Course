/*
 * Operators - Bitwise operations as seen in real shellcode/loaders
 * XOR encoders, hash functions, bit manipulation from actual samples
 */

#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;
#endif

// ============================================================================
// XOR MACROS - every loader uses these
// ============================================================================

// Cobalt Strike style
#define XOR(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++^=(k);}while(0)

// Multi-byte key
#define XORK(b,l,k,kl) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)[i%(kl)];}while(0)

// Rolling XOR (Emotet pattern)
#define XORR(b,l,k) do{BYTE*_=(b);BYTE _k=(k);for(DWORD i=0;i<(l);i++){BYTE t=_[i];_[i]^=_k;_k=t;}}while(0)

// NOT encoder
#define NOT(b,l) do{BYTE*_=(b);DWORD n=(l);while(n--){*_=~*_;_++;}}while(0)

// ADD/SUB encoder
#define ADD(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_+++=k;}while(0)
#define SUB(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++-=k;}while(0)

// ============================================================================
// ROTATE OPERATIONS - hash algorithms depend on these
// ============================================================================

#define ROL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

#define ROL8(x,n)  ((BYTE)(((x)<<(n))|((x)>>(8-(n)))))
#define ROR8(x,n)  ((BYTE)(((x)>>(n))|((x)<<(8-(n)))))

#define ROL64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define ROR64(x,n) (((x)>>(n))|((x)<<(64-(n))))

// ============================================================================
// HASH FUNCTIONS - API resolution hashes
// ============================================================================

// DJB2 - widely used, simple
// Seen in: Metasploit, custom loaders
DWORD djb2(char* s)
{
    DWORD h = 5381;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

// ROR13 - Metasploit block_api
// The classic Windows shellcode hash
DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) {
        h = ROR(h, 13);
        h += *s++;
    }
    return h;
}

// ROR13 wide - for unicode DLL names
DWORD ror13w(WCHAR* s)
{
    DWORD h = 0;
    while(*s) {
        h = ROR(h, 13);
        h += *s++;
    }
    return h;
}

// FNV-1a - faster, good distribution
DWORD fnv1a(char* s)
{
    DWORD h = 0x811c9dc5;
    while(*s) {
        h ^= *s++;
        h *= 0x01000193;
    }
    return h;
}

// CRC32 table-less (slower but smaller)
DWORD crc32(BYTE* data, DWORD len)
{
    DWORD crc = 0xFFFFFFFF;
    while(len--) {
        crc ^= *data++;
        for(int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

// ============================================================================
// PRECOMPUTED HASHES - avoid strings in binary
// ============================================================================

// DJB2 hashes
#define H_KERNEL32_DLL      0x6A4ABC5B
#define H_NTDLL_DLL         0x3CFA685D
#define H_VIRTUALALLOC      0x91AFCA54
#define H_VIRTUALPROTECT    0x7946C61B
#define H_LOADLIBRARYA      0x0726774C
#define H_GETPROCADDRESS    0x7C0DFCAA
#define H_CREATETHREAD      0xCA2BD06B

// ROR13 hashes (Metasploit compatible)
#define R_KERNEL32          0x6A4ABC5B
#define R_LOADLIBRARYA      0xEC0E4E8E
#define R_VIRTUALALLOC      0x91AFCA54

// ============================================================================
// BIT MASKING - flag manipulation
// ============================================================================

// Memory protection flags
#define PROT_R   0x02  // PAGE_READONLY
#define PROT_RW  0x04  // PAGE_READWRITE
#define PROT_RX  0x20  // PAGE_EXECUTE_READ
#define PROT_RWX 0x40  // PAGE_EXECUTE_READWRITE

// Process access rights
#define PA_TERMINATE    0x0001
#define PA_VM_OP        0x0008
#define PA_VM_READ      0x0010
#define PA_VM_WRITE     0x0020
#define PA_DUP_HANDLE   0x0040
#define PA_CREATE_THREAD 0x0002
#define PA_QUERY_INFO   0x0400
#define PA_ALL          0x1F0FFF

// Set/Clear/Check patterns
#define SET_FLAG(v,f)   ((v) |= (f))
#define CLR_FLAG(v,f)   ((v) &= ~(f))
#define HAS_FLAG(v,f)   (((v) & (f)) != 0)
#define TOG_FLAG(v,f)   ((v) ^= (f))

// ============================================================================
// BIT EXTRACTION - PE parsing, protocol parsing
// ============================================================================

// Extract byte from DWORD (little-endian)
#define BYTE0(x) ((BYTE)((x) & 0xFF))
#define BYTE1(x) ((BYTE)(((x) >> 8) & 0xFF))
#define BYTE2(x) ((BYTE)(((x) >> 16) & 0xFF))
#define BYTE3(x) ((BYTE)(((x) >> 24) & 0xFF))

// Build DWORD from bytes
#define MAKEDWORD(b0,b1,b2,b3) ((DWORD)(b0)|((DWORD)(b1)<<8)|((DWORD)(b2)<<16)|((DWORD)(b3)<<24))

// High/Low word
#define LOWORD(x) ((WORD)((x) & 0xFFFF))
#define HIWORD(x) ((WORD)(((x) >> 16) & 0xFFFF))

// PE relocation entry parsing
#define RELOC_TYPE(x)   ((x) >> 12)
#define RELOC_OFFSET(x) ((x) & 0xFFF)

// ============================================================================
// ALIGNMENT - memory operations require this
// ============================================================================

// Align up to boundary (boundary must be power of 2)
#define ALIGN_UP(x, align)   (((x) + ((align) - 1)) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))

// Page alignment
#define PAGE_ALIGN(x)     ALIGN_UP(x, 0x1000)
#define SECTION_ALIGN(x)  ALIGN_UP(x, 0x1000)
#define FILE_ALIGN(x)     ALIGN_UP(x, 0x200)

// Check alignment
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

// ============================================================================
// BRANCHLESS OPERATIONS - avoid conditional jumps
// ============================================================================

// Branchless min/max
#define BMIN(a,b) ((b) ^ (((a) ^ (b)) & -((a) < (b))))
#define BMAX(a,b) ((a) ^ (((a) ^ (b)) & -((a) < (b))))

// Branchless abs
#define BABS(x) (((x) ^ ((x) >> 31)) - ((x) >> 31))

// Branchless sign
#define BSIGN(x) (((x) >> 31) | (-(x) >> 31))

// Conditional select: (cond ? a : b)
#define BSEL(cond, a, b) ((b) ^ (((a) ^ (b)) & -(cond)))

// ============================================================================
// RC4 - common encryption in malware
// ============================================================================

// Compact RC4 (Cobalt Strike uses this)
void rc4(BYTE* data, DWORD len, BYTE* key, DWORD klen)
{
    BYTE S[256];
    for(int i = 0; i < 256; i++) S[i] = i;

    // KSA
    for(int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }

    // PRGA
    for(DWORD n = 0, i = 0, j = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

// ============================================================================
// SAMPLE PATTERNS
// ============================================================================

/*
 * Pattern: Cobalt Strike beacon XOR
 * First byte is key, rest is payload
 */
void cs_decode(BYTE* blob, DWORD len)
{
    BYTE key = blob[0];
    for(DWORD i = 1; i < len; i++)
        blob[i] ^= key;
}

/*
 * Pattern: Metasploit shikata_ga_nai decoder stub
 * Uses FPU to get EIP, then XOR decodes
 */
// d9 74 24 f4     fldz / fnstenv [esp-0Ch]
// 5e              pop esi  ; EIP in ESI
// ...

/*
 * Pattern: String hash comparison
 * Used in API resolution loops
 */
int cmp_hash(char* str, DWORD target)
{
    return djb2(str) == target;
}

/*
 * Pattern: Null-byte elimination
 * XOR immediate values to avoid nulls
 */
// mov eax, 0x12345678  ; contains no null
// xor eax, 0x12345678  ; results in 0 without encoding null

// ============================================================================
// EOF
// ============================================================================
