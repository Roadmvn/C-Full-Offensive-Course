/*
 * Bitwise Operations - Crypto primitives, hash functions, encoding
 * Core patterns from shellcode, packers, crypters
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
// ROTATION MACROS - foundation of all crypto
// ============================================================================

#define ROL8(x, n)  ((BYTE)(((x) << (n)) | ((x) >> (8 - (n)))))
#define ROR8(x, n)  ((BYTE)(((x) >> (n)) | ((x) << (8 - (n)))))
#define ROL16(x, n) ((WORD)(((x) << (n)) | ((x) >> (16 - (n)))))
#define ROR16(x, n) ((WORD)(((x) >> (n)) | ((x) << (16 - (n)))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// Shorthand
#define ROL ROL32
#define ROR ROR32

// ============================================================================
// XOR ENCODERS - most common obfuscation
// ============================================================================

// Single-byte XOR
#define XOR1(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++^=(k);}while(0)

// Multi-byte XOR
#define XORN(b,l,k,kl) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)[i%(kl)];}while(0)

// Rolling XOR (Emotet pattern)
#define XORR(b,l,k) do{BYTE*_=(b);BYTE _k=(k);for(DWORD i=0;i<(l);i++){BYTE t=_[i];_[i]^=_k;_k=t;}}while(0)

// XOR with index (adds entropy)
#define XORI(b,l,k) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)^i;}while(0)

// NOT encoder
#define NOT(b,l) do{BYTE*_=(b);DWORD n=(l);while(n--){*_=~*_;_++;}}while(0)

// ADD/SUB encoder
#define ADD(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_+++=k;}while(0)
#define SUB(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++-=k;}while(0)

// ============================================================================
// HASH FUNCTIONS - API resolution
// ============================================================================

// DJB2 - most widely used
DWORD djb2(char* s)
{
    DWORD h = 5381;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

// ROR13 - Metasploit block_api
DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) {
        h = ROR(h, 13);
        h += *s++;
    }
    return h;
}

// ROR13 wide (Unicode DLL names)
DWORD ror13w(WORD* s)
{
    DWORD h = 0;
    while(*s) {
        h = ROR(h, 13);
        h += *s++;
    }
    return h;
}

// FNV-1a - fast, good distribution
DWORD fnv1a(char* s)
{
    DWORD h = 0x811c9dc5;
    while(*s) {
        h ^= *s++;
        h *= 0x01000193;
    }
    return h;
}

// CRC32 - tableless implementation
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

// SDBM
DWORD sdbm(char* s)
{
    DWORD h = 0;
    while(*s)
        h = *s++ + (h << 6) + (h << 16) - h;
    return h;
}

// ============================================================================
// PRECOMPUTED HASHES
// ============================================================================

// DJB2 hashes
#define H_KERNEL32_DLL      0x6A4ABC5B
#define H_NTDLL_DLL         0x3CFA685D
#define H_USER32_DLL        0x63C84283
#define H_VIRTUALALLOC      0x91AFCA54
#define H_VIRTUALPROTECT    0x7946C61B
#define H_LOADLIBRARYA      0x0726774C
#define H_GETPROCADDRESS    0x7C0DFCAA
#define H_CREATETHREAD      0xCA2BD06B
#define H_NTWRITEVIRTUALMEM 0x3E8F5C21

// ROR13 hashes (Metasploit compatible)
#define R_LOADLIBRARYA      0xEC0E4E8E
#define R_GETPROCADDRESS    0x7C0DFCAA
#define R_VIRTUALALLOC      0x91AFCA54

// ============================================================================
// RC4 - common malware encryption
// ============================================================================

void rc4_init(BYTE* S, BYTE* key, DWORD klen)
{
    for(int i = 0; i < 256; i++) S[i] = i;

    for(int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }
}

void rc4_crypt(BYTE* S, BYTE* data, DWORD len)
{
    DWORD i = 0, j = 0;

    for(DWORD n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

// Compact RC4 (one function)
void rc4(BYTE* data, DWORD dlen, BYTE* key, DWORD klen)
{
    BYTE S[256];
    rc4_init(S, key, klen);
    rc4_crypt(S, data, dlen);
}

// ============================================================================
// BYTE SWAP - endian conversion
// ============================================================================

#define BSWAP16(x) (((x) >> 8) | ((x) << 8))
#define BSWAP32(x) (((x)>>24)|(((x)>>8)&0xFF00)|(((x)<<8)&0xFF0000)|((x)<<24))
#define BSWAP64(x) ((QWORD)BSWAP32((x)&0xFFFFFFFF)<<32|BSWAP32((x)>>32))

// Network byte order
#define htons(x) BSWAP16(x)
#define htonl(x) BSWAP32(x)
#define ntohs(x) BSWAP16(x)
#define ntohl(x) BSWAP32(x)

// ============================================================================
// BIT FIELD OPERATIONS
// ============================================================================

#define BIT_SET(x, n)    ((x) |= (1ULL << (n)))
#define BIT_CLR(x, n)    ((x) &= ~(1ULL << (n)))
#define BIT_TOG(x, n)    ((x) ^= (1ULL << (n)))
#define BIT_GET(x, n)    (((x) >> (n)) & 1)

#define BITS_GET(x, pos, len) (((x) >> (pos)) & ((1ULL << (len)) - 1))
#define BITS_SET(x, pos, len, val) \
    ((x) = ((x) & ~(((1ULL<<(len))-1)<<(pos))) | (((val)&((1ULL<<(len))-1))<<(pos)))

// Memory protection bits
#define PROT_X  (1 << 0)
#define PROT_W  (1 << 1)
#define PROT_R  (1 << 2)

// PE characteristics
#define C_EXEC      0x0020
#define C_CODE      0x0020
#define C_IDATA     0x0040
#define C_UDATA     0x0080
#define C_DISCARDABLE 0x02000000
#define C_SHARED    0x10000000
#define C_EXECUTE   0x20000000
#define C_READ      0x40000000
#define C_WRITE     0x80000000

// ============================================================================
// ALIGNMENT
// ============================================================================

#define ALIGN_UP(x, a)   (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))

#define PAGE_ALIGN(x)    ALIGN_UP(x, 0x1000)
#define SECTION_ALIGN(x) ALIGN_UP(x, 0x1000)
#define FILE_ALIGN(x)    ALIGN_UP(x, 0x200)

#define IS_ALIGNED(x, a) (((x) & ((a) - 1)) == 0)

// ============================================================================
// BRANCHLESS OPERATIONS
// ============================================================================

// Timing-safe (constant time)
#define BMIN(a,b) ((b) ^ (((a) ^ (b)) & -((a) < (b))))
#define BMAX(a,b) ((a) ^ (((a) ^ (b)) & -((a) < (b))))
#define BABS(x)   (((x) ^ ((x) >> 31)) - ((x) >> 31))
#define BSIGN(x)  (((x) >> 31) | (-(x) >> 31))
#define BSEL(c,a,b) ((b) ^ (((a) ^ (b)) & -(c)))

// Constant-time compare (no early exit)
int ct_cmp(BYTE* a, BYTE* b, DWORD len)
{
    BYTE diff = 0;
    for(DWORD i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

// ============================================================================
// BIT COUNTING
// ============================================================================

// Population count (count set bits)
DWORD popcnt(DWORD x)
{
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    return (x * 0x01010101) >> 24;
}

// Count leading zeros
DWORD clz(DWORD x)
{
    if(!x) return 32;
    DWORD n = 0;
    if(!(x & 0xFFFF0000)) { n += 16; x <<= 16; }
    if(!(x & 0xFF000000)) { n += 8;  x <<= 8; }
    if(!(x & 0xF0000000)) { n += 4;  x <<= 4; }
    if(!(x & 0xC0000000)) { n += 2;  x <<= 2; }
    if(!(x & 0x80000000)) { n += 1; }
    return n;
}

// Count trailing zeros
DWORD ctz(DWORD x)
{
    if(!x) return 32;
    DWORD n = 0;
    if(!(x & 0x0000FFFF)) { n += 16; x >>= 16; }
    if(!(x & 0x000000FF)) { n += 8;  x >>= 8; }
    if(!(x & 0x0000000F)) { n += 4;  x >>= 4; }
    if(!(x & 0x00000003)) { n += 2;  x >>= 2; }
    if(!(x & 0x00000001)) { n += 1; }
    return n;
}

// Find first set bit (1-indexed, 0 if none)
DWORD ffs(DWORD x)
{
    return x ? ctz(x) + 1 : 0;
}

// ============================================================================
// BASE64 - common encoding
// ============================================================================

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

DWORD b64_encode(BYTE* in, DWORD inlen, char* out)
{
    DWORD j = 0;
    for(DWORD i = 0; i < inlen; i += 3) {
        DWORD n = (in[i] << 16) |
                  (i+1 < inlen ? in[i+1] << 8 : 0) |
                  (i+2 < inlen ? in[i+2] : 0);

        out[j++] = b64_alpha[(n >> 18) & 0x3F];
        out[j++] = b64_alpha[(n >> 12) & 0x3F];
        out[j++] = (i+1 < inlen) ? b64_alpha[(n >> 6) & 0x3F] : '=';
        out[j++] = (i+2 < inlen) ? b64_alpha[n & 0x3F] : '=';
    }
    out[j] = 0;
    return j;
}

// ============================================================================
// XTEA - simple block cipher
// ============================================================================

#define XTEA_DELTA 0x9E3779B9
#define XTEA_ROUNDS 32

void xtea_encrypt(DWORD* v, DWORD* k)
{
    DWORD v0 = v[0], v1 = v[1], sum = 0;

    for(int i = 0; i < XTEA_ROUNDS; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += XTEA_DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }

    v[0] = v0; v[1] = v1;
}

void xtea_decrypt(DWORD* v, DWORD* k)
{
    DWORD v0 = v[0], v1 = v[1], sum = XTEA_DELTA * XTEA_ROUNDS;

    for(int i = 0; i < XTEA_ROUNDS; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }

    v[0] = v0; v[1] = v1;
}

// ============================================================================
// EOF
// ============================================================================
