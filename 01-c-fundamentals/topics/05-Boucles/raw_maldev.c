/*
 * Loops - Iteration patterns from real malware
 * Decoders, scanners, parsers, beacons
 */

#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef void* PVOID;
typedef void* HANDLE;
#endif

// ============================================================================
// XOR DECODER VARIANTS - every sample has one
// ============================================================================

// Basic - what Ghidra shows you
void FUN_decode_00401000(BYTE* param_1, DWORD param_2, BYTE param_3)
{
    DWORD i;
    for(i = 0; i < param_2; i++)
        param_1[i] = param_1[i] ^ param_3;
}

// Compact while - Cobalt Strike style
void xor_w(BYTE* b, DWORD l, BYTE k)
{
    while(l--) *b++ ^= k;
}

// Pointer end - common in shellcode
void xor_p(BYTE* b, BYTE* e, BYTE k)
{
    while(b < e) *b++ ^= k;
}

// Rolling XOR - Emotet, Dridex
void xor_roll(BYTE* b, DWORD l, BYTE k)
{
    BYTE t;
    while(l--) {
        t = *b;
        *b++ ^= k;
        k = t;
    }
}

// Multi-byte key - more common now
void xor_key(BYTE* b, DWORD l, BYTE* k, DWORD kl)
{
    for(DWORD i = 0; i < l; i++)
        b[i] ^= k[i % kl];
}

// ============================================================================
// MEMORY SCANNING - signature detection, config extraction
// ============================================================================

// Find single byte
BYTE* scan1(BYTE* s, BYTE* e, BYTE v)
{
    while(s < e) {
        if(*s == v) return s;
        s++;
    }
    return 0;
}

// Pattern scan - fixed signature
BYTE* sigscan(BYTE* mem, DWORD sz, BYTE* sig, DWORD slen)
{
    for(DWORD i = 0; i <= sz - slen; i++) {
        DWORD j;
        for(j = 0; j < slen && mem[i+j] == sig[j]; j++);
        if(j == slen) return mem + i;
    }
    return 0;
}

// Wildcard scan - "48 8B ?? ?? 90"
// mask: FF = exact, 00 = wildcard
BYTE* sigscan_mask(BYTE* mem, DWORD sz, BYTE* sig, BYTE* mask, DWORD slen)
{
    for(DWORD i = 0; i <= sz - slen; i++) {
        DWORD j;
        for(j = 0; j < slen; j++) {
            if((mem[i+j] & mask[j]) != (sig[j] & mask[j]))
                break;
        }
        if(j == slen) return mem + i;
    }
    return 0;
}

// MZ/PE scan - find embedded PE
BYTE* find_pe(BYTE* mem, DWORD sz)
{
    for(DWORD i = 0; i < sz - 0x40; i++) {
        if(mem[i] == 'M' && mem[i+1] == 'Z') {
            DWORD pe_off = *(DWORD*)(mem + i + 0x3C);
            if(pe_off < sz - 4) {
                if(*(DWORD*)(mem + i + pe_off) == 0x4550)  // "PE\0\0"
                    return mem + i;
            }
        }
    }
    return 0;
}

// ============================================================================
// STRING OPERATIONS - no libc
// ============================================================================

DWORD slen(char* s)
{
    char* p = s;
    while(*p) p++;
    return p - s;
}

void scpy(char* d, char* s)
{
    while((*d++ = *s++));
}

int scmp(char* a, char* b)
{
    while(*a && *a == *b) { a++; b++; }
    return *a - *b;
}

// Case-insensitive (DLL name comparison)
int scmpi(char* a, char* b)
{
    while(*a && ((*a | 0x20) == (*b | 0x20))) { a++; b++; }
    return (*a | 0x20) - (*b | 0x20);
}

// ============================================================================
// HASH LOOPS - API resolution
// ============================================================================

DWORD hash_djb2(char* s)
{
    DWORD h = 5381;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

DWORD hash_ror13(char* s)
{
    DWORD h = 0;
    while(*s) {
        h = (h >> 13) | (h << 19);
        h += *s++;
    }
    return h;
}

// Wide string hash (Unicode DLL names)
DWORD hash_ror13w(WORD* s)
{
    DWORD h = 0;
    while(*s) {
        h = (h >> 13) | (h << 19);
        h += *s++;
    }
    return h;
}

// ============================================================================
// LIST WALKING - PEB/LDR traversal pattern
// ============================================================================

// LIST_ENTRY equivalent
typedef struct _LE {
    struct _LE* Flink;
    struct _LE* Blink;
} LE;

// Walk circular doubly-linked list (PEB_LDR_DATA pattern)
// for(p = head->Flink; p != head; p = p->Flink)
void walk_ldr(LE* head, void (*cb)(LE*))
{
    LE* p = head->Flink;
    while(p != head) {
        cb(p);
        p = p->Flink;
    }
}

// ============================================================================
// EXPORT TABLE WALKING
// ============================================================================

/*
 * Pattern: Find API by hash in export table
 * Seen in every PIC shellcode
 */
typedef struct {
    DWORD NumberOfNames;
    DWORD AddressOfNames;
    DWORD AddressOfOrdinals;
    DWORD AddressOfFunctions;
} EXP_DIR;

PVOID find_api_by_hash(BYTE* base, EXP_DIR* exp, DWORD hash)
{
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*)(base + exp->AddressOfOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for(DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if(hash_djb2(name) == hash)
            return base + funcs[ords[i]];
    }
    return 0;
}

// ============================================================================
// BEACON LOOP PATTERN - C2 implant main loop
// ============================================================================

/*
 * Cobalt Strike / Metasploit / Custom C2 pattern
 *
 * void beacon_main() {
 *     while(1) {
 *         sleep_with_jitter(interval);
 *
 *         task = get_task_from_c2();
 *         if(task) {
 *             result = execute_task(task);
 *             send_result(result);
 *         }
 *
 *         if(should_exit)
 *             break;
 *     }
 * }
 */

// Jittered sleep
void sleep_jitter(DWORD base_ms, DWORD jitter_pct)
{
    DWORD jitter = (base_ms * jitter_pct) / 100;
    DWORD actual = base_ms + (GetTickCount() % jitter) - (jitter / 2);
    Sleep(actual);
}

// ============================================================================
// KEYLOGGER LOOP
// ============================================================================

/*
 * Pattern: GetAsyncKeyState polling
 *
 * while(1) {
 *     for(int vk = 0; vk < 256; vk++) {
 *         if(GetAsyncKeyState(vk) & 0x8000) {
 *             log_keystroke(vk);
 *         }
 *     }
 *     Sleep(10);
 * }
 */

// ============================================================================
// PROCESS ENUMERATION LOOP
// ============================================================================

/*
 * Pattern: CreateToolhelp32Snapshot + Process32First/Next
 *
 * hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 * pe.dwSize = sizeof(pe);
 *
 * if(Process32First(hSnap, &pe)) {
 *     do {
 *         if(hash(pe.szExeFile) == TARGET_HASH) {
 *             return pe.th32ProcessID;
 *         }
 *     } while(Process32Next(hSnap, &pe));
 * }
 */

// ============================================================================
// COPY LOOPS - memcpy alternatives
// ============================================================================

// Basic copy
void cpy(BYTE* d, BYTE* s, DWORD n)
{
    while(n--) *d++ = *s++;
}

// DWORD copy (faster for aligned data)
void cpy4(DWORD* d, DWORD* s, DWORD n)
{
    while(n--) *d++ = *s++;
}

// REP MOVSB intrinsic (if available)
#ifdef _WIN32
#define CPY(d,s,n) __movsb((BYTE*)(d), (BYTE*)(s), (n))
#else
#define CPY(d,s,n) cpy((BYTE*)(d), (BYTE*)(s), (n))
#endif

// ============================================================================
// ZERO LOOPS
// ============================================================================

void zero(BYTE* p, DWORD n)
{
    while(n--) *p++ = 0;
}

// Secure zero (prevent optimization)
void szero(volatile BYTE* p, DWORD n)
{
    while(n--) *p++ = 0;
}

// ============================================================================
// EOF
// ============================================================================
