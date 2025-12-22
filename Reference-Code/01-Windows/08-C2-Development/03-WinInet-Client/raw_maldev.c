/*
 * WinInet Client - HTTP/HTTPS/FTP via WinInet
 * Uses IE settings for proxy/cookies
 */

#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

// ============================================================================
// SIMPLE GET
// ============================================================================

BOOL inet_get(char* url, BYTE** out, DWORD* len)
{
    HINTERNET hI = 0, hF = 0;
    BOOL ret = 0;

    hI = InternetOpenA("Mozilla/5.0", 0, 0, 0, 0);  // PRECONFIG
    if(!hI) return 0;

    hF = InternetOpenUrlA(hI, url, 0, 0, 0x80000000 | 0x04000000, 0);  // RELOAD | NO_CACHE
    if(!hF) goto end;

    DWORD total = 0, rd;
    *out = HeapAlloc(GetProcessHeap(), 0, 0x100000);

    while(InternetReadFile(hF, *out + total, 0x100000 - total, &rd) && rd)
        total += rd;

    *len = total;
    ret = 1;

end:
    if(hF) InternetCloseHandle(hF);
    if(hI) InternetCloseHandle(hI);
    return ret;
}

// ============================================================================
// HTTPS POST
// ============================================================================

BOOL inet_post(char* host, char* uri, BYTE* data, DWORD dlen, BYTE** out, DWORD* len)
{
    HINTERNET hI = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    hI = InternetOpenA("Mozilla/5.0", 0, 0, 0, 0);
    if(!hI) return 0;

    hC = InternetConnectA(hI, host, 443, 0, 0, 3, 0, 0);  // INTERNET_SERVICE_HTTP
    if(!hC) goto end;

    DWORD flags = 0x80000000 | 0x04000000 | 0x800000 | 0x1000 | 0x2000;
    hR = HttpOpenRequestA(hC, "POST", uri, 0, 0, 0, flags, 0);
    if(!hR) goto end;

    // Ignore cert errors
    DWORD sslf = 0;
    DWORD sz = sizeof(sslf);
    InternetQueryOptionA(hR, 31, &sslf, &sz);
    sslf |= 0x100 | 0x80 | 0x4000 | 0x8000;
    InternetSetOptionA(hR, 31, &sslf, sizeof(sslf));

    char hdr[] = "Content-Type: application/octet-stream\r\n";
    if(!HttpSendRequestA(hR, hdr, -1, data, dlen)) goto end;

    DWORD total = 0, rd;
    *out = HeapAlloc(GetProcessHeap(), 0, 0x100000);

    while(InternetReadFile(hR, *out + total, 0x100000 - total, &rd) && rd)
        total += rd;

    *len = total;
    ret = 1;

end:
    if(hR) InternetCloseHandle(hR);
    if(hC) InternetCloseHandle(hC);
    if(hI) InternetCloseHandle(hI);
    return ret;
}

// ============================================================================
// WITH COOKIES - Blend with browser
// ============================================================================

BOOL inet_with_cookie(char* url, char* cookie, BYTE** out, DWORD* len)
{
    HINTERNET hI, hF;

    hI = InternetOpenA("Mozilla/5.0", 0, 0, 0, 0);

    // Set cookie (uses IE store)
    InternetSetCookieA(url, 0, cookie);

    hF = InternetOpenUrlA(hI, url, 0, 0, 0x80000000 | 0x04000000, 0);

    DWORD total = 0, rd;
    *out = HeapAlloc(GetProcessHeap(), 0, 0x100000);

    while(InternetReadFile(hF, *out + total, 0x100000 - total, &rd) && rd)
        total += rd;

    *len = total;

    InternetCloseHandle(hF);
    InternetCloseHandle(hI);
    return 1;
}

// ============================================================================
// DOWNLOAD FILE
// ============================================================================

BOOL inet_download(char* url, char* path)
{
    HINTERNET hI, hF;
    HANDLE hOut;

    hI = InternetOpenA("Mozilla/5.0", 0, 0, 0, 0);
    hF = InternetOpenUrlA(hI, url, 0, 0, 0x80000000, 0);

    if(!hF) {
        InternetCloseHandle(hI);
        return 0;
    }

    hOut = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);

    BYTE buf[4096];
    DWORD rd, wr;

    while(InternetReadFile(hF, buf, sizeof(buf), &rd) && rd)
        WriteFile(hOut, buf, rd, &wr, 0);

    CloseHandle(hOut);
    InternetCloseHandle(hF);
    InternetCloseHandle(hI);
    return 1;
}

// ============================================================================
// FTP UPLOAD
// ============================================================================

BOOL inet_ftp_put(char* host, char* user, char* pass, char* local, char* remote)
{
    HINTERNET hI, hF;

    hI = InternetOpenA("FTP", 1, 0, 0, 0);
    hF = InternetConnectA(hI, host, 21, user, pass, 1, 0, 0);  // INTERNET_SERVICE_FTP

    if(!hF) {
        InternetCloseHandle(hI);
        return 0;
    }

    BOOL ret = FtpPutFileA(hF, local, remote, 2, 0);  // FTP_TRANSFER_TYPE_BINARY

    InternetCloseHandle(hF);
    InternetCloseHandle(hI);
    return ret;
}

// ============================================================================
// FTP DOWNLOAD
// ============================================================================

BOOL inet_ftp_get(char* host, char* user, char* pass, char* remote, char* local)
{
    HINTERNET hI, hF;

    hI = InternetOpenA("FTP", 1, 0, 0, 0);
    hF = InternetConnectA(hI, host, 21, user, pass, 1, 0, 0);

    BOOL ret = FtpGetFileA(hF, remote, local, 0, 0, 2, 0);

    InternetCloseHandle(hF);
    InternetCloseHandle(hI);
    return ret;
}

// ============================================================================
// AUTO PROXY DETECTION
// ============================================================================

void get_proxy_info(void)
{
    HINTERNET hI = InternetOpenA("", 0, 0, 0, 0);

    INTERNET_PROXY_INFO pinfo;
    DWORD sz = sizeof(pinfo);

    if(InternetQueryOptionA(hI, 21, &pinfo, &sz)) {
        // pinfo.dwAccessType
        // pinfo.lpszProxy
    }

    InternetCloseHandle(hI);
}

// ============================================================================
// ASYNC CALLBACK
// ============================================================================

typedef struct {
    HANDLE hEvent;
    BOOL   complete;
    DWORD  status;
} ASYNC_CTX;

void CALLBACK inet_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len)
{
    ASYNC_CTX* pCtx = (ASYNC_CTX*)ctx;

    if(status == 100) {  // INTERNET_STATUS_REQUEST_COMPLETE
        pCtx->complete = 1;
        SetEvent(pCtx->hEvent);
    }
}

BOOL inet_async_get(char* url, BYTE** out, DWORD* len)
{
    ASYNC_CTX ctx = {0};
    ctx.hEvent = CreateEventA(0, 0, 0, 0);

    HINTERNET hI = InternetOpenA("Mozilla/5.0", 0, 0, 0, 0x10000000);  // INTERNET_FLAG_ASYNC
    InternetSetStatusCallback(hI, inet_cb);

    HINTERNET hF = InternetOpenUrlA(hI, url, 0, 0, 0x80000000, (DWORD_PTR)&ctx);

    // Wait for completion
    if(!hF && GetLastError() == 997) {  // ERROR_IO_PENDING
        WaitForSingleObject(ctx.hEvent, 30000);
    }

    DWORD total = 0, rd;
    *out = HeapAlloc(GetProcessHeap(), 0, 0x100000);

    while(InternetReadFile(hF, *out + total, 0x100000 - total, &rd) && rd)
        total += rd;

    *len = total;

    CloseHandle(ctx.hEvent);
    InternetCloseHandle(hF);
    InternetCloseHandle(hI);
    return 1;
}

// ============================================================================
// CREDENTIAL CACHE
// ============================================================================

BOOL inet_with_creds(char* host, char* uri, char* user, char* pass, BYTE** out, DWORD* len)
{
    HINTERNET hI, hC, hR;

    hI = InternetOpenA("Mozilla/5.0", 0, 0, 0, 0);
    hC = InternetConnectA(hI, host, 443, user, pass, 3, 0, 0);
    hR = HttpOpenRequestA(hC, "GET", uri, 0, 0, 0, 0x800000 | 0x80000000, 0);

    DWORD sslf = 0x100 | 0x80 | 0x1000 | 0x2000;
    InternetSetOptionA(hR, 31, &sslf, sizeof(sslf));

    HttpSendRequestA(hR, 0, 0, 0, 0);

    DWORD total = 0, rd;
    *out = HeapAlloc(GetProcessHeap(), 0, 0x100000);

    while(InternetReadFile(hR, *out + total, 0x100000 - total, &rd) && rd)
        total += rd;

    *len = total;

    InternetCloseHandle(hR);
    InternetCloseHandle(hC);
    InternetCloseHandle(hI);
    return 1;
}

// ============================================================================
// EOF
// ============================================================================
