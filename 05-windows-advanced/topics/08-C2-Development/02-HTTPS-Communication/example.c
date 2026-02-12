/*
 * OBJECTIF  : Communication HTTPS pour C2 (TLS, certificats, evasion)
 * PREREQUIS : HTTP Client WinHTTP, notions TLS
 * COMPILE   : cl example.c /Fe:example.exe /link winhttp.lib
 *
 * HTTPS chiffre le trafic C2 pour eviter l'inspection IDS/IPS.
 * Port 443 se fond dans le trafic web normal.
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

void demo_https_get(void) {
    printf("[1] HTTPS GET avec WinHTTP\n\n");

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { printf("    [-] WinHttpOpen echoue\n\n"); return; }

    HINTERNET hConnect = WinHttpConnect(hSession, L"www.google.com",
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/",
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE);
    if (hRequest &&
        WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             NULL, &status, &sz, NULL);
        printf("    [+] HTTPS GET -> Status %lu\n", status);
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    printf("\n");
}

void demo_cert_options(void) {
    printf("[2] Options de certificat pour C2\n\n");
    printf("    Ignorer erreurs cert (C2 self-signed) :\n");
    printf("    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |\n");
    printf("                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;\n");
    printf("    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));\n\n");
    printf("    [!] Utiliser Let's Encrypt en production (cert auto-signe = detecte)\n\n");
}

void demo_tls_fingerprint(void) {
    printf("[3] TLS Fingerprinting (JA3)\n\n");
    printf("    JA3 = hash du ClientHello (cipher suites, extensions, courbes)\n");
    printf("    WinHTTP produit un JA3 different de Chrome/Firefox\n");
    printf("    -> Detectable par proxy SSL\n\n");
    printf("    Solutions : WinInet (plus navigateur-like), ou lib TLS custom\n\n");
}

int main(void) {
    printf("[*] Demo : HTTPS Communication pour C2\n");
    printf("[*] ==========================================\n\n");
    demo_https_get();
    demo_cert_options();
    demo_tls_fingerprint();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
