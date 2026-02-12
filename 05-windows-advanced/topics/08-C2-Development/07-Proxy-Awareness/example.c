/*
 * OBJECTIF  : Detecter et utiliser les proxies pour la communication C2
 * PREREQUIS : HTTP Client, WinHTTP/WinInet
 * COMPILE   : cl example.c /Fe:example.exe /link winhttp.lib wininet.lib
 *
 * En entreprise, le trafic HTTP sort via un proxy. Un implant C2 doit
 * detecter et utiliser ce proxy pour communiquer.
 */

#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

void demo_detect_proxy(void) {
    printf("[1] Detection du proxy systeme\n\n");

    /* Methode 1 : WinHTTP proxy settings */
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie_config = {0};
    if (WinHttpGetIEProxyConfigForCurrentUser(&ie_config)) {
        printf("    [+] IE Proxy Config :\n");
        printf("    Auto-detect : %s\n", ie_config.fAutoDetect ? "OUI" : "NON");
        if (ie_config.lpszAutoConfigUrl)
            wprintf(L"    PAC URL     : %s\n", ie_config.lpszAutoConfigUrl);
        if (ie_config.lpszProxy)
            wprintf(L"    Proxy       : %s\n", ie_config.lpszProxy);
        if (ie_config.lpszProxyBypass)
            wprintf(L"    Bypass      : %s\n", ie_config.lpszProxyBypass);

        if (ie_config.lpszAutoConfigUrl) GlobalFree(ie_config.lpszAutoConfigUrl);
        if (ie_config.lpszProxy) GlobalFree(ie_config.lpszProxy);
        if (ie_config.lpszProxyBypass) GlobalFree(ie_config.lpszProxyBypass);
    } else {
        printf("    [-] Pas de config proxy IE\n");
    }

    /* Methode 2 : Variables d'environnement */
    char* http_proxy = getenv("HTTP_PROXY");
    char* https_proxy = getenv("HTTPS_PROXY");
    printf("\n    Variables d'environnement :\n");
    printf("    HTTP_PROXY  : %s\n", http_proxy ? http_proxy : "(non defini)");
    printf("    HTTPS_PROXY : %s\n\n", https_proxy ? https_proxy : "(non defini)");
}

void demo_proxy_usage(void) {
    printf("[2] Utilisation du proxy dans le C2\n\n");
    printf("    WinInet (auto) : INTERNET_OPEN_TYPE_PRECONFIG\n");
    printf("    -> Utilise automatiquement le proxy du systeme\n\n");
    printf("    WinHTTP (manuel) :\n");
    printf("    WinHttpOpen(..., WINHTTP_ACCESS_TYPE_NAMED_PROXY,\n");
    printf("                L\"http://proxy:8080\", L\"<local>\", 0);\n\n");
    printf("    [*] WinInet est prefere car transparent (pas de config)\n\n");
}

int main(void) {
    printf("[*] Demo : Proxy Awareness pour C2\n");
    printf("[*] ==========================================\n\n");
    demo_detect_proxy();
    demo_proxy_usage();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
