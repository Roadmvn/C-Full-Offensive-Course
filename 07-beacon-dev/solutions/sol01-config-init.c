/*
 * ========================================
 * SOLUTION 01: Initialize Beacon Configuration
 * ========================================
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char szHost[256];
    DWORD dwPort;
    BOOL bUseSSL;
    DWORD dwSleepTime;
    DWORD dwJitter;
    char szBeaconID[65];
    char szUserAgent[512];
    char szCheckInPath[256];
    char szResultPath[256];
} BEACON_CONFIG;

BOOL InitBeaconConfig(BEACON_CONFIG* config) {
    if (!config) return FALSE;

    ZeroMemory(config, sizeof(BEACON_CONFIG));

    strcpy(config->szHost, "192.168.1.100");
    config->dwPort = 443;
    config->bUseSSL = TRUE;
    config->dwSleepTime = 60;
    config->dwJitter = 30;

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

    strcpy(config->szCheckInPath, "/api/status");
    strcpy(config->szResultPath, "/api/update");

    return TRUE;
}

BOOL ValidateBeaconConfig(BEACON_CONFIG* config) {
    if (!config) return FALSE;

    printf("[*] Validating beacon configuration...\n");

    if (strlen(config->szHost) == 0) {
        printf("[-] Error: Host is empty\n");
        return FALSE;
    }

    if (config->dwPort == 0 || config->dwPort > 65535) {
        printf("[-] Error: Invalid port %d\n", config->dwPort);
        return FALSE;
    }

    if (config->dwSleepTime == 0) {
        printf("[-] Error: Sleep time cannot be 0\n");
        return FALSE;
    }

    if (config->dwJitter > 100) {
        printf("[-] Error: Jitter must be 0-100%% (got %d%%)\n", config->dwJitter);
        return FALSE;
    }

    if (strlen(config->szBeaconID) == 0) {
        printf("[-] Error: Beacon ID is empty\n");
        return FALSE;
    }

    if (strlen(config->szCheckInPath) == 0) {
        printf("[-] Error: Check-in path is empty\n");
        return FALSE;
    }

    if (strlen(config->szResultPath) == 0) {
        printf("[-] Error: Result path is empty\n");
        return FALSE;
    }

    printf("[+] All validation checks passed\n");
    return TRUE;
}

void PrintBeaconConfig(BEACON_CONFIG* config) {
    if (!config) return;

    printf("========================================\n");
    printf("BEACON CONFIGURATION\n");
    printf("========================================\n\n");

    printf("[C2 Server]\n");
    printf("  Host:     %s\n", config->szHost);
    printf("  Port:     %d\n", config->dwPort);
    printf("  Protocol: %s\n", config->bUseSSL ? "HTTPS" : "HTTP");
    printf("\n");

    printf("[Timing]\n");
    printf("  Sleep:    %d seconds\n", config->dwSleepTime);
    printf("  Jitter:   %d%%\n", config->dwJitter);
    int minSleep = config->dwSleepTime - (config->dwSleepTime * config->dwJitter / 100);
    int maxSleep = config->dwSleepTime + (config->dwSleepTime * config->dwJitter / 100);
    printf("  Range:    %d - %d seconds\n", minSleep, maxSleep);
    printf("\n");

    printf("[Identity]\n");
    printf("  Beacon ID:  %s\n", config->szBeaconID);
    printf("  User-Agent: %s\n", config->szUserAgent);
    printf("\n");

    printf("[Endpoints]\n");
    printf("  Check-in: %s\n", config->szCheckInPath);
    printf("  Results:  %s\n", config->szResultPath);
    printf("\n");
}

void TestValidConfig(void) {
    printf("========================================\n");
    printf("TEST 1: Valid Configuration\n");
    printf("========================================\n\n");

    BEACON_CONFIG config;

    printf("[*] Initializing config...\n");
    if (!InitBeaconConfig(&config)) {
        printf("[-] FAIL: InitBeaconConfig returned FALSE\n");
        return;
    }
    printf("[+] PASS: Config initialized\n\n");

    PrintBeaconConfig(&config);

    printf("[*] Validating config...\n");
    if (!ValidateBeaconConfig(&config)) {
        printf("[-] FAIL: Config validation failed\n");
        return;
    }
    printf("[+] PASS: Config is valid\n\n");
}

void TestInvalidPort(void) {
    printf("========================================\n");
    printf("TEST 2: Invalid Port\n");
    printf("========================================\n\n");

    BEACON_CONFIG config;
    InitBeaconConfig(&config);

    printf("[*] Setting port to 0 (invalid)...\n");
    config.dwPort = 0;

    printf("[*] Validating config...\n");
    if (ValidateBeaconConfig(&config)) {
        printf("[-] FAIL: Validation should have failed\n");
    } else {
        printf("[+] PASS: Validation correctly rejected invalid port\n");
    }
    printf("\n");
}

void TestInvalidJitter(void) {
    printf("========================================\n");
    printf("TEST 3: Invalid Jitter\n");
    printf("========================================\n\n");

    BEACON_CONFIG config;
    InitBeaconConfig(&config);

    printf("[*] Setting jitter to 150%% (invalid)...\n");
    config.dwJitter = 150;

    printf("[*] Validating config...\n");
    if (ValidateBeaconConfig(&config)) {
        printf("[-] FAIL: Validation should have failed\n");
    } else {
        printf("[+] PASS: Validation correctly rejected invalid jitter\n");
    }
    printf("\n");
}

void TestEmptyHost(void) {
    printf("========================================\n");
    printf("TEST 4: Empty Host\n");
    printf("========================================\n\n");

    BEACON_CONFIG config;
    InitBeaconConfig(&config);

    printf("[*] Clearing host string...\n");
    config.szHost[0] = '\0';

    printf("[*] Validating config...\n");
    if (ValidateBeaconConfig(&config)) {
        printf("[-] FAIL: Validation should have failed\n");
    } else {
        printf("[+] PASS: Validation correctly rejected empty host\n");
    }
    printf("\n");
}

int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("SOLUTION 01: Beacon Config Initialization\n");
    printf("========================================\n\n");

    TestValidConfig();
    TestInvalidPort();
    TestInvalidJitter();
    TestEmptyHost();

    printf("========================================\n");
    printf("ALL TESTS COMPLETE\n");
    printf("========================================\n\n");

    return 0;
}
