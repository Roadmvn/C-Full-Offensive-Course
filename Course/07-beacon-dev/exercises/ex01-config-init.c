/*
 * ========================================
 * EXERCISE 01: Initialize Beacon Configuration
 * ========================================
 *
 * OBJECTIVE:
 * Create a function that initializes a BEACON_CONFIG structure
 * from hardcoded values and validates it.
 *
 * REQUIREMENTS:
 * 1. Define the BEACON_CONFIG structure with all necessary fields
 * 2. Implement InitBeaconConfig() to set default values
 * 3. Implement ValidateBeaconConfig() to check for errors
 * 4. Test with valid and invalid configurations
 *
 * SKILLS PRACTICED:
 * - Structure design
 * - Data validation
 * - Configuration management
 *
 * ========================================
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * TODO: Define BEACON_CONFIG structure
 *
 * Required fields:
 * - C2 host (string, max 256 chars)
 * - C2 port (DWORD)
 * - Use SSL (BOOL)
 * - Sleep time in seconds (DWORD)
 * - Jitter percentage (DWORD)
 * - Beacon ID (string, max 65 chars)
 * - User-Agent (string, max 512 chars)
 * - Check-in URI path (string, max 256 chars)
 * - Result URI path (string, max 256 chars)
 */

// TODO: Define your BEACON_CONFIG structure here
typedef struct {
    // Your code here
} BEACON_CONFIG;

/*
 * TODO: Implement InitBeaconConfig()
 *
 * Initialize the config structure with:
 * - Host: "192.168.1.100"
 * - Port: 443
 * - SSL: TRUE
 * - Sleep: 60 seconds
 * - Jitter: 30%
 * - Beacon ID: "BEACON-" + computer name
 * - User-Agent: Realistic browser string
 * - Check-in path: "/api/status"
 * - Result path: "/api/update"
 *
 * Return: TRUE on success, FALSE on failure
 */
BOOL InitBeaconConfig(BEACON_CONFIG* config) {
    // TODO: Implement this function
    return FALSE;
}

/*
 * TODO: Implement ValidateBeaconConfig()
 *
 * Validate that:
 * - Host is not empty
 * - Port is between 1 and 65535
 * - Sleep time is not 0
 * - Jitter is between 0 and 100
 * - Beacon ID is not empty
 * - Paths are not empty
 *
 * Return: TRUE if valid, FALSE if invalid
 */
BOOL ValidateBeaconConfig(BEACON_CONFIG* config) {
    // TODO: Implement this function
    return FALSE;
}

/*
 * TODO: Implement PrintBeaconConfig()
 *
 * Print all configuration fields in a readable format
 */
void PrintBeaconConfig(BEACON_CONFIG* config) {
    // TODO: Implement this function
}

/*
 * TEST CASES
 */

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

/*
 * MAIN
 */

int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("EXERCISE 01: Beacon Config Initialization\n");
    printf("========================================\n\n");

    // Run tests
    TestValidConfig();
    TestInvalidPort();
    TestInvalidJitter();
    TestEmptyHost();

    printf("========================================\n");
    printf("EXERCISE COMPLETE\n");
    printf("========================================\n\n");

    /*
     * EXPECTED RESULTS:
     * - Test 1: PASS (valid config)
     * - Test 2: PASS (catches invalid port)
     * - Test 3: PASS (catches invalid jitter)
     * - Test 4: PASS (catches empty host)
     */

    return 0;
}

/*
 * ========================================
 * HINTS:
 * ========================================
 *
 * 1. Use ZeroMemory() to clear the structure before initializing
 *
 * 2. Use strcpy() or strncpy() to set string fields
 *
 * 3. GetComputerNameA() can get the computer name for Beacon ID
 *
 * 4. Validation is just checking ranges and emptiness
 *
 * 5. Use strlen() to check if strings are empty
 *
 * ========================================
 * COMPILATION:
 * ========================================
 *
 * cl.exe ex01-config-init.c
 *
 * ========================================
 */
