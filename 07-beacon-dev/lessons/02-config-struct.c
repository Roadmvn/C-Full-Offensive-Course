/*
 * ========================================
 * LESSON 02: Beacon Configuration Structure
 * ========================================
 *
 * A beacon needs a configuration to know:
 * - WHERE to connect (C2 server host/IP and port)
 * - HOW OFTEN to check-in (sleep interval)
 * - HOW to vary timing (jitter percentage)
 * - WHAT to identify as (user-agent, beacon ID)
 *
 * This lesson covers designing a robust BEACON_CONFIG structure.
 *
 * ========================================
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * ========================================
 * BEACON_CONFIG STRUCTURE
 * ========================================
 *
 * This structure holds all configuration needed by the beacon.
 * In real malware, this would be:
 * - Encrypted in the binary
 * - Obfuscated to avoid static analysis
 * - Possibly downloaded/updated from C2
 */

typedef struct {
    // C2 Server Information
    char szHost[256];           // C2 hostname or IP (e.g., "evil.com" or "192.168.1.100")
    DWORD dwPort;               // C2 port (80 for HTTP, 443 for HTTPS, custom ports)
    BOOL bUseSSL;               // Use HTTPS instead of HTTP?

    // Communication Timing
    DWORD dwSleepTime;          // Base sleep time in seconds (e.g., 60 = check-in every minute)
    DWORD dwJitter;             // Jitter percentage 0-100 (e.g., 20 = +/- 20% variation)

    // Beacon Identity
    char szBeaconID[65];        // Unique beacon identifier (UUID, hostname hash, etc.)
    char szUserAgent[512];      // HTTP User-Agent for stealth

    // Communication Paths
    char szCheckInPath[256];    // URI path for check-ins (e.g., "/api/beacon")
    char szResultPath[256];     // URI path for sending results (e.g., "/api/results")

    // Operational Settings
    DWORD dwMaxRetries;         // How many times to retry failed connections
    DWORD dwRetryDelay;         // Delay between retries in seconds
    BOOL bKillDate;             // Does this beacon have a kill date?
    SYSTEMTIME stKillDate;      // Auto-terminate after this date

} BEACON_CONFIG;

/*
 * ========================================
 * HELPER FUNCTIONS
 * ========================================
 */

// Generate a unique Beacon ID based on computer name and timestamp
BOOL GenerateBeaconID(char* buffer, DWORD bufferSize) {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);

    if (!GetComputerNameA(computerName, &size)) {
        strcpy(computerName, "UNKNOWN");
    }

    // Simple ID: computername_timestamp
    // Real implementations use crypto hashes or UUIDs
    DWORD timestamp = (DWORD)time(NULL);
    _snprintf(buffer, bufferSize, "%s_%08X", computerName, timestamp);

    return TRUE;
}

// Initialize beacon config with default values
BOOL InitBeaconConfig(BEACON_CONFIG* config) {
    if (!config) return FALSE;

    ZeroMemory(config, sizeof(BEACON_CONFIG));

    // C2 Server - HARDCODED (in real malware, this is encrypted/obfuscated)
    strcpy(config->szHost, "127.0.0.1");        // Change to your C2 server
    config->dwPort = 8080;                      // Change to your C2 port
    config->bUseSSL = FALSE;                    // HTTPS recommended for production

    // Timing - OPERATIONAL SECURITY
    config->dwSleepTime = 60;                   // 60 seconds = 1 minute check-ins
    config->dwJitter = 20;                      // 20% jitter = 48-72 second variation

    // Identity
    GenerateBeaconID(config->szBeaconID, sizeof(config->szBeaconID));

    // User-Agent - BLEND IN with normal traffic
    strcpy(config->szUserAgent,
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/120.0.0.0 Safari/537.36");

    // Communication paths - DISGUISE as normal web traffic
    strcpy(config->szCheckInPath, "/api/status");     // Looks like status check
    strcpy(config->szResultPath, "/api/update");      // Looks like update endpoint

    // Reliability settings
    config->dwMaxRetries = 3;                   // Try 3 times before giving up
    config->dwRetryDelay = 5;                   // Wait 5 seconds between retries

    // Kill date - AUTO-DESTRUCT after operation
    config->bKillDate = FALSE;                  // Disabled for this demo
    // If enabled, set stKillDate to operation end date

    return TRUE;
}

// Print beacon configuration (for debugging/demonstration)
void PrintBeaconConfig(BEACON_CONFIG* config) {
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
    printf("  Beacon ID: %s\n", config->szBeaconID);
    printf("  User-Agent: %s\n", config->szUserAgent);
    printf("\n");

    printf("[Endpoints]\n");
    printf("  Check-in: %s\n", config->szCheckInPath);
    printf("  Results:  %s\n", config->szResultPath);
    printf("\n");

    printf("[Reliability]\n");
    printf("  Max Retries: %d\n", config->dwMaxRetries);
    printf("  Retry Delay: %d seconds\n", config->dwRetryDelay);
    printf("\n");

    printf("[Operational Security]\n");
    if (config->bKillDate) {
        printf("  Kill Date: %04d-%02d-%02d %02d:%02d:%02d\n",
               config->stKillDate.wYear,
               config->stKillDate.wMonth,
               config->stKillDate.wDay,
               config->stKillDate.wHour,
               config->stKillDate.wMinute,
               config->stKillDate.wSecond);
    } else {
        printf("  Kill Date: Disabled\n");
    }
    printf("\n");
}

/*
 * ========================================
 * ADVANCED: CONFIG VALIDATION
 * ========================================
 */

// Validate configuration before using it
BOOL ValidateBeaconConfig(BEACON_CONFIG* config) {
    printf("[*] Validating beacon configuration...\n");

    // Check host
    if (strlen(config->szHost) == 0) {
        printf("[-] Error: C2 host not configured\n");
        return FALSE;
    }

    // Check port
    if (config->dwPort == 0 || config->dwPort > 65535) {
        printf("[-] Error: Invalid port %d\n", config->dwPort);
        return FALSE;
    }

    // Check sleep time (shouldn't be 0 or too long)
    if (config->dwSleepTime == 0) {
        printf("[-] Error: Sleep time cannot be 0\n");
        return FALSE;
    }

    if (config->dwSleepTime > 86400) {  // > 24 hours
        printf("[-] Warning: Sleep time very long (%d seconds)\n", config->dwSleepTime);
    }

    // Check jitter (should be 0-100%)
    if (config->dwJitter > 100) {
        printf("[-] Error: Jitter must be 0-100%% (got %d%%)\n", config->dwJitter);
        return FALSE;
    }

    // Check beacon ID
    if (strlen(config->szBeaconID) == 0) {
        printf("[-] Error: Beacon ID not set\n");
        return FALSE;
    }

    // Check paths
    if (strlen(config->szCheckInPath) == 0) {
        printf("[-] Error: Check-in path not set\n");
        return FALSE;
    }

    // Check kill date if enabled
    if (config->bKillDate) {
        SYSTEMTIME now;
        GetSystemTime(&now);

        // Simple date comparison (this is not complete, just demonstration)
        if (config->stKillDate.wYear < now.wYear ||
            (config->stKillDate.wYear == now.wYear &&
             config->stKillDate.wMonth < now.wMonth)) {
            printf("[-] Error: Kill date is in the past!\n");
            return FALSE;
        }
    }

    printf("[+] Configuration validated successfully\n");
    return TRUE;
}

/*
 * ========================================
 * ADVANCED: CHECK KILL DATE
 * ========================================
 */

// Check if beacon should self-terminate due to kill date
BOOL ShouldTerminate(BEACON_CONFIG* config) {
    if (!config->bKillDate) {
        return FALSE;  // No kill date set
    }

    SYSTEMTIME now;
    GetSystemTime(&now);

    // Convert SYSTEMTIME to FILETIME for comparison
    FILETIME ftNow, ftKill;
    SystemTimeToFileTime(&now, &ftNow);
    SystemTimeToFileTime(&config->stKillDate, &ftKill);

    // Compare
    ULARGE_INTEGER uliNow, uliKill;
    uliNow.LowPart = ftNow.dwLowDateTime;
    uliNow.HighPart = ftNow.dwHighDateTime;
    uliKill.LowPart = ftKill.dwLowDateTime;
    uliKill.HighPart = ftKill.dwHighDateTime;

    if (uliNow.QuadPart >= uliKill.QuadPart) {
        printf("[!] Kill date reached! Beacon will terminate.\n");
        return TRUE;
    }

    return FALSE;
}

/*
 * ========================================
 * DEMONSTRATION
 * ========================================
 */

int main(void) {
    BEACON_CONFIG config;

    printf("========================================\n");
    printf("BEACON CONFIG DEMONSTRATION\n");
    printf("========================================\n\n");

    // Initialize configuration
    printf("[*] Initializing beacon configuration...\n");
    if (!InitBeaconConfig(&config)) {
        printf("[-] Failed to initialize config\n");
        return 1;
    }
    printf("[+] Configuration initialized\n\n");

    // Print configuration
    PrintBeaconConfig(&config);

    // Validate configuration
    if (!ValidateBeaconConfig(&config)) {
        printf("[-] Configuration validation failed!\n");
        return 1;
    }
    printf("\n");

    // Check kill date
    printf("[*] Checking operational status...\n");
    if (ShouldTerminate(&config)) {
        printf("[!] Beacon should terminate now!\n");
        return 0;
    }
    printf("[+] Beacon operational - no kill date reached\n\n");

    // Demonstrate config modification
    printf("========================================\n");
    printf("MODIFYING CONFIGURATION\n");
    printf("========================================\n\n");

    printf("[*] Changing sleep time from %d to 120 seconds...\n", config.dwSleepTime);
    config.dwSleepTime = 120;

    printf("[*] Enabling SSL...\n");
    config.bUseSSL = TRUE;
    config.dwPort = 443;  // Standard HTTPS port

    printf("[*] Setting kill date to 2025-12-31 23:59:59...\n");
    config.bKillDate = TRUE;
    config.stKillDate.wYear = 2025;
    config.stKillDate.wMonth = 12;
    config.stKillDate.wDay = 31;
    config.stKillDate.wHour = 23;
    config.stKillDate.wMinute = 59;
    config.stKillDate.wSecond = 59;

    printf("\n");
    PrintBeaconConfig(&config);

    /*
     * KEY TAKEAWAYS:
     *
     * 1. BEACON_CONFIG centralizes all beacon settings
     * 2. Configuration should be validated before use
     * 3. Settings can be modified at runtime (e.g., server updates sleep time)
     * 4. Kill date provides automatic cleanup after operation
     * 5. User-Agent and paths should blend in with normal traffic
     *
     * REAL-WORLD CONSIDERATIONS:
     *
     * 1. Configuration encryption:
     *    - Config should be AES/XOR encrypted in binary
     *    - Decrypted only at runtime in memory
     *
     * 2. Configuration obfuscation:
     *    - Use string stacking/encoding for host/paths
     *    - Hide in resources or appended data
     *
     * 3. Dynamic configuration:
     *    - C2 server can update config via special commands
     *    - Beacon adapts to changing operational requirements
     *
     * 4. Multiple C2 profiles:
     *    - Failover to backup C2 if primary is down
     *    - Different profiles for different environments
     *
     * NEXT LESSON:
     * - Implement the sleep loop with jitter calculation
     */

    return 0;
}

/*
 * ========================================
 * COMPILATION & EXECUTION
 * ========================================
 *
 * Compile:
 *   cl.exe 02-config-struct.c
 *
 * Run:
 *   02-config-struct.exe
 *
 * Expected output:
 *   - Shows default configuration
 *   - Validates configuration
 *   - Demonstrates config modification
 *   - Shows updated configuration
 *
 * ========================================
 */
