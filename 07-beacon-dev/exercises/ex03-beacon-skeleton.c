/*
 * ========================================
 * EXERCISE 03: Beacon Skeleton
 * ========================================
 *
 * OBJECTIVE:
 * Combine everything learned to create a working beacon skeleton
 * that includes:
 * - Configuration management
 * - Sleep loop with jitter
 * - HTTP check-in (without actual command execution)
 *
 * REQUIREMENTS:
 * 1. Initialize beacon configuration
 * 2. Main loop that runs 5 check-ins
 * 3. Sleep with jitter between check-ins
 * 4. HTTP check-in to C2 server
 * 5. Parse simple task responses
 * 6. Handle no-task and exit-task scenarios
 *
 * SKILLS PRACTICED:
 * - Integrating multiple components
 * - Network communication
 * - Control flow
 * - Error handling
 *
 * ========================================
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "wininet.lib")

/*
 * TODO: Define necessary structures
 */

// Beacon configuration
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

// Task types
#define TASK_TYPE_NONE  0
#define TASK_TYPE_SLEEP 1
#define TASK_TYPE_EXIT  2

// Task structure
typedef struct {
    DWORD dwTaskID;
    DWORD dwTaskType;
    char szCommand[1024];
} BEACON_TASK;

// Beacon state
typedef struct {
    BOOL bRunning;
    DWORD dwCheckInCount;
} BEACON_STATE;

/*
 * TODO: Implement helper functions
 */

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

/*
 * TODO: Implement InitBeaconConfig()
 *
 * Initialize configuration with:
 * - Host: 127.0.0.1
 * - Port: 8080
 * - SSL: FALSE
 * - Sleep: 5 seconds (short for demo)
 * - Jitter: 20%
 * - Beacon ID: "BEACON-" + computer name
 * - User-Agent: Realistic browser string
 * - Check-in path: "/beacon"
 */
BOOL InitBeaconConfig(BEACON_CONFIG* config) {
    // TODO: Implement this
    return FALSE;
}

/*
 * TODO: Implement ParseTaskResponse()
 *
 * Parse simple task format:
 * - "NOTASK" -> TASK_TYPE_NONE
 * - "SLEEP:120" -> TASK_TYPE_SLEEP, command="120"
 * - "EXIT" -> TASK_TYPE_EXIT
 *
 * Return TRUE on success, FALSE on failure
 */
BOOL ParseTaskResponse(const char* response, DWORD responseLen, BEACON_TASK* task) {
    // TODO: Implement this
    return FALSE;
}

/*
 * TODO: Implement BeaconCheckIn()
 *
 * 1. Open WinINet connection to C2 server
 * 2. Send GET request to check-in path
 * 3. Add X-Beacon-ID header
 * 4. Read response
 * 5. Parse task from response
 * 6. Close handles
 * 7. Return TRUE on success (even if no task received)
 *
 * HINT: See Lesson 04 for reference
 */
BOOL BeaconCheckIn(BEACON_CONFIG* config, BEACON_TASK* task) {
    // TODO: Implement HTTP check-in

    // Initialize task to NONE
    if (task) {
        ZeroMemory(task, sizeof(BEACON_TASK));
        task->dwTaskType = TASK_TYPE_NONE;
    }

    // TODO: Implement WinINet logic here

    printf("[*] Attempting check-in to %s:%d%s\n",
           config->szHost,
           config->dwPort,
           config->szCheckInPath);

    // For now, simulate failure (no server running)
    printf("[-] Connection failed (no C2 server running)\n");

    return FALSE;
}

/*
 * TODO: Implement HandleTask()
 *
 * Process received task:
 * - TASK_TYPE_NONE: Do nothing
 * - TASK_TYPE_SLEEP: Update config sleep time
 * - TASK_TYPE_EXIT: Set state->bRunning = FALSE
 */
void HandleTask(BEACON_TASK* task, BEACON_CONFIG* config, BEACON_STATE* state) {
    // TODO: Implement task handling
}

/*
 * TODO: Implement main beacon loop
 */

int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("BEACON SKELETON\n");
    printf("========================================\n\n");

    // Seed RNG for jitter
    srand((unsigned int)time(NULL));

    // Initialize configuration
    BEACON_CONFIG config = {0};
    printf("[*] Initializing beacon configuration...\n");
    if (!InitBeaconConfig(&config)) {
        printf("[-] Failed to initialize config\n");
        return 1;
    }
    printf("[+] Configuration initialized\n\n");

    // Print configuration
    printf("[*] Beacon Configuration:\n");
    printf("    C2 Server: %s:%d\n", config.szHost, config.dwPort);
    printf("    Beacon ID: %s\n", config.szBeaconID);
    printf("    Sleep: %d seconds (+/- %d%%)\n",
           config.dwSleepTime,
           config.dwJitter);
    printf("    Check-in path: %s\n\n", config.szCheckInPath);

    // Initialize state
    BEACON_STATE state = {0};
    state.bRunning = TRUE;
    state.dwCheckInCount = 0;

    printf("[*] Starting beacon main loop...\n");
    printf("[*] Will perform 5 check-ins (demo mode)\n\n");

    // TODO: Main beacon loop
    // while (state.bRunning && state.dwCheckInCount < 5) {
    //     state.dwCheckInCount++;
    //
    //     printf("--- Check-in #%d ---\n", state.dwCheckInCount);
    //
    //     // Calculate sleep with jitter
    //     DWORD sleepMs = CalculateSleepWithJitter(config.dwSleepTime, config.dwJitter);
    //     printf("[*] Sleeping for %.2f seconds...\n", sleepMs / 1000.0);
    //
    //     // Sleep
    //     Sleep(sleepMs);
    //
    //     // Check in
    //     BEACON_TASK task = {0};
    //     if (BeaconCheckIn(&config, &task)) {
    //         printf("[+] Check-in successful\n");
    //
    //         // Handle any received task
    //         HandleTask(&task, &config, &state);
    //     } else {
    //         printf("[-] Check-in failed\n");
    //     }
    //
    //     printf("\n");
    // }

    if (!state.bRunning) {
        printf("[*] Beacon terminated by EXIT task\n");
    } else {
        printf("[*] Demo complete (5 check-ins finished)\n");
    }

    printf("\n");
    printf("========================================\n");
    printf("BEACON SHUTDOWN\n");
    printf("========================================\n\n");

    /*
     * EXPECTED BEHAVIOR:
     *
     * 1. Initialize config successfully
     * 2. Print configuration details
     * 3. Perform 5 check-ins:
     *    - Sleep with jitter (varying times)
     *    - Attempt HTTP check-in (fails without server)
     * 4. Clean shutdown
     *
     * BONUS CHALLENGE:
     * - Set up a simple Python HTTP server
     * - Have it return "NOTASK" or "EXIT" responses
     * - Test actual HTTP communication
     */

    return 0;
}

/*
 * ========================================
 * HINTS:
 * ========================================
 *
 * 1. InitBeaconConfig():
 *    - Use ZeroMemory() first
 *    - Use strcpy() for strings
 *    - GetComputerNameA() for beacon ID
 *
 * 2. ParseTaskResponse():
 *    - Use strcmp() to check for "NOTASK", "EXIT"
 *    - Use strncmp() and strchr() for "SLEEP:value"
 *    - Remember to set task->dwTaskType
 *
 * 3. BeaconCheckIn():
 *    - InternetOpenA() -> hInternet
 *    - InternetConnectA() -> hConnect
 *    - HttpOpenRequestA() -> hRequest
 *    - HttpSendRequestA() with custom headers
 *    - InternetReadFile() to get response
 *    - Don't forget to close all handles!
 *
 * 4. HandleTask():
 *    - Use switch statement on task->dwTaskType
 *    - For SLEEP: atoi(task->szCommand) to get new value
 *    - For EXIT: state->bRunning = FALSE
 *
 * 5. Main loop:
 *    - while condition with state.bRunning
 *    - Increment check-in counter
 *    - Calculate and print sleep time
 *    - Actually sleep
 *    - Check in and handle result
 *
 * ========================================
 * COMPILATION:
 * ========================================
 *
 * cl.exe ex03-beacon-skeleton.c /link wininet.lib
 *
 * ========================================
 * BONUS: Simple Python C2 Server
 * ========================================
 *
 * Create server.py:
 *
 * from http.server import BaseHTTPRequestHandler, HTTPServer
 *
 * class C2Handler(BaseHTTPRequestHandler):
 *     def do_GET(self):
 *         if self.path == '/beacon':
 *             print(f"[*] Check-in from: {self.headers.get('X-Beacon-ID')}")
 *             self.send_response(200)
 *             self.end_headers()
 *             self.wfile.write(b"NOTASK")  # or b"EXIT" to stop
 *
 * HTTPServer(('0.0.0.0', 8080), C2Handler).serve_forever()
 *
 * Run: python server.py
 * Then run your beacon!
 *
 * ========================================
 */
