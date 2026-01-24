/*
 * Solution 02: POST System Information
 *
 * This solution demonstrates:
 * - System information collection
 * - JSON formatting
 * - HTTP POST implementation
 * - Response parsing
 *
 * Compilation: cl /W4 ex02-post-data-solution.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

void GetOSVersion(wchar_t* buffer, DWORD bufferSize) {
    OSVERSIONINFOW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

#pragma warning(push)
#pragma warning(disable: 4996)
    if (GetVersionExW(&osvi)) {
        swprintf(buffer, bufferSize, L"Windows %lu.%lu",
                osvi.dwMajorVersion, osvi.dwMinorVersion);
    } else {
        wcscpy_s(buffer, bufferSize, L"Unknown");
    }
#pragma warning(pop)
}

const char* GetArchitecture(void) {
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);

    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return "x64";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return "x86";
        case PROCESSOR_ARCHITECTURE_ARM:
            return "ARM";
        case PROCESSOR_ARCHITECTURE_ARM64:
            return "ARM64";
        default:
            return "Unknown";
    }
}

void CollectSystemInfo(char* jsonBuffer, DWORD bufferSize) {
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computerNameSize = sizeof(computerName) / sizeof(wchar_t);

    wchar_t username[256];
    DWORD usernameSize = sizeof(username) / sizeof(wchar_t);

    wchar_t osVersion[256];

    wprintf(L"[*] Collecting system information...\n");

    // Get computer name
    if (GetComputerNameW(computerName, &computerNameSize)) {
        wprintf(L"[+] Computer: %s\n", computerName);
    } else {
        wcscpy_s(computerName, MAX_COMPUTERNAME_LENGTH + 1, L"Unknown");
    }

    // Get username
    if (GetUserNameW(username, &usernameSize)) {
        wprintf(L"[+] Username: %s\n", username);
    } else {
        wcscpy_s(username, 256, L"Unknown");
    }

    // Get OS version
    GetOSVersion(osVersion, sizeof(osVersion) / sizeof(wchar_t));
    wprintf(L"[+] OS: %s\n", osVersion);

    // Get architecture (Bonus)
    const char* arch = GetArchitecture();
    wprintf(L"[+] Architecture: %S\n", arch);

    // Get timestamp (Bonus)
    time_t currentTime = time(NULL);

    // Format as JSON
    sprintf_s(jsonBuffer, bufferSize,
        "{\n"
        "  \"computer\": \"%S\",\n"
        "  \"username\": \"%S\",\n"
        "  \"os\": \"%S\",\n"
        "  \"architecture\": \"%s\",\n"
        "  \"timestamp\": %lld\n"
        "}",
        computerName,
        username,
        osVersion,
        arch,
        (long long)currentTime
    );
}

BOOL PostSystemInfo(const char* jsonData, DWORD dataSize) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    wprintf(L"\n[*] Sending data to server...\n");

    hSession = WinHttpOpen(
        L"SystemInfoCollector/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        wprintf(L"[!] WinHttpOpen failed: %lu\n", GetLastError());
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, L"httpbin.org",
                             INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        wprintf(L"[!] WinHttpConnect failed: %lu\n", GetLastError());
        goto cleanup;
    }

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        L"/post",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        wprintf(L"[!] WinHttpOpenRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    wchar_t headers[] = L"Content-Type: application/json";

    if (!WinHttpSendRequest(hRequest, headers, (DWORD)-1,
                           (LPVOID)jsonData, dataSize, dataSize, 0)) {
        wprintf(L"[!] WinHttpSendRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        wprintf(L"[!] WinHttpReceiveResponse failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Query status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);

    if (WinHttpQueryHeaders(hRequest,
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX,
                           &statusCode,
                           &statusSize,
                           WINHTTP_NO_HEADER_INDEX)) {
        wprintf(L"[+] Status Code: %lu\n", statusCode);
    }

    if (statusCode == 200) {
        wprintf(L"[+] Data received by server\n");

        // Read and print response (Bonus - Pretty Print)
        DWORD availableBytes = 0;
        char buffer[4096];

        if (WinHttpQueryDataAvailable(hRequest, &availableBytes)) {
            if (availableBytes > 0) {
                DWORD bytesToRead = (availableBytes > sizeof(buffer) - 1) ?
                                   sizeof(buffer) - 1 : availableBytes;
                DWORD bytesRead = 0;

                if (WinHttpReadData(hRequest, buffer, bytesToRead, &bytesRead)) {
                    buffer[bytesRead] = '\0';
                    wprintf(L"\n[+] Server Response:\n%S\n", buffer);
                }
            }
        }

        result = TRUE;
    } else {
        wprintf(L"[!] Server returned error status\n");
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

int main(void) {
    char jsonData[2048];

    wprintf(L"[*] Exercise 02 Solution: POST System Information\n");
    wprintf(L"==================================================\n\n");

    // Collect system information
    CollectSystemInfo(jsonData, sizeof(jsonData));

    // Display JSON data
    wprintf(L"\n[+] JSON Data to send:\n%S\n", jsonData);

    // Send to server
    PostSystemInfo(jsonData, (DWORD)strlen(jsonData));

    wprintf(L"\n[*] Solution completed!\n");

    return 0;
}
