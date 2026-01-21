/*
 * Solution 01: Fetch Web Page
 *
 * This solution demonstrates:
 * - Complete HTTP GET implementation
 * - File I/O for saving response
 * - Header querying
 * - Error handling with retries
 *
 * Compilation: cl /W4 ex01-fetch-page-solution.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

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
        DWORD newCapacity = (buf->capacity == 0) ? 8192 : buf->capacity * 2;
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

BOOL SaveToFile(const wchar_t* filename, const char* data, DWORD size) {
    HANDLE hFile = CreateFileW(
        filename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Failed to create file: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(hFile, data, size, &bytesWritten, NULL);

    CloseHandle(hFile);

    if (!result || bytesWritten != size) {
        wprintf(L"[!] Failed to write file\n");
        return FALSE;
    }

    return TRUE;
}

BOOL FetchAndSave(const wchar_t* server, DWORD port, const wchar_t* path,
                  const wchar_t* outputFile) {

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;
    Buffer responseData;

    InitBuffer(&responseData);

    wprintf(L"[+] Connecting to %s...\n", server);

    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        wprintf(L"[!] WinHttpOpen failed: %lu\n", GetLastError());
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        wprintf(L"[!] WinHttpConnect failed: %lu\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"[+] Fetching %s...\n", path);

    DWORD flags = (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0;

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!hRequest) {
        wprintf(L"[!] WinHttpOpenRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
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

    if (statusCode != 200) {
        wprintf(L"[!] Server returned non-200 status\n");
        goto cleanup;
    }

    // Query Content-Type (Bonus)
    DWORD headerSize = 0;
    WinHttpQueryHeaders(hRequest,
                       WINHTTP_QUERY_CONTENT_TYPE,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       NULL,
                       &headerSize,
                       WINHTTP_NO_HEADER_INDEX);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        wchar_t* contentType = (wchar_t*)malloc(headerSize);
        if (contentType) {
            if (WinHttpQueryHeaders(hRequest,
                                   WINHTTP_QUERY_CONTENT_TYPE,
                                   WINHTTP_HEADER_NAME_BY_INDEX,
                                   contentType,
                                   &headerSize,
                                   WINHTTP_NO_HEADER_INDEX)) {
                wprintf(L"[+] Content-Type: %s\n", contentType);
            }
            free(contentType);
        }
    }

    // Read response data
    DWORD availableBytes = 0;
    char buffer[8192];

    do {
        availableBytes = 0;

        if (!WinHttpQueryDataAvailable(hRequest, &availableBytes)) {
            wprintf(L"[!] WinHttpQueryDataAvailable failed: %lu\n", GetLastError());
            goto cleanup;
        }

        if (availableBytes > 0) {
            DWORD bytesToRead = (availableBytes > sizeof(buffer)) ? sizeof(buffer) : availableBytes;
            DWORD bytesRead = 0;

            if (!WinHttpReadData(hRequest, buffer, bytesToRead, &bytesRead)) {
                wprintf(L"[!] WinHttpReadData failed: %lu\n", GetLastError());
                goto cleanup;
            }

            if (bytesRead > 0) {
                if (!AppendToBuffer(&responseData, buffer, bytesRead)) {
                    wprintf(L"[!] Failed to append data\n");
                    goto cleanup;
                }
            }
        }

    } while (availableBytes > 0);

    wprintf(L"[+] Response Size: %lu bytes\n", responseData.size);

    // Print first 200 bytes (Bonus)
    if (responseData.size > 0) {
        DWORD printSize = (responseData.size > 200) ? 200 : responseData.size;
        wprintf(L"\n[+] First %lu bytes:\n", printSize);
        for (DWORD i = 0; i < printSize; i++) {
            printf("%c", responseData.data[i]);
        }
        if (responseData.size > 200) {
            printf("...");
        }
        printf("\n\n");
    }

    // Save to file
    if (SaveToFile(outputFile, responseData.data, responseData.size)) {
        wprintf(L"[+] Saved to: %s\n", outputFile);
        result = TRUE;
    }

cleanup:
    FreeBuffer(&responseData);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

BOOL FetchWithRetry(const wchar_t* server, DWORD port, const wchar_t* path,
                    const wchar_t* outputFile, DWORD maxRetries) {

    for (DWORD attempt = 1; attempt <= maxRetries; attempt++) {
        wprintf(L"\n[*] Attempt %lu/%lu\n", attempt, maxRetries);

        if (FetchAndSave(server, port, path, outputFile)) {
            return TRUE;
        }

        if (attempt < maxRetries) {
            wprintf(L"[*] Retrying in 2 seconds...\n");
            Sleep(2000);
        }
    }

    wprintf(L"\n[!] All attempts failed\n");
    return FALSE;
}

int main(void) {
    wprintf(L"[*] Exercise 01 Solution: Fetch Web Page\n");
    wprintf(L"=========================================\n\n");

    // Basic implementation
    wprintf(L"[*] Test 1: Basic fetch\n");
    FetchAndSave(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/html", L"output.html");

    // With retry logic (Bonus)
    wprintf(L"\n\n[*] Test 2: Fetch with retry logic\n");
    FetchWithRetry(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/html",
                   L"output_retry.html", 3);

    wprintf(L"\n[*] Solution completed!\n");

    return 0;
}
