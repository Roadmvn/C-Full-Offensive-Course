/*
 * Lesson 02: Complete HTTP GET Request
 *
 * This lesson demonstrates:
 * - Full GET request implementation
 * - Reading entire response body
 * - Querying response headers
 * - Proper error handling
 * - Dynamic buffer allocation
 *
 * Common Use Cases in C2:
 * - Fetching tasks/commands from C2 server
 * - Downloading additional payloads
 * - Checking for updates
 *
 * Compilation: cl /W4 02-http-get.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

typedef struct {
    char* data;
    DWORD size;
    DWORD capacity;
} HttpResponse;

void InitResponse(HttpResponse* response) {
    response->data = NULL;
    response->size = 0;
    response->capacity = 0;
}

BOOL AppendToResponse(HttpResponse* response, const char* newData, DWORD dataSize) {
    if (response->size + dataSize > response->capacity) {
        DWORD newCapacity = (response->capacity == 0) ? 4096 : response->capacity * 2;
        while (newCapacity < response->size + dataSize) {
            newCapacity *= 2;
        }

        char* newBuffer = (char*)realloc(response->data, newCapacity);
        if (!newBuffer) {
            return FALSE;
        }

        response->data = newBuffer;
        response->capacity = newCapacity;
    }

    memcpy(response->data + response->size, newData, dataSize);
    response->size += dataSize;

    return TRUE;
}

void FreeResponse(HttpResponse* response) {
    if (response->data) {
        free(response->data);
        response->data = NULL;
    }
    response->size = 0;
    response->capacity = 0;
}

BOOL HttpGet(const wchar_t* server, DWORD port, const wchar_t* path,
             HttpResponse* response, DWORD* statusCode) {

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    // Initialize session
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

    // Connect to server
    hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        wprintf(L"[!] WinHttpConnect failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Create request
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

    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        wprintf(L"[!] WinHttpSendRequest failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        wprintf(L"[!] WinHttpReceiveResponse failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // Query status code
    DWORD status = 0;
    DWORD statusSize = sizeof(status);

    if (WinHttpQueryHeaders(hRequest,
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX,
                           &status,
                           &statusSize,
                           WINHTTP_NO_HEADER_INDEX)) {
        if (statusCode) {
            *statusCode = status;
        }
    }

    // Read response body
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
                if (!AppendToResponse(response, buffer, bytesRead)) {
                    wprintf(L"[!] Failed to append response data\n");
                    goto cleanup;
                }
            }
        }

    } while (availableBytes > 0);

    result = TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

void PrintHeaders(const wchar_t* server, DWORD port, const wchar_t* path) {
    HINTERNET hSession, hConnect, hRequest;

    hSession = WinHttpOpen(L"WinHTTP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD flags = (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    if (hRequest) {
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD headerSize = 0;

                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   WINHTTP_HEADER_NAME_BY_INDEX, NULL, &headerSize,
                                   WINHTTP_NO_HEADER_INDEX);

                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    wchar_t* headers = (wchar_t*)malloc(headerSize);
                    if (headers) {
                        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                               WINHTTP_HEADER_NAME_BY_INDEX, headers,
                                               &headerSize, WINHTTP_NO_HEADER_INDEX)) {
                            wprintf(L"\n[+] Response Headers:\n");
                            wprintf(L"%s\n", headers);
                        }
                        free(headers);
                    }
                }
            }
        }
        WinHttpCloseHandle(hRequest);
    }

    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

int main(void) {
    HttpResponse response;
    DWORD statusCode = 0;

    wprintf(L"[*] HTTP GET Request Demo\n");
    wprintf(L"[*] Target: http://httpbin.org/get\n\n");

    InitResponse(&response);

    // Perform GET request
    wprintf(L"[+] Sending GET request...\n");

    if (HttpGet(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/get",
                &response, &statusCode)) {

        wprintf(L"[+] Success! Status Code: %lu\n", statusCode);
        wprintf(L"[+] Response Size: %lu bytes\n\n", response.size);

        // Print response (add null terminator for printing)
        if (response.data) {
            char* printable = (char*)malloc(response.size + 1);
            if (printable) {
                memcpy(printable, response.data, response.size);
                printable[response.size] = '\0';

                wprintf(L"[+] Response Body:\n");
                printf("%s\n", printable);

                free(printable);
            }
        }

        // Query and print headers
        PrintHeaders(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/get");

    } else {
        wprintf(L"[!] GET request failed\n");
    }

    FreeResponse(&response);

    wprintf(L"\n[*] Demo completed\n");

    return 0;
}
