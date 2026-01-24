/*
 * Lesson 03: HTTP POST Requests
 *
 * POST requests are used to send data to the server.
 *
 * Common Uses in C2:
 * - Exfiltrating command output
 * - Uploading files
 * - Sending system information
 * - Registering new implant
 *
 * POST requires:
 * - Content-Type header
 * - Content-Length (handled automatically)
 * - Request body data
 *
 * Common Content-Types:
 * - application/x-www-form-urlencoded (form data)
 * - application/json (JSON data)
 * - application/octet-stream (binary data)
 * - multipart/form-data (file uploads)
 *
 * Compilation: cl /W4 03-http-post.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

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
        if (!newBuffer) return FALSE;

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

BOOL HttpPost(const wchar_t* server, DWORD port, const wchar_t* path,
              const char* postData, DWORD postDataSize,
              const wchar_t* contentType,
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
        L"POST",  // POST method
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

    // Build Content-Type header
    wchar_t headers[256];
    swprintf(headers, 256, L"Content-Type: %s", contentType);

    // Send request with body
    if (!WinHttpSendRequest(
            hRequest,
            headers,                    // Additional headers
            (DWORD)-1,                  // Headers length (auto-calculate)
            (LPVOID)postData,           // Request body
            postDataSize,               // Body length
            postDataSize,               // Total length
            0)) {                       // Context
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

void DemoFormData(void) {
    HttpResponse response;
    DWORD statusCode = 0;

    wprintf(L"\n[*] Demo 1: Form Data POST\n");
    wprintf(L"[*] Content-Type: application/x-www-form-urlencoded\n\n");

    InitResponse(&response);

    // URL-encoded form data
    const char* formData = "username=agent007&password=secret&role=admin";

    wprintf(L"[+] POST Data: %S\n", formData);
    wprintf(L"[+] Sending POST request to httpbin.org/post...\n");

    if (HttpPost(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/post",
                formData, (DWORD)strlen(formData),
                L"application/x-www-form-urlencoded",
                &response, &statusCode)) {

        wprintf(L"[+] Success! Status Code: %lu\n", statusCode);
        wprintf(L"[+] Response Size: %lu bytes\n\n", response.size);

        if (response.data) {
            char* printable = (char*)malloc(response.size + 1);
            if (printable) {
                memcpy(printable, response.data, response.size);
                printable[response.size] = '\0';
                printf("%s\n", printable);
                free(printable);
            }
        }
    }

    FreeResponse(&response);
}

void DemoJsonData(void) {
    HttpResponse response;
    DWORD statusCode = 0;

    wprintf(L"\n[*] Demo 2: JSON POST\n");
    wprintf(L"[*] Content-Type: application/json\n\n");

    InitResponse(&response);

    // JSON data (common in modern C2s)
    const char* jsonData =
        "{"
        "\"agent_id\":\"AGENT-12345\","
        "\"hostname\":\"WIN-TARGET01\","
        "\"username\":\"Administrator\","
        "\"os\":\"Windows 10\","
        "\"arch\":\"x64\","
        "\"checkin_time\":1234567890"
        "}";

    wprintf(L"[+] JSON Data:\n%S\n", jsonData);
    wprintf(L"[+] Sending POST request to httpbin.org/post...\n");

    if (HttpPost(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/post",
                jsonData, (DWORD)strlen(jsonData),
                L"application/json",
                &response, &statusCode)) {

        wprintf(L"[+] Success! Status Code: %lu\n", statusCode);
        wprintf(L"[+] Response Size: %lu bytes\n\n", response.size);

        if (response.data) {
            char* printable = (char*)malloc(response.size + 1);
            if (printable) {
                memcpy(printable, response.data, response.size);
                printable[response.size] = '\0';
                printf("%s\n", printable);
                free(printable);
            }
        }
    }

    FreeResponse(&response);
}

void DemoBinaryData(void) {
    HttpResponse response;
    DWORD statusCode = 0;

    wprintf(L"\n[*] Demo 3: Binary Data POST\n");
    wprintf(L"[*] Content-Type: application/octet-stream\n\n");

    InitResponse(&response);

    // Simulate binary data (e.g., screenshot, keylog dump)
    unsigned char binaryData[256];
    for (int i = 0; i < 256; i++) {
        binaryData[i] = (unsigned char)i;
    }

    wprintf(L"[+] Binary Data: 256 bytes\n");
    wprintf(L"[+] Sending POST request to httpbin.org/post...\n");

    if (HttpPost(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/post",
                (char*)binaryData, sizeof(binaryData),
                L"application/octet-stream",
                &response, &statusCode)) {

        wprintf(L"[+] Success! Status Code: %lu\n", statusCode);
        wprintf(L"[+] Response Size: %lu bytes\n", response.size);
        wprintf(L"[+] Binary data uploaded successfully\n");
    }

    FreeResponse(&response);
}

int main(void) {
    wprintf(L"[*] HTTP POST Request Demonstrations\n");
    wprintf(L"====================================\n");

    // Demo 1: Form-encoded data
    DemoFormData();

    // Demo 2: JSON data (modern C2 style)
    DemoJsonData();

    // Demo 3: Binary data
    DemoBinaryData();

    wprintf(L"\n[*] All POST demos completed\n");

    return 0;
}
