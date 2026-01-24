/*
 * Lesson 01: Introduction to WinHTTP API
 *
 * WinHTTP vs WinINet:
 * - WinHTTP: Server applications, services, automation (no user interaction)
 * - WinINet: Browser-like applications (uses IE settings, cookies, cache)
 *
 * For C2/malware, WinHTTP is preferred:
 * - More stable for background operations
 * - No dependency on IE settings
 * - Better for automated tasks
 *
 * WinHTTP Request Flow:
 * 1. WinHttpOpen()        - Initialize session
 * 2. WinHttpConnect()     - Connect to server
 * 3. WinHttpOpenRequest() - Create request
 * 4. WinHttpSendRequest() - Send request
 * 5. WinHttpReceiveResponse() - Receive response
 * 6. WinHttpQueryDataAvailable() - Check data size
 * 7. WinHttpReadData()    - Read response data
 * 8. WinHttpCloseHandle() - Cleanup
 *
 * Compilation: cl /W4 01-winhttp-intro.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

void PrintWinHttpError(const char* function) {
    DWORD error = GetLastError();
    wprintf(L"[!] %S failed with error: %lu\n", function, error);
}

int main(void) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    wprintf(L"[*] WinHTTP Basic Flow Demo\n");
    wprintf(L"[*] Target: http://example.com/\n\n");

    // Step 1: Initialize WinHTTP session
    // Parameters: User-Agent, Access Type, Proxy, Proxy Bypass, Flags
    wprintf(L"[+] Step 1: WinHttpOpen - Initialize session\n");
    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  // User-Agent
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,             // Use default proxy
        WINHTTP_NO_PROXY_NAME,                         // No custom proxy
        WINHTTP_NO_PROXY_BYPASS,                       // No proxy bypass
        0                                               // Synchronous mode
    );

    if (!hSession) {
        PrintWinHttpError("WinHttpOpen");
        return 1;
    }
    wprintf(L"    Session handle: 0x%p\n\n", hSession);

    // Step 2: Connect to server
    // Parameters: Session, Server Name, Port, Reserved
    wprintf(L"[+] Step 2: WinHttpConnect - Connect to server\n");
    hConnect = WinHttpConnect(
        hSession,
        L"example.com",              // Server hostname
        INTERNET_DEFAULT_HTTP_PORT,  // Port 80 for HTTP
        0                            // Reserved
    );

    if (!hConnect) {
        PrintWinHttpError("WinHttpConnect");
        WinHttpCloseHandle(hSession);
        return 1;
    }
    wprintf(L"    Connection handle: 0x%p\n\n", hConnect);

    // Step 3: Create HTTP request
    // Parameters: Connection, Verb, Object, Version, Referrer, Accept Types, Flags
    wprintf(L"[+] Step 3: WinHttpOpenRequest - Create request\n");
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",                      // HTTP method
        L"/",                        // Resource path
        NULL,                        // HTTP/1.1 (default)
        WINHTTP_NO_REFERER,          // No referrer
        WINHTTP_DEFAULT_ACCEPT_TYPES,// Accept all types
        0                            // HTTP (not HTTPS)
    );

    if (!hRequest) {
        PrintWinHttpError("WinHttpOpenRequest");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    wprintf(L"    Request handle: 0x%p\n\n", hRequest);

    // Step 4: Send request
    wprintf(L"[+] Step 4: WinHttpSendRequest - Send HTTP request\n");
    BOOL result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,  // No extra headers
        0,                               // Headers length
        WINHTTP_NO_REQUEST_DATA,         // No body data (GET)
        0,                               // Body length
        0,                               // Total length
        0                                // Context (for async)
    );

    if (!result) {
        PrintWinHttpError("WinHttpSendRequest");
        goto cleanup;
    }
    wprintf(L"    Request sent successfully\n\n");

    // Step 5: Receive response
    wprintf(L"[+] Step 5: WinHttpReceiveResponse - Wait for response\n");
    result = WinHttpReceiveResponse(hRequest, NULL);

    if (!result) {
        PrintWinHttpError("WinHttpReceiveResponse");
        goto cleanup;
    }
    wprintf(L"    Response received\n\n");

    // Query status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);

    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX
    );

    wprintf(L"[+] HTTP Status Code: %lu\n\n", statusCode);

    // Step 6: Check available data
    DWORD availableBytes = 0;
    wprintf(L"[+] Step 6: WinHttpQueryDataAvailable - Check data size\n");

    if (WinHttpQueryDataAvailable(hRequest, &availableBytes)) {
        wprintf(L"    Available bytes: %lu\n\n", availableBytes);
    }

    // Step 7: Read data (just first chunk for demo)
    if (availableBytes > 0) {
        DWORD bytesToRead = (availableBytes > 512) ? 512 : availableBytes;
        char* buffer = (char*)malloc(bytesToRead + 1);

        if (buffer) {
            DWORD bytesRead = 0;
            wprintf(L"[+] Step 7: WinHttpReadData - Read response\n");

            if (WinHttpReadData(hRequest, buffer, bytesToRead, &bytesRead)) {
                buffer[bytesRead] = '\0';
                wprintf(L"    Read %lu bytes:\n", bytesRead);
                printf("    %s...\n\n", buffer);
            }

            free(buffer);
        }
    }

    // Step 8: Cleanup
    wprintf(L"[+] Step 8: Cleanup handles\n");

cleanup:
    if (hRequest) {
        WinHttpCloseHandle(hRequest);
        wprintf(L"    Closed request handle\n");
    }
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
        wprintf(L"    Closed connection handle\n");
    }
    if (hSession) {
        WinHttpCloseHandle(hSession);
        wprintf(L"    Closed session handle\n");
    }

    wprintf(L"\n[*] WinHTTP flow completed!\n");

    return 0;
}
