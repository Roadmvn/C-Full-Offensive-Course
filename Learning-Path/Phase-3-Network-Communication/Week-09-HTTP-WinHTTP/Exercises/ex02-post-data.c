/*
 * Exercise 02: POST Data to Server
 *
 * Task:
 * Implement a function that collects system information and POSTs it to a server.
 *
 * Requirements:
 * 1. Collect system information:
 *    - Computer name (GetComputerNameW)
 *    - Username (GetUserNameW)
 *    - OS version (GetVersionExW)
 * 2. Format data as JSON
 * 3. POST to http://httpbin.org/post
 * 4. Parse response and verify data was received
 * 5. Print response status and confirmation
 *
 * JSON Format:
 * {
 *   "computer": "DESKTOP-ABC123",
 *   "username": "user",
 *   "os": "Windows 10"
 * }
 *
 * Bonus:
 * - Add timestamp field
 * - Include architecture (x86/x64)
 * - Pretty-print the response
 *
 * Expected Output:
 * [*] Collecting system information...
 * [+] Computer: DESKTOP-ABC123
 * [+] Username: user
 * [+] OS: Windows 10
 * [*] Sending data to C2...
 * [+] Status Code: 200
 * [+] Data received by server
 *
 * Compilation: cl /W4 ex02-post-data.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

// TODO: Implement system info collection
// void CollectSystemInfo(char* jsonBuffer, DWORD bufferSize)
// {
//     // Get computer name
//     // Get username
//     // Get OS version
//     // Format as JSON
// }

// TODO: Implement POST function
// BOOL PostSystemInfo(const char* jsonData, DWORD dataSize)
// {
//     // Create HTTP POST request
//     // Send JSON data
//     // Read and verify response
// }

int main(void) {
    wprintf(L"[*] Exercise 02: POST System Information\n\n");

    // TODO: Implement the exercise
    // char jsonData[1024];
    // CollectSystemInfo(jsonData, sizeof(jsonData));
    // PostSystemInfo(jsonData, strlen(jsonData));

    wprintf(L"\n[*] Exercise completed!\n");

    return 0;
}

/*
 * Hints:
 * - Use GetComputerNameW() for computer name
 * - Use GetUserNameW() for username
 * - Use GetVersionExW() for OS version (deprecated but works)
 * - Use snprintf() or sprintf_s() to build JSON string
 * - Content-Type should be "application/json"
 * - httpbin.org/post echoes back the data you sent
 */
