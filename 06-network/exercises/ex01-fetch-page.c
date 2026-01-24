/*
 * Exercise 01: Fetch Web Page
 *
 * Task:
 * Implement a function that fetches a web page and saves it to a file.
 *
 * Requirements:
 * 1. Create function: FetchAndSave(server, port, path, outputFile)
 * 2. Make GET request to http://httpbin.org/html
 * 3. Save response body to "output.html"
 * 4. Print status code and response size
 * 5. Handle errors properly
 *
 * Bonus:
 * - Add retry logic (3 attempts)
 * - Query and print Content-Type header
 * - Print first 200 bytes of response
 *
 * Expected Output:
 * [+] Connecting to httpbin.org...
 * [+] Fetching /html...
 * [+] Status Code: 200
 * [+] Response Size: XXXX bytes
 * [+] Saved to: output.html
 *
 * Compilation: cl /W4 ex01-fetch-page.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

// TODO: Implement FetchAndSave function
// BOOL FetchAndSave(const wchar_t* server, DWORD port, const wchar_t* path, const wchar_t* outputFile)
// {
//     // Your code here
// }

int main(void) {
    wprintf(L"[*] Exercise 01: Fetch Web Page\n\n");

    // TODO: Call your FetchAndSave function
    // FetchAndSave(L"httpbin.org", INTERNET_DEFAULT_HTTP_PORT, L"/html", L"output.html");

    wprintf(L"\n[*] Exercise completed!\n");

    return 0;
}

/*
 * Hints:
 * - Use WinHttpOpen, WinHttpConnect, WinHttpOpenRequest
 * - Read data in a loop with WinHttpQueryDataAvailable/WinHttpReadData
 * - Use CreateFile() and WriteFile() to save data
 * - Don't forget to close all handles
 * - Check return values and handle errors
 */
