/*
 * Exercise 03: Beacon Check-in Pattern
 *
 * Task:
 * Implement a complete beacon check-in pattern with task fetching and result reporting.
 *
 * Requirements:
 * 1. Implement FetchTask() - GET request to fetch commands
 * 2. Implement ParseTask() - Parse JSON task
 * 3. Implement ExecuteTask() - Execute command using cmd.exe
 * 4. Implement SendResults() - POST command output back
 * 5. Implement BeaconLoop() - Loop with sleep interval
 * 6. Run for 3 iterations
 *
 * Task Format (JSON):
 * {
 *   "task_id": "001",
 *   "command": "whoami",
 *   "type": "shell"
 * }
 *
 * Results Format (JSON):
 * {
 *   "task_id": "001",
 *   "status": "success",
 *   "output": "DESKTOP\\user"
 * }
 *
 * Bonus:
 * - Add jitter to sleep interval (random +/- 20%)
 * - Implement command queue (handle multiple tasks)
 * - Add error recovery and retry logic
 * - Base64 encode command output
 *
 * Expected Flow:
 * [*] Check-in #1
 * [+] Fetching task...
 * [+] Task received: whoami
 * [+] Executing command...
 * [+] Output: DESKTOP\user
 * [+] Sending results...
 * [+] Results sent successfully
 * [*] Sleeping 5000ms...
 *
 * Compilation: cl /W4 ex03-beacon-checkin.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

#define C2_SERVER L"httpbin.org"
#define C2_PORT INTERNET_DEFAULT_HTTP_PORT
#define TASK_ENDPOINT L"/get"
#define RESULT_ENDPOINT L"/post"
#define BEACON_INTERVAL 5000

// TODO: Implement task fetching
// BOOL FetchTask(char* taskBuffer, DWORD bufferSize)
// {
//     // GET request to TASK_ENDPOINT
//     // Read response
//     // Return task data
// }

// TODO: Implement task parsing
// BOOL ParseTask(const char* taskJson, char* command, DWORD commandSize)
// {
//     // Parse JSON to extract command
//     // For simplicity, you can use string search instead of full JSON parser
//     // Look for "command": "..." pattern
// }

// TODO: Implement command execution
// BOOL ExecuteTask(const char* command, char* output, DWORD outputSize)
// {
//     // Create process with cmd.exe /c <command>
//     // Capture stdout using pipes
//     // Read output into buffer
// }

// TODO: Implement results sending
// BOOL SendResults(const char* taskId, const char* output)
// {
//     // Format JSON with task_id and output
//     // POST to RESULT_ENDPOINT
//     // Verify response
// }

// TODO: Implement beacon loop
// void BeaconLoop(DWORD iterations)
// {
//     // Loop for specified iterations
//     // Fetch task
//     // Parse task
//     // Execute command
//     // Send results
//     // Sleep
// }

int main(void) {
    wprintf(L"[*] Exercise 03: Beacon Check-in Pattern\n\n");

    // TODO: Implement the beacon loop
    // BeaconLoop(3);

    wprintf(L"\n[*] Exercise completed!\n");

    return 0;
}

/*
 * Hints:
 * - For command execution, use CreateProcess() with pipes
 * - Set up STARTUPINFO with hStdOutput redirected to pipe
 * - Use ReadFile() to read command output from pipe
 * - For simple JSON parsing, use strstr() to find keys
 * - httpbin.org won't send real tasks, so simulate task data
 * - Focus on the pattern, not the actual C2 protocol
 * - In real C2, you'd encrypt all communication
 *
 * Command Execution Skeleton:
 * - CreatePipe() for stdout
 * - Set STARTUPINFO.hStdOutput to pipe
 * - CreateProcess("cmd.exe /c <command>")
 * - ReadFile() from pipe
 * - WaitForSingleObject() on process
 * - CloseHandle() everything
 */
