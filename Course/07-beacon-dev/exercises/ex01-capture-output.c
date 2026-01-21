/*
 * Exercise 01: Capture Command Output
 *
 * OBJECTIVE:
 * Implement a function that executes an arbitrary Windows command
 * and captures its output to a buffer.
 *
 * REQUIREMENTS:
 * 1. Create a function: ExecuteCommand(char* cmd, char* output, DWORD outputSize)
 * 2. Use CreateProcessA with pipe redirection
 * 3. Capture both stdout and stderr
 * 4. Wait for process completion
 * 5. Read all output into the buffer
 * 6. Handle errors gracefully
 *
 * TEST CASES:
 * - "ipconfig /all"
 * - "systeminfo"
 * - "net user"
 * - Invalid command (should handle gracefully)
 *
 * BONUS:
 * - Add timeout support (don't wait forever)
 * - Implement non-blocking read
 */

#include <windows.h>
#include <stdio.h>

#define MAX_OUTPUT (1024 * 64)  // 64 KB

/*
 * TODO: Implement this function
 *
 * Execute a Windows command and capture its output
 *
 * Parameters:
 *   cmd        - Command to execute (e.g., "ipconfig /all")
 *   output     - Buffer to store command output
 *   outputSize - Size of output buffer
 *
 * Returns:
 *   TRUE on success, FALSE on failure
 */
BOOL ExecuteCommand(char* cmd, char* output, DWORD outputSize) {
    // TODO: Implement command execution with output capture
    //
    // Steps:
    // 1. Create anonymous pipe with CreatePipe
    // 2. Set pipe handle inheritance
    // 3. Configure STARTUPINFO to redirect stdout/stderr
    // 4. Call CreateProcessA with CREATE_NO_WINDOW flag
    // 5. Close write pipe in parent
    // 6. Wait for process to complete
    // 7. Read from pipe into output buffer
    // 8. Clean up handles
    //
    // Hints:
    // - Use STARTF_USESTDHANDLES flag
    // - Set si.hStdOutput = hWritePipe
    // - Set si.hStdError = hWritePipe
    // - Use WaitForSingleObject to wait for process
    // - Read with ReadFile in a loop until no more data

    snprintf(output, outputSize, "TODO: Implement ExecuteCommand\n");
    return FALSE;
}

int main() {
    char output[MAX_OUTPUT] = {0};

    printf("=== Exercise 01: Capture Command Output ===\n\n");

    // Test 1: ipconfig
    printf("[Test 1] Executing: ipconfig\n");
    if (ExecuteCommand("ipconfig", output, sizeof(output))) {
        printf("[+] Output:\n%s\n", output);
    } else {
        printf("[-] Failed\n");
    }

    // Test 2: systeminfo (first 500 chars)
    printf("\n[Test 2] Executing: systeminfo\n");
    ZeroMemory(output, sizeof(output));
    if (ExecuteCommand("systeminfo", output, sizeof(output))) {
        output[500] = '\0';  // Truncate for display
        printf("[+] Output (truncated):\n%s...\n", output);
    } else {
        printf("[-] Failed\n");
    }

    // Test 3: Invalid command
    printf("\n[Test 3] Executing: invalid_command_xyz\n");
    ZeroMemory(output, sizeof(output));
    if (ExecuteCommand("invalid_command_xyz", output, sizeof(output))) {
        printf("[+] Output:\n%s\n", output);
    } else {
        printf("[-] Failed (expected)\n");
    }

    return 0;
}
