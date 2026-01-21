/*
 * Solution 01: Capture Command Output
 */

#include <windows.h>
#include <stdio.h>

#define MAX_OUTPUT (1024 * 64)  // 64 KB
#define PIPE_BUFFER_SIZE 4096

BOOL ExecuteCommand(char* cmd, char* output, DWORD outputSize) {
    SECURITY_ATTRIBUTES sa = {0};
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    DWORD totalBytesRead = 0;
    BOOL result = FALSE;
    char* outPtr = output;
    DWORD remaining = outputSize - 1;

    // Configure security attributes for pipe
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create anonymous pipe for output capture
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        snprintf(output, outputSize, "[-] CreatePipe failed: %d\n", GetLastError());
        return FALSE;
    }

    // Make sure read handle is not inherited
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        snprintf(output, outputSize, "[-] SetHandleInformation failed: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Configure startup info
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Execute command
    if (!CreateProcessA(
        NULL,
        cmd,
        NULL,
        NULL,
        TRUE,              // Inherit handles
        CREATE_NO_WINDOW,  // No console window
        NULL,
        NULL,
        &si,
        &pi
    )) {
        snprintf(output, outputSize, "[-] CreateProcessA failed: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Close write pipe in parent (child has its own copy)
    CloseHandle(hWritePipe);

    // Wait for process to complete (with timeout)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);  // 30 second timeout

    if (waitResult == WAIT_TIMEOUT) {
        snprintf(output, outputSize, "[-] Command timed out\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Read all output from pipe
    while (remaining > 0) {
        DWORD bytesRead = 0;
        DWORD toRead = (remaining < PIPE_BUFFER_SIZE) ? remaining : PIPE_BUFFER_SIZE;

        if (!ReadFile(hReadPipe, outPtr, toRead, &bytesRead, NULL)) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                // Normal end of pipe
                break;
            }
            snprintf(output, outputSize, "[-] ReadFile failed: %d\n", error);
            CloseHandle(hReadPipe);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }

        if (bytesRead == 0) {
            break;  // No more data
        }

        outPtr += bytesRead;
        remaining -= bytesRead;
        totalBytesRead += bytesRead;
    }

    // Null terminate
    *outPtr = '\0';

    result = TRUE;

    // Cleanup
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

int main() {
    char output[MAX_OUTPUT] = {0};

    printf("=== Solution 01: Capture Command Output ===\n\n");

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

    // Test 4: net user
    printf("\n[Test 4] Executing: net user\n");
    ZeroMemory(output, sizeof(output));
    if (ExecuteCommand("net user", output, sizeof(output))) {
        printf("[+] Output:\n%s\n", output);
    } else {
        printf("[-] Failed\n");
    }

    return 0;
}
