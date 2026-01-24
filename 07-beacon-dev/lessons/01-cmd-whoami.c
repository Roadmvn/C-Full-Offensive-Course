/*
 * Lesson 01: Command Execution - whoami
 *
 * Demonstrates executing the whoami command and capturing its output.
 * This is a foundational pattern for beacon command execution.
 *
 * Key Concepts:
 * - CreateProcessA for command execution
 * - Anonymous pipes for output capture
 * - Handle redirection (stdout -> pipe)
 * - Reading from pipe to buffer
 */

#include <windows.h>
#include <stdio.h>

#define MAX_OUTPUT 4096

BOOL ExecuteWhoami(char* output, DWORD outputSize) {
    SECURITY_ATTRIBUTES sa = {0};
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    DWORD bytesRead = 0;
    BOOL result = FALSE;

    // Configure pipe security attributes (inheritable handles)
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create anonymous pipe for output capture
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        printf("[-] CreatePipe failed: %d\n", GetLastError());
        return FALSE;
    }

    // Ensure read handle is not inherited
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    // Configure startup info to redirect stdout
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Execute whoami command
    if (!CreateProcessA(
        NULL,
        "whoami",
        NULL,
        NULL,
        TRUE,              // Inherit handles
        CREATE_NO_WINDOW,  // No console window
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[-] CreateProcessA failed: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Close write pipe in parent process
    CloseHandle(hWritePipe);

    // Wait for process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Read output from pipe
    ZeroMemory(output, outputSize);
    if (ReadFile(hReadPipe, output, outputSize - 1, &bytesRead, NULL)) {
        output[bytesRead] = '\0';
        result = TRUE;
    } else {
        printf("[-] ReadFile failed: %d\n", GetLastError());
    }

    // Cleanup
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

int main() {
    char output[MAX_OUTPUT] = {0};

    printf("[*] Executing whoami command...\n\n");

    if (ExecuteWhoami(output, sizeof(output))) {
        printf("[+] Command output:\n");
        printf("%s", output);
    } else {
        printf("[-] Failed to execute command\n");
        return 1;
    }

    return 0;
}
