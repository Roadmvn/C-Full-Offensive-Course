/*
 * Exercise 02: Test Beacon Components
 *
 * TASK:
 * Test each component of the beacon individually:
 * 1. Sleep/Jitter calculation
 * 2. Command execution
 * 3. Beacon ID generation
 * 4. HTTP communication (optional, requires server)
 *
 * This helps verify each part works before integration.
 */

#include <windows.h>
#include <stdio.h>

// TODO: Implement sleep with jitter
DWORD CalculateJitterSleep(DWORD baseTime, DWORD jitterPercent) {
    // YOUR CODE HERE
    // Hint:
    // 1. Calculate jitter range from percentage
    // 2. Generate random value in range
    // 3. Add/subtract from base time
    return baseTime; // REPLACE THIS
}

// TODO: Generate unique beacon ID
VOID GenerateBeaconId(CHAR* buffer, SIZE_T bufferSize) {
    // YOUR CODE HERE
    // Hint: Combine computer name, PID, timestamp
    // Format: COMPUTERNAME_PID_TIMESTAMP
}

// TODO: Execute command and capture output
BOOL ExecuteCommand(const CHAR* command, CHAR* output, DWORD outputSize) {
    // YOUR CODE HERE
    // Hint: Use CreateProcess with redirected stdout
    // Steps:
    // 1. Create pipe for stdout
    // 2. CreateProcess with pipe handle
    // 3. Read from pipe
    // 4. Close handles
    return FALSE; // REPLACE THIS
}

/*
 * Test function for jitter calculation
 */
VOID TestJitter(void) {
    printf("[*] Test 1: Jitter Calculation\n");

    DWORD baseTime = 5000; // 5 seconds
    DWORD jitter = 30;     // 30%

    printf("    Base time: %u ms\n", baseTime);
    printf("    Jitter:    %u%%\n", jitter);
    printf("\n    10 random sleep times:\n");

    for (int i = 0; i < 10; i++) {
        DWORD sleepTime = CalculateJitterSleep(baseTime, jitter);
        printf("    %d: %u ms (", i + 1, sleepTime);

        int diff = (int)sleepTime - (int)baseTime;
        if (diff >= 0) printf("+");
        printf("%d ms, ", diff);

        float percent = ((float)diff / baseTime) * 100.0f;
        printf("%.1f%%)\n", percent);
    }

    printf("\n    Expected range: %u - %u ms\n",
           (DWORD)(baseTime * 0.7), (DWORD)(baseTime * 1.3));
    printf("\n");
}

/*
 * Test function for beacon ID generation
 */
VOID TestBeaconId(void) {
    printf("[*] Test 2: Beacon ID Generation\n");

    CHAR beaconId[256];
    GenerateBeaconId(beaconId, sizeof(beaconId));

    printf("    Generated ID: %s\n", beaconId);
    printf("    Length:       %zu bytes\n", strlen(beaconId));

    // Test uniqueness
    printf("\n    Testing uniqueness (3 IDs with 100ms delay):\n");
    for (int i = 0; i < 3; i++) {
        CHAR id[256];
        GenerateBeaconId(id, sizeof(id));
        printf("    %d: %s\n", i + 1, id);
        Sleep(100);
    }
    printf("\n");
}

/*
 * Test function for command execution
 */
VOID TestCommandExecution(void) {
    printf("[*] Test 3: Command Execution\n");

    const CHAR* commands[] = {
        "whoami",
        "hostname",
        "ipconfig /all",
        "dir C:\\Windows\\System32\\notepad.exe"
    };

    for (int i = 0; i < 4; i++) {
        printf("    Command: %s\n", commands[i]);

        CHAR output[4096];
        memset(output, 0, sizeof(output));

        if (ExecuteCommand(commands[i], output, sizeof(output))) {
            printf("    Output (%zu bytes):\n", strlen(output));

            // Print first 200 chars
            if (strlen(output) > 200) {
                output[200] = '\0';
                printf("%.200s...\n", output);
            } else {
                printf("%s", output);
            }
        } else {
            printf("    [!] Failed to execute\n");
        }
        printf("\n");
    }
}

/*
 * Test function for HTTP communication (requires server)
 */
VOID TestHttpCommunication(void) {
    printf("[*] Test 4: HTTP Communication\n");
    printf("    This test requires a running HTTP server\n");
    printf("    Start server with: python -m http.server 8080\n\n");

    printf("    Press Enter to test HTTP GET, or 'q' to skip: ");
    char c = getchar();
    if (c == 'q' || c == 'Q') {
        printf("    Skipped\n\n");
        return;
    }

    // TODO: Implement HTTP GET test
    printf("    [!] HTTP GET test not implemented\n");
    printf("    Implement using WinHTTP functions\n\n");
}

int main(void) {
    printf("[*] Exercise 02: Beacon Component Testing\n\n");

    // Seed random number generator
    srand(GetTickCount());

    // Run tests
    TestJitter();
    TestBeaconId();
    TestCommandExecution();
    TestHttpCommunication();

    printf("[*] Testing complete!\n\n");

    printf("[*] Next steps:\n");
    printf("    1. Review any failed tests\n");
    printf("    2. Fix implementation issues\n");
    printf("    3. Integrate components into final beacon\n");
    printf("    4. Test complete beacon with C2 server\n\n");

    return 0;
}

/*
 * HINTS FOR IMPLEMENTATION:
 *
 * 1. CalculateJitterSleep:
 *    - Range = baseTime * (jitterPercent / 100)
 *    - Random offset = rand() % (2 * range) - range
 *    - Result = baseTime + offset
 *
 * 2. GenerateBeaconId:
 *    - GetComputerNameA() for hostname
 *    - GetCurrentProcessId() for PID
 *    - GetTickCount() for timestamp
 *    - snprintf() to combine
 *
 * 3. ExecuteCommand:
 *    - CreatePipe() for stdout redirection
 *    - STARTUPINFO with hStdOutput = pipe
 *    - CreateProcessA() with "cmd.exe /c command"
 *    - ReadFile() from pipe until done
 *    - WaitForSingleObject() for completion
 */
