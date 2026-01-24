/*
 * Solution: Exercise 03 - Run Shellcode Locally
 */

#include <windows.h>
#include <stdio.h>

// Safe shellcode: NOP sled + RET
unsigned char safeShellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0xC3                      // RET
};

// Function to prepare shellcode in memory
LPVOID PrepareShellcode(unsigned char* shellcode, SIZE_T size) {
    printf("[*] Preparing shellcode in memory...\n");

    // Step 1: Allocate RW memory
    printf("  [1] Allocating RW memory (%zu bytes)...\n", size);

    LPVOID pMem = VirtualAlloc(
        NULL,                       // Let system choose address
        size,                       // Size in bytes
        MEM_COMMIT | MEM_RESERVE,   // Commit and reserve
        PAGE_READWRITE              // Start with RW
    );

    if (!pMem) {
        printf("  [-] VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    printf("  [+] Allocated at 0x%p\n", pMem);

    // Step 2: Copy shellcode
    printf("  [2] Copying shellcode...\n");

    memcpy(pMem, shellcode, size);

    printf("  [+] Copied %zu bytes\n", size);

    // Step 3: Change to RX
    printf("  [3] Changing protection to RX...\n");

    DWORD oldProtect;
    if (!VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("  [-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(pMem, 0, MEM_RELEASE);
        return NULL;
    }

    printf("  [+] Protection changed to PAGE_EXECUTE_READ\n");
    printf("[+] Shellcode ready for execution\n\n");

    return pMem;
}

// Execute via function pointer
void ExecuteViaFunctionPointer(LPVOID pShellcode) {
    printf("[*] Method 1: Execute via Function Pointer\n");

    if (!pShellcode) {
        printf("[-] Invalid shellcode pointer\n");
        return;
    }

    printf("  [*] Casting to function pointer...\n");

    // Cast to function pointer
    void (*shellcodeFunc)() = (void(*)())pShellcode;

    // Execute shellcode
    shellcodeFunc();

    printf("  [+] Shellcode executed successfully\n\n");
}

// Execute via CreateThread
void ExecuteViaThread(LPVOID pShellcode) {
    printf("[*] Method 2: Execute via CreateThread\n");

    if (!pShellcode) {
        printf("[-] Invalid shellcode pointer\n");
        return;
    }

    printf("  [*] Creating thread...\n");

    HANDLE hThread = CreateThread(
        NULL,                               // Security attributes
        0,                                  // Stack size (default)
        (LPTHREAD_START_ROUTINE)pShellcode, // Start address (our shellcode)
        NULL,                               // Parameter to thread
        0,                                  // Creation flags
        NULL                                // Thread ID (don't need it)
    );

    if (!hThread) {
        printf("  [-] CreateThread failed: %lu\n", GetLastError());
        return;
    }

    printf("  [+] Thread created (Handle: 0x%p)\n", hThread);

    printf("  [*] Waiting for thread to complete...\n");

    // Wait for thread to finish
    WaitForSingleObject(hThread, INFINITE);

    printf("  [+] Thread completed\n");

    // Close thread handle
    CloseHandle(hThread);

    printf("  [+] Thread handle closed\n\n");
}

// Cleanup function
void CleanupShellcode(LPVOID pShellcode) {
    printf("[*] Cleaning up shellcode memory...\n");

    if (!pShellcode) {
        printf("[-] Invalid pointer, nothing to free\n");
        return;
    }

    if (VirtualFree(pShellcode, 0, MEM_RELEASE)) {
        printf("[+] Memory freed\n\n");
    } else {
        printf("[-] VirtualFree failed: %lu\n\n", GetLastError());
    }
}

// Bonus: Execute with error handling
BOOL ExecuteShellcodeSafe(unsigned char* shellcode, SIZE_T size) {
    printf("[*] Safe Shellcode Execution with Error Handling\n");

    LPVOID pMem = NULL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;

    __try {
        // Prepare shellcode
        pMem = PrepareShellcode(shellcode, size);
        if (!pMem) {
            printf("[-] Failed to prepare shellcode\n");
            __leave;
        }

        // Execute in thread
        hThread = CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)pMem,
            NULL,
            0,
            NULL
        );

        if (!hThread) {
            printf("[-] Failed to create thread: %lu\n", GetLastError());
            __leave;
        }

        // Wait for completion with timeout
        DWORD waitResult = WaitForSingleObject(hThread, 5000);  // 5 second timeout

        if (waitResult == WAIT_TIMEOUT) {
            printf("[-] Thread execution timeout\n");
            TerminateThread(hThread, 1);
            __leave;
        } else if (waitResult == WAIT_OBJECT_0) {
            printf("[+] Thread completed successfully\n");
        }

        success = TRUE;
        printf("[+] Shellcode executed successfully\n");

    } __finally {
        // Cleanup
        if (hThread) CloseHandle(hThread);
        if (pMem) VirtualFree(pMem, 0, MEM_RELEASE);

        printf("[+] Cleanup complete\n");
    }

    return success;
}

int main() {
    printf("========================================\n");
    printf("  Exercise 03 SOLUTION: Run Shellcode\n");
    printf("========================================\n\n");

    printf("[*] Shellcode Info:\n");
    printf("    Size: %zu bytes\n", sizeof(safeShellcode));
    printf("    Type: NOP sled + RET\n");
    printf("    Safe: Yes (just returns)\n\n");

    // Part 1: Prepare shellcode
    LPVOID pShellcode = PrepareShellcode(safeShellcode, sizeof(safeShellcode));

    if (pShellcode) {
        // Part 2: Execute via function pointer
        ExecuteViaFunctionPointer(pShellcode);

        // Part 3: Cleanup before thread execution
        CleanupShellcode(pShellcode);

        // Create fresh copy for thread execution
        pShellcode = PrepareShellcode(safeShellcode, sizeof(safeShellcode));

        // Execute via thread
        ExecuteViaThread(pShellcode);

        // Part 4: Final cleanup
        CleanupShellcode(pShellcode);
    }

    printf("========================================\n");
    printf("  Exercise Complete!\n");
    printf("========================================\n\n");

    printf("[*] What you learned:\n");
    printf("    1. Allocate executable memory (RW->RX pattern)\n");
    printf("    2. Copy shellcode to allocated memory\n");
    printf("    3. Execute via function pointer (simple)\n");
    printf("    4. Execute via CreateThread (more control)\n");
    printf("    5. Proper cleanup and error handling\n");
    printf("    6. SEH for exception handling (__try/__finally)\n\n");

    return 0;
}

/*
 * BONUS CHALLENGE SOLUTIONS:
 */

// Bonus 1: Execute via EnumWindows callback
void BonusEnumWindowsExecution() {
    unsigned char callbackShellcode[] = {
        0x48, 0x31, 0xC0,  // xor rax, rax
        0x48, 0xFF, 0xC0,  // inc rax (return TRUE)
        0xC3               // ret
    };

    LPVOID pMem = VirtualAlloc(NULL, sizeof(callbackShellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pMem, callbackShellcode, sizeof(callbackShellcode));

    DWORD old;
    VirtualProtect(pMem, sizeof(callbackShellcode), PAGE_EXECUTE_READ, &old);

    // Execute via callback
    EnumWindows((WNDENUMPROC)pMem, 0);

    VirtualFree(pMem, 0, MEM_RELEASE);
}

// Bonus 2: Execute via Fiber
void BonusFiberExecution() {
    unsigned char fiberShellcode[] = {0x90, 0x90, 0xC3};

    LPVOID pMem = VirtualAlloc(NULL, sizeof(fiberShellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pMem, fiberShellcode, sizeof(fiberShellcode));

    DWORD old;
    VirtualProtect(pMem, sizeof(fiberShellcode), PAGE_EXECUTE_READ, &old);

    // Convert thread to fiber
    LPVOID mainFiber = ConvertThreadToFiber(NULL);

    // Create fiber for shellcode
    LPVOID shellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)pMem, NULL);

    // Switch to shellcode fiber
    SwitchToFiber(shellcodeFiber);

    // Cleanup
    DeleteFiber(shellcodeFiber);
    VirtualFree(pMem, 0, MEM_RELEASE);
}

// Bonus 3: Timing measurements
void BonusTimingMeasurements() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    LPVOID pMem = VirtualAlloc(NULL, sizeof(safeShellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pMem, safeShellcode, sizeof(safeShellcode));
    DWORD old;
    VirtualProtect(pMem, sizeof(safeShellcode), PAGE_EXECUTE_READ, &old);

    // Time function pointer
    QueryPerformanceCounter(&start);
    void (*func)() = (void(*)())pMem;
    func();
    QueryPerformanceCounter(&end);
    double fpTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000000;

    // Time CreateThread
    QueryPerformanceCounter(&start);
    HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    QueryPerformanceCounter(&end);
    double threadTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000000;

    printf("Function Pointer: %.2f µs\n", fpTime);
    printf("CreateThread:     %.2f µs\n", threadTime);

    VirtualFree(pMem, 0, MEM_RELEASE);
}

// Bonus 7: XOR encoding/decoding
void BonusXorEncodeDecode() {
    unsigned char encoded[] = {0xF5, 0xF5, 0xF5, 0xA6};  // XOR 0x65
    unsigned char key = 0x65;
    SIZE_T size = sizeof(encoded);

    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decode in memory
    for (SIZE_T i = 0; i < size; i++) {
        ((unsigned char*)pMem)[i] = encoded[i] ^ key;
    }

    printf("Decoded: ");
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", ((unsigned char*)pMem)[i]);
    }
    printf("\n");  // Should be: 90 90 90 C3

    DWORD old;
    VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &old);

    // Execute decoded shellcode
    void (*func)() = (void(*)())pMem;
    func();

    VirtualFree(pMem, 0, MEM_RELEASE);
}
