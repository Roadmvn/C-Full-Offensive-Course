/*
 * Exercise 03: Run Shellcode Locally
 *
 * OBJECTIVE:
 * Execute shellcode in the current process using proper memory operations.
 * This combines VirtualAlloc, VirtualProtect, and execution techniques.
 *
 * TASKS:
 * 1. Implement function to prepare shellcode in memory (RW->RX pattern)
 * 2. Execute shellcode via function pointer
 * 3. Execute shellcode via CreateThread
 * 4. Implement proper cleanup
 * 5. Handle errors gracefully
 *
 * LEARNING GOALS:
 * - Complete shellcode execution workflow
 * - Multiple execution methods
 * - Error handling
 * - Memory management
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

    // TODO 1: Allocate RW memory
    printf("  [1] Allocating RW memory (%zu bytes)...\n", size);

    LPVOID pMem = NULL;
    // YOUR CODE HERE:
    // pMem = VirtualAlloc(...);

    if (!pMem) {
        printf("  [-] VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    printf("  [+] Allocated at 0x%p\n", pMem);

    // TODO 2: Copy shellcode
    printf("  [2] Copying shellcode...\n");

    // YOUR CODE HERE:
    // memcpy(...);

    printf("  [+] Copied %zu bytes\n", size);

    // TODO 3: Change to RX
    printf("  [3] Changing protection to RX...\n");

    DWORD oldProtect;
    // YOUR CODE HERE:
    // if (!VirtualProtect(...)) { ... }

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

    // TODO 4: Cast to function pointer and execute
    printf("  [*] Casting to function pointer...\n");

    // YOUR CODE HERE:
    // void (*func)() = ...;
    // func();

    printf("  [+] Shellcode executed successfully\n\n");
}

// Execute via CreateThread
void ExecuteViaThread(LPVOID pShellcode) {
    printf("[*] Method 2: Execute via CreateThread\n");

    if (!pShellcode) {
        printf("[-] Invalid shellcode pointer\n");
        return;
    }

    // TODO 5: Create thread to execute shellcode
    printf("  [*] Creating thread...\n");

    HANDLE hThread = NULL;
    // YOUR CODE HERE:
    // hThread = CreateThread(...);

    if (!hThread) {
        printf("  [-] CreateThread failed: %lu\n", GetLastError());
        return;
    }

    printf("  [+] Thread created (Handle: 0x%p)\n", hThread);

    // TODO 6: Wait for thread completion
    printf("  [*] Waiting for thread to complete...\n");

    // YOUR CODE HERE:
    // WaitForSingleObject(...);

    printf("  [+] Thread completed\n");

    // TODO 7: Close thread handle
    // YOUR CODE HERE:
    // CloseHandle(...);

    printf("  [+] Thread handle closed\n\n");
}

// Cleanup function
void CleanupShellcode(LPVOID pShellcode) {
    printf("[*] Cleaning up shellcode memory...\n");

    if (!pShellcode) {
        printf("[-] Invalid pointer, nothing to free\n");
        return;
    }

    // TODO 8: Free memory
    // YOUR CODE HERE:
    // VirtualFree(...);

    printf("[+] Memory freed\n\n");
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

        // Wait for completion
        DWORD waitResult = WaitForSingleObject(hThread, 5000);  // 5 second timeout

        if (waitResult == WAIT_TIMEOUT) {
            printf("[-] Thread execution timeout\n");
            TerminateThread(hThread, 1);
            __leave;
        }

        success = TRUE;
        printf("[+] Shellcode executed successfully\n");

    } __finally {
        // Cleanup
        if (hThread) CloseHandle(hThread);
        if (pMem) VirtualFree(pMem, 0, MEM_RELEASE);
    }

    return success;
}

int main() {
    printf("========================================\n");
    printf("  Exercise 03: Run Shellcode Locally\n");
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

        // Part 3: Execute via thread
        // Note: We'll create a fresh copy for thread execution
        CleanupShellcode(pShellcode);

        pShellcode = PrepareShellcode(safeShellcode, sizeof(safeShellcode));
        ExecuteViaThread(pShellcode);

        // Part 4: Cleanup
        CleanupShellcode(pShellcode);
    }

    printf("========================================\n");
    printf("  Exercise Complete!\n");
    printf("========================================\n\n");

    printf("[*] What you learned:\n");
    printf("    1. Allocate executable memory (RW->RX pattern)\n");
    printf("    2. Copy shellcode to allocated memory\n");
    printf("    3. Execute via function pointer\n");
    printf("    4. Execute via CreateThread\n");
    printf("    5. Proper cleanup and error handling\n\n");

    return 0;
}

/*
 * SOLUTION CHECKLIST:
 * [ ] PrepareShellcode allocates RW memory
 * [ ] PrepareShellcode copies shellcode
 * [ ] PrepareShellcode changes to RX protection
 * [ ] ExecuteViaFunctionPointer works correctly
 * [ ] ExecuteViaThread creates and waits for thread
 * [ ] CleanupShellcode frees memory
 * [ ] No memory leaks
 * [ ] Proper error handling
 *
 * BONUS CHALLENGES:
 * 1. Add execution via EnumWindows callback
 * 2. Implement execution via Fiber
 * 3. Add timing measurements for each execution method
 * 4. Create a more complex shellcode (e.g., call GetTickCount)
 * 5. Implement position-independent shellcode that calls MessageBoxA
 * 6. Add anti-debugging checks before execution
 * 7. Implement XOR encoding/decoding of shellcode
 *
 * REAL-WORLD APPLICATIONS:
 * - In-memory payload execution (no disk writes)
 * - Reflective DLL loading
 * - Process injection preparation
 * - Staged payload execution
 * - Custom packer/crypter development
 */
