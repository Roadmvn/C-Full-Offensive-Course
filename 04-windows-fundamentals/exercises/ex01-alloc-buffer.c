/*
 * Exercise 01: Allocate Buffer and Verify
 *
 * OBJECTIVE:
 * Practice VirtualAlloc by allocating memory, filling it with a pattern,
 * and verifying the contents.
 *
 * TASKS:
 * 1. Allocate 8192 bytes with VirtualAlloc (PAGE_READWRITE)
 * 2. Fill the buffer with repeating pattern "MALDEV42"
 * 3. Use VirtualQuery to inspect memory properties
 * 4. Verify the pattern is correctly written
 * 5. Clean up memory with VirtualFree
 *
 * LEARNING GOALS:
 * - Understand VirtualAlloc parameters
 * - Learn to query memory information
 * - Practice proper memory cleanup
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("========================================\n");
    printf("  Exercise 01: Allocate Buffer\n");
    printf("========================================\n\n");

    // TODO 1: Define buffer size
    SIZE_T bufferSize = 8192;  // 8KB

    printf("[*] Task 1: Allocate %zu bytes with VirtualAlloc\n", bufferSize);

    // TODO 2: Allocate memory with VirtualAlloc
    // Hint: Use MEM_COMMIT | MEM_RESERVE and PAGE_READWRITE
    LPVOID pBuffer = NULL;  // Replace NULL with VirtualAlloc call

    // YOUR CODE HERE:
    // pBuffer = VirtualAlloc(...);

    if (!pBuffer) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Allocated buffer at: 0x%p\n\n", pBuffer);

    // TODO 3: Fill buffer with pattern "MALDEV42"
    printf("[*] Task 2: Fill buffer with pattern 'MALDEV42'\n");

    const char* pattern = "MALDEV42";
    SIZE_T patternLen = strlen(pattern);

    // YOUR CODE HERE:
    // Write a loop to fill the entire buffer with the repeating pattern
    // Hint: Use memcpy or manual copying in a loop

    printf("[+] Buffer filled with pattern\n\n");

    // TODO 4: Query memory information
    printf("[*] Task 3: Query memory information with VirtualQuery\n");

    MEMORY_BASIC_INFORMATION mbi = {0};

    // YOUR CODE HERE:
    // Use VirtualQuery to get information about the allocated memory
    // if (VirtualQuery(...)) { ... }

    printf("[+] Memory information:\n");
    printf("    Base Address:    0x%p\n", mbi.BaseAddress);
    printf("    Region Size:     %zu bytes\n", mbi.RegionSize);
    printf("    State:           0x%08X\n", mbi.State);
    printf("    Protection:      0x%08X\n", mbi.Protect);
    printf("    Type:            0x%08X\n\n", mbi.Type);

    // TODO 5: Verify pattern
    printf("[*] Task 4: Verify pattern in buffer\n");

    BOOL patternCorrect = TRUE;

    // YOUR CODE HERE:
    // Verify that the pattern repeats correctly throughout the buffer
    // Check at least the first few repetitions

    if (patternCorrect) {
        printf("[+] Pattern verification: SUCCESS\n");
        printf("[+] First 64 bytes: ");
        for (int i = 0; i < 64; i++) {
            printf("%c", ((char*)pBuffer)[i]);
        }
        printf("\n\n");
    } else {
        printf("[-] Pattern verification: FAILED\n\n");
    }

    // TODO 6: Clean up
    printf("[*] Task 5: Free allocated memory\n");

    // YOUR CODE HERE:
    // Use VirtualFree to release the memory
    // VirtualFree(...);

    printf("[+] Memory freed\n\n");

    printf("========================================\n");
    printf("  Exercise Complete!\n");
    printf("========================================\n");

    return 0;
}

/*
 * SOLUTION CHECKLIST:
 * [ ] VirtualAlloc with correct parameters
 * [ ] Buffer filled with repeating pattern
 * [ ] VirtualQuery successfully retrieves memory info
 * [ ] Pattern verification works
 * [ ] Memory properly freed with VirtualFree
 *
 * BONUS CHALLENGES:
 * 1. Calculate how many times the pattern repeats in the buffer
 * 2. Try allocating with different protection flags (PAGE_READONLY)
 * 3. Allocate multiple regions and query each one
 * 4. Implement a hexdump function to display buffer contents
 */
