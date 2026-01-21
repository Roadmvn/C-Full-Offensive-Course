/*
 * Solution: Exercise 01 - Allocate Buffer and Verify
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("========================================\n");
    printf("  Exercise 01 SOLUTION: Allocate Buffer\n");
    printf("========================================\n\n");

    // Task 1: Define buffer size
    SIZE_T bufferSize = 8192;  // 8KB

    printf("[*] Task 1: Allocate %zu bytes with VirtualAlloc\n", bufferSize);

    // Task 2: Allocate memory with VirtualAlloc
    LPVOID pBuffer = VirtualAlloc(
        NULL,                       // Let system choose address
        bufferSize,                 // Size in bytes
        MEM_COMMIT | MEM_RESERVE,   // Commit and reserve
        PAGE_READWRITE              // Read-write protection
    );

    if (!pBuffer) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Allocated buffer at: 0x%p\n\n", pBuffer);

    // Task 3: Fill buffer with pattern "MALDEV42"
    printf("[*] Task 2: Fill buffer with pattern 'MALDEV42'\n");

    const char* pattern = "MALDEV42";
    SIZE_T patternLen = strlen(pattern);

    // Fill buffer with repeating pattern
    for (SIZE_T offset = 0; offset < bufferSize; offset += patternLen) {
        SIZE_T copySize = patternLen;

        // Handle last partial copy
        if (offset + copySize > bufferSize) {
            copySize = bufferSize - offset;
        }

        memcpy((char*)pBuffer + offset, pattern, copySize);
    }

    SIZE_T numRepetitions = bufferSize / patternLen;
    printf("[+] Buffer filled with pattern (repeated %zu times)\n\n", numRepetitions);

    // Task 4: Query memory information
    printf("[*] Task 3: Query memory information with VirtualQuery\n");

    MEMORY_BASIC_INFORMATION mbi = {0};

    if (VirtualQuery(pBuffer, &mbi, sizeof(mbi))) {
        printf("[+] Memory information:\n");
        printf("    Base Address:    0x%p\n", mbi.BaseAddress);
        printf("    Allocation Base: 0x%p\n", mbi.AllocationBase);
        printf("    Region Size:     %zu bytes\n", mbi.RegionSize);

        printf("    State:           ");
        switch (mbi.State) {
            case MEM_COMMIT:  printf("MEM_COMMIT (0x%08X)\n", mbi.State); break;
            case MEM_RESERVE: printf("MEM_RESERVE (0x%08X)\n", mbi.State); break;
            case MEM_FREE:    printf("MEM_FREE (0x%08X)\n", mbi.State); break;
            default:          printf("Unknown (0x%08X)\n", mbi.State);
        }

        printf("    Protection:      ");
        switch (mbi.Protect) {
            case PAGE_READWRITE: printf("PAGE_READWRITE (0x%08X)\n", mbi.Protect); break;
            case PAGE_READONLY:  printf("PAGE_READONLY (0x%08X)\n", mbi.Protect); break;
            default:             printf("0x%08X\n", mbi.Protect);
        }

        printf("    Type:            ");
        switch (mbi.Type) {
            case MEM_PRIVATE: printf("MEM_PRIVATE (0x%08X)\n", mbi.Type); break;
            case MEM_MAPPED:  printf("MEM_MAPPED (0x%08X)\n", mbi.Type); break;
            case MEM_IMAGE:   printf("MEM_IMAGE (0x%08X)\n", mbi.Type); break;
            default:          printf("0x%08X\n", mbi.Type);
        }
    } else {
        printf("[-] VirtualQuery failed: %lu\n", GetLastError());
    }

    printf("\n");

    // Task 5: Verify pattern
    printf("[*] Task 4: Verify pattern in buffer\n");

    BOOL patternCorrect = TRUE;

    // Verify first 5 repetitions
    for (int i = 0; i < 5; i++) {
        if (memcmp((char*)pBuffer + (i * patternLen), pattern, patternLen) != 0) {
            patternCorrect = FALSE;
            printf("[-] Pattern mismatch at repetition %d\n", i);
            break;
        }
    }

    // Also verify last repetition
    SIZE_T lastOffset = bufferSize - patternLen;
    if (memcmp((char*)pBuffer + lastOffset, pattern, patternLen) != 0) {
        patternCorrect = FALSE;
        printf("[-] Pattern mismatch at last repetition\n");
    }

    if (patternCorrect) {
        printf("[+] Pattern verification: SUCCESS\n");
        printf("[+] First 64 bytes: ");
        for (int i = 0; i < 64; i++) {
            printf("%c", ((char*)pBuffer)[i]);
        }
        printf("\n");

        printf("[+] Last 64 bytes:  ");
        for (SIZE_T i = bufferSize - 64; i < bufferSize; i++) {
            printf("%c", ((char*)pBuffer)[i]);
        }
        printf("\n\n");
    } else {
        printf("[-] Pattern verification: FAILED\n\n");
    }

    // Task 6: Clean up
    printf("[*] Task 5: Free allocated memory\n");

    if (VirtualFree(pBuffer, 0, MEM_RELEASE)) {
        printf("[+] Memory freed successfully\n\n");
    } else {
        printf("[-] VirtualFree failed: %lu\n\n", GetLastError());
    }

    printf("========================================\n");
    printf("  Exercise Complete!\n");
    printf("========================================\n\n");

    printf("[*] What you learned:\n");
    printf("    1. VirtualAlloc allocates memory with specific protections\n");
    printf("    2. MEM_COMMIT | MEM_RESERVE is the standard allocation type\n");
    printf("    3. VirtualQuery reveals detailed memory information\n");
    printf("    4. Proper verification ensures data integrity\n");
    printf("    5. VirtualFree with MEM_RELEASE frees all memory\n");

    return 0;
}

/*
 * BONUS SOLUTIONS:
 */

// Bonus 1: Calculate repetitions
void BonusCalculateRepetitions() {
    SIZE_T bufferSize = 8192;
    SIZE_T patternLen = strlen("MALDEV42");
    SIZE_T fullRepetitions = bufferSize / patternLen;
    SIZE_T remainingBytes = bufferSize % patternLen;

    printf("Full repetitions: %zu\n", fullRepetitions);
    printf("Remaining bytes: %zu\n", remainingBytes);
}

// Bonus 2: Different protection flags
void BonusDifferentProtections() {
    SIZE_T size = 4096;

    // Try different protections
    DWORD protections[] = {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE
    };

    const char* names[] = {
        "PAGE_READONLY",
        "PAGE_READWRITE",
        "PAGE_EXECUTE_READ",
        "PAGE_EXECUTE_READWRITE"
    };

    for (int i = 0; i < 4; i++) {
        LPVOID p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protections[i]);
        if (p) {
            printf("Allocated with %s\n", names[i]);
            VirtualFree(p, 0, MEM_RELEASE);
        }
    }
}

// Bonus 4: Hexdump function
void Hexdump(LPVOID pMem, SIZE_T size) {
    printf("Hexdump:\n");

    for (SIZE_T i = 0; i < size; i += 16) {
        printf("%p:  ", (void*)((BYTE*)pMem + i));

        // Hex values
        for (SIZE_T j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02X ", ((BYTE*)pMem)[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");

        // ASCII
        for (SIZE_T j = 0; j < 16; j++) {
            if (i + j < size) {
                BYTE c = ((BYTE*)pMem)[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }

        printf("|\n");
    }
}
