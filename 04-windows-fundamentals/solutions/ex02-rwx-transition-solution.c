/*
 * Solution: Exercise 02 - RW -> RX Transition
 */

#include <windows.h>
#include <stdio.h>

// Simulated shellcode (safe NOPs)
unsigned char simulatedShellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0xC3                      // RET
};

void DemoBadPattern() {
    printf("[*] BAD PATTERN: Direct RWX Allocation\n");

    SIZE_T size = sizeof(simulatedShellcode);

    // Direct RWX - VERY SUSPICIOUS
    LPVOID pBad = VirtualAlloc(
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // RWX immediately
    );

    if (pBad) {
        printf("[-] Allocated RWX memory at 0x%p\n", pBad);
        printf("[-] This is a RED FLAG for EDR/AV!\n");
        printf("[-] Reasons:\n");
        printf("    - Immediately executable AND writable\n");
        printf("    - Allows self-modifying code\n");
        printf("    - Common malware pattern\n");
        printf("    - Triggers security alerts\n");
        VirtualFree(pBad, 0, MEM_RELEASE);
    }

    printf("\n");
}

void DemoGoodPattern() {
    printf("[*] GOOD PATTERN: RW -> RX Transition\n");

    SIZE_T size = sizeof(simulatedShellcode);
    DWORD oldProtect;

    // Step 1: Allocate RW
    printf("\n[Step 1] Allocate PAGE_READWRITE memory\n");

    LPVOID pGood = VirtualAlloc(
        NULL,                       // Let system choose address
        size,                       // Size in bytes
        MEM_COMMIT | MEM_RESERVE,   // Commit and reserve
        PAGE_READWRITE              // Start with RW (NOT executable)
    );

    if (!pGood) {
        printf("[-] Allocation failed: %lu\n", GetLastError());
        return;
    }

    printf("[+] Allocated RW memory at 0x%p\n", pGood);

    // Step 2: Copy shellcode
    printf("\n[Step 2] Copy shellcode to buffer\n");

    memcpy(pGood, simulatedShellcode, size);

    printf("[+] Copied %zu bytes to buffer\n", size);

    // Step 3: Change to RX
    printf("\n[Step 3] Change protection to PAGE_EXECUTE_READ\n");

    BOOL success = VirtualProtect(
        pGood,                  // Address to protect
        size,                   // Size in bytes
        PAGE_EXECUTE_READ,      // New protection (RX, NOT writable)
        &oldProtect             // Receives old protection
    );

    if (!success) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(pGood, 0, MEM_RELEASE);
        return;
    }

    printf("[+] Protection changed successfully\n");
    printf("[+] Old protection: 0x%08X (PAGE_READWRITE)\n", oldProtect);
    printf("[+] New protection: 0x%08X (PAGE_EXECUTE_READ)\n", PAGE_EXECUTE_READ);

    // Step 4: Verify
    printf("\n[Step 4] Verify memory properties\n");

    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQuery(pGood, &mbi, sizeof(mbi))) {
        printf("[+] Current protection: 0x%08X\n", mbi.Protect);

        if (mbi.Protect == PAGE_EXECUTE_READ) {
            printf("[+] SUCCESS: Memory is now RX (executable, not writable)\n");
        } else {
            printf("[-] WARNING: Unexpected protection: 0x%08X\n", mbi.Protect);
        }
    }

    printf("\n[+] Benefits of this pattern:\n");
    printf("    - Never has RWX protection simultaneously\n");
    printf("    - More stealthy, less suspicious\n");
    printf("    - Harder for EDR to detect\n");
    printf("    - Industry best practice\n");
    printf("    - Mimics JIT compilers (legitimate behavior)\n");

    VirtualFree(pGood, 0, MEM_RELEASE);
    printf("\n");
}

void ComparePatterns() {
    printf("[*] Pattern Comparison\n");
    printf("========================================\n");

    printf("\nDirect RWX:\n");
    printf("  [Allocate] -> RWX memory\n");
    printf("  Suspicious: HIGH\n");
    printf("  Detected by: Most EDR/AV\n");
    printf("  Use case: Almost never (legacy malware)\n");

    printf("\nRW -> RX Transition:\n");
    printf("  [Allocate] -> RW memory\n");
    printf("  [Copy] -> Shellcode to buffer\n");
    printf("  [Protect] -> Change to RX\n");
    printf("  Suspicious: MEDIUM-LOW\n");
    printf("  Detected by: Advanced EDR (with behavior monitoring)\n");
    printf("  Use case: Modern malware, legitimate JIT compilers\n");

    printf("\nRW -> Execute (no X protection):\n");
    printf("  [Allocate] -> RW memory\n");
    printf("  [Copy] -> Shellcode to buffer\n");
    printf("  [Execute] -> Via callback (EnumWindows, etc.)\n");
    printf("  Suspicious: LOW\n");
    printf("  Detected by: Very advanced EDR (behavioral analysis)\n");
    printf("  Use case: Advanced malware\n");

    printf("\n========================================\n\n");
}

int main() {
    printf("========================================\n");
    printf("  Exercise 02 SOLUTION: RW -> RX Transition\n");
    printf("========================================\n\n");

    DemoBadPattern();
    DemoGoodPattern();
    ComparePatterns();

    printf("[*] Key Points:\n");
    printf("    1. VirtualAlloc with PAGE_READWRITE first\n");
    printf("    2. Copy shellcode while memory is writable\n");
    printf("    3. VirtualProtect to PAGE_EXECUTE_READ\n");
    printf("    4. Memory is never RWX simultaneously\n");
    printf("    5. This pattern is used by JIT compilers (legitimate)\n\n");

    printf("========================================\n");
    printf("  Exercise Complete!\n");
    printf("========================================\n");

    return 0;
}

/*
 * BONUS SOLUTIONS:
 */

// Bonus 1: Timing comparison
void BonusTimingComparison() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    SIZE_T size = 4096;

    // Time RWX
    QueryPerformanceCounter(&start);
    LPVOID p1 = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    QueryPerformanceCounter(&end);
    double rwxTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000000;

    // Time RW->RX
    QueryPerformanceCounter(&start);
    LPVOID p2 = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD old;
    VirtualProtect(p2, size, PAGE_EXECUTE_READ, &old);
    QueryPerformanceCounter(&end);
    double rwrxTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000000;

    printf("RWX:    %.2f µs\n", rwxTime);
    printf("RW->RX: %.2f µs\n", rwrxTime);
    printf("Overhead: %.2f µs\n", rwrxTime - rwxTime);

    VirtualFree(p1, 0, MEM_RELEASE);
    VirtualFree(p2, 0, MEM_RELEASE);
}

// Bonus 2: Self-modifying code pattern (RW -> RX -> RW -> RX)
void BonusSelfModifyingPattern() {
    SIZE_T size = 4096;
    DWORD old;

    // Initial allocation
    LPVOID p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Write code
    unsigned char code[] = {0x90, 0x90, 0xC3};
    memcpy(p, code, sizeof(code));

    // Make executable
    VirtualProtect(p, size, PAGE_EXECUTE_READ, &old);
    printf("Step 1: RW -> RX\n");

    // Execute...

    // Modify (need write access again)
    VirtualProtect(p, size, PAGE_READWRITE, &old);
    printf("Step 2: RX -> RW (for modification)\n");

    // Modify code
    unsigned char newCode[] = {0x48, 0x31, 0xC0, 0xC3};  // xor rax,rax; ret
    memcpy(p, newCode, sizeof(newCode));

    // Make executable again
    VirtualProtect(p, size, PAGE_EXECUTE_READ, &old);
    printf("Step 3: RW -> RX (after modification)\n");

    VirtualFree(p, 0, MEM_RELEASE);
}

// Bonus 4: PAGE_GUARD handling
void BonusPageGuardHandling() {
    SIZE_T size = 4096;
    DWORD old;

    LPVOID p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Add PAGE_GUARD
    VirtualProtect(p, size, PAGE_READWRITE | PAGE_GUARD, &old);

    __try {
        *(char*)p = 'A';  // First access triggers exception
        printf("After first access (guard removed)\n");
    } __except(GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ?
               EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        printf("Guard page violation caught\n");
    }

    VirtualFree(p, 0, MEM_RELEASE);
}
