/*
 * Exercise 02: RW -> RX Transition (Safer Pattern)
 *
 * OBJECTIVE:
 * Implement the proper memory protection transition pattern used in maldev.
 * This is MORE STEALTHY than direct RWX allocation.
 *
 * TASKS:
 * 1. Allocate memory with PAGE_READWRITE
 * 2. Copy data (simulated shellcode) to the buffer
 * 3. Change protection to PAGE_EXECUTE_READ using VirtualProtect
 * 4. Verify protection changed successfully
 * 5. Compare to direct RWX allocation (highlight why it's worse)
 *
 * LEARNING GOALS:
 * - Master VirtualProtect
 * - Understand stealth techniques
 * - Learn why RW->RX is better than RWX
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

    // TODO: Allocate memory with PAGE_READWRITE
    LPVOID pGood = NULL;  // Replace with VirtualAlloc call

    // YOUR CODE HERE:
    // pGood = VirtualAlloc(..., PAGE_READWRITE);

    if (!pGood) {
        printf("[-] Allocation failed: %lu\n", GetLastError());
        return;
    }

    printf("[+] Allocated RW memory at 0x%p\n", pGood);

    // Step 2: Copy shellcode
    printf("\n[Step 2] Copy shellcode to buffer\n");

    // TODO: Copy simulatedShellcode to pGood
    // YOUR CODE HERE:
    // memcpy(...);

    printf("[+] Copied %zu bytes to buffer\n", size);

    // Step 3: Change to RX
    printf("\n[Step 3] Change protection to PAGE_EXECUTE_READ\n");

    // TODO: Use VirtualProtect to change protection to PAGE_EXECUTE_READ
    BOOL success = FALSE;  // Replace with VirtualProtect call

    // YOUR CODE HERE:
    // success = VirtualProtect(..., PAGE_EXECUTE_READ, &oldProtect);

    if (!success) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(pGood, 0, MEM_RELEASE);
        return;
    }

    printf("[+] Protection changed successfully\n");
    printf("[+] Old protection: 0x%08X\n", oldProtect);
    printf("[+] New protection: PAGE_EXECUTE_READ\n");

    // Step 4: Verify
    printf("\n[Step 4] Verify memory properties\n");

    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQuery(pGood, &mbi, sizeof(mbi))) {
        printf("[+] Current protection: 0x%08X\n", mbi.Protect);

        if (mbi.Protect == PAGE_EXECUTE_READ) {
            printf("[+] SUCCESS: Memory is now RX (executable, not writable)\n");
        }
    }

    printf("\n[+] Benefits of this pattern:\n");
    printf("    - Never has RWX protection simultaneously\n");
    printf("    - More stealthy, less suspicious\n");
    printf("    - Harder for EDR to detect\n");
    printf("    - Industry best practice\n");

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
    printf("  Exercise 02: RW -> RX Transition\n");
    printf("========================================\n\n");

    DemoBadPattern();
    DemoGoodPattern();
    ComparePatterns();

    printf("[*] Your Task:\n");
    printf("    Complete the TODOs in DemoGoodPattern()\n");
    printf("    1. Allocate RW memory\n");
    printf("    2. Copy shellcode\n");
    printf("    3. Change to RX with VirtualProtect\n\n");

    printf("========================================\n");
    printf("  Exercise Complete!\n");
    printf("========================================\n");

    return 0;
}

/*
 * SOLUTION CHECKLIST:
 * [ ] Memory allocated with PAGE_READWRITE
 * [ ] Shellcode copied to buffer
 * [ ] VirtualProtect changes protection to PAGE_EXECUTE_READ
 * [ ] Old protection saved correctly
 * [ ] Verification confirms RX protection
 *
 * BONUS CHALLENGES:
 * 1. Measure timing difference between RWX and RW->RX
 * 2. Implement RW -> RX -> RW -> RX cycle (self-modifying code pattern)
 * 3. Try PAGE_EXECUTE_WRITECOPY protection
 * 4. Add PAGE_GUARD flag and handle the exception
 * 5. Implement a function that transitions between all protection types
 */
