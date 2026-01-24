/*
 * Lesson 02: VirtualProtect - Changing Memory Protections
 *
 * VirtualProtect modifies memory protection after allocation.
 * Essential for stealth shellcode execution patterns.
 *
 * CRITICAL for maldev:
 * - Implement RW->RX pattern (more stealthy than RWX)
 * - Avoid suspicious PAGE_EXECUTE_READWRITE allocations
 * - Bypass some memory scanners
 *
 * Syntax:
 * BOOL VirtualProtect(
 *   LPVOID lpAddress,      // Address to change
 *   SIZE_T dwSize,         // Size in bytes
 *   DWORD  flNewProtect,   // New protection
 *   PDWORD lpflOldProtect  // Receives old protection
 * );
 */

#include <windows.h>
#include <stdio.h>

void DemoBasicProtectionChange() {
    printf("[*] Demo 1: Basic Protection Change\n");

    SIZE_T size = 4096;

    // Allocate with RW
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) {
        printf("[-] Allocation failed\n");
        return;
    }

    printf("[+] Allocated RW memory at 0x%p\n", pMem);

    // Write data while RW
    memset(pMem, 0x41, size);
    printf("[+] Written data (protection: RW)\n");

    // Change to read-only
    DWORD oldProtect;
    if (VirtualProtect(pMem, size, PAGE_READONLY, &oldProtect)) {
        printf("[+] Changed protection to READ-ONLY\n");
        printf("[+] Old protection: 0x%08X\n", oldProtect);

        // Try to write (will crash if uncommented)
        // memset(pMem, 0x42, size); // Would cause access violation
        printf("[!] Writing now would cause ACCESS_VIOLATION\n");
    }

    VirtualFree(pMem, 0, MEM_RELEASE);
    printf("\n");
}

void DemoStealthPattern() {
    printf("[*] Demo 2: Stealth Pattern - RW -> RX\n");
    printf("[!] This is BETTER than direct RWX allocation\n\n");

    SIZE_T size = 4096;
    DWORD oldProtect;

    // BAD: Direct RWX allocation (very suspicious)
    printf("[-] BAD PATTERN:\n");
    LPVOID pBad = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pBad) {
        printf("    VirtualAlloc(..., PAGE_EXECUTE_READWRITE)\n");
        printf("    -> Immediately RWX = RED FLAG for EDR!\n");
        VirtualFree(pBad, 0, MEM_RELEASE);
    }

    printf("\n");

    // GOOD: RW -> copy -> RX pattern (more stealthy)
    printf("[+] GOOD PATTERN:\n");

    printf("    Step 1: Allocate RW\n");
    LPVOID pGood = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pGood) {
        printf("[-] Allocation failed\n");
        return;
    }

    printf("    Step 2: Copy data while RW\n");
    memset(pGood, 0x90, size); // Simulate copying shellcode

    printf("    Step 3: Change to RX (no write)\n");
    if (VirtualProtect(pGood, size, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[+] Protection changed: RW -> RX\n");
        printf("[+] Memory is now executable but not writable\n");
        printf("[!] This is MUCH less suspicious than RWX!\n");
    }

    VirtualFree(pGood, 0, MEM_RELEASE);
    printf("\n");
}

void DemoProtectionFlags() {
    printf("[*] Demo 3: Common Protection Transitions\n");

    SIZE_T size = 4096;
    DWORD oldProtect;

    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) return;

    // Common transitions in maldev
    struct {
        DWORD fromProt;
        DWORD toProt;
        const char* scenario;
    } transitions[] = {
        {PAGE_READWRITE, PAGE_EXECUTE_READ, "Shellcode execution (RW->RX)"},
        {PAGE_READWRITE, PAGE_READONLY, "Protect data from modification"},
        {PAGE_READONLY, PAGE_READWRITE, "Modify protected data"},
        {PAGE_EXECUTE_READ, PAGE_READWRITE, "Self-modifying code"},
    };

    printf("Common protection transitions:\n\n");

    for (int i = 0; i < 4; i++) {
        // Set initial protection
        VirtualProtect(pMem, size, transitions[i].fromProt, &oldProtect);

        // Perform transition
        if (VirtualProtect(pMem, size, transitions[i].toProt, &oldProtect)) {
            printf("[+] 0x%08X -> 0x%08X : %s\n",
                   transitions[i].fromProt,
                   transitions[i].toProt,
                   transitions[i].scenario);
        }
    }

    VirtualFree(pMem, 0, MEM_RELEASE);
    printf("\n");
}

void DemoPageGuard() {
    printf("[*] Demo 4: PAGE_GUARD Flag (Advanced)\n");

    SIZE_T size = 4096;
    DWORD oldProtect;

    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) return;

    // Add PAGE_GUARD flag
    if (VirtualProtect(pMem, size, PAGE_READWRITE | PAGE_GUARD, &oldProtect)) {
        printf("[+] Added PAGE_GUARD flag\n");
        printf("[!] First access will trigger STATUS_GUARD_PAGE_VIOLATION\n");
        printf("[!] Used for:\n");
        printf("    - Anti-debugging (detect memory inspection)\n");
        printf("    - Software breakpoints\n");
        printf("    - Lazy initialization\n");

        // First access triggers exception, removes guard
        __try {
            *(char*)pMem = 0x41;
            printf("[+] Accessed guarded page (exception handled by system)\n");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[!] Guard page exception caught\n");
        }
    }

    VirtualFree(pMem, 0, MEM_RELEASE);
    printf("\n");
}

void DemoMultiRegionProtect() {
    printf("[*] Demo 5: Protecting Multiple Regions\n");

    SIZE_T regionSize = 4096;
    DWORD oldProtect;

    // Allocate 3 pages
    LPVOID pBase = VirtualAlloc(NULL, regionSize * 3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBase) return;

    printf("[+] Allocated 3 pages starting at 0x%p\n", pBase);

    // Set different protections for each page
    LPVOID pPage1 = pBase;
    LPVOID pPage2 = (LPVOID)((BYTE*)pBase + regionSize);
    LPVOID pPage3 = (LPVOID)((BYTE*)pBase + regionSize * 2);

    VirtualProtect(pPage1, regionSize, PAGE_READONLY, &oldProtect);
    printf("[+] Page 1 (0x%p): READ-ONLY\n", pPage1);

    VirtualProtect(pPage2, regionSize, PAGE_READWRITE, &oldProtect);
    printf("[+] Page 2 (0x%p): READ-WRITE\n", pPage2);

    VirtualProtect(pPage3, regionSize, PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] Page 3 (0x%p): EXECUTE-READ\n", pPage3);

    printf("\n[!] Useful pattern:\n");
    printf("    - Code section: PAGE_EXECUTE_READ\n");
    printf("    - Data section: PAGE_READWRITE\n");
    printf("    - Const section: PAGE_READONLY\n");

    VirtualFree(pBase, 0, MEM_RELEASE);
    printf("\n");
}

void DemoRealWorldShellcodePattern() {
    printf("[*] Demo 6: Real-World Shellcode Execution Pattern\n");

    // Simulated shellcode (just NOPs + RET for safety)
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0xC3                      // RET
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    printf("[+] Shellcode size: %zu bytes\n", shellcodeSize);

    // Step 1: Allocate RW memory
    printf("\n[1] Allocating RW memory...\n");
    LPVOID pShellcode = VirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // Start with RW
    );

    if (!pShellcode) {
        printf("[-] Allocation failed\n");
        return;
    }
    printf("[+] Allocated at 0x%p\n", pShellcode);

    // Step 2: Copy shellcode
    printf("\n[2] Copying shellcode to buffer...\n");
    memcpy(pShellcode, shellcode, shellcodeSize);
    printf("[+] Shellcode copied\n");

    // Step 3: Change to RX
    printf("\n[3] Changing protection to RX...\n");
    DWORD oldProtect;
    if (!VirtualProtect(pShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(pShellcode, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Protection changed: RW -> RX\n");
    printf("[+] Old protection: 0x%08X\n", oldProtect);

    // Step 4: Execute (covered in lesson 04)
    printf("\n[4] Ready for execution (see lesson 04)\n");
    printf("[!] Memory at 0x%p is now executable\n", pShellcode);

    // Cleanup
    VirtualFree(pShellcode, 0, MEM_RELEASE);
    printf("\n[+] Memory freed\n\n");
}

int main() {
    printf("=================================================\n");
    printf("  VirtualProtect - Memory Protection Lesson\n");
    printf("=================================================\n\n");

    DemoBasicProtectionChange();
    DemoStealthPattern();
    DemoProtectionFlags();
    DemoPageGuard();
    DemoMultiRegionProtect();
    DemoRealWorldShellcodePattern();

    printf("[*] Key Takeaways:\n");
    printf("    1. VirtualProtect changes memory protections\n");
    printf("    2. RW->RX pattern is stealthier than direct RWX\n");
    printf("    3. PAGE_GUARD can detect memory access (anti-debug)\n");
    printf("    4. Different regions can have different protections\n");
    printf("    5. Always save old protection (required parameter)\n");
    printf("    6. Use PAGE_EXECUTE_READ for final shellcode (not RWX)\n\n");

    return 0;
}
