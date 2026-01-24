/*
 * Lesson 01: VirtualAlloc - Memory Allocation
 *
 * VirtualAlloc is the primary API for allocating memory in Windows.
 * It provides fine-grained control over memory allocation and protection.
 *
 * CRITICAL for maldev:
 * - Allocate executable memory for shellcode
 * - Control memory protections (RWX patterns)
 * - Manage memory regions for injection
 *
 * Syntax:
 * LPVOID VirtualAlloc(
 *   LPVOID lpAddress,        // Address (NULL = let system choose)
 *   SIZE_T dwSize,           // Size in bytes
 *   DWORD  flAllocationType, // MEM_COMMIT | MEM_RESERVE
 *   DWORD  flProtect         // PAGE_* protection
 * );
 */

#include <windows.h>
#include <stdio.h>

void DemoBasicAllocation() {
    printf("[*] Demo 1: Basic Memory Allocation\n");

    SIZE_T size = 4096; // 1 page

    // Allocate read-write memory
    LPVOID pMem = VirtualAlloc(
        NULL,                    // Let system choose address
        size,                    // 4KB
        MEM_COMMIT | MEM_RESERVE, // Commit and reserve
        PAGE_READWRITE           // RW protection
    );

    if (!pMem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }

    printf("[+] Allocated %zu bytes at 0x%p\n", size, pMem);
    printf("[+] Protection: PAGE_READWRITE\n");

    // Use the memory
    memset(pMem, 'A', size);
    printf("[+] Filled memory with pattern\n");

    // Free the memory
    VirtualFree(pMem, 0, MEM_RELEASE);
    printf("[+] Memory freed\n\n");
}

void DemoAllocationTypes() {
    printf("[*] Demo 2: Allocation Types (MEM_COMMIT vs MEM_RESERVE)\n");

    SIZE_T size = 65536; // 64KB

    // Step 1: Reserve address space (no physical memory yet)
    LPVOID pReserved = VirtualAlloc(
        NULL,
        size,
        MEM_RESERVE,        // Only reserve virtual address space
        PAGE_NOACCESS       // No access yet
    );

    if (!pReserved) {
        printf("[-] Reserve failed: %lu\n", GetLastError());
        return;
    }

    printf("[+] Reserved %zu bytes at 0x%p (no physical memory)\n", size, pReserved);

    // Step 2: Commit physical memory to part of reserved region
    LPVOID pCommitted = VirtualAlloc(
        pReserved,          // Use reserved address
        4096,               // Commit only 4KB
        MEM_COMMIT,         // Commit physical memory
        PAGE_READWRITE
    );

    if (!pCommitted) {
        printf("[-] Commit failed: %lu\n", GetLastError());
        VirtualFree(pReserved, 0, MEM_RELEASE);
        return;
    }

    printf("[+] Committed 4096 bytes within reserved region\n");
    printf("[+] Can now read/write to 0x%p\n", pCommitted);

    // Use committed memory
    sprintf((char*)pCommitted, "Hello from committed memory!");
    printf("[+] Written: %s\n", (char*)pCommitted);

    // Free entire reservation (includes committed regions)
    VirtualFree(pReserved, 0, MEM_RELEASE);
    printf("[+] Released entire region\n\n");
}

void DemoProtectionTypes() {
    printf("[*] Demo 3: Memory Protection Types\n");

    SIZE_T size = 4096;

    // Common protection types
    struct {
        DWORD protection;
        const char* name;
        const char* description;
    } protections[] = {
        {PAGE_NOACCESS,          "PAGE_NOACCESS",          "No access"},
        {PAGE_READONLY,          "PAGE_READONLY",          "Read only"},
        {PAGE_READWRITE,         "PAGE_READWRITE",         "Read + Write"},
        {PAGE_EXECUTE,           "PAGE_EXECUTE",           "Execute only"},
        {PAGE_EXECUTE_READ,      "PAGE_EXECUTE_READ",      "Execute + Read"},
        {PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE", "Execute + Read + Write (RWX)"}
    };

    for (int i = 0; i < 6; i++) {
        LPVOID pMem = VirtualAlloc(
            NULL,
            size,
            MEM_COMMIT | MEM_RESERVE,
            protections[i].protection
        );

        if (pMem) {
            printf("[+] %-25s : 0x%08X - %s\n",
                   protections[i].name,
                   protections[i].protection,
                   protections[i].description);
            VirtualFree(pMem, 0, MEM_RELEASE);
        }
    }

    printf("\n[!] RWX (PAGE_EXECUTE_READWRITE) is suspicious for EDR!\n");
    printf("[!] Better pattern: RW -> copy -> RX (covered in ex02)\n\n");
}

void DemoQueryMemory() {
    printf("[*] Demo 4: Query Memory Information\n");

    SIZE_T size = 8192;
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pMem) {
        printf("[-] Allocation failed\n");
        return;
    }

    // Query memory info
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(pMem, &mbi, sizeof(mbi))) {
        printf("[+] Base Address:      0x%p\n", mbi.BaseAddress);
        printf("[+] Allocation Base:   0x%p\n", mbi.AllocationBase);
        printf("[+] Region Size:       %zu bytes\n", mbi.RegionSize);
        printf("[+] State:             ");

        switch (mbi.State) {
            case MEM_COMMIT:  printf("MEM_COMMIT\n"); break;
            case MEM_RESERVE: printf("MEM_RESERVE\n"); break;
            case MEM_FREE:    printf("MEM_FREE\n"); break;
            default:          printf("Unknown\n");
        }

        printf("[+] Type:              ");
        switch (mbi.Type) {
            case MEM_PRIVATE: printf("MEM_PRIVATE\n"); break;
            case MEM_MAPPED:  printf("MEM_MAPPED\n"); break;
            case MEM_IMAGE:   printf("MEM_IMAGE\n"); break;
            default:          printf("Unknown\n");
        }

        printf("[+] Protection:        0x%08X\n", mbi.Protect);
    }

    VirtualFree(pMem, 0, MEM_RELEASE);
    printf("\n");
}

void DemoMaldevPattern() {
    printf("[*] Demo 5: Typical Maldev Allocation Pattern\n");

    // Calculate size for shellcode buffer
    SIZE_T shellcodeSize = 256;

    printf("[+] Step 1: Allocate RW memory\n");
    LPVOID pShellcode = VirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // Start with RW (safer)
    );

    if (!pShellcode) {
        printf("[-] Allocation failed: %lu\n", GetLastError());
        return;
    }

    printf("[+] Allocated %zu bytes at 0x%p\n", shellcodeSize, pShellcode);

    printf("[+] Step 2: Copy shellcode to buffer (simulated)\n");
    // In real scenario: memcpy(pShellcode, actualShellcode, shellcodeSize);
    memset(pShellcode, 0x90, shellcodeSize); // NOP sled for demo

    printf("[+] Step 3: Change protection to RX (will cover in lesson 02)\n");
    printf("[+] Step 4: Execute shellcode (will cover in lesson 04)\n");

    printf("\n[!] This is the foundation of shellcode execution!\n");

    VirtualFree(pShellcode, 0, MEM_RELEASE);
    printf("\n");
}

int main() {
    printf("==============================================\n");
    printf("  VirtualAlloc - Memory Allocation Lesson\n");
    printf("==============================================\n\n");

    DemoBasicAllocation();
    DemoAllocationTypes();
    DemoProtectionTypes();
    DemoQueryMemory();
    DemoMaldevPattern();

    printf("[*] Key Takeaways:\n");
    printf("    1. VirtualAlloc gives fine-grained memory control\n");
    printf("    2. MEM_COMMIT allocates physical memory\n");
    printf("    3. MEM_RESERVE only reserves address space\n");
    printf("    4. PAGE_EXECUTE_READWRITE is suspicious (RWX)\n");
    printf("    5. Better pattern: allocate RW, then change to RX\n");
    printf("    6. VirtualQuery reveals memory characteristics\n\n");

    return 0;
}
