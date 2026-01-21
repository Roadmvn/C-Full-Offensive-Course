/*
 * Lesson 03: ReadProcessMemory & WriteProcessMemory
 *
 * These APIs read/write memory in OTHER processes.
 * Foundation for process injection and memory manipulation.
 *
 * CRITICAL for maldev:
 * - Process injection (DLL injection, shellcode injection)
 * - Reading process memory (credentials, keys, data)
 * - Patching remote process code
 *
 * Syntax:
 * BOOL ReadProcessMemory(
 *   HANDLE  hProcess,              // Target process handle
 *   LPCVOID lpBaseAddress,         // Address to read from
 *   LPVOID  lpBuffer,              // Buffer to receive data
 *   SIZE_T  nSize,                 // Bytes to read
 *   SIZE_T  *lpNumberOfBytesRead   // Bytes actually read
 * );
 *
 * BOOL WriteProcessMemory(
 *   HANDLE  hProcess,              // Target process handle
 *   LPVOID  lpBaseAddress,         // Address to write to
 *   LPCVOID lpBuffer,              // Data to write
 *   SIZE_T  nSize,                 // Bytes to write
 *   SIZE_T  *lpNumberOfBytesWritten // Bytes actually written
 * );
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

void DemoLocalMemoryRW() {
    printf("[*] Demo 1: Local Process Memory Read/Write\n");

    // Allocate local buffer
    char localBuffer[256] = {0};
    sprintf(localBuffer, "Secret data in current process!");

    printf("[+] Original data: %s\n", localBuffer);
    printf("[+] Buffer address: 0x%p\n", localBuffer);

    // Get handle to current process
    HANDLE hSelf = GetCurrentProcess();

    // Read from our own memory
    char readBuffer[256] = {0};
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hSelf, localBuffer, readBuffer, strlen(localBuffer), &bytesRead)) {
        printf("[+] Read %zu bytes: %s\n", bytesRead, readBuffer);
    } else {
        printf("[-] ReadProcessMemory failed: %lu\n", GetLastError());
    }

    // Write to our own memory
    char newData[] = "Modified by WriteProcessMemory!";
    SIZE_T bytesWritten = 0;

    if (WriteProcessMemory(hSelf, localBuffer, newData, sizeof(newData), &bytesWritten)) {
        printf("[+] Wrote %zu bytes\n", bytesWritten);
        printf("[+] Modified data: %s\n", localBuffer);
    }

    printf("\n");
}

void DemoReadPEB() {
    printf("[*] Demo 2: Reading Process Environment Block (PEB)\n");

    HANDLE hSelf = GetCurrentProcess();

    // Get PEB address using NtQueryInformationProcess
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[-] Could not find NtQueryInformationProcess\n");
        return;
    }

    // PROCESS_BASIC_INFORMATION structure
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hSelf,
        0, // ProcessBasicInformation
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status == 0) {
        printf("[+] PEB address: 0x%p\n", pbi.PebBaseAddress);
        printf("[+] Process ID: %lu\n", (DWORD)pbi.UniqueProcessId);

        // Read BeingDebugged flag from PEB
        BYTE beingDebugged = 0;
        SIZE_T bytesRead = 0;

        // PEB.BeingDebugged is at offset +0x02 in PEB
        LPVOID pBeingDebugged = (LPVOID)((BYTE*)pbi.PebBaseAddress + 0x02);

        if (ReadProcessMemory(hSelf, pBeingDebugged, &beingDebugged, sizeof(beingDebugged), &bytesRead)) {
            printf("[+] PEB.BeingDebugged: %d\n", beingDebugged);
            if (beingDebugged) {
                printf("[!] Debugger detected via PEB!\n");
            }
        }
    }

    printf("\n");
}

void DemoMemorySearch() {
    printf("[*] Demo 3: Searching for Pattern in Memory\n");

    // Create test data with pattern
    char testData[1024] = {0};
    memset(testData, 'A', sizeof(testData));
    memcpy(testData + 500, "SECRET_KEY_12345", 16);

    printf("[+] Test buffer contains hidden pattern at offset 500\n");
    printf("[+] Searching for pattern...\n");

    HANDLE hSelf = GetCurrentProcess();
    char searchBuffer[1024] = {0};
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hSelf, testData, searchBuffer, sizeof(searchBuffer), &bytesRead)) {
        // Search for pattern
        const char* pattern = "SECRET_KEY";
        char* found = strstr(searchBuffer, pattern);

        if (found) {
            SIZE_T offset = found - searchBuffer;
            printf("[+] Pattern found at offset: %zu\n", offset);
            printf("[+] Data: %.16s\n", found);
        }
    }

    printf("\n[!] This technique used for:\n");
    printf("    - Finding credentials in memory\n");
    printf("    - Locating encryption keys\n");
    printf("    - Discovering sensitive data\n\n");
}

DWORD FindProcessByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

void DemoRemoteRead() {
    printf("[*] Demo 4: Reading Remote Process Memory (Intro)\n");
    printf("[!] Full remote injection covered in later weeks\n\n");

    // Find notepad.exe if running
    DWORD pid = FindProcessByName("notepad.exe");

    if (pid == 0) {
        printf("[-] notepad.exe not running\n");
        printf("[!] Start notepad.exe to see remote memory read\n\n");
        printf("[*] Example remote read pattern:\n");
        printf("    1. OpenProcess(PROCESS_VM_READ, FALSE, targetPID)\n");
        printf("    2. ReadProcessMemory(hProcess, remoteAddr, buffer, size, &read)\n");
        printf("    3. Process data from remote memory\n");
        printf("    4. CloseHandle(hProcess)\n\n");
        return;
    }

    printf("[+] Found notepad.exe (PID: %lu)\n", pid);

    // Open process with read access
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        printf("[!] May need administrator privileges\n\n");
        return;
    }

    printf("[+] Opened process handle: 0x%p\n", hProcess);

    // Query process image name
    char imagePath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProcess, 0, imagePath, &size)) {
        printf("[+] Process image: %s\n", imagePath);
    }

    printf("\n[!] Remote memory operations:\n");
    printf("    - Requires PROCESS_VM_READ for ReadProcessMemory\n");
    printf("    - Requires PROCESS_VM_WRITE for WriteProcessMemory\n");
    printf("    - Requires PROCESS_VM_OPERATION for VirtualAllocEx\n");
    printf("    - Full injection: Week 8 (Process Injection)\n");

    CloseHandle(hProcess);
    printf("\n");
}

void DemoMemoryDump() {
    printf("[*] Demo 5: Memory Dump Pattern\n");

    // Allocate and fill memory region
    SIZE_T size = 256;
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) return;

    // Fill with pattern
    for (SIZE_T i = 0; i < size; i++) {
        ((BYTE*)pMem)[i] = (BYTE)(i & 0xFF);
    }

    printf("[+] Created test memory region at 0x%p\n", pMem);

    // Read and dump memory
    BYTE buffer[256] = {0};
    SIZE_T bytesRead = 0;
    HANDLE hSelf = GetCurrentProcess();

    if (ReadProcessMemory(hSelf, pMem, buffer, size, &bytesRead)) {
        printf("[+] Read %zu bytes, dumping first 64 bytes:\n\n", bytesRead);

        // Hexdump format
        for (SIZE_T i = 0; i < 64; i += 16) {
            printf("%p:  ", (void*)((BYTE*)pMem + i));

            // Hex values
            for (SIZE_T j = 0; j < 16; j++) {
                if (i + j < 64) {
                    printf("%02X ", buffer[i + j]);
                } else {
                    printf("   ");
                }
            }

            printf(" |");

            // ASCII representation
            for (SIZE_T j = 0; j < 16; j++) {
                if (i + j < 64) {
                    BYTE c = buffer[i + j];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
            }

            printf("|\n");
        }
    }

    VirtualFree(pMem, 0, MEM_RELEASE);
    printf("\n");
}

int main() {
    printf("========================================================\n");
    printf("  ReadProcessMemory & WriteProcessMemory Introduction\n");
    printf("========================================================\n\n");

    DemoLocalMemoryRW();
    DemoReadPEB();
    DemoMemorySearch();
    DemoRemoteRead();
    DemoMemoryDump();

    printf("[*] Key Takeaways:\n");
    printf("    1. ReadProcessMemory reads from any process (with rights)\n");
    printf("    2. WriteProcessMemory writes to any process (with rights)\n");
    printf("    3. Works on current process or remote processes\n");
    printf("    4. Requires appropriate access rights (PROCESS_VM_*)\n");
    printf("    5. Used for memory search, dumping, injection\n");
    printf("    6. Foundation for process injection (Week 8)\n\n");

    printf("[!] Next Steps:\n");
    printf("    - Week 8: Process Injection (full remote injection)\n");
    printf("    - DLL Injection, Shellcode Injection\n");
    printf("    - VirtualAllocEx, CreateRemoteThread\n\n");

    return 0;
}
