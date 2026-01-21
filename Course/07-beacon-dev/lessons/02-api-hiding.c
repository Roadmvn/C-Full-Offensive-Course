/*
 * Lesson 02: API Hiding
 *
 * Hide API usage from Import Address Table (IAT) by:
 * 1. Dynamic resolution with GetProcAddress
 * 2. Direct syscalls (advanced)
 * 3. Manual module parsing
 */

#include <windows.h>
#include <stdio.h>

// Function pointer typedefs
typedef HANDLE (WINAPI* fnCreateFileA)(
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
);

typedef BOOL (WINAPI* fnWriteFile)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED
);

typedef BOOL (WINAPI* fnCloseHandle)(HANDLE);

int main(void) {
    printf("[*] API Hiding Demo\n\n");

    // Method 1: Standard Import (visible in IAT)
    printf("[!] Method 1: Standard Import\n");
    printf("    Pros:  Simple, direct\n");
    printf("    Cons:  Visible in IAT, easily detected\n\n");

    // This is how normal code looks - visible in IAT
    // CreateFileA("test.txt", ...);

    // Method 2: GetProcAddress (IAT shows only kernel32.dll)
    printf("[+] Method 2: GetProcAddress Resolution\n");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to get kernel32.dll handle\n");
        return 1;
    }

    fnCreateFileA pCreateFileA = (fnCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    fnWriteFile pWriteFile = (fnWriteFile)GetProcAddress(hKernel32, "WriteFile");
    fnCloseHandle pCloseHandle = (fnCloseHandle)GetProcAddress(hKernel32, "CloseHandle");

    if (!pCreateFileA || !pWriteFile || !pCloseHandle) {
        printf("[-] Failed to resolve APIs\n");
        return 1;
    }

    printf("    [+] CreateFileA:  0x%p\n", pCreateFileA);
    printf("    [+] WriteFile:    0x%p\n", pWriteFile);
    printf("    [+] CloseHandle:  0x%p\n\n", pCloseHandle);

    // Use dynamically resolved APIs
    HANDLE hFile = pCreateFileA(
        "api_hiding_test.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file\n");
        return 1;
    }

    CHAR data[] = "Written with hidden API!\n";
    DWORD written;
    pWriteFile(hFile, data, sizeof(data) - 1, &written, NULL);
    pCloseHandle(hFile);

    printf("[+] File written using dynamically resolved APIs\n\n");

    // Method 3: Obfuscated API Names
    printf("[+] Method 3: Obfuscated API Names\n");

    // XOR obfuscate API name
    CHAR apiName[] = {
        'C' ^ 0x42, 'r' ^ 0x42, 'e' ^ 0x42, 'a' ^ 0x42,
        't' ^ 0x42, 'e' ^ 0x42, 'F' ^ 0x42, 'i' ^ 0x42,
        'l' ^ 0x42, 'e' ^ 0x42, 'A' ^ 0x42, '\0'
    };

    // Deobfuscate
    for (int i = 0; i < 11; i++) {
        apiName[i] ^= 0x42;
    }

    fnCreateFileA pCreateFileA2 = (fnCreateFileA)GetProcAddress(hKernel32, apiName);
    printf("    [+] Resolved '%s': 0x%p\n\n", apiName, pCreateFileA2);

    // Method 4: API Hashing (used in shellcode)
    printf("[+] Method 4: API Hashing\n");
    printf("    - Hash API name (e.g., djb2, CRC32)\n");
    printf("    - Compare hash instead of string\n");
    printf("    - Example: CreateFileA -> 0x4FDAF6DA\n");
    printf("    - No strings in binary!\n\n");

    // Example hash function (djb2)
    auto hashAPI = [](const char* str) -> DWORD {
        DWORD hash = 5381;
        int c;
        while ((c = *str++)) {
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    };

    DWORD hash = hashAPI("CreateFileA");
    printf("    Hash of 'CreateFileA': 0x%08X\n\n", hash);

    // Comparison table
    printf("[*] IAT Analysis Comparison:\n");
    printf("    +-----------------+---------------------------+\n");
    printf("    | Method          | Visible in IAT            |\n");
    printf("    +-----------------+---------------------------+\n");
    printf("    | Standard Import | CreateFileA, WriteFile... |\n");
    printf("    | GetProcAddress  | GetProcAddress only       |\n");
    printf("    | API Hashing     | GetProcAddress only       |\n");
    printf("    | Direct Syscalls | None (ntdll bypassed)     |\n");
    printf("    +-----------------+---------------------------+\n\n");

    printf("[*] Key Points:\n");
    printf("    1. GetProcAddress hides specific APIs from IAT\n");
    printf("    2. Obfuscate API names to avoid string detection\n");
    printf("    3. API hashing removes strings completely\n");
    printf("    4. Combine with string obfuscation for DLL names\n");
    printf("    5. Direct syscalls bypass user-mode hooks\n\n");

    printf("[!] Note: Modern EDRs also monitor:\n");
    printf("    - GetProcAddress calls\n");
    printf("    - Manual PEB walking\n");
    printf("    - Syscall invocation\n");
    printf("    - Defense in depth required!\n\n");

    return 0;
}
