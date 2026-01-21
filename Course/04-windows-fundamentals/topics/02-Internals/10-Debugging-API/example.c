/*
 * Module 19: Debugging Windows
 * Compiler: cl example.c ou gcc example.c -o example.exe
 */
#include <windows.h>
#include <stdio.h>

BOOL check_debugger() {
    return IsDebuggerPresent();
}

void file_operations() {
    HANDLE hFile = CreateFileA("test.txt", GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char *data = "Hello Windows!\n";
        DWORD written;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
        CloseHandle(hFile);
        printf("File written: %d bytes\n", written);
    }
}

int main() {
    printf("=== Windows Debugging Example ===\n");
    if (check_debugger()) {
        printf("[!] Debugger detected!\n");
    } else {
        printf("[+] No debugger\n");
    }
    file_operations();
    return 0;
}
