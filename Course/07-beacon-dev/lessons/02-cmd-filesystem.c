/*
 * Lesson 02: Filesystem Commands - pwd, cd, ls
 *
 * Implements basic filesystem navigation commands without spawning cmd.exe.
 * These are implemented using Windows API calls for better stealth.
 *
 * Key Concepts:
 * - GetCurrentDirectoryA for pwd
 * - SetCurrentDirectoryA for cd
 * - FindFirstFileA/FindNextFileA for ls
 * - Directory traversal patterns
 */

#include <windows.h>
#include <stdio.h>

#define MAX_PATH_LEN 2048

// Get current working directory (pwd)
BOOL CommandPwd(char* output, DWORD outputSize) {
    DWORD len = GetCurrentDirectoryA(outputSize, output);

    if (len == 0 || len >= outputSize) {
        snprintf(output, outputSize, "[-] GetCurrentDirectory failed: %d\n", GetLastError());
        return FALSE;
    }

    // Add newline for consistency
    size_t currentLen = strlen(output);
    if (currentLen + 2 < outputSize) {
        output[currentLen] = '\n';
        output[currentLen + 1] = '\0';
    }

    return TRUE;
}

// Change directory (cd)
BOOL CommandCd(const char* path, char* output, DWORD outputSize) {
    if (!path || strlen(path) == 0) {
        snprintf(output, outputSize, "[-] Usage: cd <directory>\n");
        return FALSE;
    }

    if (!SetCurrentDirectoryA(path)) {
        snprintf(output, outputSize, "[-] Failed to change directory: %d\n", GetLastError());
        return FALSE;
    }

    // Confirm new directory
    GetCurrentDirectoryA(outputSize, output);
    size_t len = strlen(output);
    if (len + 2 < outputSize) {
        output[len] = '\n';
        output[len + 1] = '\0';
    }

    return TRUE;
}

// List directory contents (ls)
BOOL CommandLs(const char* path, char* output, DWORD outputSize) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char searchPath[MAX_PATH];
    char* outPtr = output;
    DWORD remaining = outputSize - 1;
    int written = 0;

    // Use current directory if no path specified
    if (!path || strlen(path) == 0) {
        snprintf(searchPath, sizeof(searchPath), "*");
    } else {
        snprintf(searchPath, sizeof(searchPath), "%s\\*", path);
    }

    // Start directory enumeration
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        snprintf(output, outputSize, "[-] FindFirstFile failed: %d\n", GetLastError());
        return FALSE;
    }

    // Iterate through directory entries
    do {
        // Skip "." and ".."
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Format entry with type indicator
        char entryType = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';

        written = snprintf(outPtr, remaining, "%c  %s\n",
                          entryType, findData.cFileName);

        if (written < 0 || written >= remaining) {
            break; // Buffer full
        }

        outPtr += written;
        remaining -= written;

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    // Add summary if space available
    if (remaining > 50) {
        snprintf(outPtr, remaining, "\n(d = directory, - = file)\n");
    }

    return TRUE;
}

int main() {
    char output[4096] = {0};

    // Test pwd
    printf("[*] Testing pwd command:\n");
    if (CommandPwd(output, sizeof(output))) {
        printf("%s\n", output);
    }

    // Test ls (current directory)
    printf("[*] Testing ls command:\n");
    ZeroMemory(output, sizeof(output));
    if (CommandLs(NULL, output, sizeof(output))) {
        printf("%s\n", output);
    }

    // Test cd
    printf("[*] Testing cd command (to C:\\Windows):\n");
    ZeroMemory(output, sizeof(output));
    if (CommandCd("C:\\Windows", output, sizeof(output))) {
        printf("[+] Changed to: %s\n", output);

        // Verify with pwd
        ZeroMemory(output, sizeof(output));
        CommandPwd(output, sizeof(output));
        printf("[+] Current directory: %s\n", output);
    }

    return 0;
}
