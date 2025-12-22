/*
 * Lesson 03: File Reading Command - cat
 *
 * Implements file content reading (cat command) using Windows file I/O.
 * Handles both text and binary files with size limits for safety.
 *
 * Key Concepts:
 * - CreateFileA for file opening
 * - ReadFile for content reading
 * - File size checking to prevent memory exhaustion
 * - Binary vs text file handling
 */

#include <windows.h>
#include <stdio.h>

#define MAX_FILE_SIZE (1024 * 1024 * 10)  // 10 MB limit
#define CHUNK_SIZE 4096

// Read file contents (cat)
BOOL CommandCat(const char* filePath, char* output, DWORD outputSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD fileSize = 0;
    DWORD bytesRead = 0;
    DWORD totalRead = 0;
    BOOL result = FALSE;
    char* outPtr = output;
    DWORD remaining = outputSize - 1;

    // Validate input
    if (!filePath || strlen(filePath) == 0) {
        snprintf(output, outputSize, "[-] Usage: cat <file>\n");
        return FALSE;
    }

    // Open file for reading
    hFile = CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(output, outputSize, "[-] Failed to open file '%s': %d\n",
                filePath, GetLastError());
        return FALSE;
    }

    // Get file size
    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        snprintf(output, outputSize, "[-] Failed to get file size: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    // Check file size limit
    if (fileSize > MAX_FILE_SIZE) {
        snprintf(output, outputSize, "[-] File too large (%d bytes). Max: %d bytes\n",
                fileSize, MAX_FILE_SIZE);
        CloseHandle(hFile);
        return FALSE;
    }

    // Check if file fits in output buffer
    if (fileSize >= outputSize) {
        snprintf(output, outputSize, "[-] File too large for output buffer (%d bytes). Buffer: %d bytes\n",
                fileSize, outputSize);
        CloseHandle(hFile);
        return FALSE;
    }

    // Read file in chunks
    while (totalRead < fileSize && remaining > 0) {
        DWORD toRead = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        if (!ReadFile(hFile, outPtr, toRead, &bytesRead, NULL)) {
            snprintf(output, outputSize, "[-] ReadFile failed: %d\n", GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        if (bytesRead == 0) {
            break; // EOF
        }

        outPtr += bytesRead;
        remaining -= bytesRead;
        totalRead += bytesRead;
    }

    // Null-terminate
    *outPtr = '\0';

    result = TRUE;
    CloseHandle(hFile);

    return result;
}

// Create a test file for demonstration
BOOL CreateTestFile(const char* filePath) {
    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    const char* content = "This is a test file.\n"
                         "Line 2: Hello World!\n"
                         "Line 3: Testing cat command.\n"
                         "Line 4: End of file.\n";

    DWORD written = 0;
    WriteFile(hFile, content, strlen(content), &written, NULL);
    CloseHandle(hFile);

    return TRUE;
}

int main() {
    char output[8192] = {0};
    const char* testFile = "test_cat.txt";

    // Create test file
    printf("[*] Creating test file: %s\n", testFile);
    if (!CreateTestFile(testFile)) {
        printf("[-] Failed to create test file\n");
        return 1;
    }

    // Test cat command
    printf("[*] Testing cat command:\n\n");
    if (CommandCat(testFile, output, sizeof(output))) {
        printf("--- File Contents ---\n");
        printf("%s", output);
        printf("--- End of File ---\n");
    } else {
        printf("%s", output);
    }

    // Test with non-existent file
    printf("\n[*] Testing with non-existent file:\n");
    ZeroMemory(output, sizeof(output));
    CommandCat("nonexistent.txt", output, sizeof(output));
    printf("%s", output);

    // Cleanup
    DeleteFileA(testFile);

    return 0;
}
