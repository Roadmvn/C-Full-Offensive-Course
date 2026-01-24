/*
 * Exercise 02: Implement ls Command
 *
 * OBJECTIVE:
 * Implement a full-featured 'ls' command with multiple options.
 *
 * REQUIREMENTS:
 * 1. List files in specified directory (or current if none)
 * 2. Show file attributes (directory, hidden, system, readonly)
 * 3. Display file sizes in human-readable format
 * 4. Show file modification times
 * 5. Support recursive listing (optional)
 *
 * OUTPUT FORMAT:
 * [Type] [Attrs] [Size] [Modified] [Name]
 * Example:
 * d---  4096   2024-01-15 10:30  Documents
 * -rhs  2048   2024-01-15 09:15  config.sys
 *
 * ATTRIBUTE CODES:
 * r = readonly, h = hidden, s = system, a = archive
 * d = directory, - = file
 *
 * BONUS:
 * - Add sorting by name, size, or date
 * - Add filtering (e.g., only .exe files)
 * - Recursive directory traversal
 */

#include <windows.h>
#include <stdio.h>
#include <time.h>

#define MAX_OUTPUT (1024 * 64)

/*
 * TODO: Implement this function
 *
 * Format file size to human-readable string
 *
 * Parameters:
 *   size   - File size in bytes
 *   buffer - Output buffer
 *   bufLen - Buffer size
 */
void FormatFileSize(DWORD size, char* buffer, size_t bufLen) {
    // TODO: Convert bytes to KB, MB, GB as appropriate
    // Example: 1536 bytes -> "1.5 KB"
    //         1048576 bytes -> "1.0 MB"

    snprintf(buffer, bufLen, "%d B", size);
}

/*
 * TODO: Implement this function
 *
 * Format FILETIME to readable date string
 *
 * Parameters:
 *   fileTime - Windows FILETIME structure
 *   buffer   - Output buffer
 *   bufLen   - Buffer size
 */
void FormatFileTime(FILETIME* fileTime, char* buffer, size_t bufLen) {
    // TODO: Convert FILETIME to readable format
    // Example: "2024-01-15 10:30"
    //
    // Hint: Use FileTimeToSystemTime, then format SYSTEMTIME

    snprintf(buffer, bufLen, "YYYY-MM-DD HH:MM");
}

/*
 * TODO: Implement this function
 *
 * Format file attributes to string
 *
 * Parameters:
 *   attrs  - File attributes (dwFileAttributes)
 *   buffer - Output buffer (at least 5 chars)
 */
void FormatAttributes(DWORD attrs, char* buffer) {
    // TODO: Convert attributes to "rhsa" format
    // r = readonly, h = hidden, s = system, a = archive
    // Use '-' for not set
    //
    // Example: FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM -> "-hs-"

    strcpy(buffer, "----");
}

/*
 * TODO: Implement this function
 *
 * List directory contents with detailed information
 *
 * Parameters:
 *   path       - Directory path (NULL for current)
 *   output     - Output buffer
 *   outputSize - Output buffer size
 *
 * Returns:
 *   TRUE on success, FALSE on failure
 */
BOOL ListDirectory(const char* path, char* output, DWORD outputSize) {
    // TODO: Implement directory listing with formatted output
    //
    // Steps:
    // 1. Build search path (path\* or just *)
    // 2. FindFirstFile / FindNextFile loop
    // 3. For each entry:
    //    - Format type (d or -)
    //    - Format attributes (rhsa)
    //    - Format size
    //    - Format modification time
    //    - Format name
    // 4. Append to output buffer
    //
    // Output format:
    // [Type] [Attrs] [Size] [Modified] [Name]

    snprintf(output, outputSize, "TODO: Implement ListDirectory\n");
    return FALSE;
}

int main() {
    char output[MAX_OUTPUT] = {0};

    printf("=== Exercise 02: Implement ls Command ===\n\n");

    // Test 1: List current directory
    printf("[Test 1] Listing current directory:\n");
    if (ListDirectory(NULL, output, sizeof(output))) {
        printf("%s\n", output);
    } else {
        printf("[-] Failed\n");
    }

    // Test 2: List Windows directory
    printf("\n[Test 2] Listing C:\\Windows (first 1000 chars):\n");
    ZeroMemory(output, sizeof(output));
    if (ListDirectory("C:\\Windows", output, sizeof(output))) {
        output[1000] = '\0';  // Truncate
        printf("%s...\n", output);
    } else {
        printf("[-] Failed\n");
    }

    // Test 3: List non-existent directory
    printf("\n[Test 3] Listing non-existent directory:\n");
    ZeroMemory(output, sizeof(output));
    if (ListDirectory("C:\\NonExistent", output, sizeof(output))) {
        printf("%s\n", output);
    } else {
        printf("[-] Failed (expected)\n");
    }

    return 0;
}
