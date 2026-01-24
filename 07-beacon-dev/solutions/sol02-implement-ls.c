/*
 * Solution 02: Implement ls Command
 */

#include <windows.h>
#include <stdio.h>

#define MAX_OUTPUT (1024 * 64)

void FormatFileSize(DWORD sizeLow, DWORD sizeHigh, char* buffer, size_t bufLen) {
    ULONGLONG size = ((ULONGLONG)sizeHigh << 32) | sizeLow;

    if (size < 1024) {
        snprintf(buffer, bufLen, "%llu B  ", size);
    } else if (size < 1024 * 1024) {
        snprintf(buffer, bufLen, "%.1f KB", size / 1024.0);
    } else if (size < 1024 * 1024 * 1024) {
        snprintf(buffer, bufLen, "%.1f MB", size / (1024.0 * 1024.0));
    } else {
        snprintf(buffer, bufLen, "%.1f GB", size / (1024.0 * 1024.0 * 1024.0));
    }
}

void FormatFileTime(FILETIME* fileTime, char* buffer, size_t bufLen) {
    SYSTEMTIME st;
    FILETIME localFileTime;

    // Convert to local time
    if (!FileTimeToLocalFileTime(fileTime, &localFileTime)) {
        snprintf(buffer, bufLen, "????-??-?? ??:??");
        return;
    }

    // Convert to system time
    if (!FileTimeToSystemTime(&localFileTime, &st)) {
        snprintf(buffer, bufLen, "????-??-?? ??:??");
        return;
    }

    // Format: YYYY-MM-DD HH:MM
    snprintf(buffer, bufLen, "%04d-%02d-%02d %02d:%02d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
}

void FormatAttributes(DWORD attrs, char* buffer) {
    buffer[0] = (attrs & FILE_ATTRIBUTE_READONLY) ? 'r' : '-';
    buffer[1] = (attrs & FILE_ATTRIBUTE_HIDDEN) ? 'h' : '-';
    buffer[2] = (attrs & FILE_ATTRIBUTE_SYSTEM) ? 's' : '-';
    buffer[3] = (attrs & FILE_ATTRIBUTE_ARCHIVE) ? 'a' : '-';
    buffer[4] = '\0';
}

BOOL ListDirectory(const char* path, char* output, DWORD outputSize) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char searchPath[MAX_PATH];
    char* outPtr = output;
    DWORD remaining = outputSize - 1;
    int written = 0;
    int fileCount = 0;
    int dirCount = 0;

    // Build search path
    if (!path || strlen(path) == 0) {
        snprintf(searchPath, sizeof(searchPath), "*");
    } else {
        snprintf(searchPath, sizeof(searchPath), "%s\\*", path);
    }

    // Start enumeration
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        snprintf(output, outputSize, "[-] FindFirstFile failed: %d\n", GetLastError());
        return FALSE;
    }

    // Header
    written = snprintf(outPtr, remaining,
                      "Type Attrs Size      Modified         Name\n");
    written += snprintf(outPtr + written, remaining - written,
                       "---- ---- --------- ---------------- ----\n");
    outPtr += written;
    remaining -= written;

    // Iterate through entries
    do {
        // Skip . and ..
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Determine type
        char type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';
        if (type == 'd') {
            dirCount++;
        } else {
            fileCount++;
        }

        // Format attributes
        char attrs[5];
        FormatAttributes(findData.dwFileAttributes, attrs);

        // Format size
        char sizeStr[16];
        FormatFileSize(findData.nFileSizeLow, findData.nFileSizeHigh, sizeStr, sizeof(sizeStr));

        // Format time
        char timeStr[32];
        FormatFileTime(&findData.ftLastWriteTime, timeStr, sizeof(timeStr));

        // Format line
        written = snprintf(outPtr, remaining, "%c    %s  %-9s %s  %s\n",
                          type, attrs, sizeStr, timeStr, findData.cFileName);

        if (written < 0 || written >= remaining) {
            break;  // Buffer full
        }

        outPtr += written;
        remaining -= written;

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    // Add summary
    if (remaining > 60) {
        written = snprintf(outPtr, remaining, "\n%d directories, %d files\n",
                          dirCount, fileCount);
    }

    return TRUE;
}

int main() {
    char output[MAX_OUTPUT] = {0};

    printf("=== Solution 02: Implement ls Command ===\n\n");

    // Test 1: List current directory
    printf("[Test 1] Listing current directory:\n");
    if (ListDirectory(NULL, output, sizeof(output))) {
        printf("%s\n", output);
    } else {
        printf("[-] Failed\n");
    }

    // Test 2: List Windows directory
    printf("\n[Test 2] Listing C:\\Windows (first 1500 chars):\n");
    ZeroMemory(output, sizeof(output));
    if (ListDirectory("C:\\Windows", output, sizeof(output))) {
        output[1500] = '\0';  // Truncate
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
        printf("%s\n", output);
    }

    return 0;
}
