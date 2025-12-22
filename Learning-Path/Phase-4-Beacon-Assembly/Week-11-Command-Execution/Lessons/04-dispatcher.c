/*
 * Lesson 04: Command Dispatcher Pattern
 *
 * Demonstrates a complete command dispatcher that routes commands to handlers.
 * This is the core pattern used in beacon implementations.
 *
 * Key Concepts:
 * - Command parsing (tokenization)
 * - Command routing/dispatching
 * - Handler function pattern
 * - Output buffer management
 * - Error handling and reporting
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT 8192
#define MAX_ARGS 16
#define MAX_ARG_LEN 256

// Command handler function pointer type
typedef BOOL (*CommandHandler)(int argc, char* argv[], char* output, DWORD outputSize);

// Command structure
typedef struct {
    const char* name;
    CommandHandler handler;
    const char* description;
} Command;

// Forward declarations
BOOL HandleWhoami(int argc, char* argv[], char* output, DWORD outputSize);
BOOL HandlePwd(int argc, char* argv[], char* output, DWORD outputSize);
BOOL HandleCd(int argc, char* argv[], char* output, DWORD outputSize);
BOOL HandleLs(int argc, char* argv[], char* output, DWORD outputSize);
BOOL HandleCat(int argc, char* argv[], char* output, DWORD outputSize);
BOOL HandleHelp(int argc, char* argv[], char* output, DWORD outputSize);

// Command table
Command g_Commands[] = {
    {"whoami", HandleWhoami, "Display current user"},
    {"pwd",    HandlePwd,    "Print working directory"},
    {"cd",     HandleCd,     "Change directory"},
    {"ls",     HandleLs,     "List directory contents"},
    {"cat",    HandleCat,    "Display file contents"},
    {"help",   HandleHelp,   "Show this help message"},
    {NULL, NULL, NULL}
};

// Parse command line into argc/argv
int ParseCommandLine(char* cmdLine, char* argv[], int maxArgs) {
    int argc = 0;
    char* token = NULL;
    char* context = NULL;

    token = strtok_s(cmdLine, " \t\n", &context);
    while (token != NULL && argc < maxArgs) {
        argv[argc++] = token;
        token = strtok_s(NULL, " \t\n", &context);
    }

    return argc;
}

// Dispatcher: routes command to appropriate handler
BOOL DispatchCommand(char* cmdLine, char* output, DWORD outputSize) {
    char* argv[MAX_ARGS] = {0};
    int argc = 0;
    char cmdLineCopy[1024] = {0};

    // Make a copy for parsing (strtok modifies the string)
    strncpy_s(cmdLineCopy, sizeof(cmdLineCopy), cmdLine, _TRUNCATE);

    // Parse command line
    argc = ParseCommandLine(cmdLineCopy, argv, MAX_ARGS);

    if (argc == 0) {
        snprintf(output, outputSize, "[-] No command specified\n");
        return FALSE;
    }

    // Find and execute command
    for (int i = 0; g_Commands[i].name != NULL; i++) {
        if (_stricmp(argv[0], g_Commands[i].name) == 0) {
            return g_Commands[i].handler(argc, argv, output, outputSize);
        }
    }

    // Unknown command
    snprintf(output, outputSize, "[-] Unknown command: %s\nType 'help' for available commands\n", argv[0]);
    return FALSE;
}

// Command Handlers

BOOL HandleWhoami(int argc, char* argv[], char* output, DWORD outputSize) {
    char username[256] = {0};
    DWORD size = sizeof(username);

    if (GetUserNameA(username, &size)) {
        snprintf(output, outputSize, "%s\n", username);
        return TRUE;
    }

    snprintf(output, outputSize, "[-] GetUserName failed: %d\n", GetLastError());
    return FALSE;
}

BOOL HandlePwd(int argc, char* argv[], char* output, DWORD outputSize) {
    if (GetCurrentDirectoryA(outputSize - 2, output) == 0) {
        snprintf(output, outputSize, "[-] GetCurrentDirectory failed: %d\n", GetLastError());
        return FALSE;
    }

    strcat_s(output, outputSize, "\n");
    return TRUE;
}

BOOL HandleCd(int argc, char* argv[], char* output, DWORD outputSize) {
    if (argc < 2) {
        snprintf(output, outputSize, "[-] Usage: cd <directory>\n");
        return FALSE;
    }

    if (!SetCurrentDirectoryA(argv[1])) {
        snprintf(output, outputSize, "[-] Failed to change directory: %d\n", GetLastError());
        return FALSE;
    }

    // Show new directory
    GetCurrentDirectoryA(outputSize - 2, output);
    strcat_s(output, outputSize, "\n");
    return TRUE;
}

BOOL HandleLs(int argc, char* argv[], char* output, DWORD outputSize) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];
    char* outPtr = output;
    DWORD remaining = outputSize - 1;
    int written = 0;

    // Determine search path
    if (argc > 1) {
        snprintf(searchPath, sizeof(searchPath), "%s\\*", argv[1]);
    } else {
        snprintf(searchPath, sizeof(searchPath), "*");
    }

    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        snprintf(output, outputSize, "[-] FindFirstFile failed: %d\n", GetLastError());
        return FALSE;
    }

    do {
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        char type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';
        written = snprintf(outPtr, remaining, "%c  %s\n", type, findData.cFileName);

        if (written < 0 || written >= remaining) break;

        outPtr += written;
        remaining -= written;

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return TRUE;
}

BOOL HandleCat(int argc, char* argv[], char* output, DWORD outputSize) {
    HANDLE hFile;
    DWORD fileSize, bytesRead;

    if (argc < 2) {
        snprintf(output, outputSize, "[-] Usage: cat <file>\n");
        return FALSE;
    }

    hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(output, outputSize, "[-] Failed to open file: %d\n", GetLastError());
        return FALSE;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize >= outputSize) {
        snprintf(output, outputSize, "[-] File too large\n");
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, output, outputSize - 1, &bytesRead, NULL)) {
        snprintf(output, outputSize, "[-] ReadFile failed: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    output[bytesRead] = '\0';
    CloseHandle(hFile);
    return TRUE;
}

BOOL HandleHelp(int argc, char* argv[], char* output, DWORD outputSize) {
    char* outPtr = output;
    DWORD remaining = outputSize;
    int written = 0;

    written = snprintf(outPtr, remaining, "Available Commands:\n\n");
    outPtr += written;
    remaining -= written;

    for (int i = 0; g_Commands[i].name != NULL; i++) {
        written = snprintf(outPtr, remaining, "  %-10s - %s\n",
                          g_Commands[i].name, g_Commands[i].description);
        if (written < 0 || written >= remaining) break;
        outPtr += written;
        remaining -= written;
    }

    return TRUE;
}

int main() {
    char output[MAX_OUTPUT] = {0};
    char input[256] = {0};

    printf("=== Command Dispatcher Demo ===\n");
    printf("Type 'help' for commands, 'exit' to quit\n\n");

    while (1) {
        printf("> ");

        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }

        // Remove newline
        input[strcspn(input, "\r\n")] = '\0';

        // Check for exit
        if (_stricmp(input, "exit") == 0 || _stricmp(input, "quit") == 0) {
            break;
        }

        // Skip empty input
        if (strlen(input) == 0) {
            continue;
        }

        // Dispatch command
        ZeroMemory(output, sizeof(output));
        DispatchCommand(input, output, sizeof(output));
        printf("%s\n", output);
    }

    printf("Goodbye!\n");
    return 0;
}
