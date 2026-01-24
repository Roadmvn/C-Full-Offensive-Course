/*
 * Solution 03: Full Command Dispatcher
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <sddl.h>

#define MAX_OUTPUT 8192
#define MAX_CMD_LEN 512
#define MAX_ARGS 16

typedef BOOL (*CmdHandler)(int argc, char* argv[], char* output, DWORD outputSize);

typedef struct {
    const char* name;
    CmdHandler handler;
    const char* usage;
    const char* description;
} CommandEntry;

BOOL CmdWhoami(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdPwd(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdCd(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdLs(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdCat(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdHostname(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdGetuid(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdHelp(int argc, char* argv[], char* output, DWORD outputSize);

CommandEntry g_CommandTable[] = {
    {"whoami",   CmdWhoami,   "whoami",          "Display current username"},
    {"pwd",      CmdPwd,      "pwd",             "Print working directory"},
    {"cd",       CmdCd,       "cd <path>",       "Change directory"},
    {"ls",       CmdLs,       "ls [path]",       "List directory contents"},
    {"cat",      CmdCat,      "cat <file>",      "Display file contents"},
    {"hostname", CmdHostname, "hostname",        "Display computer name"},
    {"getuid",   CmdGetuid,   "getuid",          "Display user SID"},
    {"help",     CmdHelp,     "help",            "Show this help message"},
    {NULL, NULL, NULL, NULL}
};

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

BOOL DispatchCommand(char* cmdLine, char* output, DWORD outputSize) {
    char* argv[MAX_ARGS] = {0};
    int argc = 0;
    char cmdLineCopy[MAX_CMD_LEN] = {0};

    strncpy_s(cmdLineCopy, sizeof(cmdLineCopy), cmdLine, _TRUNCATE);

    argc = ParseCommandLine(cmdLineCopy, argv, MAX_ARGS);

    if (argc == 0) {
        snprintf(output, outputSize, "[-] No command specified\n");
        return FALSE;
    }

    for (int i = 0; g_CommandTable[i].name != NULL; i++) {
        if (_stricmp(argv[0], g_CommandTable[i].name) == 0) {
            return g_CommandTable[i].handler(argc, argv, output, outputSize);
        }
    }

    snprintf(output, outputSize, "[-] Unknown command: %s\nType 'help' for available commands\n", argv[0]);
    return FALSE;
}

BOOL CmdWhoami(int argc, char* argv[], char* output, DWORD outputSize) {
    char username[256] = {0};
    DWORD size = sizeof(username);

    if (GetUserNameA(username, &size)) {
        snprintf(output, outputSize, "%s\n", username);
        return TRUE;
    }

    snprintf(output, outputSize, "[-] GetUserName failed: %d\n", GetLastError());
    return FALSE;
}

BOOL CmdPwd(int argc, char* argv[], char* output, DWORD outputSize) {
    if (GetCurrentDirectoryA(outputSize - 2, output) == 0) {
        snprintf(output, outputSize, "[-] GetCurrentDirectory failed: %d\n", GetLastError());
        return FALSE;
    }

    strcat_s(output, outputSize, "\n");
    return TRUE;
}

BOOL CmdCd(int argc, char* argv[], char* output, DWORD outputSize) {
    if (argc < 2) {
        snprintf(output, outputSize, "[-] Usage: cd <directory>\n");
        return FALSE;
    }

    if (!SetCurrentDirectoryA(argv[1])) {
        snprintf(output, outputSize, "[-] Failed to change directory: %d\n", GetLastError());
        return FALSE;
    }

    GetCurrentDirectoryA(outputSize - 2, output);
    strcat_s(output, outputSize, "\n");
    return TRUE;
}

BOOL CmdLs(int argc, char* argv[], char* output, DWORD outputSize) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];
    char* outPtr = output;
    DWORD remaining = outputSize - 1;
    int written = 0;

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

        char attrs[5];
        attrs[0] = (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 'r' : '-';
        attrs[1] = (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ? 'h' : '-';
        attrs[2] = (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) ? 's' : '-';
        attrs[3] = (findData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) ? 'a' : '-';
        attrs[4] = '\0';

        written = snprintf(outPtr, remaining, "%c %s  %s\n",
                          type, attrs, findData.cFileName);

        if (written < 0 || written >= remaining) break;

        outPtr += written;
        remaining -= written;

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return TRUE;
}

BOOL CmdCat(int argc, char* argv[], char* output, DWORD outputSize) {
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
        snprintf(output, outputSize, "[-] File too large for buffer\n");
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

BOOL CmdHostname(int argc, char* argv[], char* output, DWORD outputSize) {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = sizeof(computerName);

    if (GetComputerNameA(computerName, &size)) {
        snprintf(output, outputSize, "%s\n", computerName);
        return TRUE;
    }

    snprintf(output, outputSize, "[-] GetComputerName failed: %d\n", GetLastError());
    return FALSE;
}

BOOL CmdGetuid(int argc, char* argv[], char* output, DWORD outputSize) {
    HANDLE hToken = NULL;
    DWORD tokenInfoLen = 0;
    PTOKEN_USER pTokenUser = NULL;
    LPSTR sidString = NULL;
    BOOL result = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        snprintf(output, outputSize, "[-] OpenProcessToken failed: %d\n", GetLastError());
        return FALSE;
    }

    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);

    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, tokenInfoLen);
    if (!pTokenUser) {
        snprintf(output, outputSize, "[-] LocalAlloc failed\n");
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoLen, &tokenInfoLen)) {
        snprintf(output, outputSize, "[-] GetTokenInformation failed: %d\n", GetLastError());
        LocalFree(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
        snprintf(output, outputSize, "%s\n", sidString);
        LocalFree(sidString);
        result = TRUE;
    } else {
        snprintf(output, outputSize, "[-] ConvertSidToStringSid failed: %d\n", GetLastError());
    }

    LocalFree(pTokenUser);
    CloseHandle(hToken);
    return result;
}

BOOL CmdHelp(int argc, char* argv[], char* output, DWORD outputSize) {
    char* outPtr = output;
    DWORD remaining = outputSize;
    int written = 0;

    written = snprintf(outPtr, remaining, "Available Commands:\n\n");
    outPtr += written;
    remaining -= written;

    for (int i = 0; g_CommandTable[i].name != NULL; i++) {
        written = snprintf(outPtr, remaining, "  %-12s - %s\n",
                          g_CommandTable[i].usage, g_CommandTable[i].description);
        if (written < 0 || written >= remaining) break;
        outPtr += written;
        remaining -= written;
    }

    return TRUE;
}

int main() {
    char input[MAX_CMD_LEN] = {0};
    char output[MAX_OUTPUT] = {0};

    printf("=== Solution 03: Full Command Dispatcher ===\n");
    printf("Type 'help' for commands, 'exit' to quit\n\n");

    while (1) {
        printf("beacon> ");

        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }

        input[strcspn(input, "\r\n")] = '\0';

        if (_stricmp(input, "exit") == 0 || _stricmp(input, "quit") == 0) {
            break;
        }

        if (strlen(input) == 0) {
            continue;
        }

        ZeroMemory(output, sizeof(output));
        DispatchCommand(input, output, sizeof(output));
        printf("%s\n", output);
    }

    printf("Goodbye!\n");
    return 0;
}
