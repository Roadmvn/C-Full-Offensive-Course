/*
 * Exercise 03: Full Command Dispatcher
 *
 * OBJECTIVE:
 * Build a complete command dispatcher with all common commands.
 *
 * REQUIREMENTS:
 * Implement handlers for:
 * 1. whoami  - Current user (use GetUserNameA)
 * 2. pwd     - Current directory
 * 3. cd      - Change directory
 * 4. ls      - List directory (use detailed format from ex02)
 * 5. cat     - Read file contents
 * 6. hostname - Computer name
 * 7. getuid   - Current user SID
 * 8. help    - List all commands
 *
 * ARCHITECTURE:
 * - Command table with function pointers
 * - Parser to split command line into argc/argv
 * - Dispatcher to route to appropriate handler
 * - Consistent error handling
 * - Output buffering
 *
 * BONUS:
 * - Add command aliases (e.g., 'dir' -> 'ls')
 * - Add command history
 * - Add tab completion
 * - Add shell operators (|, >, >>, etc.)
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT 8192
#define MAX_CMD_LEN 512
#define MAX_ARGS 16

// Command handler function type
typedef BOOL (*CmdHandler)(int argc, char* argv[], char* output, DWORD outputSize);

// Command structure
typedef struct {
    const char* name;
    CmdHandler handler;
    const char* usage;
    const char* description;
} CommandEntry;

// Forward declarations
BOOL CmdWhoami(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdPwd(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdCd(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdLs(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdCat(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdHostname(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdGetuid(int argc, char* argv[], char* output, DWORD outputSize);
BOOL CmdHelp(int argc, char* argv[], char* output, DWORD outputSize);

// TODO: Define command table
CommandEntry g_CommandTable[] = {
    // TODO: Add all commands here
    // Example: {"whoami", CmdWhoami, "whoami", "Display current username"},
    {NULL, NULL, NULL, NULL}
};

/*
 * TODO: Implement command line parser
 *
 * Parse command line into argc/argv array
 */
int ParseCommandLine(char* cmdLine, char* argv[], int maxArgs) {
    // TODO: Tokenize cmdLine into argv array
    // Split on spaces/tabs, handle quotes for arguments with spaces
    // Return argc (number of arguments)

    return 0;
}

/*
 * TODO: Implement dispatcher
 *
 * Route command to appropriate handler
 */
BOOL DispatchCommand(char* cmdLine, char* output, DWORD outputSize) {
    // TODO:
    // 1. Parse command line into argc/argv
    // 2. Look up command in table
    // 3. Call handler function
    // 4. Return result

    snprintf(output, outputSize, "TODO: Implement DispatchCommand\n");
    return FALSE;
}

// ========== Command Handlers ==========

/*
 * TODO: Implement whoami command
 */
BOOL CmdWhoami(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: Get current username with GetUserNameA
    snprintf(output, outputSize, "TODO: Implement whoami\n");
    return FALSE;
}

/*
 * TODO: Implement pwd command
 */
BOOL CmdPwd(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: Get current directory with GetCurrentDirectoryA
    snprintf(output, outputSize, "TODO: Implement pwd\n");
    return FALSE;
}

/*
 * TODO: Implement cd command
 */
BOOL CmdCd(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: Change directory with SetCurrentDirectoryA
    // Validate argc >= 2 (need path argument)
    snprintf(output, outputSize, "TODO: Implement cd\n");
    return FALSE;
}

/*
 * TODO: Implement ls command
 */
BOOL CmdLs(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: List directory with FindFirstFile/FindNextFile
    // Use detailed format (type, attrs, size, date, name)
    snprintf(output, outputSize, "TODO: Implement ls\n");
    return FALSE;
}

/*
 * TODO: Implement cat command
 */
BOOL CmdCat(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: Read file contents with CreateFile/ReadFile
    // Validate argc >= 2 (need file argument)
    snprintf(output, outputSize, "TODO: Implement cat\n");
    return FALSE;
}

/*
 * TODO: Implement hostname command
 */
BOOL CmdHostname(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: Get computer name with GetComputerNameA
    snprintf(output, outputSize, "TODO: Implement hostname\n");
    return FALSE;
}

/*
 * TODO: Implement getuid command
 */
BOOL CmdGetuid(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: Get current user's SID
    // Use OpenProcessToken, GetTokenInformation, ConvertSidToStringSid
    // This is more advanced - focus on other commands first
    snprintf(output, outputSize, "TODO: Implement getuid\n");
    return FALSE;
}

/*
 * TODO: Implement help command
 */
BOOL CmdHelp(int argc, char* argv[], char* output, DWORD outputSize) {
    // TODO: List all commands from g_CommandTable
    // Format: "command - description"
    snprintf(output, outputSize, "TODO: Implement help\n");
    return FALSE;
}

int main() {
    char input[MAX_CMD_LEN] = {0};
    char output[MAX_OUTPUT] = {0};

    printf("=== Exercise 03: Full Command Dispatcher ===\n");
    printf("Type 'help' for commands, 'exit' to quit\n\n");

    while (1) {
        printf("beacon> ");

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
