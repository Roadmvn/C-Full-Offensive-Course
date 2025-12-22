# Week 11: Command Execution

## Overview

This week focuses on implementing command execution capabilities for beacon/implant development. You'll learn how to execute commands, capture their output, and build a robust command dispatcher pattern.

## Learning Objectives

By the end of this week, you will:

- Execute Windows commands and capture their output using pipes
- Implement filesystem commands (pwd, cd, ls) using Windows API
- Read file contents without spawning external processes
- Build a command dispatcher architecture
- Handle command parsing and routing
- Manage output buffers efficiently
- Implement proper error handling for commands

## Core Concepts

### 1. Command Execution with Output Capture

**Key Components:**
- Anonymous pipes for IPC (Inter-Process Communication)
- Handle redirection (stdout/stderr -> pipe)
- Process creation with `CreateProcessA`
- Non-blocking output reading

**Pattern:**
```c
CreatePipe(&hRead, &hWrite, &sa, 0);
si.hStdOutput = hWrite;
si.hStdError = hWrite;
si.dwFlags |= STARTF_USESTDHANDLES;
CreateProcessA(..., CREATE_NO_WINDOW, ...);
ReadFile(hRead, buffer, size, &bytesRead, NULL);
```

### 2. Filesystem Commands

**Direct API Implementation:**
- `whoami`: GetUserNameA
- `pwd`: GetCurrentDirectoryA
- `cd`: SetCurrentDirectoryA
- `ls`: FindFirstFile/FindNextFile
- `cat`: CreateFile/ReadFile

**Benefits:**
- No cmd.exe spawning (better stealth)
- Faster execution
- Full control over output format
- Reduced detection surface

### 3. Command Dispatcher Pattern

**Architecture:**
```c
Command Table: name -> handler function
Parser: cmdLine -> argc/argv
Dispatcher: route to handler
Handler: execute and return output
```

**Advantages:**
- Extensible (easy to add commands)
- Maintainable code organization
- Consistent error handling
- Uniform output format

## Directory Structure

```
Week-11-Command-Execution/
├── Lessons/
│   ├── 01-cmd-whoami.c          # Execute whoami, capture output
│   ├── 02-cmd-filesystem.c      # pwd, cd, ls implementations
│   ├── 03-cmd-cat.c             # File reading
│   └── 04-dispatcher.c          # Full command dispatcher
├── Exercises/
│   ├── ex01-capture-output.c    # Capture arbitrary command output
│   ├── ex02-implement-ls.c      # Detailed ls implementation
│   └── ex03-full-dispatcher.c   # Complete dispatcher with all commands
├── Solutions/
│   ├── sol01-capture-output.c
│   ├── sol02-implement-ls.c
│   └── sol03-full-dispatcher.c
├── quiz.json
├── build.bat
└── README.md
```

## Lessons

### Lesson 01: Command Execution - whoami

**File:** `Lessons/01-cmd-whoami.c`

**Topics:**
- CreatePipe for output capture
- SECURITY_ATTRIBUTES and handle inheritance
- STARTUPINFO configuration for redirection
- Process creation with CREATE_NO_WINDOW
- Reading from pipe until end-of-pipe

**Key APIs:**
- `CreatePipe()`
- `SetHandleInformation()`
- `CreateProcessA()`
- `WaitForSingleObject()`
- `ReadFile()`

### Lesson 02: Filesystem Commands

**File:** `Lessons/02-cmd-filesystem.c`

**Topics:**
- Current directory operations (pwd/cd)
- Directory enumeration (ls)
- WIN32_FIND_DATA structure
- File attribute checking

**Key APIs:**
- `GetCurrentDirectoryA()`
- `SetCurrentDirectoryA()`
- `FindFirstFileA()`
- `FindNextFileA()`
- `FindClose()`

### Lesson 03: File Reading - cat

**File:** `Lessons/03-cmd-cat.c`

**Topics:**
- File opening for reading
- File size validation
- Chunked reading for large files
- Binary vs text handling

**Key APIs:**
- `CreateFileA()`
- `GetFileSize()`
- `ReadFile()`
- `CloseHandle()`

### Lesson 04: Command Dispatcher

**File:** `Lessons/04-dispatcher.c`

**Topics:**
- Command table design
- Command parsing (tokenization)
- Function pointers for handlers
- Command routing logic
- Interactive command loop

**Pattern:**
```c
typedef BOOL (*CommandHandler)(int argc, char* argv[], char* output, DWORD outputSize);

typedef struct {
    const char* name;
    CommandHandler handler;
    const char* description;
} Command;
```

## Exercises

### Exercise 01: Capture Command Output

**File:** `Exercises/ex01-capture-output.c`

**Objective:** Implement `ExecuteCommand()` to capture output from arbitrary Windows commands.

**Requirements:**
- Execute any command passed as parameter
- Capture both stdout and stderr
- Implement timeout (don't hang on long commands)
- Handle errors gracefully

**Test Cases:**
- `ipconfig /all`
- `systeminfo`
- `net user`
- Invalid command

### Exercise 02: Implement ls Command

**File:** `Exercises/ex02-implement-ls.c`

**Objective:** Create a full-featured ls implementation.

**Requirements:**
- List files in specified directory
- Show file attributes (rhsa flags)
- Display file sizes (human-readable format)
- Show modification times
- Format output in columns

**Output Format:**
```
Type Attrs Size      Modified         Name
---- ---- --------- ---------------- ----
d    ----  4096     2024-01-15 10:30  Documents
-    r-s-  2048     2024-01-15 09:15  config.sys
```

### Exercise 03: Full Command Dispatcher

**File:** `Exercises/ex03-full-dispatcher.c`

**Objective:** Build a complete command dispatcher with multiple commands.

**Commands to Implement:**
- `whoami` - Current username
- `pwd` - Current directory
- `cd <path>` - Change directory
- `ls [path]` - List directory
- `cat <file>` - Read file
- `hostname` - Computer name
- `getuid` - User SID
- `help` - List commands

## Building and Running

### Compile All Files

```batch
build.bat
```

### Compile Individual Files

```batch
cl /nologo /W4 Lessons\01-cmd-whoami.c
cl /nologo /W4 Lessons\02-cmd-filesystem.c
cl /nologo /W4 Lessons\03-cmd-cat.c
cl /nologo /W4 Lessons\04-dispatcher.c
```

### Run Examples

```batch
Lessons\01-cmd-whoami.exe
Lessons\02-cmd-filesystem.exe
Lessons\03-cmd-cat.exe
Lessons\04-dispatcher.exe
```

## Important Concepts

### Pipe Communication

**Anonymous Pipe:**
- One-way communication channel
- Created with CreatePipe
- Returns read and write handles
- Write handle inherited by child
- Read handle used by parent

**Key Considerations:**
- Close write handle in parent after process creation
- Read handle should NOT be inherited
- Read until ERROR_BROKEN_PIPE
- Implement timeouts to prevent hangs

### Process Creation Flags

**CREATE_NO_WINDOW:**
- Prevents console window
- Essential for stealth
- Process runs hidden

**Handle Inheritance:**
- `bInheritHandles = TRUE` required for pipe redirection
- Only mark specific handles as inheritable
- Use `SetHandleInformation()` to control inheritance

### Command Parsing

**Simple Tokenization:**
```c
strtok_s(cmdLine, " \t\n", &context)
```

**Advanced Parsing:**
- Handle quoted arguments
- Escape sequences
- Multiple spaces
- Special characters

### Output Buffer Management

**Best Practices:**
- Pre-allocate sufficient buffer size
- Track remaining space
- Prevent buffer overflows
- Null-terminate strings
- Handle truncation gracefully

## Security Considerations

### Stealth

1. **Avoid cmd.exe**
   - Use Windows API instead
   - Reduces process creation alerts
   - Lower detection surface

2. **Hidden Processes**
   - CREATE_NO_WINDOW flag
   - No visible windows
   - Silent execution

3. **Output Sanitization**
   - Remove sensitive information
   - Limit output size
   - Filter command errors

### Error Handling

1. **Graceful Failures**
   - Never crash on invalid input
   - Return error messages
   - Clean up resources

2. **Resource Management**
   - Close all handles
   - Free allocated memory
   - Prevent resource leaks

## Common Pitfalls

### 1. Forgetting to Close Write Pipe in Parent

**Problem:** ReadFile never detects end-of-pipe

**Solution:**
```c
CreateProcessA(...);
CloseHandle(hWritePipe);  // Essential!
ReadFile(hReadPipe, ...);
```

### 2. Inheriting Read Handle

**Problem:** Pipe remains open, ReadFile hangs

**Solution:**
```c
SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
```

### 3. No Timeout on Wait

**Problem:** Beacon hangs on long-running commands

**Solution:**
```c
WaitForSingleObject(pi.hProcess, 30000);  // 30 second timeout
```

### 4. Buffer Overflow

**Problem:** Output larger than buffer

**Solution:**
```c
while (remaining > 0) {
    DWORD toRead = min(remaining, CHUNK_SIZE);
    ReadFile(hPipe, ptr, toRead, &read, NULL);
    remaining -= read;
}
```

## Advanced Topics

### Non-Blocking I/O

Use overlapped I/O for non-blocking reads:
```c
OVERLAPPED ol = {0};
ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
ReadFile(hPipe, buffer, size, NULL, &ol);
WaitForSingleObject(ol.hEvent, timeout);
```

### Command Aliases

```c
typedef struct {
    const char* alias;
    const char* command;
} Alias;

Alias aliases[] = {
    {"dir", "ls"},
    {"type", "cat"},
    ...
};
```

### Shell Operators

Implement pipe, redirect, etc.:
- `command1 | command2`
- `command > file.txt`
- `command >> file.txt`

## Integration with Beacon

### Typical Beacon Flow

1. Receive command from C2
2. Parse command string
3. Dispatch to handler
4. Capture output
5. Send output to C2
6. Clean up resources

### Example Integration

```c
BOOL BeaconExecuteCommand(char* cmd, char** output, DWORD* outputSize) {
    *output = (char*)malloc(MAX_OUTPUT);
    return DispatchCommand(cmd, *output, MAX_OUTPUT);
}
```

## Testing Strategy

### Unit Testing

- Test each command handler independently
- Verify output format
- Test error conditions
- Check resource cleanup

### Integration Testing

- Test dispatcher with all commands
- Verify command parsing
- Test command chains
- Validate output buffering

### Edge Cases

- Empty input
- Invalid commands
- Missing arguments
- File/directory not found
- Access denied
- Output buffer overflow

## Next Steps

After completing this week:

1. Integrate command execution into your beacon
2. Add more specialized commands (ps, kill, etc.)
3. Implement command queueing
4. Add result caching
5. Continue to Week 12: Final Beacon Assembly

## Resources

### Windows API Documentation

- [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
- [CreatePipe](https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [FindFirstFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilea)

### Related Concepts

- Inter-Process Communication (IPC)
- Process creation and management
- File system operations
- Command-line parsing

## Quiz

Complete the quiz in `quiz.json` to test your understanding of command execution concepts.

**Topics Covered:**
- Pipe creation and management
- Process creation flags
- Handle inheritance
- Directory enumeration
- Command dispatcher patterns
- Error handling
- Stealth considerations

---

**Remember:** Command execution is a core capability of any beacon. Focus on stealth, reliability, and proper resource management.
