# Week 6: Memory Operations

## Overview

This week is **CRITICAL** for malware development. You'll learn the foundation of all shellcode execution and process injection techniques. Memory operations are at the core of offensive tooling.

### Why This Week Matters

- **Foundation of Process Injection**: Every injection technique uses these APIs
- **Shellcode Execution**: Essential for in-memory payload delivery
- **Evasion Techniques**: Understanding memory protections helps bypass EDR/AV
- **Real-World Application**: Used in every modern offensive tool

### Topics Covered

1. **VirtualAlloc** - Memory allocation with fine-grained control
2. **VirtualProtect** - Changing memory protections (stealth patterns)
3. **ReadProcessMemory/WriteProcessMemory** - Cross-process memory access (intro)
4. **Local Shellcode Execution** - Putting it all together

## Learning Objectives

By the end of this week, you will:

- Master VirtualAlloc and understand allocation types (MEM_COMMIT, MEM_RESERVE)
- Implement the RW->RX pattern for stealthy shellcode execution
- Understand why RWX is suspicious and should be avoided
- Execute shellcode using multiple methods (function pointer, CreateThread, callbacks)
- Read and write process memory (foundation for Week 8)
- Use VirtualQuery to inspect memory characteristics

## File Structure

```
Week-06-Memory-Operations/
├── Lessons/
│   ├── 01-virtualalloc.c          # VirtualAlloc, allocation types
│   ├── 02-virtualprotect.c        # Protection changes, RW->RX pattern
│   ├── 03-memory-rw.c             # ReadProcessMemory/WriteProcessMemory
│   └── 04-shellcode-local.c       # Complete shellcode execution
├── Exercises/
│   ├── ex01-alloc-buffer.c        # Practice VirtualAlloc
│   ├── ex02-rwx-transition.c      # Implement RW->RX pattern
│   └── ex03-run-shellcode.c       # Execute shellcode locally
├── Solutions/
│   ├── ex01-alloc-buffer-solution.c
│   ├── ex02-rwx-transition-solution.c
│   └── ex03-run-shellcode-solution.c
├── quiz.json                      # 10 questions on memory operations
├── build.bat                      # Build script
└── README.md                      # This file
```

## Lessons

### Lesson 01: VirtualAlloc

Learn the primary Windows API for memory allocation.

**Key Concepts:**
- MEM_COMMIT vs MEM_RESERVE
- Memory protection constants (PAGE_*)
- VirtualQuery for memory inspection
- Typical maldev allocation patterns

**Critical APIs:**
```c
LPVOID VirtualAlloc(
    LPVOID lpAddress,        // NULL = let system choose
    SIZE_T dwSize,           // Size in bytes
    DWORD  flAllocationType, // MEM_COMMIT | MEM_RESERVE
    DWORD  flProtect         // PAGE_READWRITE, etc.
);
```

**Run:**
```batch
cl /Fe:01-virtualalloc.exe Lessons\01-virtualalloc.c
01-virtualalloc.exe
```

### Lesson 02: VirtualProtect

Master changing memory protections for stealth.

**Key Concepts:**
- RW->RX pattern (industry standard)
- Why RWX is a red flag
- PAGE_GUARD for anti-debugging
- Multiple region protection

**Critical APIs:**
```c
BOOL VirtualProtect(
    LPVOID lpAddress,      // Address to modify
    SIZE_T dwSize,         // Size in bytes
    DWORD  flNewProtect,   // New protection
    PDWORD lpflOldProtect  // Receives old protection
);
```

**Stealth Pattern:**
```c
// BAD: Direct RWX (very suspicious)
VirtualAlloc(..., PAGE_EXECUTE_READWRITE);

// GOOD: RW->RX transition (stealthy)
pMem = VirtualAlloc(..., PAGE_READWRITE);
memcpy(pMem, shellcode, size);
VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &old);
```

**Run:**
```batch
cl /Fe:02-virtualprotect.exe Lessons\02-virtualprotect.c
02-virtualprotect.exe
```

### Lesson 03: Memory Read/Write

Introduction to cross-process memory operations.

**Key Concepts:**
- Reading own process memory
- Reading PEB (Process Environment Block)
- Memory pattern searching
- Remote process access (intro - full coverage in Week 8)

**Critical APIs:**
```c
BOOL ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesRead
);

BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);
```

**Run:**
```batch
cl /Fe:03-memory-rw.exe Lessons\03-memory-rw.c
03-memory-rw.exe
```

### Lesson 04: Local Shellcode Execution

Complete workflow for executing shellcode.

**Key Concepts:**
- Position-independent code (PIC)
- Multiple execution methods
- Safe shellcode for testing
- MessageBox shellcode demo

**Execution Methods:**
1. **Function Pointer** - Direct call (simple)
2. **CreateThread** - Dedicated thread (common)
3. **Callbacks** - EnumWindows, etc. (stealthy)
4. **Fibers** - Cooperative multitasking (advanced)
5. **APC** - Asynchronous Procedure Call (advanced)

**Complete Pattern:**
```c
// 1. Allocate RW
pMem = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

// 2. Copy shellcode
memcpy(pMem, shellcode, size);

// 3. Change to RX
VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &old);

// 4. Execute
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
```

**Run:**
```batch
cl /Fe:04-shellcode-local.exe Lessons\04-shellcode-local.c
04-shellcode-local.exe
```

## Exercises

### Exercise 01: Allocate Buffer

Practice VirtualAlloc and memory verification.

**Tasks:**
1. Allocate 8KB buffer
2. Fill with repeating pattern
3. Use VirtualQuery to inspect
4. Verify pattern correctness
5. Clean up properly

**Run:**
```batch
cl /Fe:ex01.exe Exercises\ex01-alloc-buffer.c
ex01.exe
```

### Exercise 02: RW->RX Transition

Implement the stealth pattern used in real malware.

**Tasks:**
1. Allocate PAGE_READWRITE
2. Copy simulated shellcode
3. Change to PAGE_EXECUTE_READ
4. Compare to direct RWX
5. Understand stealth benefits

**Run:**
```batch
cl /Fe:ex02.exe Exercises\ex02-rwx-transition.c
ex02.exe
```

### Exercise 03: Run Shellcode

Execute shellcode using multiple methods.

**Tasks:**
1. Implement PrepareShellcode() function
2. Execute via function pointer
3. Execute via CreateThread
4. Handle errors properly
5. Clean up memory

**Run:**
```batch
cl /Fe:ex03.exe Exercises\ex03-run-shellcode.c
ex03.exe
```

## Key Concepts

### Memory Protection Constants

```c
PAGE_NOACCESS           // No access (0x01)
PAGE_READONLY           // Read only (0x02)
PAGE_READWRITE          // Read + Write (0x04)
PAGE_EXECUTE            // Execute only (0x10)
PAGE_EXECUTE_READ       // Execute + Read (0x20)
PAGE_EXECUTE_READWRITE  // Execute + Read + Write (RWX - suspicious!) (0x40)

// Special flags
PAGE_GUARD              // One-time exception on access (0x100)
PAGE_NOCACHE            // Disable caching (0x200)
PAGE_WRITECOMBINE       // Write-combined memory (0x400)
```

### Memory Allocation Types

```c
MEM_COMMIT    // Allocate physical memory (0x1000)
MEM_RESERVE   // Reserve address space only (0x2000)
MEM_RESET     // Reset memory contents (0x80000)

// Deallocation
MEM_DECOMMIT  // Decommit physical memory (0x4000)
MEM_RELEASE   // Release entire allocation (0x8000)
```

### Memory States (VirtualQuery)

```c
MEM_COMMIT   // Physical memory allocated
MEM_RESERVE  // Address space reserved
MEM_FREE     // Not allocated or reserved
```

### Memory Types (VirtualQuery)

```c
MEM_PRIVATE  // Private memory (VirtualAlloc)
MEM_MAPPED   // Mapped memory (file mapping)
MEM_IMAGE    // Executable image (PE file)
```

## Stealth Considerations

### RWX vs RW->RX

**RWX (AVOID):**
- Immediate red flag for EDR/AV
- Allows self-modifying code
- Uncommon in legitimate software
- High detection rate

**RW->RX (RECOMMENDED):**
- Mimics JIT compilation
- Never simultaneously writable and executable
- Lower detection rate
- Industry best practice

**RW + Callback (ADVANCED):**
- No executable protection needed
- Execute via legitimate API callbacks
- Very stealthy
- Requires careful implementation

## Building Examples

### Compile All Lessons

```batch
cl /Fe:01-virtualalloc.exe Lessons\01-virtualalloc.c
cl /Fe:02-virtualprotect.exe Lessons\02-virtualprotect.c
cl /Fe:03-memory-rw.exe Lessons\03-memory-rw.c
cl /Fe:04-shellcode-local.exe Lessons\04-shellcode-local.c
```

### Compile All Exercises

```batch
cl /Fe:ex01.exe Exercises\ex01-alloc-buffer.c
cl /Fe:ex02.exe Exercises\ex02-rwx-transition.c
cl /Fe:ex03.exe Exercises\ex03-run-shellcode.c
```

### Or use build.bat

```batch
build.bat
```

## Common Issues & Solutions

### Issue: VirtualAlloc returns NULL

**Causes:**
- Insufficient memory available
- Invalid size (too large)
- Invalid protection constant

**Solution:**
- Check GetLastError()
- Verify size is reasonable
- Ensure protection constant is valid

### Issue: VirtualProtect fails

**Causes:**
- Invalid protection transition
- Address not allocated
- Size exceeds region

**Solution:**
- Check old protection is being saved
- Verify address is from VirtualAlloc
- Ensure size matches allocation

### Issue: Shellcode crashes

**Causes:**
- Not position-independent
- Missing RET instruction
- Incorrect calling convention
- Memory not executable

**Solution:**
- Use PIC shellcode
- Verify protection is RX or RWX
- Test with simple NOP+RET first
- Check with debugger

## Real-World Applications

### Offensive Security
- **Process Injection** - Inject DLLs or shellcode into remote processes
- **Reflective Loading** - Load DLLs from memory without disk
- **Staged Payloads** - Download and execute second-stage in memory
- **Fileless Malware** - Execute entirely in memory

### Red Team Operations
- **In-Memory Execution** - Avoid disk artifacts
- **Custom Loaders** - Bypass AV signatures
- **Memory-Resident Implants** - Persistent memory-only agents
- **Evasion Techniques** - Bypass memory scanners

### Malware Analysis (Defensive)
- **Memory Forensics** - Analyze memory-resident threats
- **Shellcode Detection** - Identify executable allocations
- **Behavior Monitoring** - Track suspicious memory operations
- **YARA Rules** - Write rules for memory patterns

## Next Steps

### Week 7: DLLs and Modules
- LoadLibrary/GetProcAddress
- DLL injection basics
- Manual mapping
- Module enumeration

### Week 8: Process Injection
- Classic DLL injection
- Process hollowing
- APC injection
- Thread hijacking

### Advanced Topics (Later)
- Direct syscalls (bypass EDR hooks)
- Process Doppelgänging
- Transacted Hollowing
- Module stomping

## Resources

### Microsoft Documentation
- [VirtualAlloc function](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualProtect function](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory Protection Constants](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [VirtualQuery function](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)

### Books
- Windows Internals (Part 1) - Memory Management
- The Shellcoder's Handbook
- Practical Malware Analysis

### Tools
- **x64dbg** - Debug shellcode execution
- **Process Hacker** - View memory regions
- **VMMap** - Sysinternals memory analyzer
- **msfvenom** - Generate test shellcode

## Testing Environment

**Recommended Setup:**
- Windows 10/11 VM (for testing)
- Visual Studio or Build Tools
- x64dbg for debugging
- Process Hacker for memory inspection

**Safety Notes:**
- Test only in isolated VMs
- Use safe shellcode (NOP+RET) for learning
- Understand what your shellcode does
- Never test on production systems

## Assessment

Complete the quiz (quiz.json) to test your understanding:
- 10 questions on memory operations
- Covers VirtualAlloc, VirtualProtect, memory protections
- Passing score: 70%

## Summary

This week provides the **foundation for all offensive memory operations**. Master these concepts:

1. VirtualAlloc for memory allocation
2. VirtualProtect for changing protections
3. RW->RX pattern for stealth
4. Multiple shellcode execution methods
5. Proper error handling and cleanup

**You cannot progress in malware development without mastering this material.**

## Disclaimer

This material is for **educational purposes only**. Understanding these techniques is essential for:
- Security researchers
- Malware analysts
- Red team operators
- Security tool developers

**Use responsibly and legally.**
