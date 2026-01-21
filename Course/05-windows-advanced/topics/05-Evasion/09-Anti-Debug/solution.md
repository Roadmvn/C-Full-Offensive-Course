SOLUTIONS - MODULE 30 : ANTI-DEBUGGING

⚠️ AVERTISSEMENT : Techniques pour compréhension défensive uniquement.

SOLUTION 1 : PEB ANTI-DEBUG COMPLET

Accès PEB x64 :
PPEB peb = (PPEB)__readgsqword(0x60);

Checks :
1. BeingDebugged : peb->BeingDebugged
2. NtGlobalFlag : peb->NtGlobalFlag & 0x70  // FLG_HEAP_* flags
3. ProcessHeap Flags :
   peb->ProcessHeap->Flags != HEAP_GROWABLE
   peb->ProcessHeap->ForceFlags != 0

Bypass : Patch PEB manuellement, ScyllaHide auto-patch


SOLUTION 2 : TIMING CHECKS


### RDTSC :
start = __rdtsc();
operation();
end = __rdtsc();
if ((end - start) > threshold) exit();

QueryPerformanceCounter :
LARGE_INTEGER start, end, freq;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&start);
operation();
QueryPerformanceCounter(&end);
delta = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;

Sleep timing :
DWORD start = GetTickCount();
Sleep(1000);
DWORD actual = GetTickCount() - start;
if (actual > 1100) debugger_present();

Bypass : Patch RDTSC (NOP), hook timing APIs


SOLUTION 3 : NTQUERYINFORMATIONPROCESS


```c
typedef NTSTATUS (WINAPI *NtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
```
NtQIP pNtQIP = GetProcAddress(GetModuleHandle("ntdll"), "NtQueryInformationProcess");

ProcessDebugPort (7) :
DWORD_PTR debugPort;
pNtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) debugger();

ProcessDebugObjectHandle (30) :
HANDLE debugObject;
status = pNtQIP(GetCurrentProcess(), 30, &debugObject, sizeof(debugObject), NULL);
if (status == STATUS_SUCCESS) debugger();

ProcessDebugFlags (31) :
DWORD noDebugInherit;
pNtQIP(GetCurrentProcess(), 31, &noDebugInherit, sizeof(noDebugInherit), NULL);
if (noDebugInherit == 0) debugger();

Bypass : Hook NtQueryInformationProcess, return fake values


SOLUTION 4 : HARDWARE BREAKPOINTS

CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);

if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) {

```c
    // Hardware breakpoints présents
```
    debugger_detected();
}


```c
// DR7 contient enabled flags
```
if (ctx.Dr7 & 0xFF) {
    debugger_detected();
}

Clear hardware BP :
ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
ctx.Dr6 = ctx.Dr7 = 0;
SetThreadContext(GetCurrentThread(), &ctx);

Bypass : Hook GetThreadContext, return zeroed DR


SOLUTION 5 : INT 2D / INT3

INT 2D (kernel debugger check) :
__try {
    __asm int 2Dh
} __except(EXCEPTION_EXECUTE_HANDLER) {

```c
    // Exception si kernel debugger
```
    debugger_detected();
}

INT 3 timing :
start = __rdtsc();
__asm int 3  // 0xCC
end = __rdtsc();
if ((end - start) < 1000) debugger();  // Intercepté rapidement

SEH-based :
__try {
    *(int*)0 = 0;  // Access violation
} __except(EXCEPTION_EXECUTE_HANDLER) {

```c
    // Normal
}
// Si debugger : exception interceptée, handler pas appelé
```

Bypass : NOP int instructions, configure debugger exception passing


SOLUTION 6 : LINUX ANTI-DEBUG

ptrace check :
if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {

```c
    // errno == EPERM, déjà tracé
```
    exit(1);
}

TracerPid check :
FILE* f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int tracer = atoi(line + 10);
        if (tracer != 0) exit(1);
    }
}

LD_PRELOAD detection :
if (getenv("LD_PRELOAD")) exit(1);

Parent process :
int ppid = getppid();
char path[256];
snprintf(path, sizeof(path), "/proc/%d/cmdline", ppid);

```c
// Lire cmdline, chercher "gdb", "lldb"
```

Bypass : LD_PRELOAD anti-ptrace library, hide TracerPid


SOLUTION 7 : SCYLLAHIDE DETECTION

Pattern matching hooks :
FARPROC addr = GetProcAddress(GetModuleHandle("kernel32"), "IsDebuggerPresent");

```c
// Vérifier si premiers bytes = jmp (0xE9) au lieu de prologue normal
```

PEB patch detection :
PPEB peb = get_peb();

```c
// Lire valeur, sleep(100ms), relire
// Si changé entre temps : ScyllaHide actif
```

TitanHide driver :
HANDLE h = CreateFile("\\\\.\\TitanHide", ...);
if (h != INVALID_HANDLE_VALUE) exit(1);

Checksum code :
uint32_t checksum = crc32(IsDebuggerPresent, 20);
if (checksum != expected) patched();

Bypass : Detect-detect-detect loops, stealthier hooks


SOLUTION 8 : MULTI-LAYER PROTECTION

Architecture :

```c
void anti_debug_layer1() { PEB checks }
void anti_debug_layer2() { Timing checks }
void anti_debug_layer3() { Hardware BP }
void anti_debug_layer4() { NtQuery checks }
```

Random ordering :
int checks[] = {1, 2, 3, 4};
shuffle(checks);
for (int i : checks) run_check(i);

Delayed checks :
CreateThread(NULL, 0, delayed_check_thread, NULL, 0, NULL);

```c
// Thread vérifie périodiquement
```

Code integrity :
uint32_t expected = 0xABCD1234;
uint32_t actual = crc32(main_function, size);
if (actual != expected) exit();  // Code patched

Détection : Behavioral analysis, emulation, kernel debugging

RÉFÉRENCES :
- "Practical Malware Analysis" Chapter 16
- ScyllaHide source code (bypass examples)
- Al-Khaser anti-debug techniques
- CheckPoint anti-debug tricks
- Unprotect.it database

