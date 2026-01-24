# Cours : Windows APIs

## 1. Introduction

Les **Windows APIs** (WinAPI) permettent d'interagir avec le système d'exploitation Windows. Contrairement aux syscalls POSIX, Windows utilise une couche API riche exposée par des DLLs.

## 2. Architecture Windows

```ascii
Application
    ↓
WinAPI (kernel32.dll, user32.dll, ntdll.dll)
    ↓
Native API (ntdll.dll)
    ↓
Windows Kernel
```

## 3. Gestion de Fichiers

### Créer/Ouvrir un Fichier

```c
#include <windows.h>

HANDLE hFile = CreateFileA(
    "file.txt",
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

if (hFile == INVALID_HANDLE_VALUE) {
    printf("Erreur: %lu\n", GetLastError());
}
```

### Lire/Écrire

```c
char buffer[1024];
DWORD bytesRead;

ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL);

DWORD bytesWritten;
WriteFile(hFile, "Data", 4, &bytesWritten, NULL);

CloseHandle(hFile);
```

## 4. Processus et Threads

### Créer un Processus

```c
STARTUPINFO si = {sizeof(si)};
PROCESS_INFORMATION pi;

CreateProcessA(
    NULL,
    "notepad.exe",
    NULL, NULL, FALSE,
    0, NULL, NULL,
    &si, &pi
);

WaitForSingleObject(pi.hProcess, INFINITE);
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
```

### Créer un Thread

```c
DWORD WINAPI ThreadFunc(LPVOID param) {
    printf("Thread: %d\n", GetCurrentThreadId());
    return 0;
}

HANDLE hThread = CreateThread(
    NULL, 0,
    ThreadFunc,
    NULL, 0,
    NULL
);

WaitForSingleObject(hThread, INFINITE);
CloseHandle(hThread);
```

## 5. Mémoire

### Allocation Virtuelle

```c
LPVOID addr = VirtualAlloc(
    NULL,
    4096,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

memcpy(addr, "Data", 4);

VirtualFree(addr, 0, MEM_RELEASE);
```

### Protection Mémoire

```c
DWORD oldProtect;
VirtualProtect(
    addr,
    4096,
    PAGE_EXECUTE_READWRITE,
    &oldProtect
);
```

## 6. Registry

### Lire une Clé

```c
HKEY hKey;
RegOpenKeyExA(
    HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
    0,
    KEY_READ,
    &hKey
);

char value[256];
DWORD size = sizeof(value);
RegQueryValueExA(hKey, "ProgramFilesDir", NULL, NULL, value, &size);

RegCloseKey(hKey);
```

### Écrire une Clé

```c
RegSetValueExA(
    hKey,
    "MyValue",
    0,
    REG_SZ,
    (BYTE*)"Data",
    5
);
```

## 7. DLL Injection

### LoadLibrary

```c
HMODULE hDll = LoadLibraryA("user32.dll");
if (hDll) {
    FARPROC func = GetProcAddress(hDll, "MessageBoxA");
    FreeLibrary(hDll);
}
```

### Injection Distante

```c
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,
    FALSE,
    pid
);

LPVOID remoteAddr = VirtualAllocEx(
    hProcess,
    NULL,
    strlen(dllPath)+1,
    MEM_COMMIT,
    PAGE_READWRITE
);

WriteProcessMemory(hProcess, remoteAddr, dllPath, strlen(dllPath), NULL);

HANDLE hThread = CreateRemoteThread(
    hProcess,
    NULL, 0,
    (LPTHREAD_START_ROUTINE)LoadLibraryA,
    remoteAddr,
    0, NULL
);
```

## 8. Gestion d'Erreurs

```c
DWORD error = GetLastError();

char *message;
FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
    NULL,
    error,
    0,
    (LPSTR)&message,
    0, NULL
);

printf("Erreur: %s\n", message);
LocalFree(message);
```

## 9. Exploitation

### Process Hollowing

```c
// 1. Créer processus suspendu
CreateProcessA(..., CREATE_SUSPENDED, ...);

// 2. Unmapper section
NtUnmapViewOfSection(pi.hProcess, baseAddr);

// 3. Allouer mémoire
VirtualAllocEx(pi.hProcess, baseAddr, size, ...);

// 4. Écrire payload
WriteProcessMemory(pi.hProcess, baseAddr, payload, size, NULL);

// 5. Reprendre thread
ResumeThread(pi.hThread);
```

### Token Manipulation

```c
HANDLE hToken;
OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

// Obtenir privilèges
TOKEN_PRIVILEGES tp;
LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
tp.PrivilegeCount = 1;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
```

## 10. Persistence

### Startup Registry

```c
HKEY hKey;
RegCreateKeyExA(
    HKEY_CURRENT_USER,
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    0, NULL, 0,
    KEY_WRITE,
    NULL,
    &hKey,
    NULL
);

RegSetValueExA(hKey, "MyApp", 0, REG_SZ, path, strlen(path));
```

### Scheduled Task

```c
// Via COM ITaskScheduler
CoInitialize(NULL);
ITaskScheduler *pTS;
CoCreateInstance(&CLSID_CTaskScheduler, ...);
// ...
```

## 11. Sécurité

### ⚠️ SeDebugPrivilege

Permet d'injecter dans n'importe quel processus.

### ⚠️ ASLR Bypass

```c
HMODULE hModule = GetModuleHandleA("kernel32.dll");
printf("kernel32 base: %p\n", hModule);
```

### ⚠️ DEP Bypass

Utiliser VirtualProtect pour rendre pages exécutables.

## 12. Bonnes Pratiques

1. **Toujours** fermer les HANDLE
2. **Vérifier** retours (NULL = erreur)
3. **Utiliser** GetLastError()
4. **Éviter** hardcoded addresses
5. **Préférer** Unicode (Wide) en production

## Ressources

- [MSDN Windows API](https://docs.microsoft.com/en-us/windows/win32/api/)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/)

