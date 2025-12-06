⚠️ AVERTISSEMENT STRICT - Usage éducatif uniquement

SOLUTIONS - MODULE 26 : API HOOKING

# 
SOLUTION 1 : TRAMPOLINE COMPLÈTE

## 


```c
typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
```
MessageBoxA_t original_messagebox_trampoline = NULL;

void* create_trampoline(void* target, size_t stolen_bytes) {
    void* trampoline = VirtualAlloc(NULL, stolen_bytes + 5,
                                   MEM_COMMIT, PAGE_EXECUTE_READWRITE);


```c
    // Copier bytes volés
```
    memcpy(trampoline, target, stolen_bytes);


```c
    // JMP back vers fonction originale
```
    BYTE jmp_back[5] = { 0xE9 };
    *(DWORD*)(jmp_back + 1) = ((BYTE*)target + stolen_bytes) - ((BYTE*)trampoline + stolen_bytes) - 5;
    memcpy((BYTE*)trampoline + stolen_bytes, jmp_back, 5);

    return trampoline;
}


```c
void install_hook_with_trampoline() {
    // Créer trampoline
```
    original_messagebox_trampoline = (MessageBoxA_t)create_trampoline(MessageBoxA, 5);


```c
    // Installer hook
```
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (BYTE*)Hooked_MessageBoxA - (BYTE*)MessageBoxA - 5;

    DWORD old;
    VirtualProtect(MessageBoxA, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(MessageBoxA, jmp, 5);
    VirtualProtect(MessageBoxA, 5, old, &old);
}

int WINAPI Hooked_MessageBoxA(...) {
    printf("[HOOK] Intercepted\n");

```c
    // Appeler via trampoline
    return original_messagebox_trampoline(hWnd, lpText, lpCaption, uType);
}
```


## 
SOLUTION 3 : API UNHOOKING (PERUN'S FART)

## 

BOOL unhook_ntdll() {

```c
    // Charger ntdll.dll propre depuis disk
```
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                              GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID clean_ntdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);


```c
    // Obtenir hooked ntdll
```
    HMODULE hooked_ntdll = GetModuleHandleA("ntdll.dll");


```c
    // Comparer .text section
```
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)clean_ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)clean_ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            DWORD old;
            VirtualProtect((BYTE*)hooked_ntdll + sections[i].VirtualAddress,
                          sections[i].Misc.VirtualSize,
                          PAGE_EXECUTE_READWRITE, &old);


```c
            // Restaurer bytes originaux
```
            memcpy((BYTE*)hooked_ntdll + sections[i].VirtualAddress,
                  (BYTE*)clean_ntdll + sections[i].VirtualAddress,
                  sections[i].Misc.VirtualSize);

            VirtualProtect((BYTE*)hooked_ntdll + sections[i].VirtualAddress,
                          sections[i].Misc.VirtualSize, old, &old);
            break;
        }
    }

    UnmapViewOfFile(clean_ntdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("[+] ntdll.dll unhooked\n");
    return TRUE;
}

# 
SOLUTION 6 : HARDWARE BREAKPOINT HOOK

## 

LONG WINAPI VEH_Handler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

```c
        // Vérifier si c'est notre breakpoint
```
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)MessageBoxA) {
            printf("[HWBP HOOK] MessageBoxA intercepted\n");


```c
            // Modifier arguments
```
            ExceptionInfo->ContextRecord->Rdx = (DWORD64)"[HOOKED] Text";

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


```c
void install_hwbp_hook(void* target) {
```
    AddVectoredExceptionHandler(1, VEH_Handler);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);


```c
    // Dr0 = address to break on
```
    ctx.Dr0 = (DWORD64)target;

```c
    // Dr7 = enable Dr0
```
    ctx.Dr7 = 0x1;

    SetThreadContext(GetCurrentThread(), &ctx);
}

Référence : Polyhook, Detours, MinHook projects

