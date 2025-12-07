# Solutions - NTDLL Internals et Syscalls

## Note

Documentation des mécanismes de syscalls Windows pour la compréhension des couches système et l'analyse de sécurité.

---

## Exercice 1 : Extraire SSN depuis ntdll (Hell's Gate)

```c
#include <windows.h>
#include <stdio.h>

// Extraire System Service Number depuis stub ntdll
DWORD extract_ssn(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -1;

    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return -1;

    BYTE* pStub = (BYTE*)pFunc;

    // Pattern x64: 4C 8B D1 B8 [SSN] 00 00 00 0F 05 C3
    // Offset 0: 4C 8B D1       mov r10, rcx
    // Offset 3: B8 XX 00 00 00 mov eax, SSN
    // Offset 8: 0F 05          syscall
    // Offset A: C3             ret

    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1 &&
        pStub[3] == 0xB8) {
        // SSN à offset +4 (DWORD little-endian)
        DWORD ssn = *(DWORD*)(pStub + 4);
        return ssn;
    }

    // Si pattern différent = potentiellement hookée
    printf("[!] Pattern non standard pour %s (hookée ?)\n", functionName);
    return -1;
}

int main() {
    printf("=== EXTRACTION SSN ===\n\n");

    const char* functions[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtOpenProcess",
        "NtClose",
        NULL
    };

    for (int i = 0; functions[i] != NULL; i++) {
        DWORD ssn = extract_ssn(functions[i]);
        if (ssn != -1) {
            printf("%-30s SSN = 0x%04X (%d)\n", functions[i], ssn, ssn);
        } else {
            printf("%-30s FAILED\n", functions[i]);
        }
    }

    return 0;
}
```

**Résultat attendu (Windows 10 20H2 x64)** :
```
=== EXTRACTION SSN ===

NtAllocateVirtualMemory        SSN = 0x0018 (24)
NtProtectVirtualMemory         SSN = 0x0050 (80)
NtCreateThreadEx               SSN = 0x00C2 (194)
NtWriteVirtualMemory           SSN = 0x003A (58)
NtReadVirtualMemory            SSN = 0x003F (63)
NtOpenProcess                  SSN = 0x0026 (38)
NtClose                        SSN = 0x000F (15)
```

---

## Exercice 2 : Détecter hooks dans ntdll

```c
BOOL is_function_hooked(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);

    if (!pFunc) return FALSE;

    BYTE* pStub = (BYTE*)pFunc;

    // Pattern normal x64: 4C 8B D1 B8 ...
    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1) {
        return FALSE; // Pas hookée
    }

    // Patterns de hook courants:
    // E9 XX XX XX XX       jmp rel32
    // FF 25 XX XX XX XX    jmp [rip+offset]
    // 68 XX XX XX XX C3    push addr; ret

    if (pStub[0] == 0xE9 || pStub[0] == 0xFF || pStub[0] == 0x68) {
        return TRUE; // Hookée !
    }

    return FALSE;
}

void scan_ntdll_hooks() {
    printf("\n=== SCAN HOOKS NTDLL ===\n\n");

    const char* critical_functions[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtQueueApcThread",
        "NtOpenProcess",
        NULL
    };

    int hooked_count = 0;

    for (int i = 0; critical_functions[i] != NULL; i++) {
        BOOL hooked = is_function_hooked(critical_functions[i]);
        printf("%-30s : %s\n",
               critical_functions[i],
               hooked ? "[HOOKED]" : "[CLEAN]");

        if (hooked) hooked_count++;
    }

    printf("\n%d/%d fonctions hookées\n", hooked_count, i);

    if (hooked_count > 0) {
        printf("[!] EDR/AV détecté !\n");
    }
}
```

---

## Exercice 3 : Heaven's Gate (ntdll propre depuis disque)

```c
DWORD get_ssn_heaven_gate(const char* functionName) {
    printf("[*] Extraction via Heaven's Gate pour %s\n", functionName);

    // 1. Mapper ntdll.dll propre depuis disque
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur ouverture ntdll.dll\n");
        return -1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // 2. Trouver fonction dans ntdll propre
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDos->e_lfanew);

    DWORD exportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pCleanNtdll + exportRVA);

    DWORD* addressTable = (DWORD*)((BYTE*)pCleanNtdll + pExport->AddressOfFunctions);
    DWORD* nameTable = (DWORD*)((BYTE*)pCleanNtdll + pExport->AddressOfNames);
    WORD* ordinalTable = (WORD*)((BYTE*)pCleanNtdll + pExport->AddressOfNameOrdinals);

    DWORD ssn = -1;

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)pCleanNtdll + nameTable[i]);

        if (strcmp(name, functionName) == 0) {
            WORD ordinal = ordinalTable[i];
            DWORD funcRVA = addressTable[ordinal];
            BYTE* pFunc = (BYTE*)pCleanNtdll + funcRVA;

            // Extraire SSN depuis ntdll propre (non hookée)
            if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
                ssn = *(DWORD*)(pFunc + 4);
            }
            break;
        }
    }

    // Cleanup
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("[+] SSN extrait : 0x%04X\n", ssn);
    return ssn;
}
```

---

## Exercice 4 : Syscall direct (ASM stub)

**Fichier syscall_stub.asm** (assembleur x64) :
```asm
.code

; NTSTATUS SyscallStub(DWORD ssn, ...)
SyscallStub proc
    mov r10, rcx          ; Sauvegarder RCX (1er param = SSN)
    mov eax, r10d         ; Charger SSN dans EAX

    ; Arguments déjà dans les bons registres par calling convention x64:
    ; RDX = arg1
    ; R8 = arg2
    ; R9 = arg3
    ; [RSP+XX] = arg4+

    syscall               ; Transition vers kernel
    ret
SyscallStub endp

end
```

**Utilisation en C** :
```c
extern NTSTATUS SyscallStub(DWORD ssn, ...);

void test_direct_syscall() {
    // 1. Extraire SSN
    DWORD ssn = extract_ssn("NtAllocateVirtualMemory");
    printf("[+] SSN = 0x%04X\n", ssn);

    // 2. Paramètres
    HANDLE hProcess = (HANDLE)-1; // Current process
    PVOID baseAddr = NULL;
    SIZE_T regionSize = 0x1000;

    // 3. Appeler syscall direct
    NTSTATUS status = SyscallStub(
        ssn,
        hProcess,
        &baseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
        0,
        0
    );

    if (status == 0) {
        printf("[+] Mémoire allouée à : 0x%p\n", baseAddr);
    } else {
        printf("[-] Échec : NTSTATUS = 0x%08X\n", status);
    }
}
```

**Compilation** :
```batch
ml64 /c syscall_stub.asm
cl solution.c syscall_stub.obj /Fe:syscalls.exe
```

---

## Points clés

- ntdll.dll = seule passerelle vers kernel
- SSN = index dans SSDT, change entre versions Windows
- Hell's Gate = extraction depuis ntdll en mémoire
- Heaven's Gate = extraction depuis ntdll propre (disque)
- Syscalls directs = bypass hooks EDR
- OPSEC : Call stack anormal, combiner avec autres techniques
