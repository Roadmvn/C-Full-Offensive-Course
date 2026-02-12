# Parsing PE en C

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Implémenter un parser PE complet en C
- Convertir RVA ↔ File Offset
- Extraire toutes les informations d'un PE (sections, imports, exports, relocations)
- Créer des outils d'analyse de malware
- Manipuler les structures PE pour le Red Teaming

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Le format PE (module W11_pe_format)
- Les pointeurs et structures en C
- Les concepts de mémoire virtuelle

## Introduction

Le **parsing PE** consiste à lire et interpréter programmatiquement un fichier PE pour en extraire les informations. C'est une compétence essentielle pour :
- Analyser des malwares
- Créer des injecteurs/loaders
- Développer des outils de sécurité
- Implémenter manual mapping / reflective DLL injection

### Pourquoi ce sujet est important ?

```ascii
PARSING PE = FONDATION DU RED TEAMING WINDOWS

┌────────────────────────────────────────────────────┐
│  OUTILS D'ANALYSE                                  │
│  ├─ PE Dumper (extraire PE depuis mémoire)         │
│  ├─ Import/Export viewer                           │
│  ├─ Section analyzer                               │
│  └─ Malware triage automatique                     │
├────────────────────────────────────────────────────┤
│  INJECTION & LOADING                               │
│  ├─ Reflective DLL Injection (parse en RAM)        │
│  ├─ Manual Mapping (résoudre imports)              │
│  ├─ Process Hollowing (copier sections)            │
│  └─ Module Stomping                                │
├────────────────────────────────────────────────────┤
│  MODIFICATION & PATCHING                           │
│  ├─ IAT Hooking (localiser IAT)                    │
│  ├─ Binary patching                                │
│  ├─ Signature bypass (modifier headers)            │
│  └─ Packer/Unpacker                                │
└────────────────────────────────────────────────────┘

Analogie : Parser un PE = Lire un plan de construction
           Vous devez savoir où se trouve chaque pièce
```

## Concepts fondamentaux

### Concept 1 : RVA vs File Offset

**Problème crucial** : Les adresses dans le PE Header sont des **RVAs** (Relative Virtual Addresses), mais pour lire depuis le fichier sur disque, on a besoin du **File Offset**.

```ascii
DIFFÉRENCE RVA vs FILE OFFSET :

FICHIER SUR DISQUE :
┌──────────────────────────────────────┐
│ Headers (0x400 bytes)                │  File Offset: 0x0000
├──────────────────────────────────────┤
│ .text section                        │  File Offset: 0x0400
│ (size: 0x1000 aligned to 0x200)      │  PointerToRawData = 0x0400
│                                      │  SizeOfRawData = 0x1000
├──────────────────────────────────────┤
│ .rdata section                       │  File Offset: 0x1400
│                                      │
└──────────────────────────────────────┘

CHARGÉ EN MÉMOIRE (ImageBase = 0x00400000) :
┌──────────────────────────────────────┐
│ Headers (0x400 bytes)                │  VA: 0x00400000
├──────────────────────────────────────┤
│ .text section (aligned to 0x1000)    │  VA: 0x00401000
│                                      │  RVA = 0x1000
│                                      │  VirtualSize = 0x1000
│ [Padding to 0x1000 alignment]        │
├──────────────────────────────────────┤
│ .rdata section                       │  VA: 0x00402000
│                                      │  RVA = 0x2000
└──────────────────────────────────────┘

CONVERSION :
RVA → File Offset :
  1. Trouver section contenant RVA
  2. Offset = RVA - VirtualAddress + PointerToRawData

File Offset → RVA :
  1. Trouver section contenant Offset
  2. RVA = Offset - PointerToRawData + VirtualAddress
```

### Concept 2 : Parser depuis disque vs depuis mémoire

```ascii
DEUX SCÉNARIOS :

┌─────────────────────────────────────────┐
│ PARSING DEPUIS DISQUE                   │
│ ├─ Utiliser File Offsets                │
│ ├─ Sections alignées sur FileAlignment  │
│ ├─ IAT non résolue (juste noms)         │
│ └─ Relocations non appliquées            │
│                                         │
│ Usage : Analyse statique, malware triage│
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ PARSING DEPUIS MÉMOIRE                  │
│ ├─ Utiliser RVAs directement             │
│ ├─ Sections alignées sur SectionAlign   │
│ ├─ IAT résolue (adresses réelles)       │
│ └─ Relocations appliquées                │
│                                         │
│ Usage : Dump processus, hook analysis   │
└─────────────────────────────────────────┘
```

### Concept 3 : Validation du PE

Avant de parser, **TOUJOURS VALIDER** :

```c
BOOL is_valid_pe(LPVOID pBase) {
    // Check 1: DOS Signature
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ'
        return FALSE;
    }

    // Check 2: e_lfanew dans limites raisonnables
    if (pDosHeader->e_lfanew > 0x1000 || pDosHeader->e_lfanew < 0x40) {
        return FALSE; // Suspect
    }

    // Check 3: PE Signature
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) { // 'PE\0\0'
        return FALSE;
    }

    // Check 4: Machine type valide
    WORD machine = pNtHeaders->FileHeader.Machine;
    if (machine != IMAGE_FILE_MACHINE_I386 &&
        machine != IMAGE_FILE_MACHINE_AMD64 &&
        machine != IMAGE_FILE_MACHINE_ARM64) {
        return FALSE;
    }

    // Check 5: Nombre de sections raisonnable
    if (pNtHeaders->FileHeader.NumberOfSections > 96) {
        return FALSE; // Suspect
    }

    return TRUE;
}
```

## Mise en pratique

### Étape 1 : Conversion RVA ↔ File Offset

```c
#include <windows.h>
#include <stdio.h>

// Convertir RVA → File Offset
DWORD rva_to_offset(LPVOID pBase, DWORD rva) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    // Si RVA dans headers, pas de conversion
    if (rva < pNtHeaders->OptionalHeader.SizeOfHeaders) {
        return rva;
    }

    // Chercher section contenant RVA
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD sectionStart = pSectionHeader[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + pSectionHeader[i].Misc.VirtualSize;

        if (rva >= sectionStart && rva < sectionEnd) {
            // Formule : Offset = RVA - VirtualAddress + PointerToRawData
            DWORD offset = rva - pSectionHeader[i].VirtualAddress +
                          pSectionHeader[i].PointerToRawData;
            return offset;
        }
    }

    return 0; // RVA invalide
}

// Convertir File Offset → RVA
DWORD offset_to_rva(LPVOID pBase, DWORD offset) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    // Si offset dans headers
    if (offset < pNtHeaders->OptionalHeader.SizeOfHeaders) {
        return offset;
    }

    // Chercher section contenant offset
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD sectionStart = pSectionHeader[i].PointerToRawData;
        DWORD sectionEnd = sectionStart + pSectionHeader[i].SizeOfRawData;

        if (offset >= sectionStart && offset < sectionEnd) {
            // Formule : RVA = Offset - PointerToRawData + VirtualAddress
            DWORD rva = offset - pSectionHeader[i].PointerToRawData +
                       pSectionHeader[i].VirtualAddress;
            return rva;
        }
    }

    return 0; // Offset invalide
}

// Helper : Convertir RVA → pointeur (pour parsing en mémoire)
LPVOID rva_to_ptr(LPVOID pBase, DWORD rva) {
    return (LPVOID)((BYTE*)pBase + rva);
}

// Helper : Convertir RVA → pointeur (pour parsing sur disque)
LPVOID rva_to_ptr_disk(LPVOID pBase, DWORD rva) {
    DWORD offset = rva_to_offset(pBase, rva);
    if (offset == 0) return NULL;
    return (LPVOID)((BYTE*)pBase + offset);
}
```

### Étape 2 : Parser complet des sections

```c
typedef struct _SECTION_INFO {
    char name[9];          // Nom (8 + null terminator)
    DWORD virtualAddress;
    DWORD virtualSize;
    DWORD rawAddress;
    DWORD rawSize;
    DWORD characteristics;
    BOOL isExecutable;
    BOOL isWritable;
    BOOL isReadable;
} SECTION_INFO;

BOOL parse_sections(LPVOID pBase, SECTION_INFO** sections, int* count) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    *count = pNtHeaders->FileHeader.NumberOfSections;
    *sections = (SECTION_INFO*)malloc(sizeof(SECTION_INFO) * (*count));
    if (!*sections) return FALSE;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < *count; i++) {
        // Copier nom (8 bytes max, pas toujours null-terminated)
        memset((*sections)[i].name, 0, 9);
        memcpy((*sections)[i].name, pSectionHeader[i].Name, 8);

        (*sections)[i].virtualAddress = pSectionHeader[i].VirtualAddress;
        (*sections)[i].virtualSize = pSectionHeader[i].Misc.VirtualSize;
        (*sections)[i].rawAddress = pSectionHeader[i].PointerToRawData;
        (*sections)[i].rawSize = pSectionHeader[i].SizeOfRawData;
        (*sections)[i].characteristics = pSectionHeader[i].Characteristics;

        // Parse permissions
        DWORD c = pSectionHeader[i].Characteristics;
        (*sections)[i].isExecutable = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
        (*sections)[i].isWritable = (c & IMAGE_SCN_MEM_WRITE) != 0;
        (*sections)[i].isReadable = (c & IMAGE_SCN_MEM_READ) != 0;
    }

    return TRUE;
}

void print_sections(SECTION_INFO* sections, int count) {
    printf("\n=== SECTIONS (%d) ===\n", count);
    printf("%-10s %-12s %-12s %-12s %-12s %s\n",
           "Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Perms");
    printf("──────────────────────────────────────────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        printf("%-10s 0x%08X   0x%08X   0x%08X   0x%08X   %c%c%c\n",
               sections[i].name,
               sections[i].virtualAddress,
               sections[i].virtualSize,
               sections[i].rawAddress,
               sections[i].rawSize,
               sections[i].isReadable ? 'R' : '-',
               sections[i].isWritable ? 'W' : '-',
               sections[i].isExecutable ? 'X' : '-');
    }
}
```

### Étape 3 : Parser les imports (depuis disque)

```c
typedef struct _IMPORT_FUNCTION {
    char name[256];
    WORD hint;
    BOOL importByOrdinal;
    DWORD ordinal;
} IMPORT_FUNCTION;

typedef struct _IMPORT_DLL {
    char dllName[256];
    IMPORT_FUNCTION* functions;
    int functionCount;
} IMPORT_DLL;

BOOL parse_imports_disk(LPVOID pBase, IMPORT_DLL** imports, int* dllCount) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        *dllCount = 0;
        return TRUE; // Pas d'imports
    }

    // Convertir RVA → File Offset
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)rva_to_ptr_disk(pBase, importRVA);
    if (!pImportDesc) return FALSE;

    // Compter DLLs
    *dllCount = 0;
    PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDesc;
    while (pTemp->Name != 0) {
        (*dllCount)++;
        pTemp++;
    }

    *imports = (IMPORT_DLL*)malloc(sizeof(IMPORT_DLL) * (*dllCount));
    if (!*imports) return FALSE;

    // Parser chaque DLL
    for (int i = 0; i < *dllCount; i++) {
        // Nom DLL
        char* dllName = (char*)rva_to_ptr_disk(pBase, pImportDesc[i].Name);
        strncpy((*imports)[i].dllName, dllName, 255);
        (*imports)[i].dllName[255] = 0;

        // Compter fonctions
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)rva_to_ptr_disk(pBase, pImportDesc[i].OriginalFirstThunk);
        int funcCount = 0;
        PIMAGE_THUNK_DATA pTempThunk = pThunk;
        while (pTempThunk->u1.AddressOfData != 0) {
            funcCount++;
            pTempThunk++;
        }

        (*imports)[i].functionCount = funcCount;
        (*imports)[i].functions = (IMPORT_FUNCTION*)malloc(sizeof(IMPORT_FUNCTION) * funcCount);
        if (!(*imports)[i].functions) return FALSE;

        // Parser fonctions
        for (int j = 0; j < funcCount; j++) {
            if (pThunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // Import par ordinal
                (*imports)[i].functions[j].importByOrdinal = TRUE;
                (*imports)[i].functions[j].ordinal = IMAGE_ORDINAL64(pThunk[j].u1.Ordinal);
                sprintf((*imports)[i].functions[j].name, "Ordinal_%u", (*imports)[i].functions[j].ordinal);
            } else {
                // Import par nom
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)rva_to_ptr_disk(pBase, (DWORD)pThunk[j].u1.AddressOfData);
                (*imports)[i].functions[j].importByOrdinal = FALSE;
                (*imports)[i].functions[j].hint = pImport->Hint;
                strncpy((*imports)[i].functions[j].name, (char*)pImport->Name, 255);
                (*imports)[i].functions[j].name[255] = 0;
            }
        }
    }

    return TRUE;
}

void print_imports(IMPORT_DLL* imports, int dllCount) {
    printf("\n=== IMPORTS (%d DLLs) ===\n", dllCount);

    for (int i = 0; i < dllCount; i++) {
        printf("\n[%s] (%d functions)\n", imports[i].dllName, imports[i].functionCount);

        for (int j = 0; j < imports[i].functionCount && j < 20; j++) { // Limit display
            if (imports[i].functions[j].importByOrdinal) {
                printf("  - Ordinal %u\n", imports[i].functions[j].ordinal);
            } else {
                printf("  - %s (hint: %u)\n", imports[i].functions[j].name, imports[i].functions[j].hint);
            }
        }

        if (imports[i].functionCount > 20) {
            printf("  ... (%d more)\n", imports[i].functionCount - 20);
        }
    }
}
```

### Étape 4 : Parser les exports

```c
typedef struct _EXPORT_FUNCTION {
    char name[256];
    DWORD address;  // RVA
    WORD ordinal;
    BOOL hasName;
} EXPORT_FUNCTION;

typedef struct _EXPORT_INFO {
    char dllName[256];
    EXPORT_FUNCTION* functions;
    int functionCount;
} EXPORT_INFO;

BOOL parse_exports_disk(LPVOID pBase, EXPORT_INFO* exportInfo) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) {
        exportInfo->functionCount = 0;
        return TRUE; // Pas d'exports
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)rva_to_ptr_disk(pBase, exportRVA);
    if (!pExportDir) return FALSE;

    // Nom de la DLL
    char* dllName = (char*)rva_to_ptr_disk(pBase, pExportDir->Name);
    strncpy(exportInfo->dllName, dllName, 255);
    exportInfo->dllName[255] = 0;

    exportInfo->functionCount = pExportDir->NumberOfFunctions;
    exportInfo->functions = (EXPORT_FUNCTION*)malloc(sizeof(EXPORT_FUNCTION) * exportInfo->functionCount);
    if (!exportInfo->functions) return FALSE;

    // Tables
    DWORD* addressTable = (DWORD*)rva_to_ptr_disk(pBase, pExportDir->AddressOfFunctions);
    DWORD* nameTable = (DWORD*)rva_to_ptr_disk(pBase, pExportDir->AddressOfNames);
    WORD* ordinalTable = (WORD*)rva_to_ptr_disk(pBase, pExportDir->AddressOfNameOrdinals);

    // Parser fonctions
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
        exportInfo->functions[i].address = addressTable[i];
        exportInfo->functions[i].ordinal = (WORD)(i + pExportDir->Base);
        exportInfo->functions[i].hasName = FALSE;
        sprintf(exportInfo->functions[i].name, "Ordinal_%u", exportInfo->functions[i].ordinal);
    }

    // Associer noms
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        WORD ordinal = ordinalTable[i];
        char* funcName = (char*)rva_to_ptr_disk(pBase, nameTable[i]);

        exportInfo->functions[ordinal].hasName = TRUE;
        strncpy(exportInfo->functions[ordinal].name, funcName, 255);
        exportInfo->functions[ordinal].name[255] = 0;
    }

    return TRUE;
}

void print_exports(EXPORT_INFO* exportInfo) {
    if (exportInfo->functionCount == 0) {
        printf("\nPas d'exports\n");
        return;
    }

    printf("\n=== EXPORTS (%s) ===\n", exportInfo->dllName);
    printf("Total: %d fonctions\n\n", exportInfo->functionCount);
    printf("%-6s %-40s %s\n", "Ord", "Name", "RVA");
    printf("─────────────────────────────────────────────────────────────\n");

    int displayed = 0;
    for (int i = 0; i < exportInfo->functionCount && displayed < 50; i++) {
        if (exportInfo->functions[i].address != 0) {
            printf("%-6u %-40s 0x%08X\n",
                   exportInfo->functions[i].ordinal,
                   exportInfo->functions[i].name,
                   exportInfo->functions[i].address);
            displayed++;
        }
    }

    if (exportInfo->functionCount > 50) {
        printf("... (%d more)\n", exportInfo->functionCount - 50);
    }
}
```

### Étape 5 : Parser la relocation table

```c
typedef struct _RELOCATION_ENTRY {
    DWORD pageRVA;
    WORD* entries;
    int entryCount;
} RELOCATION_ENTRY;

BOOL parse_relocations_disk(LPVOID pBase, RELOCATION_ENTRY** relocs, int* blockCount) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    DWORD relocRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRVA == 0 || relocSize == 0) {
        *blockCount = 0;
        return TRUE; // Pas de relocations
    }

    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)rva_to_ptr_disk(pBase, relocRVA);
    if (!pReloc) return FALSE;

    // Compter blocks
    *blockCount = 0;
    PIMAGE_BASE_RELOCATION pTemp = pReloc;
    DWORD offset = 0;
    while (offset < relocSize && pTemp->SizeOfBlock != 0) {
        (*blockCount)++;
        offset += pTemp->SizeOfBlock;
        pTemp = (PIMAGE_BASE_RELOCATION)((BYTE*)pTemp + pTemp->SizeOfBlock);
    }

    *relocs = (RELOCATION_ENTRY*)malloc(sizeof(RELOCATION_ENTRY) * (*blockCount));
    if (!*relocs) return FALSE;

    // Parser blocks
    pTemp = pReloc;
    for (int i = 0; i < *blockCount; i++) {
        (*relocs)[i].pageRVA = pTemp->VirtualAddress;
        (*relocs)[i].entryCount = (pTemp->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        (*relocs)[i].entries = (WORD*)malloc(sizeof(WORD) * (*relocs)[i].entryCount);

        WORD* entries = (WORD*)((BYTE*)pTemp + sizeof(IMAGE_BASE_RELOCATION));
        memcpy((*relocs)[i].entries, entries, sizeof(WORD) * (*relocs)[i].entryCount);

        pTemp = (PIMAGE_BASE_RELOCATION)((BYTE*)pTemp + pTemp->SizeOfBlock);
    }

    return TRUE;
}

void print_relocations(RELOCATION_ENTRY* relocs, int blockCount) {
    if (blockCount == 0) {
        printf("\nPas de relocations\n");
        return;
    }

    printf("\n=== RELOCATIONS (%d blocks) ===\n", blockCount);

    int totalEntries = 0;
    for (int i = 0; i < blockCount && i < 10; i++) {
        printf("\nBlock %d: Page RVA 0x%08X (%d entries)\n",
               i, relocs[i].pageRVA, relocs[i].entryCount);

        for (int j = 0; j < relocs[i].entryCount && j < 5; j++) {
            WORD entry = relocs[i].entries[j];
            WORD type = entry >> 12;
            WORD offset = entry & 0xFFF;

            const char* typeStr;
            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE: typeStr = "ABSOLUTE"; break;
                case IMAGE_REL_BASED_HIGH: typeStr = "HIGH"; break;
                case IMAGE_REL_BASED_LOW: typeStr = "LOW"; break;
                case IMAGE_REL_BASED_HIGHLOW: typeStr = "HIGHLOW"; break;
                case IMAGE_REL_BASED_DIR64: typeStr = "DIR64"; break;
                default: typeStr = "UNKNOWN";
            }

            printf("  [%d] Type: %s, Offset: 0x%03X, RVA: 0x%08X\n",
                   j, typeStr, offset, relocs[i].pageRVA + offset);
        }

        if (relocs[i].entryCount > 5) {
            printf("  ... (%d more)\n", relocs[i].entryCount - 5);
        }

        totalEntries += relocs[i].entryCount;
    }

    if (blockCount > 10) {
        printf("\n... (%d more blocks)\n", blockCount - 10);
    }

    printf("\nTotal relocations: %d\n", totalEntries);
}
```

### Étape 6 : Programme complet - PE Analyzer

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PE_file>\n", argv[0]);
        return 1;
    }

    // Ouvrir fichier
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Erreur: impossible d'ouvrir '%s'\n", argv[1]);
        return 1;
    }

    // Mapper en mémoire
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printf("Erreur: CreateFileMapping\n");
        CloseHandle(hFile);
        return 1;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        printf("Erreur: MapViewOfFile\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Valider PE
    if (!is_valid_pe(pBase)) {
        printf("Erreur: '%s' n'est pas un PE valide\n", argv[1]);
        goto cleanup;
    }

    printf("═══════════════════════════════════════════════════════════\n");
    printf("   PE ANALYZER - %s\n", argv[1]);
    printf("═══════════════════════════════════════════════════════════\n");

    // Headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    printf("\n[+] DOS Header:\n");
    printf("    Signature: MZ (0x%04X)\n", pDosHeader->e_magic);
    printf("    PE Offset: 0x%08X\n", pDosHeader->e_lfanew);

    printf("\n[+] NT Headers:\n");
    printf("    Signature: PE (0x%08X)\n", pNtHeaders->Signature);
    printf("    Machine: ");
    switch (pNtHeaders->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: printf("x86\n"); break;
        case IMAGE_FILE_MACHINE_AMD64: printf("x64\n"); break;
        case IMAGE_FILE_MACHINE_ARM64: printf("ARM64\n"); break;
        default: printf("Unknown (0x%04X)\n", pNtHeaders->FileHeader.Machine);
    }
    printf("    ImageBase: 0x%016llX\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("    EntryPoint (RVA): 0x%08X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("    SizeOfImage: 0x%08X (%u bytes)\n",
           pNtHeaders->OptionalHeader.SizeOfImage,
           pNtHeaders->OptionalHeader.SizeOfImage);

    // Sections
    SECTION_INFO* sections = NULL;
    int sectionCount = 0;
    if (parse_sections(pBase, &sections, &sectionCount)) {
        print_sections(sections, sectionCount);
        free(sections);
    }

    // Imports
    IMPORT_DLL* imports = NULL;
    int importCount = 0;
    if (parse_imports_disk(pBase, &imports, &importCount)) {
        print_imports(imports, importCount);

        // Free
        for (int i = 0; i < importCount; i++) {
            free(imports[i].functions);
        }
        free(imports);
    }

    // Exports
    EXPORT_INFO exportInfo = {0};
    if (parse_exports_disk(pBase, &exportInfo)) {
        print_exports(&exportInfo);
        if (exportInfo.functions) free(exportInfo.functions);
    }

    // Relocations
    RELOCATION_ENTRY* relocs = NULL;
    int relocCount = 0;
    if (parse_relocations_disk(pBase, &relocs, &relocCount)) {
        print_relocations(relocs, relocCount);

        // Free
        for (int i = 0; i < relocCount; i++) {
            free(relocs[i].entries);
        }
        free(relocs);
    }

    printf("\n═══════════════════════════════════════════════════════════\n");

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 0;
}
```

## Application offensive

### Contexte Red Team

Le parsing PE est utilisé dans de nombreuses techniques offensives :

#### 1. Reflective DLL Injection

```c
// Parser PE en mémoire pour injection
BOOL reflective_load_library(LPVOID dllBuffer) {
    // 1. Valider PE
    if (!is_valid_pe(dllBuffer)) return FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBuffer + pDosHeader->e_lfanew);

    // 2. Allouer mémoire à ImageBase
    LPVOID pImageBase = VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 3. Copier headers
    memcpy(pImageBase, dllBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // 4. Copier sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((BYTE*)pImageBase + pSectionHeader[i].VirtualAddress);
        LPVOID src = (LPVOID)((BYTE*)dllBuffer + pSectionHeader[i].PointerToRawData);
        memcpy(dest, src, pSectionHeader[i].SizeOfRawData);
    }

    // 5. Parser et résoudre imports (voir W13)
    // 6. Appliquer relocations (voir W13)
    // 7. Appeler DllMain

    return TRUE;
}
```

#### 2. IAT Hooking

```c
// Localiser fonction dans IAT pour hooking
LPVOID* find_iat_entry(LPVOID pBase, const char* dllName, const char* funcName) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)rva_to_ptr(pBase, importRVA);

    while (pImportDesc->Name != 0) {
        char* currentDll = (char*)rva_to_ptr(pBase, pImportDesc->Name);

        if (_stricmp(currentDll, dllName) == 0) {
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)rva_to_ptr(pBase, pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)rva_to_ptr(pBase, pImportDesc->FirstThunk);

            while (pOrigThunk->u1.AddressOfData != 0) {
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)rva_to_ptr(pBase, (DWORD)pOrigThunk->u1.AddressOfData);

                    if (strcmp((char*)pImport->Name, funcName) == 0) {
                        // Retourner adresse dans IAT
                        return (LPVOID*)&pFirstThunk->u1.Function;
                    }
                }
                pOrigThunk++;
                pFirstThunk++;
            }
        }
        pImportDesc++;
    }

    return NULL;
}

// Usage:
LPVOID* iatEntry = find_iat_entry(GetModuleHandle(NULL), "kernel32.dll", "CreateFileW");
if (iatEntry) {
    DWORD oldProtect;
    VirtualProtect(iatEntry, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
    *iatEntry = (LPVOID)MyHookedCreateFileW; // Hook !
    VirtualProtect(iatEntry, sizeof(LPVOID), oldProtect, &oldProtect);
}
```

#### 3. PE Dumping (extraire processus depuis mémoire)

```c
// Dumper module depuis mémoire vers disque
BOOL dump_pe_from_memory(LPVOID pBase, const char* outputPath) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    DWORD fileSize = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    // Calculer taille fichier
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD sectionEnd = pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData;
        if (sectionEnd > fileSize) fileSize = sectionEnd;
    }

    // Allouer buffer
    LPVOID buffer = malloc(fileSize);
    if (!buffer) return FALSE;
    memset(buffer, 0, fileSize);

    // Copier headers
    memcpy(buffer, pBase, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // Copier sections (mémoire → disque)
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((BYTE*)buffer + pSectionHeader[i].PointerToRawData);
        LPVOID src = (LPVOID)((BYTE*)pBase + pSectionHeader[i].VirtualAddress);

        DWORD size = min(pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Misc.VirtualSize);
        memcpy(dest, src, size);
    }

    // Écrire fichier
    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        free(buffer);
        return FALSE;
    }

    DWORD written;
    WriteFile(hFile, buffer, fileSize, &written, NULL);
    CloseHandle(hFile);
    free(buffer);

    return TRUE;
}
```

### Considérations OPSEC

```ascii
PARSING PE : POINTS D'ATTENTION

┌────────────────────────────────────────┐
│ ERREURS COMMUNES À ÉVITER              │
│ ├─ Ne pas valider PE avant parsing     │
│ ├─ Confusion RVA / File Offset         │
│ ├─ Buffer overflow sur noms (8 bytes)  │
│ ├─ Oublier que Name[8] pas toujours \0│
│ └─ Ne pas gérer import par ordinal     │
├────────────────────────────────────────┤
│ DÉTECTIONS LORS DU PARSING             │
│ ├─ Accès mémoire suspects              │
│ ├─ Énumération IAT d'autres processus  │
│ ├─ Lecture répétée de PE sur disque    │
│ └─ Pattern de parsing reconnaissable   │
└────────────────────────────────────────┘

BONNES PRATIQUES :
✓ TOUJOURS valider signatures (MZ, PE)
✓ Vérifier bounds (sections, RVA, offsets)
✓ Gérer imports par ordinal ET par nom
✓ Utiliser try/except pour accès mémoire
✓ Nettoyer allocations (free memory)
✓ Parser en mémoire si possible (plus rapide)
```

## Résumé

- Parsing PE = extraire programmatiquement les informations d'un exécutable
- RVA → File Offset : chercher section, appliquer formule (RVA - VirtualAddress + PointerToRawData)
- File Offset → RVA : formule inverse (Offset - PointerToRawData + VirtualAddress)
- Parser depuis disque : utiliser File Offsets (PointerToRawData)
- Parser depuis mémoire : utiliser RVAs directement
- Import Table : liste des DLLs et fonctions importées (par nom ou ordinal)
- Export Table : fonctions exposées par une DLL
- Relocation Table : corrections d'adresses si ImageBase change
- Validation cruciale : vérifier MZ, PE, bounds, sections

## Ressources complémentaires

- [PE Format Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE Insider - Parsing Tutorial](https://github.com/corkami/docs/blob/master/PE/PE.md)
- [LordPE - PE Editor](https://www.aldeid.com/wiki/LordPE)
- [CFF Explorer VIII](https://ntcore.com/?page_id=388)
- [Hasherezade's libpeconv](https://github.com/hasherezade/libpeconv)

---

**Navigation**
- [Module précédent](../01-PE-Format/)
- [Module suivant](../03-PE-Loading/)
