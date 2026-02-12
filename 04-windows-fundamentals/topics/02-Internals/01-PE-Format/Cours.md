# Format PE (Portable Executable)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Comprendre la structure complète d'un fichier PE (DOS header, NT headers, sections)
- Identifier les différentes sections et leur rôle (.text, .data, .rdata, .rsrc)
- Analyser les tables d'imports et d'exports
- Manipuler les structures PE en C
- Exploiter cette connaissance pour le Red Teaming (injection, patching, obfuscation)

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (structures, pointeurs)
- Les bases de l'assembleur x86/x64
- Le système d'exploitation Windows

## Introduction

Le format **PE (Portable Executable)** est le format de fichier exécutable utilisé par Windows depuis Windows NT. Tous les fichiers .exe, .dll, .sys (drivers), .ocx, et même certains .cpl et .scr sont des fichiers PE.

### Pourquoi ce sujet est important ?

```ascii
POUR UN RED TEAMER, COMPRENDRE LE FORMAT PE EST ESSENTIEL :

┌────────────────────────────────────────────────────┐
│  INJECTION DE CODE                                 │
│  ├─ Reflective DLL Injection                       │
│  ├─ Process Hollowing                              │
│  ├─ Module Stomping                                │
│  └─ PE Injection                                   │
├────────────────────────────────────────────────────┤
│  EVASION                                           │
│  ├─ Patching Import Address Table (IAT)           │
│  ├─ Obfuscation des sections                      │
│  ├─ Manipulation des headers                      │
│  └─ Bypass signature-based detection              │
├────────────────────────────────────────────────────┤
│  ANALYSE                                           │
│  ├─ Reverse engineering de malware                │
│  ├─ Identification de packers                     │
│  ├─ Extraction de ressources                      │
│  └─ Détection de code malveillant                 │
└────────────────────────────────────────────────────┘

Analogie : Le PE est comme l'ADN d'un programme Windows
           Savoir le lire = Savoir manipuler n'importe quel .exe
```

## Concepts fondamentaux

### Concept 1 : Vue d'ensemble de la structure PE

Un fichier PE est organisé en **couches successives** :

```ascii
STRUCTURE COMPLÈTE D'UN FICHIER PE :

┌──────────────────────────────────────────────────┐  Offset 0x0000
│  DOS HEADER (64 bytes)                           │
│  ├─ e_magic: 0x5A4D ('MZ')                       │  ← Signature MS-DOS
│  ├─ e_lfanew: Offset vers PE Header              │  ← Pointeur crucial
│  └─ DOS Stub (code 16-bit legacy)                │
├──────────────────────────────────────────────────┤  Offset e_lfanew
│  PE SIGNATURE (4 bytes)                          │
│  └─ 'PE\0\0' (0x50450000)                        │  ← Signature PE
├──────────────────────────────────────────────────┤
│  FILE HEADER (20 bytes)                          │
│  ├─ Machine: 0x14C (x86) ou 0x8664 (x64)        │
│  ├─ NumberOfSections                             │
│  ├─ TimeDateStamp                                │
│  ├─ SizeOfOptionalHeader                         │
│  └─ Characteristics (flags)                      │
├──────────────────────────────────────────────────┤
│  OPTIONAL HEADER (224/240 bytes)                 │
│  ├─ Magic: 0x10B (PE32) / 0x20B (PE32+)         │
│  ├─ AddressOfEntryPoint (OEP)                    │  ← Point d'entrée
│  ├─ ImageBase (adresse chargement)               │
│  ├─ SectionAlignment / FileAlignment             │
│  ├─ SizeOfImage                                  │
│  ├─ SizeOfHeaders                                │
│  ├─ Subsystem (GUI/CUI/Native)                   │
│  └─ DATA DIRECTORIES (16 entries)                │
│      ├─ [0] Export Table                         │
│      ├─ [1] Import Table                         │  ← APIs importées
│      ├─ [2] Resource Table                       │
│      ├─ [3] Exception Table                      │
│      ├─ [5] Base Relocation Table                │
│      ├─ [9] TLS Table                            │
│      └─ [14] CLR Header (.NET)                   │
├──────────────────────────────────────────────────┤
│  SECTION TABLE (40 bytes × N sections)           │
│  ├─ SECTION 1 (.text)                            │
│  │   ├─ Name: ".text\0\0\0"                      │
│  │   ├─ VirtualSize                              │
│  │   ├─ VirtualAddress (RVA)                     │
│  │   ├─ SizeOfRawData                            │
│  │   ├─ PointerToRawData (offset fichier)       │
│  │   └─ Characteristics: IMAGE_SCN_MEM_EXECUTE   │
│  ├─ SECTION 2 (.rdata)                           │
│  ├─ SECTION 3 (.data)                            │
│  └─ ...                                          │
├──────────────────────────────────────────────────┤
│  SECTIONS CONTENT                                │
│  ├─ .text  (CODE exécutable)                     │
│  ├─ .rdata (Import/Export tables, strings)       │
│  ├─ .data  (Variables globales initialisées)     │
│  ├─ .bss   (Variables non initialisées)          │
│  ├─ .rsrc  (Ressources: icons, dialogs...)       │
│  └─ .reloc (Relocation table)                    │
└──────────────────────────────────────────────────┘

CONCEPTS CLÉS :
- RVA (Relative Virtual Address) : Offset depuis ImageBase
- File Offset : Position dans le fichier sur disque
- Virtual Address : Adresse en mémoire après chargement
```

### Concept 2 : DOS Header - L'héritage MS-DOS

```c
// Structure IMAGE_DOS_HEADER (winnt.h)
typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;      // 0x5A4D ('MZ') - Magic number
    WORD   e_cblp;       // Bytes on last page
    WORD   e_cp;         // Pages in file
    WORD   e_crlc;       // Relocations
    WORD   e_cparhdr;    // Size of header in paragraphs
    WORD   e_minalloc;   // Minimum extra paragraphs needed
    WORD   e_maxalloc;   // Maximum extra paragraphs needed
    WORD   e_ss;         // Initial SS value
    WORD   e_sp;         // Initial SP value
    WORD   e_csum;       // Checksum
    WORD   e_ip;         // Initial IP value
    WORD   e_cs;         // Initial CS value
    WORD   e_lfarlc;     // File address of relocation table
    WORD   e_ovno;       // Overlay number
    WORD   e_res[4];     // Reserved
    WORD   e_oemid;      // OEM identifier
    WORD   e_oeminfo;    // OEM information
    WORD   e_res2[10];   // Reserved
    LONG   e_lfanew;     // Offset vers PE Header ← IMPORTANT !
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

**Pourquoi 'MZ' ?** : Initiales de Mark Zbikowski, architecte MS-DOS chez Microsoft.

**DOS Stub** : Code 16-bit qui affiche "This program cannot be run in DOS mode" si exécuté sous DOS.

```ascii
VÉRIFICATION RAPIDE SI UN FICHIER EST UN PE :

Offset  Hex        ASCII
──────────────────────────
0x0000  4D 5A      'MZ'    ← Premier check : signature DOS
0x0002  90 00
0x0004  03 00
...
0x003C  D8 00 00 00        ← e_lfanew = 0x000000D8 (offset PE header)
...
0x00D8  50 45 00 00        ← 'PE\0\0' à l'offset indiqué
```

### Concept 3 : NT Headers - Le cerveau du PE

```c
// Structure IMAGE_NT_HEADERS (32-bit)
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;                      // 'PE\0\0' (0x50450000)
    IMAGE_FILE_HEADER FileHeader;         // 20 bytes
    IMAGE_OPTIONAL_HEADER32 OptionalHeader; // 224 bytes
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// Structure IMAGE_NT_HEADERS (64-bit)
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader; // 240 bytes
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

#### IMAGE_FILE_HEADER

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;              // 0x14C (x86), 0x8664 (x64), 0xAA64 (ARM64)
    WORD  NumberOfSections;     // Nombre de sections
    DWORD TimeDateStamp;        // Date compilation (Unix timestamp)
    DWORD PointerToSymbolTable; // Offset table symboles (obsolète)
    DWORD NumberOfSymbols;      // Nombre symboles
    WORD  SizeOfOptionalHeader; // Taille Optional Header
    WORD  Characteristics;      // Flags du fichier
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// Characteristics importants
#define IMAGE_FILE_EXECUTABLE_IMAGE    0x0002  // Fichier exécutable
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020  // Supporte >2GB
#define IMAGE_FILE_DLL                 0x2000  // C'est une DLL
```

#### IMAGE_OPTIONAL_HEADER

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD    Magic;                 // 0x20B (PE32+) ou 0x10B (PE32)
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;            // Taille section .text
    DWORD   SizeOfInitializedData; // Taille .data
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;   // RVA du point d'entrée (OEP)
    DWORD   BaseOfCode;            // RVA début section code
    ULONGLONG ImageBase;           // Adresse chargement préférée
    DWORD   SectionAlignment;      // Alignement en mémoire (ex: 0x1000)
    DWORD   FileAlignment;         // Alignement sur disque (ex: 0x200)
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;     // Reserved
    DWORD   SizeOfImage;           // Taille totale en mémoire
    DWORD   SizeOfHeaders;         // Taille headers (DOS+NT+Sections)
    DWORD   CheckSum;              // Checksum (requis pour drivers)
    WORD    Subsystem;             // GUI/CUI/Native
    WORD    DllCharacteristics;    // ASLR, DEP, etc.
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD   LoaderFlags;           // Obsolète
    DWORD   NumberOfRvaAndSizes;   // Nombre Data Directories (16)
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // Tables importantes
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

**Data Directories (les 16 tables)** :

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;  // RVA de la table
    DWORD Size;            // Taille de la table
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

// Index des Data Directories
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Reserved
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // CLR Runtime Header (.NET)
```

### Concept 4 : Sections - Le contenu du PE

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];              // Nom section (ex: ".text\0\0\0")
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;      // Taille réelle en mémoire
    } Misc;
    DWORD VirtualAddress;       // RVA (adresse en mémoire)
    DWORD SizeOfRawData;        // Taille dans le fichier
    DWORD PointerToRawData;     // Offset dans le fichier
    DWORD PointerToRelocations; // Obsolète
    DWORD PointerToLinenumbers; // Obsolète
    WORD  NumberOfRelocations;  // Obsolète
    WORD  NumberOfLinenumbers;  // Obsolète
    DWORD Characteristics;      // Flags (R/W/X)
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// Characteristics (permissions)
#define IMAGE_SCN_CNT_CODE               0x00000020  // Contient code
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040  // Data initialisée
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080  // Data non init (.bss)
#define IMAGE_SCN_MEM_EXECUTE            0x20000000  // Exécutable
#define IMAGE_SCN_MEM_READ               0x40000000  // Readable
#define IMAGE_SCN_MEM_WRITE              0x80000000  // Writable
```

**Sections typiques** :

```ascii
┌──────────┬───────────────────┬─────────────────┐
│ Section  │ Contenu           │ Permissions     │
├──────────┼───────────────────┼─────────────────┤
│ .text    │ Code exécutable   │ R-X (Read+Exec) │
│ .rdata   │ Read-only data    │ R-- (Read only) │
│          │ - Import table    │                 │
│          │ - Export table    │                 │
│          │ - Strings const   │                 │
│ .data    │ Variables globales│ RW- (Read+Write)│
│          │ initialisées      │                 │
│ .bss     │ Variables globales│ RW-             │
│          │ non initialisées  │                 │
│ .rsrc    │ Ressources        │ R--             │
│          │ - Icons           │                 │
│          │ - Dialogs         │                 │
│          │ - Manifests       │                 │
│ .reloc   │ Relocation table  │ R--             │
│ .pdata   │ Exception handlers│ R-- (x64 only)  │
│ .idata   │ Import data       │ R--             │
│ .edata   │ Export data       │ R--             │
│ .tls     │ Thread local      │ RW-             │
└──────────┴───────────────────┴─────────────────┘
```

### Concept 5 : Import Address Table (IAT)

La IAT contient les adresses des fonctions importées depuis les DLLs.

```ascii
FONCTIONNEMENT DE L'IAT :

AVANT CHARGEMENT (sur disque) :
┌─────────────────────────────────────┐
│ Import Directory (dans .rdata)      │
│ ├─ kernel32.dll                     │
│ │   ├─ GetProcAddress               │
│ │   ├─ LoadLibraryA                 │
│ │   └─ CreateFileA                  │
│ ├─ user32.dll                       │
│     ├─ MessageBoxA                  │
│     └─ CreateWindowExA              │
└─────────────────────────────────────┘

APRÈS CHARGEMENT (en mémoire) :
┌─────────────────────────────────────┐
│ Import Address Table (IAT)          │
│ ├─ [0x00401000] → 0x7FFE12345678    │ ← Adresse réelle GetProcAddress
│ ├─ [0x00401008] → 0x7FFE1234ABCD    │ ← Adresse réelle LoadLibraryA
│ ├─ [0x00401010] → 0x7FFE1234DEF0    │ ← Adresse réelle CreateFileA
│ ├─ [0x00401018] → 0x7FFE9ABC1234    │ ← MessageBoxA
│ └─ [0x00401020] → 0x7FFE9ABC5678    │ ← CreateWindowExA
└─────────────────────────────────────┘

QUAND VOTRE CODE APPELLE :
call [0x00401000]  → Appelle GetProcAddress via IAT
```

**Structure Import Directory** :

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;  // RVA vers Import Name Table (INT)
    };
    DWORD TimeDateStamp;           // 0 si non bound
    DWORD ForwarderChain;          // -1 si pas de forwarders
    DWORD Name;                    // RVA nom de la DLL
    DWORD FirstThunk;              // RVA vers Import Address Table (IAT)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;        // Adresse de la fonction
        ULONGLONG Ordinal;         // Import par ordinal
        ULONGLONG AddressOfData;   // RVA vers IMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD  Hint;        // Index dans export table
    CHAR  Name[1];     // Nom de la fonction (null-terminated)
} IMAGE_IMPORT_BY_NAME;
```

## Mise en pratique

### Étape 1 : Parser le DOS Header

```c
#include <windows.h>
#include <stdio.h>

void parse_dos_header(const char* filepath) {
    // Ouvrir fichier
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Erreur ouverture fichier\n");
        return;
    }

    // Mapper en mémoire
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // Lire DOS Header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;

    printf("=== DOS HEADER ===\n");
    printf("Signature: 0x%04X ", pDosHeader->e_magic);
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) { // 0x5A4D = 'MZ'
        printf("('MZ') ✓ Valide\n");
    } else {
        printf("✗ INVALIDE (pas un PE)\n");
        goto cleanup;
    }

    printf("Offset PE Header: 0x%08X\n", pDosHeader->e_lfanew);

    // Vérifier signature PE
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    printf("Signature PE: 0x%08X ", pNtHeaders->Signature);
    if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE) { // 'PE\0\0'
        printf("('PE\\0\\0') ✓ Valide\n");
    } else {
        printf("✗ INVALIDE\n");
    }

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}
```

### Étape 2 : Parser les NT Headers

```c
void parse_nt_headers(LPVOID pBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    printf("\n=== FILE HEADER ===\n");
    printf("Machine: 0x%04X ", pNtHeaders->FileHeader.Machine);
    switch (pNtHeaders->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:  printf("(x86)\n"); break;
        case IMAGE_FILE_MACHINE_AMD64: printf("(x64)\n"); break;
        case IMAGE_FILE_MACHINE_ARM64: printf("(ARM64)\n"); break;
        default: printf("(Unknown)\n");
    }

    printf("Nombre de sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("TimeDateStamp: 0x%08X ", pNtHeaders->FileHeader.TimeDateStamp);
    time_t timestamp = pNtHeaders->FileHeader.TimeDateStamp;
    printf("(%s)\n", ctime(&timestamp));

    printf("Characteristics: 0x%04X\n", pNtHeaders->FileHeader.Characteristics);
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf("  - IMAGE_FILE_EXECUTABLE_IMAGE\n");
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
        printf("  - IMAGE_FILE_DLL\n");
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        printf("  - IMAGE_FILE_LARGE_ADDRESS_AWARE\n");

    printf("\n=== OPTIONAL HEADER ===\n");
    printf("Magic: 0x%04X ", pNtHeaders->OptionalHeader.Magic);
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("(PE32+/x64)\n");
    } else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("(PE32/x86)\n");
    }

    printf("AddressOfEntryPoint: 0x%08X (OEP)\n",
           pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("ImageBase: 0x%016llX\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("SectionAlignment: 0x%08X\n", pNtHeaders->OptionalHeader.SectionAlignment);
    printf("FileAlignment: 0x%08X\n", pNtHeaders->OptionalHeader.FileAlignment);
    printf("SizeOfImage: 0x%08X (%u bytes)\n",
           pNtHeaders->OptionalHeader.SizeOfImage,
           pNtHeaders->OptionalHeader.SizeOfImage);
    printf("SizeOfHeaders: 0x%08X\n", pNtHeaders->OptionalHeader.SizeOfHeaders);

    printf("Subsystem: ");
    switch (pNtHeaders->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:              printf("Native\n"); break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:         printf("Windows GUI\n"); break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:         printf("Windows CUI\n"); break;
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: printf("Boot Application\n"); break;
        default: printf("Unknown\n");
    }

    printf("DllCharacteristics: 0x%04X\n", pNtHeaders->OptionalHeader.DllCharacteristics);
    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        printf("  - ASLR enabled\n");
    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        printf("  - DEP/NX enabled\n");
    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
        printf("  - High Entropy ASLR (64-bit)\n");
}
```

### Étape 3 : Énumérer les sections

```c
void parse_sections(LPVOID pBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    printf("\n=== SECTIONS (%d) ===\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("%-8s %-10s %-10s %-10s %-10s %s\n",
           "Name", "VirtAddr", "VirtSize", "RawSize", "RawOffset", "Characteristics");
    printf("────────────────────────────────────────────────────────────────────\n");

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        printf("%-8.8s 0x%08X 0x%08X 0x%08X 0x%08X ",
               pSectionHeader[i].Name,
               pSectionHeader[i].VirtualAddress,
               pSectionHeader[i].Misc.VirtualSize,
               pSectionHeader[i].SizeOfRawData,
               pSectionHeader[i].PointerToRawData);

        DWORD c = pSectionHeader[i].Characteristics;
        printf("%c%c%c ",
               (c & IMAGE_SCN_MEM_READ) ? 'R' : '-',
               (c & IMAGE_SCN_MEM_WRITE) ? 'W' : '-',
               (c & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-');

        if (c & IMAGE_SCN_CNT_CODE) printf("[CODE] ");
        if (c & IMAGE_SCN_CNT_INITIALIZED_DATA) printf("[IDATA] ");
        if (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("[UDATA] ");

        printf("\n");
    }
}
```

### Étape 4 : Parser la Import Table

```c
void parse_imports(LPVOID pBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        printf("\nPas d'imports\n");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + importRVA);

    printf("\n=== IMPORTS ===\n");
    while (pImportDesc->Name != 0) {
        char* dllName = (char*)((BYTE*)pBase + pImportDesc->Name);
        printf("\n[%s]\n", dllName);

        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBase + pImportDesc->OriginalFirstThunk);

        while (pThunk->u1.AddressOfData != 0) {
            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + pThunk->u1.AddressOfData);
                printf("  - %s\n", pImport->Name);
            } else {
                printf("  - Ordinal: %llu\n", IMAGE_ORDINAL(pThunk->u1.Ordinal));
            }
            pThunk++;
        }

        pImportDesc++;
    }
}
```

## Application offensive

### Contexte Red Team

Le format PE est au cœur de nombreuses techniques offensives :

1. **Reflective DLL Injection** : Charger une DLL en mémoire sans passer par LoadLibrary
   - Parser manuellement le PE
   - Résoudre les imports
   - Appliquer les relocations
   - Exécuter le point d'entrée

2. **IAT Hooking** : Modifier l'Import Address Table pour intercepter les appels API
   - Localiser l'IAT via Data Directory[1]
   - Remplacer l'adresse d'une fonction par la nôtre
   - Rediriger les appels vers notre hook

3. **Manual Mapping** : Charger un PE en contournant le loader Windows
   - Allouer mémoire à ImageBase
   - Copier headers + sections
   - Résoudre imports
   - Traiter relocations
   - Appeler TLS callbacks
   - Exécuter DllMain/EntryPoint

4. **PE Obfuscation** :
   - Chiffrer sections .text
   - Modifier headers pour tromper AV
   - Ajouter fake sections
   - Stripper les symbols

### Considérations OPSEC

```ascii
DÉTECTIONS À ÉVITER :

┌────────────────────────────────────────┐
│ SIGNATURES STATIQUES                   │
│ ├─ Entropy anormale (sections chiffrées)
│ ├─ Sections RWX (Read+Write+Execute)   │
│ ├─ SizeOfImage anormal                 │
│ ├─ Imports suspects (VirtualAlloc...)  │
│ └─ Timestamp incohérent                │
├────────────────────────────────────────┤
│ DÉTECTIONS COMPORTEMENTALES            │
│ ├─ Load PE depuis mémoire (pas disque) │
│ ├─ Modification IAT en runtime         │
│ ├─ Manual mapping détecté              │
│ └─ Relocation table manquante          │
└────────────────────────────────────────┘

BONNES PRATIQUES :
✓ Utiliser des sections standards (.text, .rdata, .data)
✓ Respecter les alignements normaux
✓ Éviter RWX (utiliser RX + copie RW séparée)
✓ Nettoyer les headers après injection
✓ Utiliser des timestamps réalistes
✓ Limiter les imports suspects
```

## Résumé

- Le format PE structure tous les exécutables Windows (.exe, .dll, .sys)
- Structure : DOS Header → PE Signature → NT Headers → Section Table → Sections
- Les NT Headers contiennent 16 Data Directories (Import, Export, Reloc, TLS...)
- L'IAT (Import Address Table) stocke les adresses des fonctions importées
- Comprendre le PE est essentiel pour : injection, hooking, obfuscation, malware analysis
- RVA (Relative Virtual Address) = Offset depuis ImageBase
- Conversion RVA ↔ File Offset nécessaire pour parser depuis disque

## Ressources complémentaires

- [Microsoft PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE-bear - PE Analysis Tool](https://github.com/hasherezade/pe-bear)
- [CFF Explorer](https://ntcore.com/?page_id=388)
- [Corkami PE Poster](https://github.com/corkami/pics/blob/master/binary/pe101/pe101-64.pdf)
- [Malware Unicorn PE Tutorial](https://malwareunicorn.org/workshops/pe.html)

---

**Navigation**
- [Module précédent](../../09-Tokens-Privileges/)
- [Module suivant](../02-PE-Parsing/)
