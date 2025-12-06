# Cours : Format Mach-O (macOS Executable)

## 1. Introduction - Les Formats Exécutables

### 1.1 Qu'est-ce qu'un Format Exécutable ?

Quand vous compilez un programme C, le compilateur crée un **fichier binaire** qui contient :
- Le **code machine** (instructions CPU)
- Les **données** (variables globales, constantes)
- Des **métadonnées** (comment charger le programme, dépendances, etc.)

Ce fichier suit un **format** spécifique que le système d'exploitation sait interpréter.

### 1.2 Les Trois Grands Formats

```ascii
┌──────────────┬─────────────────┬──────────────────────┐
│ Système      │ Format          │ Extension            │
├──────────────┼─────────────────┼──────────────────────┤
│ Linux/Unix   │ ELF             │ (aucune) ou .elf     │
│              │ Executable and  │                      │
│              │ Linkable Format │                      │
├──────────────┼─────────────────┼──────────────────────┤
│ Windows      │ PE/COFF         │ .exe, .dll           │
│              │ Portable        │                      │
│              │ Executable      │                      │
├──────────────┼─────────────────┼──────────────────────┤
│ macOS/iOS    │ Mach-O          │ (aucune), .dylib     │
│              │ Mach Object     │                      │
└──────────────┴─────────────────┴──────────────────────┘
```

### 1.3 Pourquoi Comprendre Mach-O ?

Pour l'**exploitation macOS**, vous devez comprendre Mach-O pour :
- **Analyser** des malwares
- **Patcher** des binaires (modifier le code)
- **Injecter** des dylibs
- **Bypasser** le code signing
- **Comprendre** comment le loader (dyld) fonctionne

## 1.4 Vue d'Ensemble d'un Fichier Mach-O

```ascii
FICHIER BINAIRE (example.app/Contents/MacOS/example) :

┌─────────────────────────────────────┐  Offset 0x0
│                                     │
│  MACH HEADER (64 bytes)             │  ← Métadonnées de base
│  - Magic : 0xFEEDFACF               │
│  - CPU Type : ARM64                 │
│  - File Type : EXECUTABLE           │
│  - Number of Commands : 15          │
│                                     │
├─────────────────────────────────────┤  Offset 0x40
│                                     │
│  LOAD COMMANDS (~1-2 KB)            │  ← Instructions pour le loader
│  - LC_SEGMENT_64 (__TEXT)           │
│  - LC_SEGMENT_64 (__DATA)           │
│  - LC_LOAD_DYLIB (libSystem.dylib)  │
│  - LC_MAIN (entry point)            │
│  - LC_CODE_SIGNATURE                │
│  - ...                              │
│                                     │
├─────────────────────────────────────┤  Offset variable
│                                     │
│  __TEXT SEGMENT (Code)              │  ← Code exécutable
│  - __text : code machine            │
│  - __cstring : "Hello World\n"      │
│  - __const : constantes             │
│                                     │
├─────────────────────────────────────┤
│                                     │
│  __DATA SEGMENT (Données)           │  ← Données modifiables
│  - __data : globales initialisées   │
│  - __bss : globales non-init        │
│  - __common : données communes      │
│                                     │
├─────────────────────────────────────┤
│                                     │
│  __LINKEDIT SEGMENT                 │  ← Infos de linking
│  - Symbol table                     │
│  - String table                     │
│  - Code signature                   │
│                                     │
└─────────────────────────────────────┘  Fin fichier
```

## 2. Structure Mach-O

```ascii
┌──────────────────┐
│  Mach Header     │ ← Métadonnées
├──────────────────┤
│  Load Commands   │ ← Instructions de chargement
├──────────────────┤
│  __TEXT Segment  │ ← Code exécutable (RX)
│    __text        │
│    __cstring     │
├──────────────────┤
│  __DATA Segment  │ ← Données (RW)
│    __data        │
│    __bss         │
├──────────────────┤
│  __LINKEDIT      │ ← Infos de linking
└──────────────────┘
```

## 3. Mach Header

```c
struct mach_header_64 {
    uint32_t    magic;          // 0xFEEDFACF (ARM64)
    cpu_type_t  cputype;        // CPU_TYPE_ARM64
    cpu_subtype_t cpusubtype;
    uint32_t    filetype;       // MH_EXECUTE, MH_DYLIB...
    uint32_t    ncmds;          // Nombre de load commands
    uint32_t    sizeofcmds;
    uint32_t    flags;
    uint32_t    reserved;
};
```

## 4. Load Commands

Instruc

tions pour le loader.

```c
// LC_SEGMENT_64 : Charger un segment
struct segment_command_64 {
    uint32_t cmd;           // LC_SEGMENT_64
    uint32_t cmdsize;
    char segname[16];       // "__TEXT", "__DATA"
    uint64_t vmaddr;        // Adresse virtuelle
    uint64_t vmsize;
    uint64_t fileoff;       // Offset dans fichier
    uint64_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t nsects;        // Nombre de sections
    uint32_t flags;
};
```

**Commandes courantes** :
- `LC_SEGMENT_64` : Segment à charger
- `LC_LOAD_DYLIB` : Bibliothèque dynamique
- `LC_MAIN` : Point d'entrée
- `LC_CODE_SIGNATURE` : Signature de code

## 5. Segments et Sections

### __TEXT (RX)

- `__text` : Code machine
- `__cstring` : Strings constantes
- `__const` : Constantes

### __DATA (RW)

- `__data` : Données initialisées
- `__bss` : Données non initialisées
- `__common` : Données communes

## 6. Analyser avec otool

```bash
# Header
otool -h binary

# Load commands
otool -l binary

# Désassembler
otool -tv binary

# Strings
otool -s __TEXT __cstring binary

# Dylibs
otool -L binary
```

## 7. Parsing en C

```c
#include <mach-o/loader.h>
#include <mach-o/fat.h>

void parse_macho(const char *path) {
    int fd = open(path, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    
    void *file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    struct mach_header_64 *header = (struct mach_header_64*)file;
    
    if (header->magic == MH_MAGIC_64) {
        printf("Mach-O 64-bit\n");
        printf("CPU Type: %d\n", header->cputype);
        printf("File Type: %d\n", header->filetype);
    }
    
    // Parcourir load commands
    struct load_command *lc = (struct load_command*)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64*)lc;
            printf("Segment: %s\n", seg->segname);
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    munmap(file, st.st_size);
    close(fd);
}
```

## 8. Code Signing

macOS nécessite que les binaires soient signés.

```bash
# Vérifier signature
codesign -dv binary

# Signer
codesign -s - binary

# Retirer signature (pour modification)
codesign --remove-signature binary
```

## 9. Exploitation

### Modifier un Mach-O

```c
// Patcher une instruction
struct mach_header_64 *header = ...;
struct segment_command_64 *text_seg = find_segment(header, "__TEXT");

// Trouver section __text
struct section_64 *text_sect = find_section(text_seg, "__text");

// Patcher à offset
uint32_t *code = (uint32_t*)(file + text_sect->offset);
code[10] = 0xD65F03C0;  // RET (ARM64)
```

### Injection de Dylib

```bash
# Ajouter un LC_LOAD_DYLIB
insert_dylib malicious.dylib binary
```

## 10. Ressources

- [Mach-O Programming Topics](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/)
- [loader.h](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h)

