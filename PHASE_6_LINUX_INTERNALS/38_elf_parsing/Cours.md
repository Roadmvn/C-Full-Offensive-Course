# Module 38 : ELF Parsing - Analyser les Exécutables Linux

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas comprendre et manipuler le format ELF (Executable and Linkable Format) :
- Lire et parser la structure ELF d'un binaire Linux
- Extraire les headers, sections et segments
- Identifier les entry points et imports/exports
- Modifier des binaires à la volée
- Injecter du code dans des exécutables

## 📚 Théorie

### C'est quoi ELF ?

**ELF** (Executable and Linkable Format) est le format standard des exécutables, bibliothèques partagées et fichiers objets sur Linux.

**Types de fichiers ELF** :
```ascii
┌────────────────────────────────────────────┐
│         FICHIERS ELF                       │
├────────────────────────────────────────────┤
│                                            │
│  1. Exécutables (.exe équivalent)          │
│     /bin/ls, /usr/bin/gcc, etc.            │
│     Type: ET_EXEC ou ET_DYN (PIE)          │
│                                            │
│  2. Bibliothèques partagées (.so)          │
│     libc.so.6, libssl.so                   │
│     Type: ET_DYN                           │
│                                            │
│  3. Fichiers objets (.o)                   │
│     main.o, utils.o                        │
│     Type: ET_REL (relocatable)             │
│                                            │
│  4. Core dumps                             │
│     core.12345                             │
│     Type: ET_CORE                          │
│                                            │
└────────────────────────────────────────────┘
```

### Pourquoi parser ELF ?

**Utilité Red Team** :
1. **Analyse statique** : Comprendre un binaire sans l'exécuter
2. **Injection de code** : Ajouter du shellcode dans un exécutable
3. **Patching** : Modifier le comportement d'un programme
4. **Rootkits** : Cacher du code dans des binaires légitimes
5. **Backdoors** : Créer des portes dérobées persistantes

### Structure d'un fichier ELF

```ascii
┌─────────────────────────────────────────────────────────┐
│                 FICHIER ELF                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. ELF HEADER (64 bytes)                               │
│     ┌─────────────────────────────────────┐            │
│     │ Magic: 0x7F 'E' 'L' 'F'             │            │
│     │ Class: 32-bit ou 64-bit             │            │
│     │ Endianness: Little/Big endian       │            │
│     │ Type: EXEC, DYN, REL, CORE          │            │
│     │ Machine: x86-64, ARM, etc.          │            │
│     │ Entry point: 0x401000               │            │
│     │ Program header offset               │            │
│     │ Section header offset               │            │
│     └─────────────────────────────────────┘            │
│           ↓                                             │
│  2. PROGRAM HEADERS (View runtime)                      │
│     ┌─────────────────────────────────────┐            │
│     │ Segment 1: PT_LOAD (code)           │            │
│     │   Offset: 0x0                       │            │
│     │   Virtual addr: 0x400000            │            │
│     │   Size: 0x1000                      │            │
│     │   Flags: R-E (read + execute)       │            │
│     ├─────────────────────────────────────┤            │
│     │ Segment 2: PT_LOAD (data)           │            │
│     │   Offset: 0x1000                    │            │
│     │   Virtual addr: 0x601000            │            │
│     │   Size: 0x500                       │            │
│     │   Flags: RW- (read + write)         │            │
│     ├─────────────────────────────────────┤            │
│     │ Segment 3: PT_DYNAMIC               │            │
│     │   Infos pour le dynamic linker      │            │
│     └─────────────────────────────────────┘            │
│           ↓                                             │
│  3. SECTIONS (View linking)                             │
│     ┌─────────────────────────────────────┐            │
│     │ .text    - Code exécutable          │            │
│     │ .rodata  - Données read-only        │            │
│     │ .data    - Données initialisées     │            │
│     │ .bss     - Données non-init         │            │
│     │ .symtab  - Table des symboles       │            │
│     │ .strtab  - Table des strings        │            │
│     │ .plt     - Procedure Linkage Table  │            │
│     │ .got     - Global Offset Table      │            │
│     └─────────────────────────────────────┘            │
│           ↓                                             │
│  4. SECTION HEADERS                                     │
│     Descripteurs de chaque section                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### ELF Header - Structure détaillée

**En C (64-bit)** :
```c
typedef struct {
    unsigned char e_ident[16];  // Magic + metadata
    uint16_t      e_type;       // Type fichier (ET_EXEC, etc.)
    uint16_t      e_machine;    // Architecture (EM_X86_64)
    uint32_t      e_version;    // Version ELF
    uint64_t      e_entry;      // Entry point (adresse _start)
    uint64_t      e_phoff;      // Program header offset
    uint64_t      e_shoff;      // Section header offset
    uint32_t      e_flags;      // Flags spécifiques
    uint16_t      e_ehsize;     // Taille ELF header (64)
    uint16_t      e_phentsize;  // Taille program header entry
    uint16_t      e_phnum;      // Nombre program headers
    uint16_t      e_shentsize;  // Taille section header entry
    uint16_t      e_shnum;      // Nombre section headers
    uint16_t      e_shstrndx;   // Index section string table
} Elf64_Ehdr;
```

**e_ident détaillé** :
```ascii
Offset  Valeur          Signification
──────────────────────────────────────────
0       0x7F            Magic byte
1-3     'E' 'L' 'F'     "ELF" ASCII
4       1 ou 2          Class (1=32bit, 2=64bit)
5       1 ou 2          Data (1=little, 2=big endian)
6       1               Version
7       0-255           OS/ABI (0=SYSV, 3=Linux)
8       0               ABI version
9-15    0 (padding)     Réservé
```

### Program Headers vs Section Headers

**Program Headers** (vue runtime) :
- Utilisés par le **loader** au lancement du programme
- Définissent les **segments** en mémoire
- Permissions (R, W, X)

**Section Headers** (vue linking) :
- Utilisés par le **linker** lors de la compilation
- Définissent les **sections** (.text, .data, etc.)
- Peuvent être supprimés après compilation (stripping)

```ascii
COMPILATION              RUNTIME
═══════════              ═══════

 main.c                 Processus en mémoire
    ↓                   ┌────────────────┐
  gcc                   │  0x400000      │
    ↓                   │  Segment CODE  │
 main.o                 │  (R-X)         │
    ↓                   │  .text         │
Section Headers         │  .rodata       │
 (.text, .data)         ├────────────────┤
    ↓                   │  0x600000      │
  ld (linker)           │  Segment DATA  │
    ↓                   │  (RW-)         │
 main (ELF)             │  .data         │
Program Headers         │  .bss          │
 (LOAD segments)        └────────────────┘
```

## 🔍 Visualisation

### Anatomie complète d'un ELF

```ascii
Fichier: /bin/ls (exemple)
═══════════════════════════════════════════════════════════

Offset      Contenu                 Description
────────────────────────────────────────────────────────────
0x0000      7F 45 4C 46 02 01 01    ELF Header
            ┌──┬──┬──┬──┬──┬──┬──
            │7F│E │L │F │02│01│01   Magic + Class + Endian
            └──┴──┴──┴──┴──┴──┴──
            00 00 00 00 00 00 00    Padding
            03 00                   e_type = ET_DYN
            3E 00                   e_machine = EM_X86_64
            01 00 00 00             e_version = 1
            E0 5C 00 00 00 00 00    e_entry = 0x5CE0
            40 00 00 00 00 00 00    e_phoff = 0x40
            [...]

0x0040      Program Headers (13 entries)
            ┌────────────────────────────────────┐
            │ PT_PHDR    │ Flags: R   │          │
            │ PT_INTERP  │ Flags: R   │          │
            │ PT_LOAD    │ Flags: R E │ 0x0-...  │
            │ PT_LOAD    │ Flags: RW  │ 0x...    │
            │ PT_DYNAMIC │ Flags: RW  │          │
            │ PT_NOTE    │ Flags: R   │          │
            │ PT_GNU_EH_FRAME         │          │
            │ PT_GNU_STACK│ Flags: RW │          │
            │ PT_GNU_RELRO│ Flags: R  │          │
            └────────────────────────────────────┘

0x1000      .text section (code exécutable)
            48 83 EC 08             sub rsp, 0x8
            E8 1F 00 00 00          call ...
            [... instructions assembleur ...]

0x3000      .rodata section (strings)
            "usage: ls [OPTION]... [FILE]...\n"
            "List information about the FILEs\n"
            [... autres strings ...]

0x5000      .data section (variables globales)
            [... données initialisées ...]

0x6000      .bss section (non initialisé)
            [... réservé pour variables non-init ...]

0xEOF       Section Headers (67 entries)
            ┌────────────────────────────────────┐
            │ .interp    │ Type: PROGBITS  │     │
            │ .note      │ Type: NOTE      │     │
            │ .hash      │ Type: HASH      │     │
            │ .dynsym    │ Type: DYNSYM    │     │
            │ .dynstr    │ Type: STRTAB    │     │
            │ .text      │ Type: PROGBITS  │     │
            │ .rodata    │ Type: PROGBITS  │     │
            │ .data      │ Type: PROGBITS  │     │
            │ .bss       │ Type: NOBITS    │     │
            │ .symtab    │ Type: SYMTAB    │     │
            │ .strtab    │ Type: STRTAB    │     │
            └────────────────────────────────────┘
```

### Chargement en mémoire

```ascii
FICHIER ELF                         MÉMOIRE PROCESSUS
═══════════                         ═════════════════

┌─────────────┐                    Hautes adresses
│  Section    │                    ┌──────────────────┐
│  Headers    │                    │   Stack          │
├─────────────┤                    │   (RW-)          │
│             │                    ├──────────────────┤
│  .bss       │────┐               │   [heap]         │
│  .data      │────┼──────────────→│   0x600000       │
│  .rodata    │────┘               │   Segment DATA   │
│  .text      │────┐               │   (RW-)          │
│             │    │               ├──────────────────┤
├─────────────┤    └──────────────→│   0x400000       │
│  Program    │                    │   Segment CODE   │
│  Headers    │                    │   (R-X)          │
├─────────────┤                    │   .text          │
│  ELF Header │                    │   .rodata        │
└─────────────┘                    ├──────────────────┤
                                   │   [vdso]         │
                                   │   [vvar]         │
                                   └──────────────────┘
                                   Basses adresses
```

## 💻 Exemple pratique

### Exemple 1 : Lire le ELF Header

```c
// elf_reader.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

// Fonction pour vérifier si c'est un fichier ELF
int is_elf(Elf64_Ehdr *hdr) {
    return (hdr->e_ident[EI_MAG0] == ELFMAG0 &&
            hdr->e_ident[EI_MAG1] == ELFMAG1 &&
            hdr->e_ident[EI_MAG2] == ELFMAG2 &&
            hdr->e_ident[EI_MAG3] == ELFMAG3);
}

// Afficher les infos ELF header
void print_elf_header(Elf64_Ehdr *hdr) {
    printf("=== ELF HEADER ===\n");

    // Magic
    printf("Magic:   %02x %c%c%c\n",
           hdr->e_ident[EI_MAG0],
           hdr->e_ident[EI_MAG1],
           hdr->e_ident[EI_MAG2],
           hdr->e_ident[EI_MAG3]);

    // Class
    printf("Class:   ");
    if (hdr->e_ident[EI_CLASS] == ELFCLASS32)
        printf("32-bit\n");
    else if (hdr->e_ident[EI_CLASS] == ELFCLASS64)
        printf("64-bit\n");
    else
        printf("Unknown\n");

    // Endianness
    printf("Data:    ");
    if (hdr->e_ident[EI_DATA] == ELFDATA2LSB)
        printf("Little endian\n");
    else if (hdr->e_ident[EI_DATA] == ELFDATA2MSB)
        printf("Big endian\n");

    // Type
    printf("Type:    ");
    switch (hdr->e_type) {
        case ET_NONE: printf("NONE\n"); break;
        case ET_REL:  printf("REL (Relocatable)\n"); break;
        case ET_EXEC: printf("EXEC (Executable)\n"); break;
        case ET_DYN:  printf("DYN (Shared object/PIE)\n"); break;
        case ET_CORE: printf("CORE (Core dump)\n"); break;
        default:      printf("Unknown\n");
    }

    // Machine
    printf("Machine: ");
    switch (hdr->e_machine) {
        case EM_X86_64: printf("x86-64\n"); break;
        case EM_AARCH64: printf("ARM64\n"); break;
        case EM_386:    printf("x86\n"); break;
        default:        printf("Unknown (%d)\n", hdr->e_machine);
    }

    // Entry point
    printf("Entry:   0x%lx\n", hdr->e_entry);

    // Headers offsets
    printf("Program headers: offset=0x%lx count=%d\n",
           hdr->e_phoff, hdr->e_phnum);
    printf("Section headers: offset=0x%lx count=%d\n",
           hdr->e_shoff, hdr->e_shnum);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }

    // Ouvrir le fichier
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Lire l'ELF header
    Elf64_Ehdr hdr;
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("read");
        close(fd);
        return 1;
    }

    // Vérifier magic ELF
    if (!is_elf(&hdr)) {
        fprintf(stderr, "Not an ELF file\n");
        close(fd);
        return 1;
    }

    // Afficher les infos
    print_elf_header(&hdr);

    close(fd);
    return 0;
}
```

**Compilation et test** :
```bash
gcc -o elf_reader elf_reader.c
./elf_reader /bin/ls
```

**Sortie** :
```
=== ELF HEADER ===
Magic:   7f ELF
Class:   64-bit
Data:    Little endian
Type:    DYN (Shared object/PIE)
Machine: x86-64
Entry:   0x5ce0
Program headers: offset=0x40 count=13
Section headers: offset=0x21e08 count=28
```

### Exemple 2 : Extraction de sections

```c
// elf_extractor.c - Extrait une section d'un ELF
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

int extract_section(const char *elf_file, const char *section_name, const char *output) {
    int fd = open(elf_file, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct stat st;
    fstat(fd, &st);

    // Mapper le fichier en mémoire
    void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    Elf64_Ehdr *hdr = (Elf64_Ehdr *)data;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(data + hdr->e_shoff);

    // String table des noms de sections
    Elf64_Shdr *shstrtab = &shdr[hdr->e_shstrndx];
    char *strtab = (char *)(data + shstrtab->sh_offset);

    // Chercher la section
    for (int i = 0; i < hdr->e_shnum; i++) {
        if (strcmp(strtab + shdr[i].sh_name, section_name) == 0) {
            printf("Found '%s': offset=0x%lx size=0x%lx\n",
                   section_name, shdr[i].sh_offset, shdr[i].sh_size);

            // Écrire dans fichier
            int out_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out_fd < 0) {
                perror("open output");
                munmap(data, st.st_size);
                close(fd);
                return -1;
            }

            write(out_fd, data + shdr[i].sh_offset, shdr[i].sh_size);
            close(out_fd);

            printf("Extracted to %s\n", output);
            munmap(data, st.st_size);
            close(fd);
            return 0;
        }
    }

    fprintf(stderr, "Section '%s' not found\n", section_name);
    munmap(data, st.st_size);
    close(fd);
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <elf> <section> <output>\n", argv[0]);
        return 1;
    }

    return extract_section(argv[1], argv[2], argv[3]);
}
```

**Utilisation** :
```bash
gcc -o elf_extractor elf_extractor.c

# Extraire .text
./elf_extractor /bin/ls .text ls_text.bin

# Voir le code machine
hexdump -C ls_text.bin | head -20
```

### Exemple 3 : Injection de shellcode

```c
// elf_injector.c - Injecte du shellcode dans un ELF
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <string.h>

// Shellcode exit(42)
unsigned char shellcode[] = {
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,  // mov rax, 60
    0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00,  // mov rdi, 42
    0x0f, 0x05                                  // syscall
};

int inject(const char *input, const char *output) {
    int fd = open(input, O_RDONLY);
    if (fd < 0) {
        perror("open input");
        return -1;
    }

    struct stat st;
    fstat(fd, &st);

    unsigned char *data = malloc(st.st_size);
    read(fd, data, st.st_size);
    close(fd);

    Elf64_Ehdr *hdr = (Elf64_Ehdr *)data;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(data + hdr->e_shoff);

    // String table
    Elf64_Shdr *shstrtab = &shdr[hdr->e_shstrndx];
    char *strtab = (char *)(data + shstrtab->sh_offset);

    // Trouver .text
    for (int i = 0; i < hdr->e_shnum; i++) {
        if (strcmp(strtab + shdr[i].sh_name, ".text") == 0) {
            printf("Injecting shellcode into .text\n");

            // Modifier entry point
            uint64_t old_entry = hdr->e_entry;
            hdr->e_entry = shdr[i].sh_addr;

            // Injecter shellcode
            memcpy(data + shdr[i].sh_offset, shellcode, sizeof(shellcode));

            printf("Old entry: 0x%lx → New entry: 0x%lx\n", old_entry, hdr->e_entry);
            break;
        }
    }

    // Écrire fichier modifié
    fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        perror("open output");
        free(data);
        return -1;
    }

    write(fd, data, st.st_size);
    close(fd);
    free(data);

    printf("Injected ELF written to %s\n", output);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_elf> <output_elf>\n", argv[0]);
        return 1;
    }

    return inject(argv[1], argv[2]);
}
```

**Test** :
```bash
gcc -o elf_injector elf_injector.c

# Créer programme test
echo 'int main() { return 0; }' > test.c
gcc -o test test.c

# Injecter shellcode
./elf_injector test test_backdoor

# Tester
./test_backdoor
echo $?  # Affiche: 42
```

## 🎯 Application Red Team

### 1. Backdoor via GOT/PLT Hijacking

**Technique** : Modifier la Global Offset Table pour rediriger les appels de fonctions.

```c
// Remplacer exit() par un shellcode custom
// 1. Trouver .got.plt
// 2. Localiser entrée exit@got
// 3. Remplacer adresse par shellcode
```

### 2. Persistence via .init_array

**Injecter code qui s'exécute avant main()** :

```c
// Modifier .init_array pour ajouter constructeur malveillant
// Le code sera exécuté automatiquement au lancement
```

### 3. Analyse de malware

**Parser un binaire suspect** :
```bash
# Extraire strings suspectes
./elf_extractor malware .rodata strings.txt
strings strings.txt | grep -i "http\|password\|key"

# Extraire code
./elf_extractor malware .text code.bin

# Désassembler
objdump -D -b binary -m i386:x86-64 code.bin
```

## 📝 Points clés

### À retenir absolument

1. **Structure ELF**
   - Header → Program Headers → Sections → Section Headers
   - Magic: `0x7F 'E' 'L' 'F'`
   - Entry point dans `e_entry`

2. **Program vs Section Headers**
   - Program = vue runtime (loader)
   - Section = vue linking (linker)

3. **Sections importantes**
   - `.text` = code exécutable
   - `.rodata` = données read-only
   - `.data` = données initialisées
   - `.bss` = données non-init
   - `.got`/`.plt` = dynamic linking

4. **Outils CLI**
   ```bash
   readelf -a file    # Infos complètes
   objdump -d file    # Désassembler
   nm file            # Symboles
   strings file       # Strings
   ```

## ➡️ Prochaine étape

**Module 39 : Persistence Linux**

Maintenant que tu sais parser et modifier des ELF, le prochain module te montrera comment créer de la persistence sur Linux via différentes techniques de backdooring système.

## 📚 Ressources

- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [readelf man page](https://linux.die.net/man/1/readelf)
- `/usr/include/elf.h` - Structures C
