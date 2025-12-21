# PE Format - Parsing et manipulation

## Objectif
Maîtriser le format PE (Portable Executable) pour créer des loaders, packers, et injecteurs. Base de tout maldev Windows : Cobalt Strike beacon, Donut, reflective DLL injection.

## Prérequis
- Types C et pointeurs
- Notion d'adressage mémoire (RVA vs VA)
- Bases de l'assembleur x86/x64

---

## Théorie

### Structure globale d'un PE

```
┌─────────────────────────────────────────┐
│ DOS Header (0x40 bytes)                 │ ← "MZ" magic
│   e_lfanew → pointe vers PE header      │
├─────────────────────────────────────────┤
│ DOS Stub (optionnel)                    │ ← "This program cannot..."
├─────────────────────────────────────────┤
│ PE Signature (4 bytes)                  │ ← "PE\0\0" (0x4550)
├─────────────────────────────────────────┤
│ File Header (20 bytes)                  │ ← Machine, NumberOfSections
├─────────────────────────────────────────┤
│ Optional Header (variable)              │ ← ImageBase, EntryPoint, DataDirectories
├─────────────────────────────────────────┤
│ Section Headers (40 bytes × N)          │ ← .text, .data, .rdata...
├─────────────────────────────────────────┤
│ Section Data                            │
│   .text  (code exécutable)              │
│   .data  (variables globales)           │
│   .rdata (constantes, imports)          │
│   .reloc (relocations)                  │
│   ...                                   │
└─────────────────────────────────────────┘
```

### RVA vs VA vs Raw Offset

| Terme | Signification | Exemple |
|-------|---------------|---------|
| **Raw Offset** | Offset dans le fichier sur disque | 0x400 |
| **RVA** | Relative Virtual Address - offset depuis ImageBase | 0x1000 |
| **VA** | Virtual Address - adresse réelle en mémoire | 0x00401000 |

**Formules :**
```
VA = ImageBase + RVA
RVA = VA - ImageBase
Raw = RVA - Section.VirtualAddress + Section.PointerToRawData
```

### Data Directories

Les 16 Data Directories indexent les structures importantes :

| Index | Nom | Usage maldev |
|-------|-----|--------------|
| 0 | Export | Résolution d'API custom |
| 1 | Import | IAT hooking, import reconstruction |
| 2 | Resource | Payload storage, icon extraction |
| 3 | Exception | Exception handler hijacking |
| 5 | Relocation | Loader reflective, ASLR bypass |
| 9 | TLS | TLS callbacks (anti-debug, init code) |
| 14 | CLR | .NET loader detection |

---

## Analyse du code `raw_maldev.c`

### Section 1 : Macros de navigation

```c
#define RVA(b,r)     ((BYTE*)(b)+(r))
#define DEREF(p)     (*(DWORD_PTR*)(p))
#define DEREF32(p)   (*(DWORD*)(p))
#define DEREF16(p)   (*(WORD*)(p))
```

**Explication :**

| Macro | Ce qu'elle fait | Exemple |
|-------|-----------------|---------|
| `RVA(b,r)` | Calcule VA depuis base + offset | `RVA(0x10000, 0x1000)` → `0x11000` |
| `DEREF(p)` | Lit un pointeur/QWORD à l'adresse | Lire entrée IAT |
| `DEREF32(p)` | Lit un DWORD à l'adresse | Lire e_lfanew |
| `DEREF16(p)` | Lit un WORD à l'adresse | Lire magic MZ |

```c
// Header access
#define DOS(m)       ((PIMAGE_DOS_HEADER)(m))
#define NT(m)        ((PIMAGE_NT_HEADERS)RVA(m,DOS(m)->e_lfanew))
#define FILE_H(m)    (&NT(m)->FileHeader)
#define OPT(m)       (&NT(m)->OptionalHeader)
```

**Visualisation :**
```
m (base) ──► DOS Header
              │
              └─ e_lfanew (offset 0x3C) ──► NT Headers
                                              ├─ Signature ("PE\0\0")
                                              ├─ FileHeader
                                              └─ OptionalHeader
```

```c
#define SEC(m)  ((PIMAGE_SECTION_HEADER)RVA(m,DOS(m)->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+FILE_H(m)->SizeOfOptionalHeader))
```

**Calcul de l'offset des sections :**
```
Section Headers offset = e_lfanew
                       + 4 (PE signature)
                       + 20 (FILE_HEADER)
                       + SizeOfOptionalHeader (variable: 224 ou 240)
```

---

### Section 2 : Data Directory access

```c
#define DIR(m,i)     (&OPT(m)->DataDirectory[i])
#define EXP(m)       ((PIMAGE_EXPORT_DIRECTORY)RVA(m,DIR(m,0)->VirtualAddress))
#define IMP(m)       ((PIMAGE_IMPORT_DESCRIPTOR)RVA(m,DIR(m,1)->VirtualAddress))
#define RELOC(m)     ((PIMAGE_BASE_RELOCATION)RVA(m,DIR(m,5)->VirtualAddress))
#define TLS(m)       ((PIMAGE_TLS_DIRECTORY)RVA(m,DIR(m,9)->VirtualAddress))
```

**Pattern de lecture :**
1. `DIR(m,i)` retourne un `IMAGE_DATA_DIRECTORY` avec `{VirtualAddress, Size}`
2. `VirtualAddress` est un RVA
3. On le convertit en VA avec `RVA(m, ...)`
4. On caste vers la structure appropriée

---

### Section 3 : Validation PE

```c
#define IS_PE(m)     (DEREF16(m)==0x5A4D && DEREF32(RVA(m,DEREF32(RVA(m,0x3C))))==0x4550)
#define IS_64(m)     (OPT(m)->Magic==0x20B)
#define IS_DLL(m)    (FILE_H(m)->Characteristics&0x2000)
```

**Décomposition de `IS_PE` :**
```c
DEREF16(m) == 0x5A4D           // Offset 0x00: "MZ" signature
    &&
DEREF32(                       // Lire DWORD...
    RVA(m,                     // ...à l'adresse base+...
        DEREF32(RVA(m, 0x3C))  // ...valeur de e_lfanew
    )
) == 0x4550                    // Doit être "PE\0\0"
```

**Magic numbers :**

| Valeur | Signification |
|--------|---------------|
| `0x5A4D` | "MZ" - Mark Zbikowski (créateur du format DOS) |
| `0x4550` | "PE\0\0" - Portable Executable signature |
| `0x10B` | PE32 (Optional Header Magic) |
| `0x20B` | PE32+ / PE64 |
| `0x2000` | IMAGE_FILE_DLL characteristic |

---

### Section 4 : Hash functions

```c
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

__forceinline DWORD hash_ror13(char* s)
{
    DWORD h = 0;
    while(*s) {
        h = ROR(h, 13);  // Rotation à droite de 13 bits
        h += *s++;       // Ajoute le caractère
    }
    return h;
}
```

**Pourquoi ROR13 ?**
- Utilisé par Metasploit `block_api`
- Compatible avec des milliers de shellcodes existants
- Valeur 13 = bon compromis distribution/collisions

**Exemple de calcul :**
```
"VirtualAlloc" → 0x91AFCA54

V: h = 0 → ROR(0,13) + 'V' = 86
i: h = 86 → ROR(86,13) = 45088768 → + 'i' = 45088873
...
```

```c
// Case insensitive pour les DLLs
__forceinline DWORD hash_dll(WCHAR* s)
{
    DWORD h = 0;
    while(*s) {
        WCHAR c = *s++;
        if(c >= 'A' && c <= 'Z') c += 0x20;  // tolower
        h = ROR(h, 13);
        h += c;
    }
    return h;
}
```

**Pourquoi case-insensitive ?** Windows n'est pas sensible à la casse pour les DLLs. `KERNEL32.DLL` = `kernel32.dll`.

---

### Section 5 : Résolution d'exports

```c
PVOID get_proc_by_name(PVOID base, char* name)
{
    PIMAGE_EXPORT_DIRECTORY exp = EXP(base);

    // 3 tableaux parallèles
    DWORD* names = (DWORD*)RVA(base, exp->AddressOfNames);      // Noms (RVAs)
    WORD*  ords  = (WORD*)RVA(base, exp->AddressOfNameOrdinals); // Ordinaux
    DWORD* funcs = (DWORD*)RVA(base, exp->AddressOfFunctions);   // Adresses (RVAs)

    for(DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fn = (char*)RVA(base, names[i]);

        // strcmp inline (pas de CRT)
        char* a = fn; char* b = name;
        while(*a && *a == *b) { a++; b++; }

        if(*a == *b)
            return RVA(base, funcs[ords[i]]);
    }
    return 0;
}
```

**Structure Export Directory :**
```
┌────────────────────────────────────────────────────┐
│ Export Directory                                   │
│   AddressOfNames     ──────► ["func1", "func2"...] │ (RVAs vers strings)
│   AddressOfNameOrdinals ──► [0, 1, 2...]           │ (index dans Functions)
│   AddressOfFunctions ──────► [0x1234, 0x5678...]   │ (RVAs vers code)
│   NumberOfNames                                    │
│   NumberOfFunctions                                │
│   Base (ordinal base, souvent 1)                   │
└────────────────────────────────────────────────────┘
```

**Algorithme :**
1. Cherche le nom dans `AddressOfNames`
2. Récupère l'index `i`
3. Lit l'ordinal dans `AddressOfNameOrdinals[i]`
4. Retourne `AddressOfFunctions[ordinal]`

```c
// Résolution par hash - évite les strings dans le binaire
PVOID get_proc_by_hash(PVOID base, DWORD hash)
{
    // ... même structure ...
    for(DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fn = (char*)RVA(base, names[i]);
        if(hash_ror13(fn) == hash)
            return RVA(base, funcs[ords[i]]);
    }
    return 0;
}
```

**Avantage :** Pas de strings "VirtualAlloc", "CreateThread" etc. dans le binaire. Juste des hash comme `0x91AFCA54`.

---

### Section 6 : Forwarded exports

```c
BOOL is_forwarded(PVOID base, PVOID func)
{
    PIMAGE_DATA_DIRECTORY dir = DIR(base, 0);  // Export directory
    DWORD rva = (DWORD)((BYTE*)func - (BYTE*)base);
    return (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size);
}
```

**Qu'est-ce qu'un forwarded export ?**

Certaines fonctions ne sont pas dans la DLL mais redirigent vers une autre :
```
ntdll.dll!RtlExitUserProcess → ntdll.dll!RtlExitUserThread
kernel32.dll!HeapAlloc → ntdll.dll!RtlAllocateHeap
```

**Détection :** Si l'adresse de la fonction pointe DANS la section export (pas dans .text), c'est un forward. Le contenu est une string comme `"NTDLL.RtlAllocateHeap"`.

---

### Section 7 : Section operations

```c
PIMAGE_SECTION_HEADER get_section(PVOID base, char* name)
{
    WORD count = FILE_H(base)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(base);

    for(WORD i = 0; i < count; i++) {
        // Compare les 8 premiers bytes (nom de section = 8 chars max)
        int j;
        for(j = 0; j < 8 && sec[i].Name[j] == name[j]; j++);
        if(j == 8 || (!sec[i].Name[j] && !name[j]))
            return &sec[i];
    }
    return 0;
}
```

**Noms de sections courants :**

| Nom | Contenu |
|-----|---------|
| `.text` | Code exécutable |
| `.data` | Variables globales initialisées |
| `.rdata` | Constantes, imports |
| `.bss` | Variables non initialisées |
| `.reloc` | Table de relocations |
| `.rsrc` | Resources (icons, strings) |
| `.pdata` | Exception handlers (x64) |

**Sections suspectes (packers/malware) :**
- `.UPX0`, `.UPX1` - UPX packer
- Noms aléatoires/illisibles
- Sections avec R+W+X simultanément

```c
DWORD rva_to_raw(PVOID base, DWORD rva)
{
    PIMAGE_SECTION_HEADER sec = rva_to_section(base, rva);
    if(!sec) return 0;
    return rva - sec->VirtualAddress + sec->PointerToRawData;
}
```

**Formule de conversion RVA → Raw :**
```
Raw = RVA - Section.VirtualAddress + Section.PointerToRawData
```

---

### Section 8 : Relocations

```c
void process_relocs(PVOID base, DWORD_PTR delta)
{
    PIMAGE_DATA_DIRECTORY dir = DIR(base, 5);
    if(!dir->Size) return;

    PIMAGE_BASE_RELOCATION reloc = RELOC(base);

    while(reloc->VirtualAddress) {
        // Nombre d'entrées = (SizeOfBlock - 8) / 2
        DWORD count = (reloc->SizeOfBlock - 8) / 2;
        WORD* entry = (WORD*)(reloc + 1);  // Après le header

        for(DWORD i = 0; i < count; i++) {
            BYTE type = entry[i] >> 12;     // 4 bits hauts = type
            WORD off  = entry[i] & 0xFFF;   // 12 bits bas = offset
            PVOID addr = RVA(base, reloc->VirtualAddress + off);

            if(type == IMAGE_REL_BASED_HIGHLOW)      // 0x03 - 32-bit
                *(DWORD*)addr += (DWORD)delta;
            else if(type == IMAGE_REL_BASED_DIR64)   // 0x0A - 64-bit
                *(QWORD*)addr += delta;
        }

        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}
```

**Pourquoi les relocations ?**

Le PE est compilé pour un `ImageBase` spécifique (ex: `0x00400000`). Si chargé ailleurs (ASLR), toutes les adresses absolues dans le code doivent être ajustées.

**Structure :**
```
┌─────────────────────────────────────────┐
│ IMAGE_BASE_RELOCATION                   │
│   VirtualAddress  (page RVA)            │
│   SizeOfBlock     (taille totale)       │
├─────────────────────────────────────────┤
│ WORD entries[]                          │
│   [15:12] = Type (3=HIGHLOW, 10=DIR64)  │
│   [11:0]  = Offset dans la page         │
└─────────────────────────────────────────┘
```

**Types de relocation :**

| Type | Valeur | Taille | Usage |
|------|--------|--------|-------|
| ABSOLUTE | 0 | - | Padding (ignoré) |
| HIGHLOW | 3 | 4 bytes | PE32 |
| DIR64 | 10 | 8 bytes | PE64 |

---

### Section 9 : Import resolution

```c
void process_imports(PVOID base, t_LLA pLLA, t_GPA pGPA)
{
    PIMAGE_IMPORT_DESCRIPTOR imp = IMP(base);

    while(imp->Name) {
        char* dll = (char*)RVA(base, imp->Name);
        HMODULE hMod = pLLA(dll);  // LoadLibraryA

        // OriginalFirstThunk = noms, FirstThunk = IAT
        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)RVA(base,
            imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)RVA(base, imp->FirstThunk);

        while(orig->u1.AddressOfData) {
            if(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                // Import par ordinal
                iat->u1.Function = (ULONGLONG)pGPA(hMod,
                    (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
            else {
                // Import par nom
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)
                    RVA(base, orig->u1.AddressOfData);
                iat->u1.Function = (ULONGLONG)pGPA(hMod, ibn->Name);
            }
            orig++; iat++;
        }
        imp++;
    }
}
```

**Structure Import :**
```
IMPORT_DESCRIPTOR[]
├─ Name (RVA vers "kernel32.dll")
├─ OriginalFirstThunk (INT - Import Name Table)
├─ FirstThunk (IAT - Import Address Table)
└─ ...

INT: [nom1] [nom2] [nom3] [0]     ← RVAs vers IMAGE_IMPORT_BY_NAME
IAT: [nom1] [nom2] [nom3] [0]     ← Avant chargement

Après chargement par le loader:
IAT: [addr1] [addr2] [addr3] [0]  ← Adresses réelles des fonctions
```

**`IMAGE_ORDINAL_FLAG64` (0x8000000000000000) :** Si ce bit est set, c'est un import par ordinal (numéro), pas par nom.

---

### Section 10 : TLS Callbacks

```c
void run_tls_callbacks(PVOID base, DWORD reason)
{
    PIMAGE_DATA_DIRECTORY dir = DIR(base, 9);
    if(!dir->Size) return;

    PIMAGE_TLS_DIRECTORY tls = TLS(base);
    PIMAGE_TLS_CALLBACK* cbs = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

    if(!cbs) return;

    while(*cbs) {
        (*cbs)(base, reason, 0);  // Appelle chaque callback
        cbs++;
    }
}
```

**TLS Callbacks = code exécuté AVANT main()**

Utilisations maldev :
- Anti-debug (s'exécute avant le debugger break)
- Initialisation de crypto
- Unpacking
- Détection de sandbox

---

### Section 11 : Reflective loader

```c
PVOID load_pe(PVOID raw, DWORD raw_sz)
{
    if(!IS_PE(raw)) return 0;

    // 1. Allocation mémoire
    DWORD img_sz = OPT(raw)->SizeOfImage;
    PVOID base = VirtualAlloc((PVOID)OPT(raw)->ImageBase, img_sz, 0x3000, 0x40);
    if(!base)
        base = VirtualAlloc(0, img_sz, 0x3000, 0x40);

    // 2. Copie des headers
    __movsb(base, raw, OPT(raw)->SizeOfHeaders);

    // 3. Copie des sections
    WORD nsec = FILE_H(raw)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(raw);
    for(WORD i = 0; i < nsec; i++) {
        if(sec[i].SizeOfRawData)
            __movsb(RVA(base, sec[i].VirtualAddress),
                    RVA(raw, sec[i].PointerToRawData),
                    sec[i].SizeOfRawData);
    }

    // 4. Relocations
    DWORD_PTR delta = (DWORD_PTR)base - OPT(raw)->ImageBase;
    if(delta)
        process_relocs(base, delta);

    // 5. Imports
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    t_LLA pLLA = (t_LLA)get_proc_by_name(k32, "LoadLibraryA");
    t_GPA pGPA = (t_GPA)get_proc_by_name(k32, "GetProcAddress");
    process_imports(base, pLLA, pGPA);

    // 6. TLS
    run_tls_callbacks(base, DLL_PROCESS_ATTACH);

    // 7. Protections mémoire
    for(WORD i = 0; i < nsec; i++) {
        DWORD prot = 0;
        DWORD chr = sec[i].Characteristics;

        if(chr & IMAGE_SCN_MEM_EXECUTE)
            prot = (chr & IMAGE_SCN_MEM_WRITE) ? 0x40 : 0x20;  // RWX ou RX
        else
            prot = (chr & IMAGE_SCN_MEM_WRITE) ? 0x04 : 0x02;  // RW ou R

        DWORD old;
        VirtualProtect(RVA(base, sec[i].VirtualAddress),
                       sec[i].Misc.VirtualSize, prot, &old);
    }

    return base;  // Retourne EntryPoint = base + OPT(raw)->AddressOfEntryPoint
}
```

**Étapes d'un reflective loader :**
1. Validation du PE
2. Allocation mémoire (préférence pour ImageBase, sinon anywhere)
3. Copie des headers
4. Copie des sections (mapping virtuel)
5. Traitement des relocations (si base différente)
6. Résolution des imports
7. Exécution TLS callbacks
8. Application des protections mémoire
9. Saut vers EntryPoint

---

### Section 12 : Code cave finder

```c
DWORD find_cave(PVOID base, DWORD min_sz)
{
    WORD nsec = FILE_H(base)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(base);

    for(WORD i = 0; i < nsec; i++) {
        // Seulement sections exécutables
        if(!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE* start = RVA(base, sec[i].VirtualAddress);
        BYTE* end = start + sec[i].Misc.VirtualSize;

        DWORD cave_sz = 0;
        BYTE* cave_start = 0;

        for(BYTE* p = start; p < end; p++) {
            if(*p == 0x00 || *p == 0xCC) {  // NULL ou INT3
                if(!cave_start) cave_start = p;
                cave_sz++;
            } else {
                if(cave_sz >= min_sz)
                    return (DWORD)(cave_start - (BYTE*)base);
                cave_sz = 0;
                cave_start = 0;
            }
        }

        if(cave_sz >= min_sz)
            return (DWORD)(cave_start - (BYTE*)base);
    }
    return 0;
}
```

**Code cave :** Zone de bytes 0x00 ou 0xCC (padding du compilateur) dans une section exécutable. Parfait pour injecter du shellcode sans modifier la taille du PE.

---

## Références

### Documentation officielle
- [PE Format - Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [IMAGE_DOS_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_dos_header)
- [IMAGE_NT_HEADERS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64)
- [IMAGE_SECTION_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)

### Outils
- [PE-bear](https://github.com/hasherezade/pe-bear) - PE viewer/editor
- [CFF Explorer](https://ntcore.com/?page_id=388) - PE analysis
- [pestudio](https://www.winitor.com/) - Static PE analysis
- [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy) - Packer detection

### Ressources maldev
- [Reflective DLL Injection - Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [Donut](https://github.com/TheWover/donut) - Shellcode generator
- [sRDI](https://github.com/monoxgas/sRDI) - Shellcode Reflective DLL Injection

---

## Exercices

### Exercice 1 : Extraire l'EntryPoint
Écris une fonction qui retourne l'adresse de l'EntryPoint d'un PE mappé.

### Exercice 2 : Lister les imports
Écris une fonction qui affiche toutes les DLLs importées et leurs fonctions.

### Exercice 3 : Calculer un hash
Calcule le hash ROR13 de "VirtualAlloc" et vérifie qu'il donne `0x91AFCA54`.

### Exercice 4 : Injecter dans un code cave
1. Trouve un code cave dans notepad.exe
2. Écris un shellcode MessageBox
3. Modifie l'EntryPoint pour pointer vers le cave
4. Le cave doit sauter vers l'ancien EntryPoint après exécution

---

## Résumé

| Technique | Fonction | Usage |
|-----------|----------|-------|
| Navigation PE | `DOS()`, `NT()`, `SEC()` | Parsing de tout PE |
| Hash API | `hash_ror13()` | Éviter les strings |
| Export resolution | `get_proc_by_hash()` | Shellcode, loader |
| Relocations | `process_relocs()` | Loader reflective |
| Import resolution | `process_imports()` | Loader, unpacker |
| Code cave | `find_cave()` | Injection sans resize |
| Reflective load | `load_pe()` | In-memory execution |
