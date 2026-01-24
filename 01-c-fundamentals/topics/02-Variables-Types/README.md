# Variables & Types - Perspective Maldev

## Objectif
Comprendre comment les types C sont utilisés dans le code malveillant réel : parsing PE, structures de config, exploitation de vulnérabilités.

## Prérequis
- Bases du C (compilation, syntaxe)
- Notion de mémoire (bits, octets)

---

## Théorie

### Pourquoi les types sont critiques en maldev

En reverse engineering, tu analyses du code **sans les noms de variables**. Ghidra/IDA te donnent des types génériques (`DAT_00401000`, `uVar1`). Comprendre les types = comprendre ce que fait le malware.

### Types Windows vs Types standards

| Windows | Standard C | Taille | Usage maldev |
|---------|-----------|--------|--------------|
| `BYTE` | `unsigned char` | 1 | Shellcode, XOR keys |
| `WORD` | `unsigned short` | 2 | Ports, PE magic (MZ=0x5A4D) |
| `DWORD` | `unsigned int` | 4 | Adresses 32-bit, RVA, flags |
| `QWORD` | `unsigned long long` | 8 | Adresses 64-bit |
| `PVOID` | `void*` | 4/8 | Pointeurs génériques |

**Pourquoi unsigned ?** Les adresses mémoire et offsets sont toujours positifs. Un `int` signé peut devenir négatif et casser les comparaisons.

---

## Analyse du code `raw_maldev.c`

### Section 1 : Définitions de types cross-platform

```c
#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
// ...
#endif
```

**Explication :** Sur Windows, `<windows.h>` définit ces types. Sur Linux (pour analyse/compilation), on les redéfinit manuellement. Permet de compiler le même code partout.

---

### Section 2 : Structure Ghidra style

```c
typedef struct _UNK_STRUCT_0x18 {
    DWORD dw0;      // offset +0x00
    DWORD dw4;      // offset +0x04
    PVOID p8;       // offset +0x08
    DWORD dwC;      // offset +0x0C
    DWORD dw10;     // offset +0x10
    WORD  w14;      // offset +0x14
    BYTE  b16;      // offset +0x16
    BYTE  pad17;    // offset +0x17 (padding)
} UNK_STRUCT;
```

**Explication :** C'est exactement ce que Ghidra génère quand il analyse une structure inconnue :
- Noms = offset hexadécimal (`dw0` = DWORD à offset 0)
- Préfixes indiquent le type (`dw`=DWORD, `p`=pointeur, `w`=WORD, `b`=BYTE)
- `0x18` = taille totale (24 bytes)
- `pad17` = padding d'alignement

**Exercice mental :** Si tu vois `mov eax, [rcx+0x10]` dans le désassembleur, tu sais que c'est `dw10`.

---

### Section 3 : Config Cobalt Strike

```c
#pragma pack(push,1)
typedef struct {
    WORD  wVer;           // +0x00 - Version du beacon
    WORD  wPayloadType;   // +0x02 - HTTP, HTTPS, DNS, SMB
    DWORD dwPort;         // +0x04 - Port C2
    DWORD dwSleepTime;    // +0x08 - Intervalle de callback (ms)
    DWORD dwMaxGetSize;   // +0x0C - Taille max requête GET
    DWORD dwJitter;       // +0x10 - Variation aléatoire du sleep
    DWORD dwMaxDNS;       // +0x14 - Taille max label DNS
    BYTE  bPublicKey[16]; // +0x18 - Clé publique (tronquée)
    BYTE  bC2Server[256]; // +0x28 - Adresse C2
} BEACON_CFG;
#pragma pack(pop)
```

**Explication :**
- `#pragma pack(push,1)` : Désactive le padding. Sans ça, le compilateur ajoute des bytes pour aligner sur 4/8 bytes.
- Structure réelle extraite de samples Cobalt Strike
- Les analystes malware cherchent ce pattern pour extraire la config C2

**Pourquoi `pack(1)` ?** Les configs sont souvent chiffrées/stockées en binaire. Le padding casserait le parsing.

---

### Section 4 : Macros de navigation PE

```c
#define RVA2VA(base, rva)    ((PVOID)((DWORD_PTR)(base) + (DWORD)(rva)))
#define DEREF(p)             (*(DWORD_PTR*)(p))
#define DEREF32(p)           (*(DWORD*)(p))
#define DEREF16(p)           (*(WORD*)(p))
#define DEREF8(p)            (*(BYTE*)(p))
```

**Explication détaillée :**

| Macro | Ce qu'elle fait | Exemple |
|-------|-----------------|---------|
| `RVA2VA(base, rva)` | Convertit RVA en adresse virtuelle | `RVA2VA(0x10000, 0x1000)` → `0x11000` |
| `DEREF(p)` | Lit un pointeur/QWORD à l'adresse p | Lire une adresse dans une table |
| `DEREF32(p)` | Lit un DWORD à l'adresse p | Lire `e_lfanew` du DOS header |
| `DEREF16(p)` | Lit un WORD à l'adresse p | Lire le magic MZ (0x5A4D) |

**RVA (Relative Virtual Address) :** Offset depuis la base du module chargé en mémoire. Le PE stocke tout en RVA, pas en adresses absolues.

---

### Section 5 : Fonction décompilée vs récupérée

**Version Ghidra brute :**
```c
DWORD FUN_00401000(PVOID param_1)
{
    WORD uVar1;
    DWORD uVar2;
    BYTE *pbVar3;

    uVar1 = DEREF16(param_1);
    if (uVar1 != 0x5a4d) {  // MZ check
        return 0;
    }
    pbVar3 = (BYTE*)param_1 + DEREF32((BYTE*)param_1 + 0x3c);
    uVar2 = DEREF32(pbVar3);
    if (uVar2 != 0x4550) {  // PE check
        return 0;
    }
    return DEREF32(pbVar3 + 0x50);  // SizeOfImage
}
```

**Version analysée :**
```c
DWORD GetImageSize(PVOID pBase)
{
    // Vérifie signature DOS "MZ" (0x5A4D)
    if(DEREF16(pBase) != 0x5A4D) return 0;

    // e_lfanew à offset +0x3C = offset vers PE header
    BYTE* pNT = (BYTE*)pBase + DEREF32((BYTE*)pBase + 0x3C);

    // Vérifie signature PE "PE\0\0" (0x4550)
    if(DEREF32(pNT) != 0x4550) return 0;

    // SizeOfImage à offset +0x50 du NT header
    return DEREF32(pNT + 0x50);
}
```

**Magic numbers expliqués :**
- `0x5A4D` = "MZ" en little-endian (Mark Zbikowski, créateur du format DOS)
- `0x4550` = "PE\0\0" en little-endian
- `0x3C` = offset de `e_lfanew` dans IMAGE_DOS_HEADER
- `0x50` = offset de `SizeOfImage` dans IMAGE_OPTIONAL_HEADER

---

### Section 6 : Union pour crypto

```c
typedef union {
    BYTE  b[8];
    WORD  w[4];
    DWORD d[2];
    QWORD q;
} CRYPTO_BLOCK;
```

**Explication :** Une union permet d'accéder aux mêmes 8 bytes de différentes manières :
- `b[0]` à `b[7]` : byte par byte
- `w[0]` à `w[3]` : par WORD (2 bytes)
- `d[0]` et `d[1]` : par DWORD (4 bytes)
- `q` : comme un seul QWORD (8 bytes)

**Usage :** XOR sur des blocs de 8 bytes. Au lieu de 8 opérations XOR sur des bytes, tu fais 1 XOR sur un QWORD.

```c
void decrypt_block(CRYPTO_BLOCK* blk, DWORD key)
{
    blk->d[0] ^= key;  // XOR premiers 4 bytes
    blk->d[1] ^= key;  // XOR derniers 4 bytes
}
```

---

### Section 7 : Bitfields

```c
typedef struct {
    DWORD type_offset : 12;  // bits 0-11
    DWORD type        : 4;   // bits 12-15
    DWORD reserved    : 16;  // bits 16-31
} RELOC_ENTRY;
```

**Explication :** Les bitfields permettent de mapper les bits d'un DWORD sur des champs nommés. Utilisé pour les relocations PE :
- `type_offset` : 12 bits = offset dans la page (0-4095)
- `type` : 4 bits = type de relocation (0-15)

---

### Section 8 : Function pointers

```c
typedef PVOID (WINAPI *t_VirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
```

**Décomposition :**
- `typedef` : On définit un nouveau type
- `PVOID` : Type de retour (pointeur)
- `WINAPI` : Convention d'appel (__stdcall sur x86)
- `*t_VirtualAlloc` : Nom du type (pointeur de fonction)
- `(PVOID, SIZE_T, DWORD, DWORD)` : Paramètres

**Usage :** Résolution dynamique d'API (évite les imports statiques)
```c
t_VirtualAlloc pVA = (t_VirtualAlloc)GetProcAddress(hK32, "VirtualAlloc");
pVA(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

---

### Section 9 : Integer overflow

```c
DWORD calc_size_vuln(DWORD count, DWORD elem_sz)
{
    return count * elem_sz;  // VULNÉRABLE
}
```

**Exploit :** Si `count = 0x10000001` et `elem_sz = 0x100` :
- Résultat attendu : `0x1000000100` (dépasse 32 bits)
- Résultat réel : `0x00000100` (troncation)

→ Allocation de 256 bytes au lieu de 4GB, puis buffer overflow.

**CVE réel :** CVE-2021-21224 (Chrome V8) utilisait ce pattern.

---

### Section 10 : Stack strings

```c
void get_kernel32(char* out)
{
    out[0]='k'; out[1]='e'; out[2]='r'; out[3]='n';
    out[4]='e'; out[5]='l'; out[6]='3'; out[7]='2';
    out[8]='.'; out[9]='d'; out[10]='l'; out[11]='l';
    out[12]=0;
}
```

**Pourquoi ?** La string "kernel32.dll" n'apparaît pas dans `.rodata`. Les scanners AV/EDR cherchent ces strings. En les construisant sur la stack, elles n'existent que pendant l'exécution.

---

## Références

### Documentation officielle
- [PE Format - Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [IMAGE_DOS_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_dos_header)
- [IMAGE_NT_HEADERS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64)

### Analyse de samples
- [Cobalt Strike Config Extraction - Didier Stevens](https://blog.didierstevens.com/2021/11/29/rejetto-hfs-httpfileserver-cobalt-strike-beacon/)
- [Emotet Config Parsing](https://www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-004.pdf)

### Tools
- [Ghidra](https://ghidra-sre.org/)
- [PE-bear](https://github.com/hasherezade/pe-bear)
- [CFF Explorer](https://ntcore.com/?page_id=388)

---

## Exercices

### Exercice 1 : Identifier les types
Dans ce code décompilé, identifie chaque variable :
```c
DWORD FUN_004010A0(PVOID p1) {
    if(DEREF16(p1) != 0x5A4D) return 0;
    DWORD v1 = DEREF32((BYTE*)p1 + 0x3C);
    // Que représente v1 ?
}
```

### Exercice 2 : Calculer les offsets
Calcule la taille totale et les offsets de cette structure :
```c
typedef struct {
    BYTE  a;
    DWORD b;
    WORD  c;
    BYTE  d[3];
} TEST;
```
Avec et sans `#pragma pack(1)`.

### Exercice 3 : Parser une config
Écris une fonction qui extrait le port et le sleep time d'une structure `BEACON_CFG` chiffrée en XOR avec la clé `0xDEADBEEF`.

---

## Résumé

| Concept | Usage maldev |
|---------|--------------|
| Types Windows | Parsing PE, shellcode |
| `#pragma pack` | Configs binaires, protocoles |
| Unions | Crypto, manipulation de blocs |
| Bitfields | Parsing de formats binaires |
| Function pointers | Résolution dynamique d'API |
| Integer overflow | Exploitation mémoire |
| Stack strings | Évasion de détection |
