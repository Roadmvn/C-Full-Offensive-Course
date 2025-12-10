# Module 01 - Hello World : Les Fondations

## Pourquoi tu dois maîtriser ça

```
Python implant : python.exe → 45MB + runtime détectable
C implant      : implant.exe → 3KB + aucune dépendance
```

**Le C te donne le contrôle total.** Pas de VM, pas d'interpréteur, juste toi et le CPU.

---

## Binaire, Hexa, Bytes : Les bases absolues

> **IMPORTANT :** Cette section est fondamentale. Si tu galères avec le binaire/hexa, tu galèreras partout (shellcode, reverse, exploitation). Prends le temps.

### Pourquoi 3 systèmes ?

```
Humain pense en décimal  →  255
CPU travaille en binaire →  11111111
Sécu utilise l'hexa      →  0xFF
```

L'hexa est un **compromis** : plus compact que le binaire, plus proche de la machine que le décimal.

---

### Le binaire (base 2)

> **Binaire** = seulement 0 et 1. C'est ce que le CPU comprend vraiment.

**Chaque position a une valeur :**

```
Position :   7    6    5    4    3    2    1    0
Valeur :   128   64   32   16    8    4    2    1
            │    │    │    │    │    │    │    │
Exemple :   1    1    0    0    1    0    1    0  = 128+64+8+2 = 202
```

**Convertir binaire → décimal :**
```
11001010 = 128 + 64 + 0 + 0 + 8 + 0 + 2 + 0 = 202
```

**Convertir décimal → binaire :**
```
202 ÷ 2 = 101 reste 0  ↑
101 ÷ 2 = 50  reste 1  │  Lire de bas en haut
50  ÷ 2 = 25  reste 0  │  → 11001010
25  ÷ 2 = 12  reste 1  │
12  ÷ 2 = 6   reste 0  │
6   ÷ 2 = 3   reste 0  │
3   ÷ 2 = 1   reste 1  │
1   ÷ 2 = 0   reste 1  ↓
```

---

### L'hexadécimal (base 16)

> **Hexa** = 16 symboles (0-9 puis A-F). Chaque chiffre hexa = 4 bits.

**Table de correspondance :**

| Hexa | Décimal | Binaire |
|------|---------|---------|
| 0 | 0 | 0000 |
| 1 | 1 | 0001 |
| 2 | 2 | 0010 |
| 3 | 3 | 0011 |
| 4 | 4 | 0100 |
| 5 | 5 | 0101 |
| 6 | 6 | 0110 |
| 7 | 7 | 0111 |
| 8 | 8 | 1000 |
| 9 | 9 | 1001 |
| A | 10 | 1010 |
| B | 11 | 1011 |
| C | 12 | 1100 |
| D | 13 | 1101 |
| E | 14 | 1110 |
| F | 15 | 1111 |

**Convertir binaire → hexa (le plus simple) :**
```
11001010
│││││││└─ Groupe par 4 : 1100 | 1010
                          ↓      ↓
                          C      A    → 0xCA
```

**Convertir hexa → décimal :**
```
0xCA = (C × 16) + A = (12 × 16) + 10 = 192 + 10 = 202
```

**En C, préfixes :**
```c
int dec = 202;       // Décimal
int hex = 0xCA;      // Hexa (préfixe 0x)
int bin = 0b11001010; // Binaire (préfixe 0b, C99+)
// Les trois valent 202
```

---

### Bits, Bytes, Nibbles

| Terme | Définition | Exemple |
|-------|------------|---------|
| **Bit** | 0 ou 1 | `1` |
| **Nibble** | 4 bits | `1010` = 0xA |
| **Byte** | 8 bits = 2 nibbles | `11001010` = 0xCA |
| **Word** | 2 bytes (16 bits) | `0xCAFE` |
| **DWORD** | 4 bytes (32 bits) | `0xDEADBEEF` |
| **QWORD** | 8 bytes (64 bits) | `0xDEADBEEFCAFEBABE` |

```
1 byte = 8 bits = 2 chiffres hexa = valeurs 0-255 (0x00-0xFF)
```

**Valeurs limites à connaître :**
```
1 byte  : 0 - 255         (0x00 - 0xFF)
2 bytes : 0 - 65535       (0x0000 - 0xFFFF)
4 bytes : 0 - 4294967295  (0x00000000 - 0xFFFFFFFF)
```

---

### ASCII : Bytes = Caractères

> Chaque caractère est représenté par un byte (0-127 pour ASCII standard).

**Valeurs à connaître par cœur :**

| Char | Hexa | Décimal | Note |
|------|------|---------|------|
| `'A'` | 0x41 | 65 | Majuscules : 0x41-0x5A |
| `'Z'` | 0x5A | 90 | |
| `'a'` | 0x61 | 97 | Minuscules : 0x61-0x7A |
| `'z'` | 0x7A | 122 | |
| `'0'` | 0x30 | 48 | Chiffres : 0x30-0x39 |
| `'9'` | 0x39 | 57 | |
| `' '` | 0x20 | 32 | Espace |
| `'\n'` | 0x0A | 10 | Newline |
| `'\r'` | 0x0D | 13 | Carriage return |
| `'\0'` | 0x00 | 0 | Null byte (fin de string) |

**Astuce majuscule ↔ minuscule :**
```
'A' (0x41) + 0x20 = 'a' (0x61)
'a' (0x61) - 0x20 = 'A' (0x41)
'a' ^ 0x20 = 'A'   // XOR pour toggle
```

---

### Lire un hexdump

Tu verras souvent ce format en reverse/forensic :

```
00000000: 4865 6c6c 6f20 576f 726c 6421 0a00 0000  Hello World!....
│         │                                        │
Offset    Données en hexa                          ASCII (. = non-imprimable)
```

**Exercice mental :** Que dit ce hexdump ?
```
00000000: 5365 6372 6574                           Secret
```
→ `0x53` = 'S', `0x65` = 'e', `0x63` = 'c', `0x72` = 'r', `0x65` = 'e', `0x74` = 't'

---

### Endianness : Little vs Big

> **Endianness** = ordre des bytes en mémoire.

```
Valeur : 0xDEADBEEF

Big Endian (réseau, sparc) :
Adresse :  0x00  0x01  0x02  0x03
Bytes :    DE    AD    BE    EF    ← Ordre "naturel"

Little Endian (x86, x64) :
Adresse :  0x00  0x01  0x02  0x03
Bytes :    EF    BE    AD    DE    ← Inversé !
```

**IMPORTANT pour l'exploitation :**
```c
// Tu veux écrire l'adresse 0x00401234 sur x86
// En mémoire : 34 12 40 00 (little endian)

unsigned char addr[] = {0x34, 0x12, 0x40, 0x00};
```

> **Règle :** x86/x64 = Little Endian. Les bytes sont "à l'envers" en mémoire.

---

### Valeurs magiques en sécu

```
0x90       = NOP (instruction qui ne fait rien)
0xCC       = INT3 (breakpoint debugger)
0xCD 0x80  = syscall Linux 32-bit
0x0F 0x05  = syscall Linux 64-bit

0x41414141 = "AAAA" (pattern overflow)
0xDEADBEEF = Marqueur mémoire classique
0xCAFEBABE = Magic Java .class
0x7F454C46 = Magic ELF (`.ELF`)
0x4D5A     = Magic PE/DOS (`MZ`)
```

---

### En C : Afficher en différentes bases

```c
int val = 202;

printf("Décimal : %d\n", val);    // 202
printf("Hexa    : 0x%X\n", val);  // 0xCA
printf("Hexa    : 0x%02X\n", val);// 0xCA (2 chiffres min)
printf("Octal   : %o\n", val);    // 312

// Afficher un byte array en hexa
unsigned char buf[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
for (int i = 0; i < 5; i++) {
    printf("%02X ", buf[i]);
}
// Output: 48 65 6C 6C 6F
```

---

### Résumé des conversions

```
Décimal → Hexa   : 255 → FF (diviser par 16)
Hexa → Décimal   : FF → (15×16)+15 = 255
Binaire → Hexa   : 11111111 → 1111|1111 → F|F → FF
Hexa → Binaire   : CA → C=1100, A=1010 → 11001010
```

**Raccourcis utiles :**
```
0xFF = 255 = 1 byte max
0xFFFF = 65535 = 2 bytes max
0x100 = 256
0x1000 = 4096 (page size)
```

---

## C'est quoi un programme ?

### Ce que tu écris vs ce que le CPU voit

```c
printf("Hello");
```

↓ Compilation ↓

```
48 89 e5 48 83 ec 10 48 8d 3d 00 00 00 00 e8 00 00 00 00
```

> **Opcodes** = instructions machine en hexa. C'est ça que le processeur exécute vraiment.

### Pourquoi le C ?

| Langage | Runtime | Taille binaire | Contrôle mémoire | Usage offensif |
|---------|---------|----------------|------------------|----------------|
| Python | python.exe | Lourd | Non | Scripts, recon |
| Go | Inclus | ~2MB+ | Non | Tools rapides |
| **C** | **Aucun** | **3KB possible** | **Total** | **Implants, shellcode** |
| ASM | Aucun | Minimal | Total | Shellcode pur |

**C = le sweet spot** entre contrôle et productivité.

---

## La compilation (ce qui se passe vraiment)

```
hello.c → [Préprocesseur] → [Compilateur] → [Assembleur] → [Linker] → hello
            #include         C → ASM        ASM → .o       .o → EXE
```

### Étape par étape

**1. Préprocesseur** - Traite les `#include`, `#define`
```bash
gcc -E hello.c -o hello.i    # Voir le résultat
```
> **Impact :** Chaque `#include` ajoute du code. `stdio.h` = ~800 lignes copiées.

**2. Compilation** - C → Assembleur
```bash
gcc -S hello.c -o hello.s    # Voir l'ASM généré
```
> **Impact :** Ta string `"Hello"` apparaît ici en clair dans `.LC0`.

**3. Assemblage** - ASM → Code objet
```bash
gcc -c hello.c -o hello.o    # Fichier objet
```

**4. Linking** - Résout les symboles, crée l'exécutable
```bash
gcc hello.o -o hello         # Exécutable final
```

### Linking : Dynamique vs Statique

| Type | Commande | Taille | Dépendances | Usage |
|------|----------|--------|-------------|-------|
| Dynamique | `gcc hello.c -o hello` | ~8KB | libc.so | Standard |
| Statique | `gcc hello.c -o hello -static` | ~800KB | Aucune | Portabilité |

```bash
ldd hello         # Voir les dépendances
ldd hello_static  # "not a dynamic executable"
```

> **Statique** = tout est inclus. Plus gros mais fonctionne partout.

---

## Structure minimale d'un programme C

### Le strict minimum
```c
int main(void) {
    return 0;
}
```
C'est tout. Aucun `#include` nécessaire.

### Avec affichage
```c
#include <stdio.h>

int main(void) {
    printf("Hello World!\n");
    return 0;
}
```

### Ce qui se passe vraiment

```
Système → _start (CRT) → __libc_start_main → main() → exit()
```

> **`_start`** = le VRAI point d'entrée. `main()` est appelé par le CRT (C Runtime).
> En analyse de malware, cherche l'**entry point** dans le header PE/ELF, pas `main()`.

### Return code

```bash
./programme
echo $?    # Linux : affiche le code retour
```

- `0` = succès
- `1-255` = erreur

```bash
./exploit && ./post_exploit   # post_exploit s'exécute SI exploit retourne 0
```

---

## Strings : Le piège #1

### Le problème
```c
printf("Connecting to C2 server...\n");
```

```bash
$ strings malware.exe | grep C2
Connecting to C2 server...    ← GRILLÉ
```

> **`.rodata`** = section read-only où vont tes strings. Visible en clair dans le binaire.

### Solutions rapides

**1. Stack strings**
```c
char msg[] = {'H','e','l','l','o','\0'};  // Construit au runtime
```

**2. XOR au runtime**
```c
unsigned char enc[] = {0x2A, 0x27, 0x38, 0x38, 0x3B};  // "hello" ^ 0x42
for(int i=0; i<5; i++) enc[i] ^= 0x42;
```

→ Détails au **Module 08 (Strings)**

---

## CRT : Avec ou sans ?

> **CRT** (C Runtime Library) = code qui initialise ton programme avant `main()` et fournit printf, malloc, etc.

### Comparaison

| Aspect | Avec CRT | Sans CRT |
|--------|----------|----------|
| Taille | ~50-100KB | ~3-5KB |
| Dépendances | msvcrt.dll / libc.so | Aucune |
| Imports (IAT) | Nombreux | Minimal |
| Facilité | Simple | Avancé |

### Exemple Windows sans CRT

```c
#include <windows.h>

void _start(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteConsoleA(h, "Hello\n", 6, NULL, NULL);
    ExitProcess(0);
}
```
Compilation : `cl /GS- /nologo hello.c /link /ENTRY:_start /NODEFAULTLIB kernel32.lib`

> **Pourquoi sans CRT ?** Moins de surface d'analyse, IAT plus discret, contrôle total.
> Pour apprendre : utilise le CRT. Pour les implants : évalue au cas par cas.

---

## Options de compilation essentielles

### GCC (Linux/macOS)

```bash
gcc hello.c -o hello              # Basique
gcc hello.c -o hello -O2          # Optimisé
gcc hello.c -o hello -s           # Strip symboles
gcc hello.c -o hello -static      # Pas de dépendances
gcc hello.c -o hello -O2 -s       # Prod-ready
```

### Flags et leur impact

| Flag | Effet | OPSEC |
|------|-------|-------|
| `-g` | Symboles debug | Facile à reverser |
| `-s` | Strip symboles | Plus dur à reverser |
| `-O2`/`-O3` | Optimise | Code moins lisible |
| `-static` | Tout inclus | Pas de deps externes |
| `-fPIC` | Position Independent | Requis pour libs/shellcode |

### Cross-compilation Windows

```bash
x86_64-w64-mingw32-gcc hello.c -o hello.exe -s -O2
```

---

## Analyse de ton binaire

### Commandes Linux

```bash
file hello           # Type de fichier
ldd hello            # Dépendances
strings hello        # Strings visibles
nm hello             # Symboles
readelf -h hello     # Headers ELF
objdump -d hello     # Désassemblage
```

### Commandes Windows

```cmd
dumpbin /headers hello.exe    # Headers PE
dumpbin /imports hello.exe    # Imports (IAT)
dumpbin /exports hello.exe    # Exports
```

### Checklist d'analyse

```
□ Strings sensibles visibles ?     → strings binary | grep -i password
□ Imports suspects ?               → Combo VirtualAlloc + WriteProcess + CreateThread
□ Taille raisonnable ?             → Un hello world de 5MB = suspect
□ Symboles présents ?              → nm binary (si oui → strip)
```

---

## Exercices pratiques

### Exo 1 : Compile et analyse (5 min)

```c
#include <stdio.h>
int main(void) {
    printf("Hello Offensive World!\n");
    return 0;
}
```

```bash
gcc hello.c -o hello
strings hello | grep Hello          # Visible ?
gcc hello.c -o hello_stripped -s
ls -la hello hello_stripped         # Compare les tailles
```

### Exo 2 : Avec et sans CRT (10 min - Windows)

Compare la taille et les imports entre :
- Version standard avec `printf`
- Version sans CRT avec `WriteConsoleA`

```bash
dumpbin /imports version1.exe
dumpbin /imports version2.exe
```

### Exo 3 : Cacher une string (5 min)

Fais en sorte que `"secret_password"` n'apparaisse pas dans `strings` :

```c
int main(void) {
    // TODO: Construis la string sans qu'elle soit en .rodata
    char password[16];
    // ...
    return 0;
}
```

---

## Checklist

```
□ Je comprends le binaire et sais convertir binaire ↔ décimal
□ Je connais la table hexa (0-F) et sais convertir hexa ↔ binaire
□ Je sais lire un hexdump et reconnaître des strings ASCII
□ Je comprends le little endian et pourquoi 0x1234 = 34 12 en mémoire
□ Je connais les magic bytes courants (NOP, MZ, ELF, etc.)
□ Je comprends les 4 étapes de compilation
□ Je sais ce qu'est le CRT et pourquoi l'éviter parfois
□ Je sais analyser un binaire avec strings, nm, ldd
□ Je connais les flags de compilation essentiels
□ Je sais pourquoi mes strings sont visibles et comment les cacher
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **Bit** | 0 ou 1, unité minimale |
| **Byte** | 8 bits, valeurs 0-255 |
| **Nibble** | 4 bits = 1 chiffre hexa |
| **Little Endian** | Bytes stockés du moins au plus significatif (x86) |
| **Hexdump** | Affichage mémoire en hexa + ASCII |
| **Opcode** | Instruction machine en hexa |
| **CRT** | C Runtime - code d'init avant main() |
| **ELF** | Format binaire Linux (Executable and Linkable Format) |
| **PE** | Format binaire Windows (Portable Executable) |
| **IAT** | Import Address Table - liste des fonctions importées |
| **.rodata** | Section read-only contenant les strings |
| **Strip** | Supprimer les symboles de debug |
| **Entry point** | Vraie première instruction exécutée (_start, pas main) |

---

## Prochaine étape

**Module suivant →** [02 - Variables et Types](../02_variables_types/)

---

**Temps lecture :** 15 min | **Pratique :** 30 min
