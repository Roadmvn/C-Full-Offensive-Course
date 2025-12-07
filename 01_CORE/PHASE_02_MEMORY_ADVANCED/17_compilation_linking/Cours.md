# Cours : Compilation et Linking

## Objectif du Module

Maîtriser le processus de compilation complet : comprendre les 4 étapes (préprocesseur, compilation, assemblage, linking), utiliser les flags GCC/Clang essentiels, différencier static vs dynamic linking, comprendre les formats binaires PE (Windows) et ELF (Linux/macOS), analyser les symbols et la symbol table, et utiliser strip pour retirer les symboles. Application Red Team : compilation pour évasion, obfuscation binaire, analyse de malware.

---

## 1. Les 4 Étapes de Compilation

```
SOURCE.C → PRÉPROCESSEUR → COMPILATION → ASSEMBLAGE → LINKING → EXÉCUTABLE

┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
│ .c     │ →  │ .i     │ →  │ .s     │ →  │ .o     │ →  │ exe    │
│ Source │    │ Préproc│    │ Asm    │    │ Objet  │    │ Final  │
└────────┘    └────────┘    └────────┘    └────────┘    └────────┘
    ↓             ↓             ↓             ↓             ↓
  Code C      #include      Assembleur    Code       Exécutable
             #define         x86-64      machine        lié
```

### 1.1 Étape 1 : Préprocesseur (.c → .i)

```bash
gcc -E source.c -o source.i
```

**Rôle :**
- Résout les `#include` (copie-colle les headers)
- Remplace les `#define` (macros)
- Évalue les `#ifdef, #ifndef, #if`
- Supprime les commentaires

**Exemple :**
```c
// source.c
#include <stdio.h>
#define MAX 100

int main() {
    printf("Max: %d\n", MAX);
    return 0;
}
```

Après préprocesseur (`source.i`) :
```c
// Tout le contenu de stdio.h (plusieurs milliers de lignes)
// ...

int main() {
    printf("Max: %d\n", 100);  // MAX remplacé par 100
    return 0;
}
```

### 1.2 Étape 2 : Compilation (.i → .s)

```bash
gcc -S source.c -o source.s
```

**Rôle :** Transforme le code C en assembleur.

**Exemple :**
```c
int add(int a, int b) {
    return a + b;
}
```

Devient (`source.s`) :
```asm
add:
    push    rbp
    mov     rbp, rsp
    mov     DWORD PTR [rbp-4], edi
    mov     DWORD PTR [rbp-8], esi
    mov     edx, DWORD PTR [rbp-4]
    mov     eax, DWORD PTR [rbp-8]
    add     eax, edx
    pop     rbp
    ret
```

### 1.3 Étape 3 : Assemblage (.s → .o)

```bash
gcc -c source.c -o source.o
```

**Rôle :** Transforme l'assembleur en code machine (binaire).

**Exemple :**
```
source.o (fichier binaire) :

0000000000000000 <add>:
   0:   55                      push   %rbp
   1:   48 89 e5                mov    %rsp,%rbp
   4:   89 7d fc                mov    %edi,-0x4(%rbp)
   7:   89 75 f8                mov    %esi,-0x8(%rbp)
   a:   8b 55 fc                mov    -0x4(%rbp),%edx
   d:   8b 45 f8                mov    -0x8(%rbp),%eax
  10:   01 d0                   add    %edx,%eax
  12:   5d                      pop    %rbp
  13:   c3                      ret
```

### 1.4 Étape 4 : Linking (.o → exécutable)

```bash
gcc source.o -o program
```

**Rôle :** Lie les fichiers objets et les bibliothèques.

```
AVANT linking :

main.o :
├─ Fonction main()
└─ Appelle printf() (undefined)

libc.a/libc.so :
├─ Fonction printf()
└─ Fonction malloc()

═══════════════════════════════════

APRÈS linking :

program (exécutable) :
├─ main() → lié
├─ printf() → lié (depuis libc)
└─ malloc() → lié (depuis libc)
```

---

## 2. Flags GCC/Clang Essentiels

### 2.1 Optimisation

```bash
-O0  # Aucune optimisation (debug)
-O1  # Optimisations basiques
-O2  # Optimisations recommandées (prod)
-O3  # Optimisations agressives
-Os  # Optimiser pour la TAILLE
-Ofast  # Optimisations extrêmes (peut casser standards)
```

**Impact :**
```c
int sum(int n) {
    int result = 0;
    for (int i = 0; i < n; i++) {
        result += i;
    }
    return result;
}
```

Avec `-O0` (debug) → Boucle complète
Avec `-O3` (prod) → Remplacé par formule mathématique `n*(n-1)/2`

### 2.2 Debug

```bash
-g      # Symboles de debug (pour gdb)
-ggdb   # Symboles spécifiques GDB
-g3     # Inclure les macros
```

### 2.3 Warnings

```bash
-Wall       # Warnings essentiels
-Wextra     # Warnings supplémentaires
-Werror     # Traiter warnings comme erreurs
-w          # Supprimer TOUS les warnings
```

### 2.4 Sécurité

```bash
# Protections ACTIVÉES (défense)
-fstack-protector-all      # Canary sur toutes les fonctions
-D_FORTIFY_SOURCE=2        # Checks runtime
-fPIE -pie                 # Position Independent Executable
-Wl,-z,relro,-z,now        # RELRO (RELocation Read-Only)

# Protections DÉSACTIVÉES (exploitation)
-fno-stack-protector       # Pas de canary
-z execstack               # Stack exécutable
-no-pie                    # Adresses fixes
-Wl,-z,norelro             # Pas de RELRO
```

### 2.5 Compilation Multi-Fichiers

```bash
# Méthode 1 : Tout en une commande
gcc main.c utils.c -o program

# Méthode 2 : Étape par étape (recommandé)
gcc -c main.c -o main.o
gcc -c utils.c -o utils.o
gcc main.o utils.o -o program
```

---

## 3. Static vs Dynamic Linking

### 3.1 Static Linking (.a)

```bash
# Créer bibliothèque statique
gcc -c lib.c -o lib.o
ar rcs libmylib.a lib.o

# Lier statiquement
gcc main.c -L. -lmylib -o program
```

**Avantages :**
- Pas de dépendances externes
- Plus rapide à l'exécution
- Portable (fonctionne partout)

**Inconvénients :**
- Binaire plus gros
- Pas de mises à jour de lib sans recompiler

**Schéma :**
```
Compilation :
┌──────────┐    ┌────────────┐
│ main.c   │ +  │ libutil.a  │  →  program (5 MB)
└──────────┘    └────────────┘
                 (bibliothèque
                  COPIÉE dans
                  l'exécutable)
```

### 3.2 Dynamic Linking (.so, .dll, .dylib)

```bash
# Linux : Créer bibliothèque dynamique
gcc -fPIC -shared lib.c -o libmylib.so

# Lier dynamiquement
gcc main.c -L. -lmylib -o program

# Exécution
export LD_LIBRARY_PATH=.
./program
```

**Avantages :**
- Binaire plus petit
- Mises à jour centralisées
- Partagé entre processus (économie RAM)

**Inconvénients :**
- Dépendances à gérer
- Légèrement plus lent (indirection)

**Schéma :**
```
Compilation :
┌──────────┐
│ main.c   │  →  program (100 KB)
└──────────┘
                 ↓ (référence seulement)
               libutil.so (1 MB)
                 ↑
        Chargée à l'EXÉCUTION
```

---

## 4. Formats Binaires

### 4.1 ELF (Linux/BSD/Android)

```
STRUCTURE ELF :

┌─────────────────────────────┐
│ ELF Header                  │  Signature 0x7F 'E' 'L' 'F'
├─────────────────────────────┤
│ Program Headers (segments)  │  Infos chargement mémoire
├─────────────────────────────┤
│ .text (code)                │  Code exécutable
├─────────────────────────────┤
│ .data (données initialisées)│  Variables globales
├─────────────────────────────┤
│ .bss (données non-init)     │  Variables non-initialisées
├─────────────────────────────┤
│ .rodata (read-only)         │  Constantes
├─────────────────────────────┤
│ .symtab (symbol table)      │  Symboles (fonctions, vars)
├─────────────────────────────┤
│ .strtab (string table)      │  Noms des symboles
└─────────────────────────────┘
```

**Analyser un ELF :**
```bash
file program              # Type de fichier
readelf -h program        # Header ELF
readelf -S program        # Sections
readelf -l program        # Segments (program headers)
readelf -s program        # Symboles
objdump -d program        # Désassembler
```

### 4.2 Mach-O (macOS/iOS)

```
STRUCTURE MACH-O :

┌─────────────────────────────┐
│ Mach-O Header               │
├─────────────────────────────┤
│ Load Commands               │  Infos chargement
├─────────────────────────────┤
│ __TEXT (code)               │
├─────────────────────────────┤
│ __DATA (données)            │
├─────────────────────────────┤
│ __LINKEDIT (infos linking)  │
└─────────────────────────────┘
```

**Analyser un Mach-O :**
```bash
file program
otool -h program   # Header
otool -l program   # Load commands
otool -L program   # Bibliothèques liées
otool -tV program  # Désassembler
```

### 4.3 PE (Windows)

```
STRUCTURE PE :

┌─────────────────────────────┐
│ DOS Header ("MZ")           │
├─────────────────────────────┤
│ DOS Stub                    │
├─────────────────────────────┤
│ PE Header ("PE\0\0")        │
├─────────────────────────────┤
│ Section Table               │
├─────────────────────────────┤
│ .text (code)                │
├─────────────────────────────┤
│ .data (données)             │
├─────────────────────────────┤
│ .rdata (read-only)          │
├─────────────────────────────┤
│ .idata (imports)            │
├─────────────────────────────┤
│ .edata (exports)            │
└─────────────────────────────┘
```

---

## 5. Symbols et Symbol Table

### 5.1 Qu'est-ce qu'un Symbole ?

Un symbole = Nom associé à une adresse (fonction, variable globale).

```bash
nm program  # Lister les symboles
```

**Output :**
```
0000000000001149 T main          # T = Text (fonction)
0000000000004010 D global_var    # D = Data (variable initialisée)
0000000000004020 B uninit_var    # B = BSS (variable non-initialisée)
                 U printf        # U = Undefined (externe)
```

**Types de symboles :**
```
T/t  → Text (fonction dans .text)
D/d  → Data (variable initialisée)
B/b  → BSS (variable non-initialisée)
R/r  → Read-only data (.rodata)
U    → Undefined (externe, à lier)
W/w  → Weak symbol
```

### 5.2 strip - Retirer les Symboles

```bash
# Binaire AVEC symboles
gcc -g program.c -o program
ls -lh program  # → 50 KB

# Binaire SANS symboles
strip program
ls -lh program  # → 14 KB

# strip sélectif
strip --strip-debug program     # Garder symboles dynamiques
strip --strip-all program       # Tout retirer
```

**Impact :**
```
AVANT strip :

$ nm program
0000000000001149 T main
0000000000001165 T add
0000000000001180 T multiply

$ gdb program
(gdb) break main  # ✓ Fonctionne

═══════════════════════════════════

APRÈS strip :

$ nm program
nm: program: no symbols

$ gdb program
(gdb) break main  # ✗ Symbole inconnu
```

---

## 6. Application Red Team

### 6.1 Compilation pour Évasion

```bash
# Désactiver toutes les protections
gcc -fno-stack-protector \     # Pas de canary
    -z execstack \             # Stack exécutable
    -no-pie \                  # Adresses fixes (pas de PIE)
    -D_FORTIFY_SOURCE=0 \      # Pas de fortify
    -Wl,-z,norelro \           # Pas de RELRO
    exploit.c -o exploit

# Optimiser taille (furtivité)
gcc -Os -s malware.c -o malware

# Static linking (portabilité)
gcc -static payload.c -o payload  # Fonctionne partout
```

### 6.2 Vérifier les Protections

```bash
# Linux
checksec --file=program

# Output :
# RELRO           : Partial RELRO
# Stack           : No canary found
# NX              : NX disabled  # ← Stack exécutable !
# PIE             : No PIE
```

### 6.3 Obfuscation à la Compilation

```bash
# Strip agressif
strip --strip-all binary

# Obfuscation flags
gcc -O3 \                     # Optimisation max
    -fomit-frame-pointer \    # Retirer frame pointer
    -s \                      # strip automatique
    -ffunction-sections \     # Séparer fonctions
    -fdata-sections \         # Séparer données
    code.c -o code
```

### 6.4 Analyse de Malware

```bash
# Identifier format
file malware

# Symboles et imports
nm malware
readelf -d malware    # Linux (sections dynamiques)
otool -L malware      # macOS (bibliothèques)

# Strings
strings malware

# Dépendances
ldd malware           # Linux
otool -L malware      # macOS

# Désassembler
objdump -d malware
radare2 malware
ghidra malware
```

### 6.5 Injection de Bibliothèques

```bash
# Linux : LD_PRELOAD
gcc -fPIC -shared evil.c -o evil.so
LD_PRELOAD=./evil.so /bin/ls  # Injecte evil.so avant libc

# macOS : DYLD_INSERT_LIBRARIES
gcc -fPIC -shared evil.c -o evil.dylib
DYLD_INSERT_LIBRARIES=./evil.dylib /bin/ls
```

---

## 7. Checklist de Compréhension

- [ ] Les 4 étapes de compilation ?
- [ ] Différence -O0 vs -O3 ?
- [ ] Static vs dynamic linking ?
- [ ] Structure d'un ELF/PE/Mach-O ?
- [ ] Qu'est-ce qu'un symbole ?
- [ ] Impact de strip ?
- [ ] Comment désactiver les protections ?

---

## 8. Exercices Pratiques

Voir `exercice.txt` pour :
- Compiler avec différentes optimisations
- Créer une bibliothèque statique et dynamique
- Analyser un binaire avec readelf/otool
- Compiler un exploit sans protections
- Créer un hook avec LD_PRELOAD

---

## 9. Commandes de Référence

```bash
# Compilation
gcc -Wall -g -O0 code.c -o debug      # Debug
gcc -Wall -O2 -s code.c -o release    # Release

# Analyse Linux
file binary
size binary
ldd binary
readelf -h binary    # Header
readelf -S binary    # Sections
readelf -l binary    # Segments
readelf -s binary    # Symboles
objdump -d binary    # Désassembler
nm binary            # Symboles

# Analyse macOS
file binary
size binary
otool -h binary      # Header
otool -l binary      # Load commands
otool -L binary      # Bibliothèques
otool -tV binary     # Désassembler

# Strip
strip binary
strip --strip-debug binary
strip --strip-all binary
```

---

**Félicitations !** Tu as terminé la PHASE 2 - Concepts Avancés. Tu maîtrises maintenant les pointeurs, la mémoire, les structures, les fichiers, les macros, et la compilation. Direction la PHASE 3 pour l'exploitation et le Red Team avancé !
