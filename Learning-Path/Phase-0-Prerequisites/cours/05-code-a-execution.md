# Cours 05 : Du Code Source à l'Exécution

## Introduction

Ce cours connecte tous les concepts précédents en montrant le parcours complet : du code C que vous écrivez jusqu'à l'exécution par le processeur.

---

## Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DU CODE SOURCE À L'EXÉCUTION                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────┐                                                          │
│   │  hello.c     │  Code source C                                          │
│   │  (texte)     │                                                          │
│   └──────┬───────┘                                                          │
│          │                                                                  │
│          ▼  Préprocesseur (cpp)                                            │
│   ┌──────────────┐                                                          │
│   │  hello.i     │  Code préprocessé (macros expansées, includes)          │
│   │  (texte)     │                                                          │
│   └──────┬───────┘                                                          │
│          │                                                                  │
│          ▼  Compilateur (cc1)                                              │
│   ┌──────────────┐                                                          │
│   │  hello.s     │  Code assembleur                                        │
│   │  (texte)     │                                                          │
│   └──────┬───────┘                                                          │
│          │                                                                  │
│          ▼  Assembleur (as)                                                │
│   ┌──────────────┐                                                          │
│   │  hello.o     │  Code objet (binaire)                                   │
│   │  (binaire)   │                                                          │
│   └──────┬───────┘                                                          │
│          │                                                                  │
│          ▼  Éditeur de liens (ld)                                          │
│   ┌──────────────┐                                                          │
│   │  hello       │  Exécutable (binaire)                                   │
│   │  (binaire)   │                                                          │
│   └──────┬───────┘                                                          │
│          │                                                                  │
│          ▼  Chargeur (loader)                                              │
│   ┌──────────────┐                                                          │
│   │  Processus   │  En mémoire, en cours d'exécution                       │
│   │  en mémoire  │                                                          │
│   └──────────────┘                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Étape 1 : Le Préprocesseur

Le préprocesseur traite les directives commençant par `#`.

### Exemple

```c
// hello.c
#include <stdio.h>

#define MESSAGE "Hello"
#define MAX(a,b) ((a) > (b) ? (a) : (b))

int main() {
    printf("%s World!\n", MESSAGE);
    int x = MAX(5, 3);
    return 0;
}
```

### Après préprocesseur (simplifié)

```c
// hello.i (très simplifié)
// ... des milliers de lignes de stdio.h ...

extern int printf(const char *format, ...);

int main() {
    printf("%s World!\n", "Hello");
    int x = ((5) > (3) ? (5) : (3));
    return 0;
}
```

### Directives principales

```
┌─────────────────────────────────────────────────────────────────┐
│              DIRECTIVES PRÉPROCESSEUR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  #include <fichier>    Inclure un fichier système              │
│  #include "fichier"    Inclure un fichier local                │
│                                                                 │
│  #define NOM valeur    Définir une constante                   │
│  #define MACRO(x) ...  Définir une macro avec paramètres       │
│  #undef NOM            Supprimer une définition                 │
│                                                                 │
│  #if condition         Compilation conditionnelle              │
│  #ifdef NOM            Si NOM est défini                       │
│  #ifndef NOM           Si NOM n'est pas défini                 │
│  #else                 Sinon                                    │
│  #endif                Fin de condition                         │
│                                                                 │
│  #pragma               Instructions spécifiques au compilateur │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Voir le résultat

```bash
gcc -E hello.c -o hello.i
# ou
cpp hello.c > hello.i
```

---

## Étape 2 : La Compilation

Le compilateur transforme le C en assembleur.

### Code C

```c
int add(int a, int b) {
    int result = a + b;
    return result;
}
```

### Code Assembleur généré (x86, simplifié)

```nasm
add:
    push   ebp              ; Sauvegarder l'ancien base pointer
    mov    ebp, esp         ; Nouveau base pointer
    sub    esp, 4           ; Espace pour 'result' (variable locale)

    mov    eax, [ebp+8]     ; Charger 'a' (premier argument)
    add    eax, [ebp+12]    ; Ajouter 'b' (deuxième argument)
    mov    [ebp-4], eax     ; Stocker dans 'result'

    mov    eax, [ebp-4]     ; Valeur de retour dans EAX

    mov    esp, ebp         ; Restaurer le stack pointer
    pop    ebp              ; Restaurer le base pointer
    ret                     ; Retourner
```

### Voir le résultat

```bash
gcc -S hello.c -o hello.s
# ou avec optimisations
gcc -S -O2 hello.c -o hello.s
```

### Impact des optimisations

```
┌─────────────────────────────────────────────────────────────────┐
│                 NIVEAUX D'OPTIMISATION                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  -O0 : Pas d'optimisation (défaut)                             │
│        Code fidèle au source, facile à débugger                │
│                                                                 │
│  -O1 : Optimisations légères                                   │
│        Réduit la taille sans trop augmenter le temps           │
│                                                                 │
│  -O2 : Optimisations standard                                  │
│        Bon équilibre performance/taille                         │
│                                                                 │
│  -O3 : Optimisations agressives                                │
│        Maximum de performance, code plus gros                   │
│                                                                 │
│  -Os : Optimiser pour la taille                                │
│        Utile pour le shellcode                                 │
│                                                                 │
│  -Og : Optimiser pour le debug                                 │
│        Performance raisonnable + débuggabilité                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Étape 3 : L'Assemblage

L'assembleur convertit le code assembleur en code machine.

### Voir le résultat

```bash
gcc -c hello.c -o hello.o
# ou depuis l'assembleur
as hello.s -o hello.o
```

### Examiner le fichier objet

```bash
# Voir les sections
objdump -h hello.o

# Voir le code désassemblé
objdump -d hello.o

# Voir les symboles
nm hello.o

# Voir le contenu hexadécimal
hexdump -C hello.o | head -20
```

### Structure d'un fichier objet

```
┌─────────────────────────────────────────────────────────────────┐
│                  FICHIER OBJET (.o)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                      HEADER                              │    │
│  │  (Format ELF sur Linux, COFF sur Windows)               │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   SECTION .text                          │    │
│  │  (Code machine des fonctions)                           │    │
│  │  55 89 e5 83 ec 10 ...                                  │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   SECTION .data                          │    │
│  │  (Données initialisées)                                 │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   SECTION .bss                           │    │
│  │  (Données non initialisées - juste la taille)          │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               TABLE DES SYMBOLES                         │    │
│  │  main: .text, offset 0x0, global                        │    │
│  │  add:  .text, offset 0x20, global                       │    │
│  │  printf: undefined, external                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               TABLE DE RELOCATION                        │    │
│  │  (Adresses à corriger lors de l'édition de liens)       │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Étape 4 : L'Édition de Liens

L'éditeur de liens (linker) combine les fichiers objets et résout les références.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ÉDITION DE LIENS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│   │ main.o   │  │ utils.o  │  │ libc.so  │                      │
│   │          │  │          │  │          │                      │
│   │ main()   │  │ helper() │  │ printf() │                      │
│   │ appelle  │  │          │  │ malloc() │                      │
│   │ helper() │  │          │  │ etc.     │                      │
│   │ printf() │  │          │  │          │                      │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘                      │
│        │             │             │                            │
│        └─────────────┼─────────────┘                            │
│                      │                                          │
│                      ▼                                          │
│               ┌─────────────┐                                   │
│               │   LINKER    │                                   │
│               │     (ld)    │                                   │
│               └──────┬──────┘                                   │
│                      │                                          │
│                      ▼                                          │
│               ┌─────────────┐                                   │
│               │  programme  │  Exécutable complet               │
│               │ (exécutable)│                                   │
│               └─────────────┘                                   │
│                                                                 │
│  Le linker :                                                    │
│  1. Combine toutes les sections .text ensemble                 │
│  2. Combine toutes les sections .data ensemble                 │
│  3. Résout les références (helper → adresse dans utils.o)      │
│  4. Ajoute les informations pour les libs dynamiques           │
│  5. Crée l'en-tête exécutable (ELF/PE)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Liaison Statique vs Dynamique

```
┌─────────────────────────────────────────────────────────────────┐
│              STATIQUE vs DYNAMIQUE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  LIAISON STATIQUE (-static)                                    │
│  ─────────────────────────                                      │
│  • Tout le code est inclus dans l'exécutable                   │
│  • Fichier plus gros                                            │
│  • Pas de dépendances externes                                  │
│  • Utilisé pour les outils portables                           │
│                                                                 │
│  ┌──────────────────────────────────────┐                       │
│  │           EXÉCUTABLE                 │                       │
│  │  ┌────────────────────────────────┐  │                       │
│  │  │ Votre code                     │  │                       │
│  │  ├────────────────────────────────┤  │                       │
│  │  │ Code de libc (printf, etc.)   │  │                       │
│  │  └────────────────────────────────┘  │                       │
│  └──────────────────────────────────────┘                       │
│                                                                 │
│  LIAISON DYNAMIQUE (défaut)                                    │
│  ─────────────────────────                                      │
│  • Seules les références sont incluses                         │
│  • Fichier plus petit                                           │
│  • Les libs sont chargées à l'exécution                        │
│  • Mises à jour des libs sans recompilation                    │
│                                                                 │
│  ┌──────────────────────┐   ┌──────────────────────┐            │
│  │     EXÉCUTABLE       │   │      libc.so         │            │
│  │  ┌────────────────┐  │   │  ┌────────────────┐  │            │
│  │  │ Votre code     │  │   │  │ printf()       │  │            │
│  │  │ appel: printf──┼──┼───┼──│ malloc()       │  │            │
│  │  │                │  │   │  │ etc.           │  │            │
│  │  └────────────────┘  │   │  └────────────────┘  │            │
│  └──────────────────────┘   └──────────────────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### PLT et GOT

```
┌─────────────────────────────────────────────────────────────────┐
│                    PLT et GOT                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PLT (Procedure Linkage Table) : Table de trampolines          │
│  GOT (Global Offset Table) : Table des adresses résolues       │
│                                                                 │
│  Appel à printf() (première fois) :                            │
│                                                                 │
│  1. Code appelle printf@plt                                    │
│  2. PLT saute vers l'adresse dans GOT                          │
│  3. GOT contient initialement l'adresse du résolveur          │
│  4. Le résolveur trouve printf dans libc                       │
│  5. L'adresse de printf est écrite dans GOT                    │
│  6. printf est exécuté                                          │
│                                                                 │
│  Appels suivants :                                              │
│  1. Code appelle printf@plt                                    │
│  2. PLT saute vers l'adresse dans GOT                          │
│  3. GOT contient maintenant la vraie adresse de printf        │
│  4. printf est exécuté directement                             │
│                                                                 │
│  ⚠️ La GOT est une cible pour l'exploitation :                 │
│     Écraser une entrée GOT = rediriger les appels             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Étape 5 : Le Chargement

Quand vous exécutez un programme, le chargeur (loader) le met en mémoire.

```
┌─────────────────────────────────────────────────────────────────┐
│                    CHARGEMENT                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  $ ./hello                                                      │
│                                                                 │
│  1. Le shell appelle execve("./hello", ...)                    │
│                                                                 │
│  2. Le noyau :                                                  │
│     a. Lit l'en-tête ELF                                       │
│     b. Crée un nouvel espace d'adressage                       │
│     c. Mappe les segments en mémoire                           │
│     d. Configure les permissions (R/W/X)                       │
│                                                                 │
│  3. Pour les libs dynamiques :                                  │
│     a. Le noyau charge ld-linux.so (le linker dynamique)      │
│     b. ld-linux.so charge les bibliothèques requises          │
│     c. Les symboles sont résolus                               │
│                                                                 │
│  4. Le contrôle passe à _start (point d'entrée)               │
│     a. _start appelle __libc_start_main                        │
│     b. Qui appelle main(argc, argv, envp)                      │
│                                                                 │
│  5. Votre code s'exécute !                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Le Format ELF (Linux)

```
┌─────────────────────────────────────────────────────────────────┐
│                    FORMAT ELF                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    ELF HEADER                            │    │
│  │  Magic: 7F 45 4C 46 (0x7F "ELF")                        │    │
│  │  Classe: 32/64 bits                                      │    │
│  │  Type: exécutable, objet, shared lib                    │    │
│  │  Point d'entrée: adresse de _start                      │    │
│  │  Offset des headers                                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               PROGRAM HEADERS                            │    │
│  │  (Décrivent comment charger le programme)               │    │
│  │  LOAD: Segments à charger en mémoire                    │    │
│  │  INTERP: Chemin du linker dynamique                     │    │
│  │  DYNAMIC: Information pour les libs dynamiques          │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    SECTIONS                              │    │
│  │  .text: Code exécutable                                 │    │
│  │  .rodata: Données en lecture seule                      │    │
│  │  .data: Données initialisées                            │    │
│  │  .bss: Données non initialisées                         │    │
│  │  .plt/.got: Tables pour les libs dynamiques             │    │
│  │  .symtab: Table des symboles                            │    │
│  │  .strtab: Noms des symboles                             │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               SECTION HEADERS                            │    │
│  │  (Décrivent chaque section)                             │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  Outils : readelf -a, objdump -d, file                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Le Format PE (Windows)

```
┌─────────────────────────────────────────────────────────────────┐
│                    FORMAT PE (Windows)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   DOS HEADER                             │    │
│  │  Magic: "MZ" (Mark Zbikowski)                           │    │
│  │  Pointeur vers PE Header                                │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   DOS STUB                               │    │
│  │  "This program cannot be run in DOS mode"               │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   PE HEADER                              │    │
│  │  Signature: "PE\0\0"                                    │    │
│  │  Machine type, nombre de sections                       │    │
│  │  Timestamp, caractéristiques                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                OPTIONAL HEADER                           │    │
│  │  Point d'entrée (AddressOfEntryPoint)                   │    │
│  │  ImageBase (adresse de chargement préférée)             │    │
│  │  Data Directories (imports, exports, etc.)              │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                SECTION HEADERS                           │    │
│  │  .text, .data, .rdata, .rsrc, .reloc                    │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    SECTIONS                              │    │
│  │  (Le contenu réel)                                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  Outils : PE-bear, CFF Explorer, dumpbin                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Commandes de Compilation Utiles

```bash
# Compilation complète (défaut)
gcc hello.c -o hello

# Voir toutes les étapes
gcc -v hello.c -o hello

# Arrêter après le préprocesseur
gcc -E hello.c -o hello.i

# Arrêter après la compilation (assembleur)
gcc -S hello.c -o hello.s

# Arrêter après l'assemblage (objet)
gcc -c hello.c -o hello.o

# Compilation statique
gcc -static hello.c -o hello

# Avec informations de debug
gcc -g hello.c -o hello

# Sans protections (pour tests de sécurité)
gcc -fno-stack-protector -z execstack -no-pie hello.c -o hello

# 32 bits sur un système 64 bits
gcc -m32 hello.c -o hello
```

---

## Pertinence pour la Sécurité Offensive

```
┌─────────────────────────────────────────────────────────────────┐
│              APPLICATIONS EN SÉCURITÉ                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Reverse Engineering :                                          │
│  • Désassembler pour comprendre le code                        │
│  • Identifier les fonctions vulnérables                        │
│  • Trouver les chaînes cachées                                 │
│                                                                 │
│  Exploitation :                                                 │
│  • Comprendre où le code est chargé (pour ASLR bypass)        │
│  • Identifier PLT/GOT pour les redirections                    │
│  • Trouver les gadgets ROP dans .text                          │
│                                                                 │
│  Évasion :                                                      │
│  • Modifier les headers pour contourner la détection           │
│  • Packer/crypter les sections                                 │
│  • Supprimer les symboles (strip)                              │
│                                                                 │
│  Développement d'outils :                                       │
│  • Compiler sans dépendances (-static)                         │
│  • Optimiser la taille (-Os)                                   │
│  • Cross-compiler pour différentes cibles                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Résumé

```
┌─────────────────────────────────────────────────────────────────┐
│                        POINTS CLÉS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Le parcours :                                                  │
│  .c → (préprocesseur) → .i → (compilateur) → .s →             │
│  (assembleur) → .o → (linker) → exécutable → (loader) → RAM   │
│                                                                 │
│  • Le préprocesseur traite les #include et #define             │
│                                                                 │
│  • Le compilateur génère de l'assembleur optimisé              │
│                                                                 │
│  • L'assembleur crée du code machine relocatable               │
│                                                                 │
│  • Le linker combine les objets et résout les symboles         │
│                                                                 │
│  • Le loader mappe l'exécutable en mémoire                     │
│                                                                 │
│  • PLT/GOT sont des cibles d'exploitation importantes          │
│                                                                 │
│  • Connaître les formats (ELF/PE) est essentiel                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [04 - Le Système d'Exploitation](04-systeme-exploitation.md) | [Exercices](../exercices/exercice-01.md) |
