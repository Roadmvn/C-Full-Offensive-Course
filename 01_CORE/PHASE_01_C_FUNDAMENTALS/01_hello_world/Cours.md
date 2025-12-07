# Module 01 : Hello World - Les fondations

## Objectifs

À la fin de ce module, tu seras capable de :
- Comprendre ce qu'est réellement un programme et comment il s'exécute
- Maîtriser le processus de compilation et ses implications en sécurité
- Écrire et compiler ton premier programme C
- Comprendre les choix architecturaux qui impactent la discrétion d'un binaire

---

## Partie 0 : Les bases absolues (pour vrais débutants)

Avant de commencer à coder, il faut comprendre quelques concepts fondamentaux. Si tu connais déjà le binaire et l'hexadécimal, tu peux passer à la Partie 1.

### Les systèmes de numération

Dans la vie quotidienne, on compte en **base 10** (décimal). On utilise 10 chiffres : 0, 1, 2, 3, 4, 5, 6, 7, 8, 9.

Quand on arrive à 9, on "repart à zéro" et on ajoute 1 à gauche : 10, 11, 12...

```
Décimal : 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13...
```

**Pourquoi base 10 ?** Probablement parce qu'on a 10 doigts !

### Le binaire (base 2)

Les ordinateurs n'ont pas de doigts. Ils fonctionnent avec de l'électricité qui a deux états :
- **Courant** = 1
- **Pas de courant** = 0

C'est tout. Un ordinateur ne "comprend" que des 0 et des 1. C'est le **binaire** (base 2).

En binaire, on n'a que 2 chiffres : 0 et 1. Quand on arrive à 1, on repart à zéro et on ajoute 1 à gauche :

```
Décimal  →  Binaire
   0     →     0
   1     →     1
   2     →    10      (on a utilisé 0 et 1, donc on repart : "1" puis "0")
   3     →    11
   4     →   100      (on repart encore)
   5     →   101
   6     →   110
   7     →   111
   8     →  1000
  ...
  255    →  11111111  (8 bits = 1 octet)
```

**Un bit** = un chiffre binaire (0 ou 1)
**Un octet (byte)** = 8 bits = peut représenter 256 valeurs (de 0 à 255)

**Pourquoi c'est important ?**
Tout ce que fait ton ordinateur (afficher du texte, jouer de la musique, exécuter un malware) est au final une suite de 0 et de 1.

### L'hexadécimal (base 16)

Écrire en binaire, c'est long. `11111111` c'est juste 255 !

L'**hexadécimal** (base 16) est un compromis pratique. On utilise 16 symboles :
```
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F
```

Où A=10, B=11, C=12, D=13, E=14, F=15.

```
Décimal  →  Hexa  →  Binaire
   0     →   0    →     0000
   1     →   1    →     0001
   9     →   9    →     1001
  10     →   A    →     1010
  15     →   F    →     1111
  16     →  10    →    10000
 255     →  FF    →  11111111
 256     →  100   → 100000000
```

**L'avantage clé** : 1 chiffre hexa = exactement 4 bits.
Donc `FF` = `1111 1111` = 255. C'est compact et facile à convertir mentalement.

**Notation** : Pour distinguer l'hexa du décimal, on écrit :
- `0xFF` ou `0xff` (préfixe 0x, convention C)
- `FFh` (suffixe h, convention assembleur)

### Pourquoi l'hexa est partout en sécurité ?

1. **Les adresses mémoire** sont affichées en hexa :
   ```
   0x7fff5fbff8c0  (beaucoup plus lisible que 140734799804608)
   ```

2. **Les opcodes** (instructions processeur) sont en hexa :
   ```
   48 89 e5  (au lieu de 01001000 10001001 11100101)
   ```

3. **L'analyse de binaires** utilise l'hexa pour les dumps mémoire :
   ```
   00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21              |Hello World!|
   ```

4. **Les couleurs** en informatique : `#FF0000` = rouge (FF de rouge, 00 de vert, 00 de bleu)

### La table ASCII

Comment l'ordinateur représente-t-il les lettres avec des nombres ?

La table **ASCII** (American Standard Code for Information Interchange) assigne un nombre à chaque caractère :

```
Caractère  →  Décimal  →  Hexa  →  Binaire
    A      →    65     →  0x41  →  01000001
    B      →    66     →  0x42  →  01000010
    Z      →    90     →  0x5A  →  01011010
    a      →    97     →  0x61  →  01100001
    0      →    48     →  0x30  →  00110000
    9      →    57     →  0x39  →  00111001
  espace   →    32     →  0x20  →  00100000
   \n      →    10     →  0x0A  →  00001010  (nouvelle ligne)
```

**Astuce** : La différence entre majuscule et minuscule est toujours 32 (0x20).
`'A'` (65) + 32 = `'a'` (97)

**Pourquoi c'est important pour la sécurité ?**
Quand tu analyses un binaire avec `strings` ou un éditeur hexa, tu vois :
```
48 65 6c 6c 6f  →  "Hello"
```
Savoir lire l'hexa te permet de repérer des strings, des patterns, des signatures.

### Exercice mental rapide

Avant de continuer, assure-toi de comprendre :

1. `0xFF` en décimal = ? (Réponse : 255)
2. `0x10` en décimal = ? (Réponse : 16)
3. Quel caractère est `0x41` ? (Réponse : 'A')
4. Combien de valeurs peut contenir 1 octet ? (Réponse : 256, de 0 à 255)

Si ces réponses sont claires, tu es prêt pour la suite !

---

## Partie 1 : Qu'est-ce qu'un programme ?

### Le concept de base

Un programme, c'est une suite d'instructions que le processeur exécute séquentiellement. Mais pour vraiment comprendre, il faut aller plus loin.

**Ton processeur ne comprend qu'une chose : le langage machine (binaire).**

Quand tu écris :
```c
printf("Hello");
```

Le processeur ne voit pas ça. Il voit quelque chose comme :
```
48 89 e5 48 83 ec 10 48 8d 3d 00 00 00 00 e8 00 00 00 00 ...
```

Ces octets hexadécimaux sont des **opcodes** - les instructions directes du processeur.

### Pourquoi le C ?

Le C est un langage **compilé** et **bas niveau** :

| Langage | Type | Niveau | Contrôle mémoire | Usage Red Team |
|---------|------|--------|------------------|----------------|
| Python | Interprété | Haut | Non | Scripts, automation |
| Java | Compilé (bytecode) | Haut | Non | Rare |
| C | Compilé (natif) | Bas | Oui | Malware, exploits, implants |
| Assembly | Direct | Très bas | Total | Shellcode, exploits |

**Le C te donne :**
- Accès direct à la mémoire (pointeurs)
- Contrôle total sur la structure du binaire
- Binaires natifs sans dépendances runtime (pas de JVM, pas d'interpréteur)
- Performance maximale

**En contexte offensif, c'est crucial car :**
- Tu contrôles exactement ce que fait ton binaire
- Pas de runtime détectable (contrairement à Python → python.exe)
- Binaires plus petits et autonomes
- Accès aux APIs système bas niveau

---

## Partie 2 : La compilation en détail

### Vue d'ensemble

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   hello.c   │────>│ Préprocesseur│────>│ Compilateur │────>│ Assembleur  │
│   (source)  │     │   (cpp)     │     │   (cc1)     │     │   (as)      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                   │
                                                                   v
                                        ┌─────────────┐     ┌─────────────┐
                                        │   hello     │<────│   Linker    │
                                        │(exécutable) │     │   (ld)      │
                                        └─────────────┘     └─────────────┘
```

### Étape 1 : Le préprocesseur

Le préprocesseur traite toutes les lignes commençant par `#` :

```c
#include <stdio.h>   // Copie le contenu de stdio.h ici
#define SIZE 100     // Remplace SIZE par 100 partout
```

**Ce qui se passe vraiment avec `#include <stdio.h>` :**

Le préprocesseur va chercher le fichier `stdio.h` et copie TOUT son contenu dans ton fichier. Sur Linux, ce fichier fait environ 800 lignes et inclut lui-même d'autres fichiers.

Tu peux voir le résultat :
```bash
gcc -E hello.c -o hello.i
wc -l hello.i  # Souvent 500-1000+ lignes juste pour un printf !
```

**Implication Red Team :**
Chaque `#include` ajoute potentiellement des informations dans ton binaire final. Plus tu inclus, plus ton binaire contient de références détectables.

### Étape 2 : La compilation

Le compilateur transforme le code C en assembleur :

```bash
gcc -S hello.c -o hello.s
```

Résultat (simplifié) :
```asm
main:
    push    rbp
    mov     rbp, rsp
    lea     rdi, [rip+.LC0]    ; Charge l'adresse de "Hello"
    call    printf             ; Appelle printf
    mov     eax, 0             ; Valeur de retour = 0
    pop     rbp
    ret
.LC0:
    .string "Hello World!"     ; Ta string est stockée ici !
```

**Implication Red Team :**
Ta string `"Hello World!"` est visible en clair dans le binaire. C'est pourquoi les malwares chiffrent leurs strings.

### Étape 3 : L'assemblage

L'assembleur convertit l'assembleur en code objet (fichier `.o`) :

```bash
gcc -c hello.c -o hello.o
```

Le fichier `.o` contient du code machine, mais pas encore exécutable - il manque les adresses finales et les bibliothèques.

### Étape 4 : Le linking (édition de liens)

C'est ici que ça devient intéressant pour nous.

Le linker :
1. Résout les symboles (où est `printf` ?)
2. Lie les bibliothèques nécessaires
3. Crée l'exécutable final avec son format (ELF sur Linux, PE sur Windows)

**Deux types de linking :**

| Type | Description | Taille binaire | Dépendances | Usage Red Team |
|------|-------------|----------------|-------------|----------------|
| Dynamique | Lie à des .so/.dll externes | Petit (~8KB) | Oui | Standard |
| Statique | Inclut tout dans le binaire | Gros (~800KB+) | Non | Portabilité |

```bash
# Linking dynamique (par défaut)
gcc hello.c -o hello
ldd hello  # Montre les dépendances

# Linking statique
gcc hello.c -o hello_static -static
ldd hello_static  # "not a dynamic executable"
```

---

## Partie 3 : La structure d'un programme C

### Le minimum vital

```c
int main(void) {
    return 0;
}
```

C'est tout. Pas besoin de `#include` si tu n'utilises aucune fonction externe.

### Avec affichage standard

```c
#include <stdio.h>

int main(void) {
    printf("Hello World!\n");
    return 0;
}
```

### Explication détaillée

#### `#include <stdio.h>` - Ce que ça fait vraiment

`stdio.h` (Standard Input/Output Header) déclare des fonctions comme :
- `printf()` - Afficher du texte formaté
- `scanf()` - Lire une entrée
- `fopen()`, `fclose()` - Manipuler des fichiers
- Et bien d'autres...

**Mais `stdio.h` ne contient PAS le code de printf !**

Il contient seulement la **déclaration** (prototype) :
```c
int printf(const char *format, ...);
```

Le vrai code de `printf` est dans la **bibliothèque C** (libc.so sur Linux, msvcrt.dll sur Windows). Le linker fait le lien entre ton appel et le code réel.

#### `int main(void)` - Le point d'entrée

`main` est le point d'entrée **conventionnel** de ton programme. Quand le système lance ton exécutable :

1. Le loader charge ton binaire en mémoire
2. Il exécute du code d'initialisation (CRT - C Runtime)
3. Ce code d'init appelle `main()`
4. Ton code s'exécute
5. `main()` retourne
6. Le code de cleanup s'exécute
7. Le processus se termine

```
Système ──> _start (CRT) ──> __libc_start_main ──> main() ──> exit()
```

**Implication Red Team :**
Le vrai point d'entrée n'est PAS `main()` ! C'est `_start` ou équivalent. En analyse de malware, il faut chercher le vrai entry point dans le header PE/ELF.

#### `return 0` - Le code de sortie

La convention :
- `0` = Succès
- `1-255` = Erreur (le numéro peut indiquer le type d'erreur)

```bash
./mon_programme
echo $?  # Affiche le code de retour (Linux)
echo %ERRORLEVEL%  # Windows
```

**Utilisation en scripting :**
```bash
./exploit && ./post_exploit  # post_exploit s'exécute seulement si exploit retourne 0
```

---

## Partie 4 : printf() et ses implications

### Comment fonctionne printf

```c
printf("Age: %d ans\n", 25);
```

`printf` est une fonction **variadique** (nombre variable d'arguments) qui :
1. Parse la format string (`"Age: %d ans\n"`)
2. Remplace les spécificateurs (`%d`) par les arguments (25)
3. Écrit le résultat sur stdout

### Spécificateurs de format essentiels

| Spécificateur | Type | Exemple | Résultat |
|---------------|------|---------|----------|
| `%d` ou `%i` | Entier signé | `printf("%d", -42)` | `-42` |
| `%u` | Entier non signé | `printf("%u", 42)` | `42` |
| `%x` | Hexa minuscule | `printf("%x", 255)` | `ff` |
| `%X` | Hexa majuscule | `printf("%X", 255)` | `FF` |
| `%p` | Pointeur | `printf("%p", ptr)` | `0x7fff5fbff8c0` |
| `%s` | String | `printf("%s", "Hi")` | `Hi` |
| `%c` | Caractère | `printf("%c", 65)` | `A` |
| `%f` | Float/Double | `printf("%f", 3.14)` | `3.140000` |
| `%%` | Littéral % | `printf("%%")` | `%` |

### Formatage avancé

```c
printf("%08x", 255);      // "000000ff" - padding avec 0, largeur 8
printf("%-10s", "Hi");    // "Hi        " - aligné à gauche, largeur 10
printf("%5.2f", 3.14159); // " 3.14" - largeur 5, 2 décimales
```

### Les strings dans le binaire

**C'est ici que beaucoup font l'erreur de compréhension.**

Quand tu écris :
```c
printf("Connecting to C2 server...\n");
```

Cette string est stockée en clair dans la section `.rodata` (read-only data) de ton binaire.

**Vérification :**
```bash
strings mon_binaire | grep "C2"
# Résultat : "Connecting to C2 server..."
```

Les analystes de malware utilisent `strings` comme première étape d'analyse. Toute string en clair est visible.

**Solutions offensives :**

1. **Chiffrement au runtime :**
```c
// String chiffrée à la compilation
unsigned char encrypted[] = {0x43, 0x6f, 0x6e, 0x6e, ...};

// Déchiffrement au runtime
char* decrypted = xor_decrypt(encrypted, key);
printf("%s", decrypted);
```

2. **Construction caractère par caractère :**
```c
char msg[20];
msg[0] = 'H'; msg[1] = 'e'; msg[2] = 'l'; // etc.
```

3. **Stack strings :**
```c
char msg[] = {'H', 'e', 'l', 'l', 'o', '\0'};
```

Nous verrons ces techniques en détail dans le module sur l'obfuscation (W33).

---

## Partie 5 : Le CRT (C Runtime) - Mythes et réalités

### C'est quoi le CRT ?

Le CRT (C Runtime Library) est le code qui :
- Initialise l'environnement avant `main()`
- Fournit les fonctions standard (printf, malloc, etc.)
- Nettoie après `main()`

Sur Windows : `msvcrt.dll`, `ucrtbase.dll`, ou CRT statique
Sur Linux : `libc.so.6` (glibc)

### Le mythe : "stdio.h fait cramer le malware"

**FAUX.** Utiliser `stdio.h` ou `printf` ne déclenche pas automatiquement une détection.

**Ce qui compte pour la détection :**

1. **Les imports suspects** - L'IAT (Import Address Table) liste toutes les fonctions importées. Un binaire qui importe `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` ensemble = suspect.

2. **Les signatures** - Les antivirus cherchent des patterns de bytes connus, pas le fait que tu utilises printf.

3. **Le comportement** - L'EDR surveille ce que ton programme FAIT, pas les headers inclus.

4. **L'entropie** - Un binaire packé/chiffré a une entropie élevée = suspect.

### Pourquoi éviter le CRT quand même ?

| Avec CRT | Sans CRT |
|----------|----------|
| Binaire ~50-100KB minimum | Binaire ~3-5KB possible |
| Dépendance à msvcrt.dll | Autonome |
| Plus d'imports dans l'IAT | IAT minimal |
| Code d'init/cleanup visible | Contrôle total |

**Le vrai avantage de ne pas utiliser le CRT :**
- Binaire plus petit (moins de surface d'analyse)
- Moins d'imports (IAT plus discret)
- Contrôle total sur le point d'entrée
- Pas de code "parasite" du CRT

### Exemple : Avec vs Sans CRT (Windows)

**Avec CRT :**
```c
#include <stdio.h>

int main(void) {
    printf("Hello\n");
    return 0;
}
// Binaire : ~60KB, importe KERNEL32.dll, msvcrt.dll
```

**Sans CRT :**
```c
#include <windows.h>

void _start(void) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteConsoleA(hOut, "Hello\n", 6, NULL, NULL);
    ExitProcess(0);
}
// Binaire : ~3KB, importe seulement KERNEL32.dll
```

**Encore plus bas niveau (syscall direct) :**
```c
// Appel direct au kernel, sans aucune DLL
// (Technique avancée, voir modules WINDOWS)
```

### Conclusion sur le CRT

- Utilise le CRT pour apprendre et pour les outils non critiques
- Évite le CRT quand la taille et la discrétion comptent
- Ce n'est pas une question de détection directe, mais d'optimisation globale

---

## Partie 6 : Compilation - Options importantes

### GCC (Linux/macOS)

```bash
# Compilation basique
gcc hello.c -o hello

# Avec optimisations (binaire plus petit, plus rapide)
gcc hello.c -o hello -O2

# Sans symboles de debug (plus petit, plus dur à reverser)
gcc hello.c -o hello -s

# Statique (aucune dépendance externe)
gcc hello.c -o hello -static

# Tout combiné pour un binaire "propre"
gcc hello.c -o hello -O2 -s -static
```

### Options importantes pour la sécurité/reverse

| Option | Effet | Implication |
|--------|-------|-------------|
| `-g` | Ajoute symboles debug | Facile à reverser ! |
| `-s` | Strip les symboles | Plus dur à reverser |
| `-O0` à `-O3` | Niveau d'optimisation | -O0 facile à lire, -O3 optimisé |
| `-static` | Linking statique | Pas de dépendances |
| `-fPIC` | Position Independent Code | Requis pour les libs partagées |

### Windows (MSVC)

```cmd
cl hello.c /Fe:hello.exe
cl hello.c /Fe:hello.exe /O2       # Optimisé
cl hello.c /Fe:hello.exe /MT       # CRT statique
```

### Windows (MinGW)

```bash
x86_64-w64-mingw32-gcc hello.c -o hello.exe
x86_64-w64-mingw32-gcc hello.c -o hello.exe -s -O2  # Optimisé, strippé
```

---

## Partie 7 : Analyse de ton binaire

Après compilation, analyse ce que tu as créé :

### Sur Linux

```bash
# Infos générales
file hello

# Dépendances
ldd hello

# Symboles
nm hello

# Strings
strings hello

# Headers ELF
readelf -h hello

# Désassemblage
objdump -d hello
```

### Sur Windows

```cmd
# Avec des outils comme PE-bear, CFF Explorer, ou dumpbin
dumpbin /headers hello.exe
dumpbin /imports hello.exe
dumpbin /exports hello.exe
```

### Ce que tu dois vérifier

1. **Strings visibles** - Y a-t-il des strings sensibles ?
2. **Imports** - Quelles DLLs/fonctions sont importées ?
3. **Taille** - Est-ce raisonnable ?
4. **Sections** - Structure standard ou suspecte ?

---

## Résumé

| Concept | Ce qu'il faut retenir |
|---------|----------------------|
| Compilation | 4 étapes : préprocesseur → compilateur → assembleur → linker |
| Point d'entrée | `main()` est appelé par le CRT, le vrai entry point est `_start` |
| Strings | Visibles en clair avec `strings`, penser à l'obfuscation |
| CRT | Pas de détection directe, mais impacte taille/imports |
| Printf | Utile pour debug, mais les strings restent dans le binaire |
| Return | 0 = succès, utilisé pour le chaînage de commandes |

---

## Exercices pratiques

Voir [exercice.md](exercice.md)

## Code exemple

Voir [example.c](example.c)

---

**Module suivant** : [02 - Variables et Types](../02_variables_types/)
