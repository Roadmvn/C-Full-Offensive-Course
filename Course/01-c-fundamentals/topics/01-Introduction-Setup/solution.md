# Solutions - Module 01 : Hello World

## Solution Exercice 1 : Compilation et exécution

### Réponses aux questions

**Quel est le code de retour affiché ?**
```bash
$ ./hello
Hello World!
$ echo $?
0
```
Le code de retour est `0`, indiquant un succès.

**Que se passe-t-il si tu retires `return 0;` ?**

Sans `return 0;`, le comportement dépend du compilateur :
- GCC moderne : retourne automatiquement 0 pour `main()`
- Ancien comportement : valeur indéfinie (souvent la dernière valeur dans le registre EAX)

C'est une mauvaise pratique de ne pas mettre `return` explicitement.

---

## Solution Exercice 2 : Analyse du binaire

### Résultats typiques

```bash
$ gcc hello.c -o hello
$ ls -lh hello
-rwxr-xr-x 1 user user 16K  hello      # ~16KB dynamique

$ gcc hello.c -o hello_static -static
$ ls -lh hello_static
-rwxr-xr-x 1 user user 880K hello_static  # ~880KB statique !
```

**Différence de taille** : Le binaire statique est ~50x plus gros car il inclut toute la libc.

**Pourquoi "not a dynamic executable" ?**
```bash
$ ldd hello
    linux-vdso.so.1 => ...
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
    /lib64/ld-linux-x86-64.so.2 => ...

$ ldd hello_static
    not a dynamic executable
```
Le binaire statique n'a pas de section `.dynamic` - tout est inclus dedans.

**Strings visibles** :
```bash
$ strings hello | grep -i hello
Hello World!
```
Oui, la string est visible en clair !

---

## Solution Exercice 3 : Expérimentation printf

```c
#include <stdio.h>

int main(void) {
    printf("=== Informations systeme ===\n");
    printf("Architecture : 64 bits\n");
    printf("Adresse de main : %p\n", (void*)&main);
    printf("Taille d'un int : %zu octets\n", sizeof(int));
    printf("Valeur hexa de 255 : 0x%X\n", 255);
    printf("Caractere ASCII 65 : %c\n", 65);

    return 0;
}
```

### Explications

- `(void*)&main` : On prend l'adresse de la fonction main et on la caste en `void*` pour `%p`
- `sizeof(int)` : Retourne un `size_t`, on utilise `%zu` pour l'afficher
- `%X` : Affiche en hexadécimal majuscule (ff devient FF)
- `%c` avec `65` : Affiche le caractère ASCII 65, qui est 'A'

---

## Solution Exercice 4 : Codes de retour

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    // Vérification : il faut au moins 2 arguments (programme + argument)
    if (argc < 2) {
        printf("Usage: %s <mot_de_passe>\n", argv[0]);
        return 1;  // Erreur : pas assez d'arguments
    }

    // Comparaison avec le mot secret
    if (strcmp(argv[1], "secret") == 0) {
        printf("Acces autorise\n");
        return 0;  // Succès
    } else {
        printf("Acces refuse\n");
        return 1;  // Échec
    }
}
```

### Test

```bash
$ gcc check_arg.c -o check_arg

$ ./check_arg secret && echo "==> Commande suivante executee"
Acces autorise
==> Commande suivante executee

$ ./check_arg mauvais && echo "==> Commande suivante executee"
Acces refuse
# (rien après car return 1 = échec, && ne continue pas)

$ ./check_arg mauvais || echo "==> Echec detecte"
Acces refuse
==> Echec detecte
```

### Explication

- `&&` : Exécute la commande suivante SEULEMENT si la précédente retourne 0
- `||` : Exécute la commande suivante SEULEMENT si la précédente retourne non-0

---

## Solution Exercice 5 : Étapes de compilation

### Résultats attendus

```bash
$ wc -l test.i
723 test.i   # ~700+ lignes après inclusion de stdio.h !
```

**Pourquoi autant ?** `stdio.h` inclut d'autres headers, qui en incluent d'autres, etc. Tout est "aplati" dans le fichier `.i`.

**String dans test.s :**
```bash
$ grep "Test compilation" test.s
    .string "Test compilation"
```
Oui, la string est visible dans la section `.rodata`.

**Symboles avec nm :**
```bash
$ nm test.o
                 U _GLOBAL_OFFSET_TABLE_
0000000000000000 T main
                 U puts
```
- `T main` : Symbole défini dans la section Text (code)
- `U puts` : Symbole Undefined (sera résolu au linking)

Note : Le compilateur a optimisé `printf("%s\n", ...)` en `puts()` !

---

## Solution Exercice 6 : Impact des options

### Résultats typiques

```bash
$ ls -lh hello_*
-rwxr-xr-x 1 user user  20K hello_debug
-rwxr-xr-x 1 user user  15K hello_release
-rwxr-xr-x 1 user user 870K hello_stealth
```

**Différence de taille** :
- `hello_debug` : Plus gros à cause des symboles de debug
- `hello_release` : Plus petit, strippé
- `hello_stealth` : Énorme car statique

**Pourquoi nm ne montre rien sur hello_release ?**
```bash
$ nm hello_release
nm: hello_release: no symbols
```
L'option `-s` (strip) a supprimé tous les symboles de debug.

**Plus difficile à reverser** : `hello_release` car pas de symboles. Mais `hello_stealth` est autonome et ne dépend de rien.

---

## Solution Exercice 7 : String cachée

### Partie A : Vérification du problème

```bash
$ gcc evil.c -o evil
$ strings evil | grep -i evil
Connecting to evil-server.com on port 4444
```
La string est bien visible.

### Partie B : Solution avec stack string

```c
#include <stdio.h>

int main(void) {
    // Construction caractère par caractère sur la stack
    // Pas de string littérale dans .rodata
    char msg[50];

    msg[0]  = 'C'; msg[1]  = 'o'; msg[2]  = 'n'; msg[3]  = 'n';
    msg[4]  = 'e'; msg[5]  = 'c'; msg[6]  = 't'; msg[7]  = 'i';
    msg[8]  = 'n'; msg[9]  = 'g'; msg[10] = ' '; msg[11] = 't';
    msg[12] = 'o'; msg[13] = ' '; msg[14] = 'e'; msg[15] = 'v';
    msg[16] = 'i'; msg[17] = 'l'; msg[18] = '-'; msg[19] = 's';
    msg[20] = 'e'; msg[21] = 'r'; msg[22] = 'v'; msg[23] = 'e';
    msg[24] = 'r'; msg[25] = '.'; msg[26] = 'c'; msg[27] = 'o';
    msg[28] = 'm'; msg[29] = ' '; msg[30] = 'o'; msg[31] = 'n';
    msg[32] = ' '; msg[33] = 'p'; msg[34] = 'o'; msg[35] = 'r';
    msg[36] = 't'; msg[37] = ' '; msg[38] = '4'; msg[39] = '4';
    msg[40] = '4'; msg[41] = '4'; msg[42] = '\0';

    printf("%s\n", msg);
    return 0;
}
```

### Vérification

```bash
$ gcc evil_hidden.c -o evil_hidden
$ strings evil_hidden | grep -i evil
# (rien !)
$ ./evil_hidden
Connecting to evil-server.com on port 4444
```

**Explication** : Les caractères individuels sont des instructions `mov` dans le code, pas des strings dans `.rodata`. L'outil `strings` ne les trouve pas car il cherche des séquences de caractères imprimables consécutifs.

### Alternative avec tableau d'initialisation

```c
char msg[] = {'e','v','i','l','-','s','e','r','v','e','r','.','c','o','m','\0'};
```

Cette méthode est plus propre mais peut parfois être détectée selon le compilateur.

---

## Solution Exercice 8 : Sans le CRT (Windows)

### Code complet

```c
#include <windows.h>

// Notre point d'entrée personnalisé
// Pas de main(), pas de CRT
void _start(void) {
    // GetStdHandle : récupère le handle de sortie console
    // STD_OUTPUT_HANDLE = -11
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Notre message
    char msg[] = "Hello sans CRT!\n";

    // Variable pour recevoir le nombre de caractères écrits
    DWORD written;

    // WriteConsoleA : écrit directement sur la console
    // A = version ANSI (pas Unicode)
    WriteConsoleA(
        hOut,               // Handle de sortie
        msg,                // Buffer à écrire
        sizeof(msg) - 1,    // Taille (sans le \0)
        &written,           // Caractères écrits
        NULL                // Réservé
    );

    // ExitProcess : termine le processus proprement
    // Pas de return car pas de CRT pour le gérer
    ExitProcess(0);
}
```

### Compilation

```bash
# Avec CRT (normal)
x86_64-w64-mingw32-gcc hello.c -o hello_crt.exe

# Sans CRT
x86_64-w64-mingw32-gcc nocrt.c -o nocrt.exe \
    -nostdlib \      # Pas de bibliothèque standard
    -lkernel32 \     # Lie seulement kernel32
    -e _start        # Point d'entrée = _start
```

### Résultats

```bash
$ ls -lh *.exe
-rwxr-xr-x 1 user user  58K hello_crt.exe
-rwxr-xr-x 1 user user 4.5K nocrt.exe
```

**Différence** : ~13x plus petit sans le CRT !

### Imports

Avec un outil PE (pe-bear, CFF Explorer, ou objdump) :

**hello_crt.exe** importe :
- KERNEL32.dll (beaucoup de fonctions)
- msvcrt.dll (printf, __getmainargs, _cexit, etc.)

**nocrt.exe** importe :
- KERNEL32.dll uniquement
  - GetStdHandle
  - WriteConsoleA
  - ExitProcess

---

## Points clés à retenir

1. **La compilation a 4 étapes** : chacune laisse des traces analysables

2. **Les strings sont visibles** : Toujours penser à l'obfuscation en contexte offensif

3. **Les options de compilation importent** :
   - `-g` : Debug = facile à reverser
   - `-s` : Strip = plus difficile
   - `-static` : Autonome mais gros

4. **Le CRT ajoute du poids** : Sans CRT = binaire minimal

5. **Les codes de retour** : Permettent le chaînage de commandes et la détection d'erreurs

6. **Analyser avant de déployer** : Toujours vérifier avec `strings`, `nm`, `ldd` ce que contient ton binaire
