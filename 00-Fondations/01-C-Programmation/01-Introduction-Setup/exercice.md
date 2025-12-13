# Exercices - Module 01 : Hello World

## Exercice 1 : Compilation et exécution (Très facile)

**Objectif** : Compiler et exécuter ton premier programme.

### Instructions

1. Crée un fichier `hello.c` avec ce contenu :
```c
#include <stdio.h>

int main(void) {
    printf("Hello World!\n");
    return 0;
}
```

2. Compile-le :
```bash
gcc hello.c -o hello
```

3. Exécute-le :
```bash
./hello
```

4. Vérifie le code de retour :
```bash
echo $?
```

### Questions

- Quel est le code de retour affiché ?
- Que se passe-t-il si tu retires `return 0;` ?

---

## Exercice 2 : Analyse du binaire (Facile)

**Objectif** : Comprendre ce que contient ton binaire.

### Instructions

1. Compile `hello.c` normalement :
```bash
gcc hello.c -o hello
```

2. Analyse le binaire :
```bash
# Type du fichier
file hello

# Taille
ls -lh hello

# Dépendances
ldd hello

# Strings visibles
strings hello | grep -i hello
```

3. Compile en statique :
```bash
gcc hello.c -o hello_static -static
```

4. Compare :
```bash
ls -lh hello hello_static
ldd hello_static
```

### Questions

- Quelle est la différence de taille entre les deux binaires ?
- Pourquoi `ldd hello_static` affiche "not a dynamic executable" ?
- Peux-tu trouver ta string "Hello World!" avec `strings` ?

---

## Exercice 3 : Expérimentation printf (Facile)

**Objectif** : Maîtriser les spécificateurs de format.

### Instructions

Crée un programme qui affiche :
```
=== Informations système ===
Architecture : 64 bits
Adresse de main : 0x[adresse en hexa]
Taille d'un int : 4 octets
Valeur hexa de 255 : 0xFF
Caractère ASCII 65 : A
```

### Indices

- `%p` pour une adresse
- `%X` pour hexadécimal majuscule
- `%c` pour un caractère
- `%zu` pour un `size_t` (résultat de `sizeof`)
- `&main` donne l'adresse de la fonction main

### Squelette

```c
#include <stdio.h>

int main(void) {
    printf("=== Informations systeme ===\n");
    // À toi de compléter...

    return 0;
}
```

---

## Exercice 4 : Codes de retour (Moyen)

**Objectif** : Comprendre l'utilité des codes de retour.

### Instructions

1. Crée un programme `check_arg.c` qui :
   - Retourne `0` si on lui passe l'argument "secret"
   - Retourne `1` sinon

2. Teste avec :
```bash
./check_arg secret && echo "Acces autorise"
./check_arg mauvais && echo "Acces autorise"
```

### Indice

```c
int main(int argc, char *argv[]) {
    // argc = nombre d'arguments
    // argv[0] = nom du programme
    // argv[1] = premier argument (si présent)
}
```

Pour comparer des strings, utilise `strcmp()` de `<string.h>` :
```c
if (strcmp(argv[1], "secret") == 0) {
    // Égal
}
```

---

## Exercice 5 : Étapes de compilation (Moyen)

**Objectif** : Visualiser chaque étape de la compilation.

### Instructions

1. Crée un fichier `test.c` :
```c
#include <stdio.h>
#define MESSAGE "Test compilation"

int main(void) {
    printf("%s\n", MESSAGE);
    return 0;
}
```

2. Exécute chaque étape séparément :
```bash
# Préprocesseur seulement
gcc -E test.c -o test.i

# Compilation en assembleur
gcc -S test.c -o test.s

# Assemblage en objet
gcc -c test.c -o test.o

# Linking final
gcc test.o -o test
```

3. Examine chaque fichier :
```bash
wc -l test.i          # Combien de lignes après préprocesseur ?
cat test.s            # Regarde l'assembleur généré
file test.o           # Type du fichier objet
nm test.o             # Symboles dans l'objet
```

### Questions

- Combien de lignes fait `test.i` ? Pourquoi autant ?
- Peux-tu trouver ta string "Test compilation" dans `test.s` ?
- Quel symbole vois-tu avec `nm test.o` ?

---

## Exercice 6 : Impact des options de compilation (Moyen)

**Objectif** : Comprendre l'impact des options du compilateur.

### Instructions

Compile le même programme avec différentes options :

```bash
# Sans optimisation, avec debug
gcc hello.c -o hello_debug -O0 -g

# Avec optimisation, strippé
gcc hello.c -o hello_release -O2 -s

# Statique, optimisé, strippé
gcc hello.c -o hello_stealth -O2 -s -static
```

Compare :
```bash
ls -lh hello_*
nm hello_debug | head -20
nm hello_release 2>&1
strings hello_debug | wc -l
strings hello_release | wc -l
```

### Questions

- Quelle est la différence de taille ?
- Pourquoi `nm hello_release` ne montre rien (ou erreur) ?
- Lequel serait plus difficile à analyser pour un reverse engineer ?

---

## Exercice 7 : String cachée (Challenge)

**Objectif** : Comprendre pourquoi les strings sont un problème.

### Partie A : Le problème

1. Crée un programme avec une "string sensible" :
```c
#include <stdio.h>

int main(void) {
    printf("Connecting to evil-server.com on port 4444\n");
    return 0;
}
```

2. Compile et cherche la string :
```bash
gcc evil.c -o evil
strings evil | grep -i evil
```

Tu devrais trouver ta string en clair.

### Partie B : Une solution basique

Réécris le programme pour que la string ne soit PAS visible avec `strings` :

**Indice** : Construis la string caractère par caractère sur la stack.

```c
#include <stdio.h>

int main(void) {
    char msg[50];
    msg[0] = 'C';
    msg[1] = 'o';
    // Continue...
    msg[49] = '\0';

    printf("%s\n", msg);
    return 0;
}
```

### Vérification

```bash
gcc evil_hidden.c -o evil_hidden
strings evil_hidden | grep -i evil
# Ne devrait rien trouver !
```

---

## Exercice 8 : Sans le CRT (Challenge - Windows)

**Objectif** : Créer un binaire minimal sans le C Runtime.

> Cet exercice nécessite un environnement Windows ou MinGW.

### Instructions

1. Crée `nocrt.c` :
```c
#include <windows.h>

// Point d'entrée personnalisé (pas main)
void _start(void) {
    // Récupère le handle de la console
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Écrit directement
    char msg[] = "Hello sans CRT!\n";
    DWORD written;
    WriteConsoleA(hOut, msg, sizeof(msg) - 1, &written, NULL);

    // Termine le processus
    ExitProcess(0);
}
```

2. Compile sans CRT (MinGW) :
```bash
x86_64-w64-mingw32-gcc nocrt.c -o nocrt.exe -nostdlib -lkernel32 -e _start
```

3. Compare les tailles :
```bash
# Avec CRT
x86_64-w64-mingw32-gcc hello.c -o hello_crt.exe

# Sans CRT
x86_64-w64-mingw32-gcc nocrt.c -o nocrt.exe -nostdlib -lkernel32 -e _start

ls -lh hello_crt.exe nocrt.exe
```

### Questions

- Quelle est la différence de taille ?
- Quels imports vois-tu dans chaque binaire ? (utilise `objdump -p` ou un outil PE)

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Expliquer les 4 étapes de compilation
- [ ] Compiler un programme avec différentes options
- [ ] Analyser un binaire avec `file`, `ldd`, `strings`, `nm`
- [ ] Expliquer pourquoi les strings sont un problème de sécurité
- [ ] Comprendre la différence linking statique vs dynamique
- [ ] Utiliser les codes de retour dans des scripts

---

## Solutions

Voir [solution.c](solution.c) pour les solutions commentées.
