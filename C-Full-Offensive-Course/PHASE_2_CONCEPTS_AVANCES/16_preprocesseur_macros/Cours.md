# Cours : Préprocesseur et Macros

## Objectif du Module

Maîtriser le préprocesseur C : comprendre les directives #include, #define (constantes et macros), #ifdef/#ifndef (compilation conditionnelle), macros variadic (__VA_ARGS__), macros prédéfinies (__FILE__, __LINE__), et utiliser les macros pour l'obfuscation de code. Application Red Team : obfuscation, compilation multi-plateforme, anti-debug.

---

## 1. Le Préprocesseur - Avant la Compilation

Le préprocesseur s'exécute AVANT le compilateur. Il transforme ton code source.

```
ÉTAPES DE COMPILATION :

1. PRÉPROCESSEUR (.c → .i)
   ├─ Résout les #include
   ├─ Remplace les #define
   └─ Évalue les #ifdef

2. COMPILATEUR (.i → .s)
   └─ Génère assembleur

3. ASSEMBLEUR (.s → .o)
   └─ Code machine

4. LINKER (.o → exécutable)
   └─ Lie les bibliothèques
```

**Voir le résultat du préprocesseur :**
```bash
gcc -E program.c -o program.i
cat program.i
```

---

## 2. #include - Inclusion de Code

### 2.1 Deux Syntaxes

```c
#include <stdio.h>    // Bibliothèques système (dans /usr/include)
#include "myheader.h" // Fichiers locaux (répertoire actuel)
```

### 2.2 Que Fait #include ?

```
AVANT préprocesseur :

// main.c
#include "utils.h"

int main() {
    fonction_utils();
}

// utils.h
void fonction_utils() {
    printf("Hello\n");
}

═══════════════════════════════════

APRÈS préprocesseur (.i) :

// Le contenu de utils.h est COPIÉ-COLLÉ

void fonction_utils() {
    printf("Hello\n");
}

int main() {
    fonction_utils();
}
```

### 2.3 Include Guards (Éviter Double Inclusion)

```c
// utils.h
#ifndef UTILS_H
#define UTILS_H

void fonction_utils();

#endif
```

**Pourquoi ?**
```
Sans guards :

#include "utils.h"
#include "utils.h"  // ERREUR : Définition multiple

Avec guards :

#include "utils.h"  // UTILS_H défini
#include "utils.h"  // Déjà défini, skip
```

---

## 3. #define - Constantes et Macros

### 3.1 Constantes Simples

```c
#define PI 3.14159
#define MAX 100
#define VERSION "1.0.0"

// Utilisation
float circonference = 2 * PI * rayon;
int arr[MAX];
printf("Version %s\n", VERSION);
```

**Après préprocesseur :**
```c
// Toutes les occurrences sont REMPLACÉES
float circonference = 2 * 3.14159 * rayon;
int arr[100];
printf("Version %s\n", "1.0.0");
```

### 3.2 Macros Fonctionnelles

```c
#define SQUARE(x) ((x) * (x))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
```

**Utilisation :**
```c
int result = SQUARE(5);     // ((5) * (5)) = 25
int max = MAX(10, 20);      // ((10) > (20) ? (10) : (20)) = 20
```

### 3.3 Danger : Side-Effects

```c
#define SQUARE(x) x*x  // MAUVAIS : pas de parenthèses

int a = SQUARE(1+2);
// Devient : 1+2*1+2 = 1+2+2 = 5 (pas 9 !)

#define SQUARE(x) ((x)*(x))  // BON

int a = SQUARE(1+2);
// Devient : ((1+2)*(1+2)) = 9 ✓
```

**Side-effects :**
```c
#define MAX(a,b) ((a) > (b) ? (a) : (b))

int i = 5;
int max = MAX(i++, 10);
// Devient : ((i++) > (10) ? (i++) : (10))
// i++ exécuté DEUX FOIS si vrai !
```

---

## 4. Compilation Conditionnelle (#ifdef, #ifndef, #if)

### 4.1 #ifdef / #ifndef

```c
#define DEBUG

#ifdef DEBUG
    printf("Mode debug activé\n");
#endif

#ifndef RELEASE
    printf("Pas en production\n");
#endif
```

### 4.2 #if defined()

```c
#if defined(WINDOWS)
    #include <windows.h>
#elif defined(LINUX)
    #include <unistd.h>
#else
    #error "Plateforme non supportée"
#endif
```

### 4.3 Compilation Multi-Plateforme

```c
#ifdef _WIN32
    #define CLEAR "cls"
    #define PATH_SEP "\\"
#else
    #define CLEAR "clear"
    #define PATH_SEP "/"
#endif

// Utilisation
system(CLEAR);
char path[256];
sprintf(path, "%s%sfile.txt", dir, PATH_SEP);
```

---

## 5. Macros Prédéfinies

```c
__FILE__    // Nom du fichier actuel
__LINE__    // Numéro de ligne actuel
__DATE__    // Date de compilation (ex: "Dec 05 2025")
__TIME__    // Heure de compilation (ex: "14:30:00")
__func__    // Nom de la fonction actuelle (C99+)
```

**Utilisation :**
```c
#define LOG(msg) printf("[%s:%d] %s\n", __FILE__, __LINE__, msg)

void fonction() {
    LOG("Début fonction");  // [main.c:42] Début fonction
}
```

---

## 6. Macros Avancées

### 6.1 Stringification (#)

Convertit un argument en chaîne de caractères.

```c
#define STRINGIFY(x) #x

printf("%s\n", STRINGIFY(Hello));  // "Hello"
printf("%s\n", STRINGIFY(42));     // "42"
```

### 6.2 Token Pasting (##)

Concatène deux tokens.

```c
#define CONCAT(a,b) a##b

int CONCAT(var, 1) = 10;  // int var1 = 10;
int CONCAT(var, 2) = 20;  // int var2 = 20;
```

### 6.3 Macros Variadic (__VA_ARGS__)

```c
#define LOG(fmt, ...) printf("[LOG] " fmt "\n", ##__VA_ARGS__)

LOG("Test");              // printf("[LOG] Test\n");
LOG("Valeur: %d", 42);    // printf("[LOG] Valeur: %d\n", 42);
LOG("x=%d, y=%d", 10, 20); // printf("[LOG] x=%d, y=%d\n", 10, 20);
```

---

## 7. Application Red Team

### 7.1 Obfuscation de Code

```c
#define EXEC system
#define HIDE(str) str
#define XOR(a,b) ((a)^(b))

// Code obfusqué
EXEC(HIDE("whoami"));
int key = XOR(0x41, 0x20);
```

### 7.2 Compilation Conditionnelle pour Payloads

```c
#ifdef WINDOWS
    #define SHELL "cmd.exe"
    #include <windows.h>
#elif defined(LINUX)
    #define SHELL "/bin/sh"
    #include <unistd.h>
#elif defined(__APPLE__)
    #define SHELL "/bin/zsh"
    #include <unistd.h>
#endif

// Code générique
execl(SHELL, SHELL, NULL);
```

### 7.3 Anti-Debug avec Macros

```c
#ifdef DEBUG
    #define CHECK_DEBUGGER() exit(0)  // Quitte si debug
#else
    #define CHECK_DEBUGGER() ((void)0)  // Ne fait rien
#endif

int main() {
    CHECK_DEBUGGER();
    // ... code malveillant ...
    return 0;
}
```

### 7.4 Obfuscation d'API Calls

```c
#define API(lib, func) GetProcAddress(LoadLibrary(lib), func)
#define CALL(func, ...) ((void(*)())func)(__VA_ARGS__)

// Utilisation
void *kernel32 = LoadLibrary("kernel32.dll");
void *WinExec = GetProcAddress(kernel32, "WinExec");
((int(*)(const char*, int))WinExec)("calc.exe", 1);

// Avec macros (plus obscur)
CALL(API("kernel32.dll", "WinExec"), "calc.exe", 1);
```

### 7.5 Encryption de Strings à la Compilation

```c
#define XOR_KEY 0x42
#define ENCRYPT_CHAR(c) ((c) ^ XOR_KEY)

// String encryptée
unsigned char encrypted[] = {
    ENCRYPT_CHAR('H'),
    ENCRYPT_CHAR('e'),
    ENCRYPT_CHAR('l'),
    ENCRYPT_CHAR('l'),
    ENCRYPT_CHAR('o'),
    0
};

// Déchiffrement runtime
void decrypt(unsigned char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] ^= XOR_KEY;
    }
}

decrypt(encrypted);
printf("%s\n", encrypted);  // "Hello"
```

### 7.6 Macro pour Build Info

```c
#define BUILD_INFO() \
    printf("Compiled: %s %s\n", __DATE__, __TIME__); \
    printf("File: %s\n", __FILE__); \
    printf("Version: %s\n", VERSION);

BUILD_INFO();
// Compiled: Dec 05 2025 14:30:00
// File: malware.c
// Version: 1.0.0
```

---

## 8. Bonnes Pratiques

```c
// 1. Toujours MAJUSCULES
#define MAX 100
#define SQUARE(x) ((x)*(x))

// 2. Parenthéser les arguments
#define ADD(a,b) ((a)+(b))  // BON
#define ADD(a,b) a+b        // MAUVAIS

// 3. Éviter les side-effects
// Utiliser inline au lieu de macro si complexe
static inline int max(int a, int b) {
    return a > b ? a : b;
}

// 4. Documenter les macros complexes
#define LOG(msg) \  // Macro de logging
    printf("[%s:%d] %s\n", __FILE__, __LINE__, msg)
```

---

## 9. Erreurs Courantes

```c
// MAUVAIS : pas de parenthèses
#define SQUARE(x) x*x
SQUARE(1+2)  // → 1+2*1+2 = 5 (pas 9)

// BON
#define SQUARE(x) ((x)*(x))
SQUARE(1+2)  // → ((1+2)*(1+2)) = 9

// MAUVAIS : side-effects
#define MAX(a,b) ((a)>(b)?(a):(b))
MAX(i++, j++)  // i ou j incrémenté 2 fois !

// BON : utiliser fonction inline
static inline int max(int a, int b) {
    return a > b ? a : b;
}

// MAUVAIS : oublier le \ pour multi-lignes
#define MACRO \
    ligne1; \
    ligne2;
```

---

## 10. Debug et Visualisation

```bash
# Voir le résultat du préprocesseur
gcc -E program.c -o program.i

# Voir toutes les macros prédéfinies
gcc -dM -E - < /dev/null

# Compiler avec définition
gcc -DDEBUG -DVERSION=\"1.0\" program.c -o program
```

---

## 11. Checklist de Compréhension

- [ ] Différence #include <> vs #include "" ?
- [ ] Pourquoi parenthéser les macros ?
- [ ] À quoi sert #ifdef ?
- [ ] Comment utiliser __VA_ARGS__ ?
- [ ] Qu'est-ce que __FILE__ et __LINE__ ?
- [ ] Différence #define vs const ?
- [ ] Comment voir la sortie du préprocesseur ?

---

## 12. Exercices Pratiques

Voir `exercice.txt` pour :
- Créer des macros de debugging
- Implémenter compilation multi-plateforme
- Obfusquer des strings
- Créer un système de logging avec macros

---

**Prochaine étape :** Module 17 - Compilation et Linking (étapes de compilation, gcc flags, static/dynamic linking, PE/ELF, symbols, strip).
