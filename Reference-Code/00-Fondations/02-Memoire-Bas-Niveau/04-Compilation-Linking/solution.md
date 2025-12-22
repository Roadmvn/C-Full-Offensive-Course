# MODULE 17 : COMPILATION ET LINKING - SOLUTIONS

## Exercice 1 : Étapes de compilation

```c
// main.c
#include <stdio.h>

#define GREETING "Hello"

int main(void) {
    printf("%s, World!\n", GREETING);
    return 0;
}
```

```bash
# Étape 1: Préprocesseur
gcc -E main.c -o main.i
# Résultat: macros expansées, includes intégrés

# Étape 2: Compilation vers assembleur
gcc -S main.c -o main.s
# Résultat: code assembleur

# Étape 3: Assemblage
gcc -c main.c -o main.o
# Résultat: code machine objet (binaire)

# Étape 4: Linking
gcc main.o -o main
# Résultat: exécutable final

# Analyse
cat main.i | head -20      # Voir macros expansées
cat main.s                  # Voir assembleur
nm main.o                   # Symboles objet
file main                   # Type de l'exécutable
```

## Exercice 2 : Optimisations

```c
// benchmark.c
#include <stdio.h>
#include <time.h>

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n-1) + fibonacci(n-2);
}

int main(void) {
    clock_t start = clock();
    int result = fibonacci(35);
    clock_t end = clock();
    
    double time = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Result: %d, Time: %.3f seconds\n", result, time);
    return 0;
}
```

```bash
# Compiler avec différents niveaux
gcc -O0 benchmark.c -o bench_O0
gcc -O1 benchmark.c -o bench_O1
gcc -O2 benchmark.c -o bench_O2
gcc -O3 benchmark.c -o bench_O3
gcc -Os benchmark.c -o bench_Os

# Comparer tailles
size bench_O*

# Résultats typiques:
#    text    data     bss     dec
#    1234     544      16    1794    bench_O0
#     980     544      16    1540    bench_O2
#     856     544      16    1416    bench_Os

# Comparer performances
time ./bench_O0  # ~5 secondes
time ./bench_O2  # ~2 secondes
time ./bench_O3  # ~2 secondes

# Voir l'assembleur
objdump -d bench_O0 > asm_O0.txt
objdump -d bench_O3 > asm_O3.txt
diff asm_O0.txt asm_O3.txt
```

## Exercice 3 : Bibliothèque statique

```c
// mylib.c
#include <stdio.h>

void lib_hello(void) {
    printf("Hello from library!\n");
}

int lib_add(int a, int b) {
    return a + b;
}

int lib_multiply(int a, int b) {
    return a * b;
}
```

```c
// mylib.h
#ifndef MYLIB_H
#define MYLIB_H

void lib_hello(void);
int lib_add(int a, int b);
int lib_multiply(int a, int b);

#endif
```

```c
// main.c
#include <stdio.h>
#include "mylib.h"

int main(void) {
    lib_hello();
    printf("5 + 3 = %d\n", lib_add(5, 3));
    printf("5 * 3 = %d\n", lib_multiply(5, 3));
    return 0;
}
```

```bash
# Créer bibliothèque statique
gcc -c mylib.c -o mylib.o
ar rcs libmylib.a mylib.o

# Vérifier contenu
ar -t libmylib.a
nm libmylib.a

# Compiler et lier
gcc main.c -L. -lmylib -o main_static

# Vérifier que le code est dans le binaire
nm main_static | grep lib_
# T lib_hello
# T lib_add
# T lib_multiply

# Taille
size main_static
```

## Exercice 4 : Bibliothèque dynamique

```bash
# Créer bibliothèque partagée
gcc -fPIC -c mylib.c -o mylib.o
gcc -shared mylib.o -o libmylib.so   # Linux
# ou
gcc -shared mylib.o -o libmylib.dylib # macOS

# Compiler avec lib dynamique
gcc main.c -L. -lmylib -o main_dynamic

# Configurer path (Linux)
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
# ou (macOS)
export DYLD_LIBRARY_PATH=.:$DYLD_LIBRARY_PATH

# Exécuter
./main_dynamic

# Vérifier dépendances
ldd main_dynamic              # Linux
otool -L main_dynamic         # macOS

# Résultat macOS:
# main_dynamic:
#   libmylib.dylib (compatibility version 0.0.0)
#   /usr/lib/libSystem.B.dylib

# Comparer tailles
ls -lh main_static main_dynamic
# main_static:  ~20 KB
# main_dynamic: ~8 KB
```

## Exercice 5 : Analyse de symboles

```c
// symbols.c
#include <stdio.h>

// Symbole global
int global_var = 42;

// Symbole static (local au fichier)
static int static_var = 100;

// Fonction globale
void global_function(void) {
    printf("Global function\n");
}

// Fonction static
static void static_function(void) {
    printf("Static function\n");
}

// Fonction externe (définie ailleurs)
extern void external_function(void);

int main(void) {
    global_function();
    static_function();
    return 0;
}
```

```bash
# Compiler sans strip
gcc symbols.c -o symbols

# Lister tous les symboles
nm symbols

# Filtrer par type
nm symbols | grep ' T '   # Fonctions text
nm symbols | grep ' D '   # Data initialisée
nm symbols | grep ' B '   # BSS
nm symbols | grep ' U '   # Undefined

# Version lisible
nm -C symbols             # Demangle C++ names
nm -n symbols             # Trier par adresse
nm -S symbols             # Afficher taille

# Compiler avec strip
gcc -s symbols.c -o symbols_stripped
nm symbols_stripped
# nm: no symbols

# Strip manuel
cp symbols symbols_copy
strip symbols_copy
nm symbols_copy

# Garder seulement symboles dynamiques
strip --strip-debug symbols_copy
nm symbols_copy

# Linux: analyse détaillée
readelf -s symbols        # Tous les symboles
readelf -s --wide symbols # Format large

# macOS: analyse détaillée
nm -m symbols             # Plus d'infos
otool -I symbols          # Symboles indirects
```

## Exercice 6 : Protections de sécurité

```c
// vuln.c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnérable!
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
```

```bash
# Version sécurisée (toutes protections)
gcc -Wall -Wextra \
    -fstack-protector-all \
    -D_FORTIFY_SOURCE=2 \
    -fPIE -pie \
    -Wl,-z,relro,-z,now \
    vuln.c -o vuln_secure

# Version vulnérable (aucune protection)
gcc -fno-stack-protector \
    -z execstack \
    -no-pie \
    -D_FORTIFY_SOURCE=0 \
    vuln.c -o vuln_insecure

# Vérifier protections (nécessite checksec)
checksec --file=vuln_secure
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

checksec --file=vuln_insecure
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE

# Test exploitation
./vuln_insecure $(python3 -c 'print("A"*100)')
# Devrait crasher

./vuln_secure $(python3 -c 'print("A"*100)')
# *** stack smashing detected ***

# Comparer assembleur
objdump -d vuln_secure > secure.asm
objdump -d vuln_insecure > insecure.asm
diff secure.asm insecure.asm
# Identifier stack canary checks
```

## Exercice 7 : Analyse de format binaire

```bash
# Compiler exemple
gcc example.c -o example

# === LINUX ===

# Header ELF
readelf -h example
# Magic:   7f 45 4c 46 02 01 01 00
# Class:   ELF64
# Entry point address: 0x1050

# Sections
readelf -S example
#   [Nr] Name         Type     Address          Offset    Size
#   [13] .text        PROGBITS 0000000000001050  00001050  000001a5
#   [14] .rodata      PROGBITS 0000000000002000  00002000  00000018
#   [24] .data        PROGBITS 0000000000004000  00003000  00000010
#   [25] .bss         NOBITS   0000000000004010  00003010  00000008

# Program headers (segments)
readelf -l example

# Dumper section .text
objdump -s -j .text example

# Dumper section .rodata
objdump -s -j .rodata example

# === macOS ===

# Header Mach-O
otool -h example
# magic      cputype cpusubtype  filetype
# 0xfeedfacf 16777223 3           2

# Load commands
otool -l example

# Segments
otool -l example | grep -A5 "segname __TEXT"
otool -l example | grep -A5 "segname __DATA"

# Désassembler
otool -tV example

# Strings
strings example

# === UNIVERSEL ===

# Type de fichier
file example
# example: ELF 64-bit LSB executable, x86-64

# Taille des sections
size example
#    text    data     bss     dec
#    1545     600      16    2161

# Hexdump
hexdump -C example | head -20

# Point d'entrée
objdump -f example
```

## Exercice 8 : Injection de bibliothèque

```c
// evil.c - Hook de printf
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

// Type de la vraie fonction printf
typedef int (*real_printf_t)(const char*, ...);

// Notre hook
int printf(const char *format, ...) {
    // Obtenir la vraie fonction
    real_printf_t real_printf = (real_printf_t)dlsym(RTLD_NEXT, "printf");
    
    // Message de notre hook
    real_printf("[HOOKED] ");
    
    // Appeler la vraie fonction
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    
    return ret;
}
```

```bash
# Compiler bibliothèque malveillante (Linux)
gcc -fPIC -shared evil.c -o evil.so -ldl

# Compiler bibliothèque malveillante (macOS)
gcc -fPIC -shared evil.c -o evil.dylib

# Test sur programme simple
echo 'int main() { printf("Hello\n"); return 0; }' > test.c
gcc test.c -o test

# Injection (Linux)
LD_PRELOAD=./evil.so ./test
# [HOOKED] Hello

# Injection (macOS) - peut nécessiter désactiver SIP
DYLD_INSERT_LIBRARIES=./evil.dylib ./test

# Test sur commande système (Linux)
LD_PRELOAD=./evil.so /bin/ls
# Tous les printf de ls seront hookés!

# Hook plus sophistiqué
cat > advanced_hook.c << 'HOOKEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

typedef int (*real_printf_t)(const char*, ...);

int printf(const char *format, ...) {
    real_printf_t real_printf = (real_printf_t)dlsym(RTLD_NEXT, "printf");
    
    // Logger tous les appels
    FILE *log = fopen("/tmp/printf.log", "a");
    if (log) {
        fprintf(log, "printf called: %s\n", format);
        fclose(log);
    }
    
    // Filtrer certains patterns
    if (strstr(format, "password") != NULL) {
        return real_printf("[CENSORED]\n");
    }
    
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    
    return ret;
}
HOOKEOF

gcc -fPIC -shared advanced_hook.c -o advanced_hook.so -ldl
LD_PRELOAD=./advanced_hook.so ./test
cat /tmp/printf.log
```

## BONUS : Script d'analyse automatique

```bash
#!/bin/bash
# analyze_binary.sh

BINARY=$1

if [ -z "$BINARY" ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

echo "=== ANALYSE DE $BINARY ==="

echo -e "\n[*] Type de fichier:"
file $BINARY

echo -e "\n[*] Taille des sections:"
size $BINARY

echo -e "\n[*] Symboles:"
nm $BINARY | head -20

echo -e "\n[*] Dépendances:"
if [[ "$OSTYPE" == "darwin"* ]]; then
    otool -L $BINARY
else
    ldd $BINARY
fi

echo -e "\n[*] Strings intéressantes:"
strings $BINARY | grep -E "(http|ftp|password|key|secret)" | head -10

echo -e "\n[*] Protections:"
if command -v checksec &> /dev/null; then
    checksec --file=$BINARY
else
    echo "checksec non disponible"
fi

echo -e "\n=== FIN DE L'ANALYSE ==="
```

NOTES:
- Toujours vérifier les protections avec checksec
- ldd peut exécuter du code, attention avec les binaires inconnus
- LD_PRELOAD ne fonctionne pas sur les binaires setuid
- Sur macOS, DYLD_* nécessite souvent de désactiver SIP
- Analyser toujours dans un environnement sûr (VM)
