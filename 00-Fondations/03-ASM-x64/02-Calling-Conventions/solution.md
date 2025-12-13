# Solutions - Conventions d'Appel

## Exercice 1 : Découverte (Très facile)

### Objectif
Observer comment les arguments sont passés aux fonctions en x64.

### Solution

```c
/*
 * Exercice 1 : Observer les conventions d'appel
 * Compiler avec : gcc -O0 solution1.c -o solution1
 */
#include <stdio.h>

// Fonction avec plusieurs arguments
// System V (Linux) : RDI, RSI, RDX, RCX, R8, R9, puis stack
int add_numbers(int a, int b, int c, int d, int e, int f) {
    printf("[*] Fonction appelée avec:\n");
    printf("    a (RDI) = %d\n", a);
    printf("    b (RSI) = %d\n", b);
    printf("    c (RDX) = %d\n", c);
    printf("    d (RCX) = %d\n", d);
    printf("    e (R8)  = %d\n", e);
    printf("    f (R9)  = %d\n", f);

    return a + b + c + d + e + f;
}

int main() {
    printf("[*] Exercice 1 : Conventions d'appel x64\n");
    printf("==========================================\n\n");

    // Appeler la fonction avec 6 arguments
    int result = add_numbers(10, 20, 30, 40, 50, 60);

    printf("\n[+] Résultat: %d\n", result);

    // Observer avec GDB :
    // $ gdb ./solution1
    // (gdb) break add_numbers
    // (gdb) run
    // (gdb) info registers rdi rsi rdx rcx r8 r9
    //
    // Vous verrez :
    // rdi = 10 (0xa)
    // rsi = 20 (0x14)
    // rdx = 30 (0x1e)
    // rcx = 40 (0x28)
    // r8  = 50 (0x32)
    // r9  = 60 (0x3c)

    printf("\n[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Compilation et Débogage

```bash
# Compiler sans optimisations pour faciliter le debug
gcc -O0 -g solution1.c -o solution1

# Désassembler pour voir l'assembleur
objdump -d solution1 | grep -A 30 "<add_numbers>:"

# Déboguer avec GDB
gdb ./solution1
(gdb) break add_numbers
(gdb) run
(gdb) info registers rdi rsi rdx rcx r8 r9
```

### Résultat attendu
```
[*] Exercice 1 : Conventions d'appel x64
==========================================

[*] Fonction appelée avec:
    a (RDI) = 10
    b (RSI) = 20
    c (RDX) = 30
    d (RCX) = 40
    e (R8)  = 50
    f (R9)  = 60

[+] Résultat: 210

[+] Exercice terminé avec succès
```

### Explication

Sur Linux x64 (System V ABI), les 6 premiers arguments entiers sont passés dans l'ordre :
1. `RDI` - Premier argument
2. `RSI` - Deuxième argument
3. `RDX` - Troisième argument
4. `RCX` - Quatrième argument
5. `R8` - Cinquième argument
6. `R9` - Sixième argument
7. Arguments suivants : sur la stack

---

## Exercice 2 : Modification (Facile)

### Objectif
Créer une fonction avec plus de 6 arguments pour voir l'utilisation de la stack.

### Solution

```c
/*
 * Exercice 2 : Arguments sur la stack
 * Plus de 6 arguments = utilisation de la stack
 */
#include <stdio.h>

// Fonction avec 10 arguments (6 registres + 4 sur stack)
long calculate(int arg1, int arg2, int arg3, int arg4,
               int arg5, int arg6, int arg7, int arg8,
               int arg9, int arg10) {

    printf("[*] Arguments dans les registres:\n");
    printf("    arg1 (RDI) = %d\n", arg1);
    printf("    arg2 (RSI) = %d\n", arg2);
    printf("    arg3 (RDX) = %d\n", arg3);
    printf("    arg4 (RCX) = %d\n", arg4);
    printf("    arg5 (R8)  = %d\n", arg5);
    printf("    arg6 (R9)  = %d\n", arg6);

    printf("\n[*] Arguments sur la stack:\n");
    printf("    arg7  (RSP+8)  = %d\n", arg7);
    printf("    arg8  (RSP+16) = %d\n", arg8);
    printf("    arg9  (RSP+24) = %d\n", arg9);
    printf("    arg10 (RSP+32) = %d\n", arg10);

    return arg1 + arg2 + arg3 + arg4 + arg5 +
           arg6 + arg7 + arg8 + arg9 + arg10;
}

// Fonction pour examiner la stack
void examine_stack(void) {
    // Obtenir RSP
    unsigned long rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));

    printf("\n[*] Valeur de RSP: 0x%lx\n", rsp);
    printf("[*] Alignement: %s\n",
           (rsp % 16 == 0) ? "OK (16 bytes)" : "INCORRECT");
}

int main() {
    printf("[*] Exercice 2 : Arguments sur la stack\n");
    printf("==========================================\n\n");

    examine_stack();

    // Appel avec 10 arguments
    long result = calculate(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    printf("\n[+] Résultat total: %ld\n", result);

    // Désassembler pour voir :
    // mov edi, 1     ; arg1 → RDI
    // mov esi, 2     ; arg2 → RSI
    // mov edx, 3     ; arg3 → RDX
    // mov ecx, 4     ; arg4 → RCX
    // mov r8d, 5     ; arg5 → R8
    // mov r9d, 6     ; arg6 → R9
    // push 10        ; arg10 → stack
    // push 9         ; arg9  → stack
    // push 8         ; arg8  → stack
    // push 7         ; arg7  → stack
    // call calculate

    printf("[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Visualisation de la Stack

```
AVANT l'appel à calculate():
                    ┌──────────────────┐
         RSP+40 →   │   arg10 (10)     │
                    ├──────────────────┤
         RSP+32 →   │   arg9  (9)      │
                    ├──────────────────┤
         RSP+24 →   │   arg8  (8)      │
                    ├──────────────────┤
         RSP+16 →   │   arg7  (7)      │
                    ├──────────────────┤
         RSP+8  →   │   (alignement)   │
                    ├──────────────────┤
         RSP    →   │                  │
                    └──────────────────┘

APRÈS l'instruction CALL:
                    ┌──────────────────┐
         RSP+48 →   │   arg10 (10)     │
                    ├──────────────────┤
         RSP+40 →   │   arg9  (9)      │
                    ├──────────────────┤
         RSP+32 →   │   arg8  (8)      │
                    ├──────────────────┤
         RSP+24 →   │   arg7  (7)      │
                    ├──────────────────┤
         RSP+16 →   │   (alignement)   │
                    ├──────────────────┤
         RSP+8  →   │   return addr    │  ← Ajouté par CALL
                    ├──────────────────┤
         RSP    →   │                  │
                    └──────────────────┘
```

### Résultat attendu
```
[*] Exercice 2 : Arguments sur la stack
==========================================

[*] Valeur de RSP: 0x7fffffffe3a0
[*] Alignement: OK (16 bytes)

[*] Arguments dans les registres:
    arg1 (RDI) = 1
    arg2 (RSI) = 2
    arg3 (RDX) = 3
    arg4 (RCX) = 4
    arg5 (R8)  = 5
    arg6 (R9)  = 6

[*] Arguments sur la stack:
    arg7  (RSP+8)  = 7
    arg8  (RSP+16) = 8
    arg9  (RSP+24) = 9
    arg10 (RSP+32) = 10

[+] Résultat total: 55
[+] Exercice terminé avec succès
```

---

## Exercice 3 : Création (Moyen)

### Objectif
Écrire un shellcode qui appelle execve("/bin/sh", NULL, NULL) avec les bons registres.

### Solution

```c
/*
 * Exercice 3 : Shellcode execve avec conventions d'appel
 * Linux x64 syscall : RAX=59, RDI=pathname, RSI=argv, RDX=envp
 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// Shellcode execve("/bin/sh", NULL, NULL)
// Taille: 27 bytes
unsigned char shellcode[] =
    // xor rsi, rsi          ; RSI = 0 (argv = NULL)
    "\x48\x31\xf6"

    // push rsi              ; Mettre NULL sur la stack
    "\x56"

    // movabs rdi, 0x68732f2f6e69622f  ; "/bin//sh" en little-endian
    "\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"

    // push rdi              ; Mettre "/bin//sh" sur la stack
    "\x57"

    // mov rdi, rsp          ; RDI = pointeur vers "/bin//sh"
    "\x48\x89\xe7"

    // xor rdx, rdx          ; RDX = 0 (envp = NULL)
    "\x48\x31\xd2"

    // mov al, 59            ; RAX = 59 (numéro syscall execve)
    "\xb0\x3b"

    // syscall               ; Appel système
    "\x0f\x05";

// Fonction pour rendre la mémoire exécutable et exécuter le shellcode
void execute_shellcode(unsigned char *code, size_t size) {
    printf("[*] Taille du shellcode: %zu bytes\n", size);
    printf("[*] Hexdump:\n");

    // Afficher le shellcode
    for (size_t i = 0; i < size; i++) {
        printf("\\x%02x", code[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n\n");

    // Allouer mémoire exécutable
    void *exec_mem = mmap(NULL, size,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return;
    }

    printf("[*] Mémoire exécutable allouée à: %p\n", exec_mem);

    // Copier le shellcode
    memcpy(exec_mem, code, size);

    printf("[*] Shellcode copié\n");
    printf("[!] Exécution du shellcode...\n\n");

    // Exécuter !
    ((void(*)())exec_mem)();

    // Ne devrait jamais arriver ici (execve remplace le processus)
    munmap(exec_mem, size);
}

// Fonction pour analyser le shellcode
void analyze_shellcode(void) {
    printf("[*] ANALYSE DU SHELLCODE\n");
    printf("==========================================\n\n");

    printf("Convention d'appel pour syscall Linux x64:\n");
    printf("  RAX = Numéro du syscall (59 pour execve)\n");
    printf("  RDI = 1er argument (pathname)\n");
    printf("  RSI = 2ème argument (argv)\n");
    printf("  RDX = 3ème argument (envp)\n");
    printf("  R10 = 4ème argument (si nécessaire)\n");
    printf("  R8  = 5ème argument (si nécessaire)\n");
    printf("  R9  = 6ème argument (si nécessaire)\n\n");

    printf("Notre shellcode fait:\n");
    printf("  1. xor rsi, rsi          → RSI = 0 (argv = NULL)\n");
    printf("  2. push rsi              → NULL terminator\n");
    printf("  3. mov rdi, '/bin//sh'   → Chaîne sur registre\n");
    printf("  4. push rdi              → Chaîne sur stack\n");
    printf("  5. mov rdi, rsp          → RDI = pointeur vers chaîne\n");
    printf("  6. xor rdx, rdx          → RDX = 0 (envp = NULL)\n");
    printf("  7. mov al, 59            → RAX = 59 (execve)\n");
    printf("  8. syscall               → Appel système\n\n");
}

int main() {
    printf("[*] Exercice 3 : Shellcode execve\n");
    printf("==========================================\n\n");

    // Analyser d'abord
    analyze_shellcode();

    printf("[!] ATTENTION: Ce shellcode va lancer /bin/sh\n");
    printf("[!] Le processus actuel sera remplacé\n");
    printf("[!] Appuyez sur Entrée pour continuer...\n");
    getchar();

    // Exécuter
    execute_shellcode(shellcode, sizeof(shellcode) - 1);

    return 0;
}
```

### Explication Détaillée

#### Pourquoi ces registres ?

```
SYSCALL LINUX x64 :
- Différent de la convention d'appel normale !
- Utilise R10 au lieu de RCX (car RCX est écrasé par syscall)

execve(const char *pathname, char *const argv[], char *const envp[])
         ↓ RDI              ↓ RSI                 ↓ RDX

RAX = 59 (numéro syscall)
RDI = "/bin/sh" (pathname)
RSI = NULL (argv)
RDX = NULL (envp)
```

#### Astuce du double slash

```c
"/bin//sh" au lieu de "/bin/sh"
Pourquoi ? Pour avoir exactement 8 bytes (64 bits)
Peut être chargé en une seule instruction movabs

Le noyau traite "//" comme "/" donc aucun problème
```

### Compilation
```bash
gcc solution3.c -o solution3 -z execstack
./solution3
```

### Résultat attendu
```
[*] Exercice 3 : Shellcode execve
==========================================

[*] ANALYSE DU SHELLCODE
==========================================

Convention d'appel pour syscall Linux x64:
  RAX = Numéro du syscall (59 pour execve)
  RDI = 1er argument (pathname)
  RSI = 2ème argument (argv)
  RDX = 3ème argument (envp)
  R10 = 4ème argument (si nécessaire)
  R8  = 5ème argument (si nécessaire)
  R9  = 6ème argument (si nécessaire)

Notre shellcode fait:
  1. xor rsi, rsi          → RSI = 0 (argv = NULL)
  2. push rsi              → NULL terminator
  3. mov rdi, '/bin//sh'   → Chaîne sur registre
  4. push rdi              → Chaîne sur stack
  5. mov rdi, rsp          → RDI = pointeur vers chaîne
  6. xor rdx, rdx          → RDX = 0 (envp = NULL)
  7. mov al, 59            → RAX = 59 (execve)
  8. syscall               → Appel système

[!] ATTENTION: Ce shellcode va lancer /bin/sh
[!] Le processus actuel sera remplacé
[!] Appuyez sur Entrée pour continuer...

[*] Taille du shellcode: 27 bytes
[*] Hexdump:
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48
\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05

[*] Mémoire exécutable allouée à: 0x7f1234560000
[*] Shellcode copié
[!] Exécution du shellcode...

$ whoami
user
$ exit
```

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Construire une chaîne ROP pour appeler mprotect() et rendre une région exécutable, puis y sauter.

### Solution

```c
/*
 * Exercice 4 : ROP Chain pour appeler mprotect()
 * mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC)
 * Arguments: RDI=addr, RSI=len, RDX=prot
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>

// Shellcode simple qui affiche un message
unsigned char shellcode[] =
    // write(1, "PWNED!\n", 7)
    "\x48\xc7\xc0\x01\x00\x00\x00"     // mov rax, 1 (sys_write)
    "\x48\xc7\xc7\x01\x00\x00\x00"     // mov rdi, 1 (stdout)
    "\x48\x8d\x35\x0a\x00\x00\x00"     // lea rsi, [rip+10] (message)
    "\x48\xc7\xc2\x07\x00\x00\x00"     // mov rdx, 7 (length)
    "\x0f\x05"                         // syscall
    "\xc3"                             // ret
    "PWNED!\n";

// Gadgets ROP (dans un vrai exploit, on les trouve avec ropper/ROPgadget)
// Pour cet exemple, on simule avec des fonctions
void gadget_pop_rdi(void) {
    __asm__("pop %rdi; ret");
}

void gadget_pop_rsi(void) {
    __asm__("pop %rsi; ret");
}

void gadget_pop_rdx(void) {
    __asm__("pop %rdx; ret");
}

// Simulation d'une ROP chain
typedef struct {
    void *gadgets[100];
    int count;
} ROPChain;

void rop_init(ROPChain *rop) {
    rop->count = 0;
}

void rop_add(ROPChain *rop, void *gadget) {
    rop->gadgets[rop->count++] = gadget;
}

void demonstrate_rop(void) {
    printf("[*] DÉMONSTRATION ROP CHAIN\n");
    printf("==========================================\n\n");

    // Allouer une région non-exécutable
    void *buffer = mmap(NULL, 0x1000,
                        PROT_READ | PROT_WRITE,  // Pas PROT_EXEC !
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (buffer == MAP_FAILED) {
        perror("mmap");
        return;
    }

    printf("[+] Région allouée (RW-): %p\n", buffer);

    // Copier le shellcode dans la région non-exécutable
    memcpy(buffer, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copié dans la région\n");

    // Construire la ROP chain pour appeler mprotect
    printf("\n[*] Construction de la ROP chain:\n");

    ROPChain rop;
    rop_init(&rop);

    // Objectif: mprotect(buffer, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
    printf("    Gadget 1: pop rdi; ret\n");
    printf("    Valeur:   %p (adresse buffer)\n", buffer);

    printf("    Gadget 2: pop rsi; ret\n");
    printf("    Valeur:   0x1000 (taille)\n");

    printf("    Gadget 3: pop rdx; ret\n");
    printf("    Valeur:   0x7 (PROT_READ|PROT_WRITE|PROT_EXEC)\n");

    printf("    Fonction: mprotect()\n");
    printf("    Retour:   adresse du shellcode\n");

    // Appeler directement mprotect (simulation du ROP)
    printf("\n[*] Exécution de mprotect()...\n");
    int result = mprotect(buffer, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    if (result == -1) {
        perror("mprotect");
        munmap(buffer, 0x1000);
        return;
    }

    printf("[+] mprotect() réussi, région maintenant RWX\n");

    // Exécuter le shellcode
    printf("[*] Exécution du shellcode...\n\n");
    ((void(*)())buffer)();

    printf("\n[+] Shellcode exécuté avec succès!\n");

    // Nettoyer
    munmap(buffer, 0x1000);
}

// Fonction pour afficher une vraie ROP chain
void show_rop_chain_example(void) {
    printf("\n[*] EXEMPLE DE ROP CHAIN RÉELLE\n");
    printf("==========================================\n\n");

    printf("Structure de la stack après buffer overflow:\n\n");

    printf("RSP →  ┌────────────────────────────┐\n");
    printf("       │  gadget: pop rdi; ret      │  ← Retour initial\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  0x7fffffffe000 (buffer)   │  ← Argument RDI\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  gadget: pop rsi; ret      │\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  0x1000 (size)             │  ← Argument RSI\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  gadget: pop rdx; ret      │\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  0x7 (RWX)                 │  ← Argument RDX\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  mprotect@plt              │  ← Appel fonction\n");
    printf("       ├────────────────────────────┤\n");
    printf("       │  0x7fffffffe000 (buffer)   │  ← Jump vers shellcode\n");
    printf("       └────────────────────────────┘\n\n");

    printf("Déroulement:\n");
    printf("  1. RET → pop rdi; ret\n");
    printf("     RDI = 0x7fffffffe000\n\n");

    printf("  2. RET → pop rsi; ret\n");
    printf("     RSI = 0x1000\n\n");

    printf("  3. RET → pop rdx; ret\n");
    printf("     RDX = 0x7\n\n");

    printf("  4. RET → mprotect()\n");
    printf("     Appel: mprotect(0x7fffffffe000, 0x1000, 7)\n\n");

    printf("  5. RET → 0x7fffffffe000\n");
    printf("     Exécution du shellcode!\n\n");
}

int main() {
    printf("[*] Exercice 4 : ROP Chain pour mprotect\n");
    printf("==========================================\n\n");

    // Afficher l'exemple théorique
    show_rop_chain_example();

    // Démonstration pratique
    demonstrate_rop();

    printf("\n[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Explication de la ROP Chain

#### Qu'est-ce qu'une ROP Chain ?

```
ROP = Return-Oriented Programming

Principe:
1. On n'a PAS le droit d'exécuter du code arbitraire (DEP/NX)
2. On réutilise des bouts de code existants (gadgets)
3. Chaque gadget se termine par RET
4. On contrôle la stack → on contrôle l'ordre d'exécution
```

#### Pourquoi mprotect ?

```
mprotect() permet de changer les permissions d'une région mémoire

mprotect(void *addr, size_t len, int prot)
         ↓ RDI         ↓ RSI       ↓ RDX

Si on rend une région RWX, on peut y exécuter du shellcode !
```

#### Trouver les gadgets

```bash
# Avec ropper
ropper --file /lib/x86_64-linux-gnu/libc.so.6 --search "pop rdi"

# Avec ROPgadget
ROPgadget --binary /bin/ls --only "pop|ret"

# Avec objdump
objdump -d /bin/ls | grep -B1 "ret"
```

### Compilation et exécution
```bash
gcc -O0 solution4.c -o solution4
./solution4
```

### Résultat attendu
```
[*] Exercice 4 : ROP Chain pour mprotect
==========================================

[*] EXEMPLE DE ROP CHAIN RÉELLE
==========================================

Structure de la stack après buffer overflow:

RSP →  ┌────────────────────────────┐
       │  gadget: pop rdi; ret      │  ← Retour initial
       ├────────────────────────────┤
       │  0x7fffffffe000 (buffer)   │  ← Argument RDI
       ├────────────────────────────┤
       │  gadget: pop rsi; ret      │
       ├────────────────────────────┤
       │  0x1000 (size)             │  ← Argument RSI
       ├────────────────────────────┤
       │  gadget: pop rdx; ret      │
       ├────────────────────────────┤
       │  0x7 (RWX)                 │  ← Argument RDX
       ├────────────────────────────┤
       │  mprotect@plt              │  ← Appel fonction
       ├────────────────────────────┤
       │  0x7fffffffe000 (buffer)   │  ← Jump vers shellcode
       └────────────────────────────┘

Déroulement:
  1. RET → pop rdi; ret
     RDI = 0x7fffffffe000

  2. RET → pop rsi; ret
     RSI = 0x1000

  3. RET → pop rdx; ret
     RDX = 0x7

  4. RET → mprotect()
     Appel: mprotect(0x7fffffffe000, 0x1000, 7)

  5. RET → 0x7fffffffe000
     Exécution du shellcode!

[*] DÉMONSTRATION ROP CHAIN
==========================================

[+] Région allouée (RW-): 0x7f1234560000
[+] Shellcode copié dans la région

[*] Construction de la ROP chain:
    Gadget 1: pop rdi; ret
    Valeur:   0x7f1234560000 (adresse buffer)
    Gadget 2: pop rsi; ret
    Valeur:   0x1000 (taille)
    Gadget 3: pop rdx; ret
    Valeur:   0x7 (PROT_READ|PROT_WRITE|PROT_EXEC)
    Fonction: mprotect()
    Retour:   adresse du shellcode

[*] Exécution de mprotect()...
[+] mprotect() réussi, région maintenant RWX
[*] Exécution du shellcode...

PWNED!

[+] Shellcode exécuté avec succès!

[+] Exercice terminé avec succès
```

---

## Tableau Récapitulatif

### System V (Linux/macOS) vs Windows x64

| Élément | System V AMD64 | Windows x64 |
|---------|----------------|-------------|
| **Arguments entiers** |
| 1er | RDI | RCX |
| 2ème | RSI | RDX |
| 3ème | RDX | R8 |
| 4ème | RCX | R9 |
| 5ème | R8 | Stack |
| 6ème | R9 | Stack |
| **Shadow Space** | Non | Oui (32 bytes) |
| **Retour** | RAX | RAX |
| **Caller-saved** | RAX, RCX, RDX, RSI, RDI, R8-R11 | RAX, RCX, RDX, R8-R11 |
| **Callee-saved** | RBX, RBP, R12-R15 | RBX, RBP, RDI, RSI, R12-R15 |
| **Alignement stack** | 16 bytes | 16 bytes |

### Syscalls Linux x64

| Registre | Utilisation |
|----------|-------------|
| RAX | Numéro du syscall |
| RDI | 1er argument |
| RSI | 2ème argument |
| RDX | 3ème argument |
| R10 | 4ème argument (au lieu de RCX) |
| R8 | 5ème argument |
| R9 | 6ème argument |

---

## Critères de Réussite

Avant de passer au module suivant, tu dois :

- [ ] Connaître les 6 registres d'arguments System V (RDI, RSI, RDX, RCX, R8, R9)
- [ ] Connaître les 4 registres d'arguments Windows (RCX, RDX, R8, R9)
- [ ] Comprendre le shadow space Windows
- [ ] Savoir que R10 remplace RCX pour les syscalls Linux
- [ ] Différencier caller-saved et callee-saved
- [ ] Construire un shellcode respectant les conventions
- [ ] Comprendre le principe d'une ROP chain

---

**Prochaine étape :** Module 25 - Shellcode x64
