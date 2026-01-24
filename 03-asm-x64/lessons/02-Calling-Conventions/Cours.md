# Module 24 : Conventions d'Appel x64

## Objectifs

À la fin de ce module, tu seras capable de :
- Comprendre les conventions d'appel System V ABI (Linux/macOS)
- Maîtriser la convention Windows x64
- Analyser le passage de paramètres et la gestion de la stack
- Exploiter ces connaissances pour le reverse engineering et l'exploitation

---

## 1. Pourquoi les Conventions d'Appel ?

### Le Problème Fondamental

```
Quand tu appelles une fonction, comment le processeur sait :
- Où sont les arguments ?
- Où mettre la valeur de retour ?
- Quels registres préserver ?
- Comment gérer la stack ?

SANS CONVENTION :
┌─────────────────────────────────────────────────────────────┐
│  Programme A : "Je mets les args dans RAX, RBX, RCX"       │
│  Bibliothèque B : "Moi je les attends dans R8, R9, R10"    │
│  → CRASH ! Incompatibilité totale                          │
└─────────────────────────────────────────────────────────────┘

AVEC CONVENTION :
┌─────────────────────────────────────────────────────────────┐
│  Tout le monde suit les mêmes règles                       │
│  → Code interopérable, bibliothèques compatibles           │
└─────────────────────────────────────────────────────────────┘
```

### Importance pour l'Exploitation

```
POUR LE REVERSE ENGINEERING :
- Identifier les arguments d'une fonction
- Comprendre les valeurs de retour
- Reconstruire les prototypes de fonctions

POUR L'EXPLOITATION :
- Construire des payloads ROP corrects
- Appeler des fonctions système (execve, mprotect)
- Contrôler le flux d'exécution
```

---

## 2. System V AMD64 ABI (Linux/macOS)

### 2.1 Passage des Arguments

```
ARGUMENTS ENTIERS/POINTEURS (dans l'ordre) :
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│   RDI   │   RSI   │   RDX   │   RCX   │   R8    │   R9    │
│  arg 1  │  arg 2  │  arg 3  │  arg 4  │  arg 5  │  arg 6  │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘

ARGUMENTS FLOTTANTS :
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│  XMM0   │  XMM1   │  XMM2   │  XMM3   │  XMM4   │  XMM5   │  XMM6   │  XMM7   │
│ float 1 │ float 2 │ float 3 │ float 4 │ float 5 │ float 6 │ float 7 │ float 8 │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘

ARGUMENTS SUPPLÉMENTAIRES : Sur la stack (de droite à gauche)
```

### 2.2 Exemple Pratique

```c
// Fonction C
int exemple(int a, char *b, long c, int d, int e, int f, int g);

// En assembleur, les arguments sont :
// a → RDI (1er entier)
// b → RSI (2ème, pointeur = entier)
// c → RDX (3ème)
// d → RCX (4ème)
// e → R8  (5ème)
// f → R9  (6ème)
// g → [RSP+8] (7ème, sur la stack)
```

### 2.3 Valeur de Retour

```
RETOUR ENTIER/POINTEUR :
┌─────────┐
│   RAX   │  ← Valeur de retour (jusqu'à 64 bits)
└─────────┘

RETOUR 128 BITS :
┌─────────┬─────────┐
│   RAX   │   RDX   │  ← Partie basse / Partie haute
└─────────┴─────────┘

RETOUR FLOTTANT :
┌─────────┐
│  XMM0   │  ← Valeur flottante
└─────────┘
```

### 2.4 Registres Caller-Saved vs Callee-Saved

```
CALLER-SAVED (l'appelant doit sauvegarder) :
┌─────────────────────────────────────────────────────────┐
│  RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11             │
│  → La fonction appelée peut les écraser                 │
└─────────────────────────────────────────────────────────┘

CALLEE-SAVED (l'appelé doit préserver) :
┌─────────────────────────────────────────────────────────┐
│  RBX, RBP, R12, R13, R14, R15                          │
│  → La fonction doit les restaurer avant de retourner    │
└─────────────────────────────────────────────────────────┘

TOUJOURS PRÉSERVÉS :
┌─────────────────────────────────────────────────────────┐
│  RSP (stack pointer) - Doit être aligné sur 16 bytes   │
└─────────────────────────────────────────────────────────┘
```

### 2.5 Layout de la Stack

```
AVANT L'APPEL (call instruction) :
                    ┌──────────────────┐
         RSP+16 →   │   arg 8 (si >6)  │
                    ├──────────────────┤
         RSP+8  →   │   arg 7          │
                    ├──────────────────┤
         RSP    →   │   (alignement)   │
                    └──────────────────┘

APRÈS L'APPEL (dans la fonction) :
                    ┌──────────────────┐
         RSP+24 →   │   arg 8          │
                    ├──────────────────┤
         RSP+16 →   │   arg 7          │
                    ├──────────────────┤
         RSP+8  →   │   return address │  ← Poussée par CALL
                    ├──────────────────┤
         RSP    →   │   saved RBP      │  ← Si prologue standard
                    └──────────────────┘
```

---

## 3. Convention Windows x64

### 3.1 Passage des Arguments

```
ARGUMENTS ENTIERS/POINTEURS :
┌─────────┬─────────┬─────────┬─────────┐
│   RCX   │   RDX   │   R8    │   R9    │
│  arg 1  │  arg 2  │  arg 3  │  arg 4  │
└─────────┴─────────┴─────────┴─────────┘

ARGUMENTS FLOTTANTS (mêmes positions) :
┌─────────┬─────────┬─────────┬─────────┐
│  XMM0   │  XMM1   │  XMM2   │  XMM3   │
│ float 1 │ float 2 │ float 3 │ float 4 │
└─────────┴─────────┴─────────┴─────────┘

IMPORTANT : Seulement 4 registres, le reste sur la stack !
```

### 3.2 Shadow Space (Spécifique Windows)

```
SHADOW SPACE : 32 bytes réservés sur la stack

┌──────────────────────────────────────────────────────────┐
│  L'appelant DOIT réserver 32 bytes même si <4 arguments  │
│  La fonction appelée peut y sauvegarder RCX, RDX, R8, R9 │
└──────────────────────────────────────────────────────────┘

LAYOUT STACK WINDOWS :
                    ┌──────────────────┐
         RSP+48 →   │   arg 6          │
                    ├──────────────────┤
         RSP+40 →   │   arg 5          │
                    ├──────────────────┤
         RSP+32 →   │   shadow (R9)    │  ┐
                    ├──────────────────┤  │
         RSP+24 →   │   shadow (R8)    │  │ Shadow
                    ├──────────────────┤  │ Space
         RSP+16 →   │   shadow (RDX)   │  │ 32 bytes
                    ├──────────────────┤  │
         RSP+8  →   │   shadow (RCX)   │  ┘
                    ├──────────────────┤
         RSP    →   │   return address │
                    └──────────────────┘
```

### 3.3 Comparaison Linux vs Windows

```
┌────────────────┬─────────────────┬─────────────────┐
│                │   System V      │   Windows x64   │
├────────────────┼─────────────────┼─────────────────┤
│ Arg 1          │      RDI        │      RCX        │
│ Arg 2          │      RSI        │      RDX        │
│ Arg 3          │      RDX        │      R8         │
│ Arg 4          │      RCX        │      R9         │
│ Arg 5          │      R8         │      Stack      │
│ Arg 6          │      R9         │      Stack      │
│ Arg 7+         │      Stack      │      Stack      │
├────────────────┼─────────────────┼─────────────────┤
│ Shadow Space   │      Non        │   Oui (32 B)    │
│ Registres args │      6          │      4          │
│ Retour         │      RAX        │      RAX        │
└────────────────┴─────────────────┴─────────────────┘
```

---

## 4. Appels Système (Syscalls)

### 4.1 Linux Syscalls

```
NUMÉRO DE SYSCALL : RAX

ARGUMENTS :
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│   RDI   │   RSI   │   RDX   │   R10   │   R8    │   R9    │
│  arg 1  │  arg 2  │  arg 3  │  arg 4  │  arg 5  │  arg 6  │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘

⚠️ ATTENTION : R10 au lieu de RCX (RCX utilisé par syscall)

INSTRUCTION : syscall
RETOUR : RAX (valeur de retour ou -errno)
```

### 4.2 Exemple : execve("/bin/sh", NULL, NULL)

```asm
; Linux x64 - execve syscall (numéro 59)
section .data
    binsh db "/bin/sh", 0

section .text
global _start
_start:
    ; execve("/bin/sh", NULL, NULL)
    xor rax, rax
    mov al, 59          ; syscall number (execve)

    lea rdi, [rel binsh] ; arg1: pathname
    xor rsi, rsi         ; arg2: argv = NULL
    xor rdx, rdx         ; arg3: envp = NULL

    syscall              ; Appel système
```

### 4.3 Windows Syscalls

```
NUMÉRO DE SYSCALL : RAX (varie selon version Windows!)

ARGUMENTS : Comme convention normale (RCX, RDX, R8, R9, stack)

INSTRUCTION : syscall

⚠️ Les numéros de syscall changent entre versions Windows !
   → Préférer utiliser les API documentées (ntdll.dll)
```

---

## 5. Applications Offensives

### 5.1 Construction de Shellcode

```c
// Pour appeler execve dans un shellcode Linux :
// On doit placer les arguments dans les bons registres

/*
Shellcode execve("/bin/sh", NULL, NULL) :

    xor rsi, rsi         ; RSI = 0 (argv)
    push rsi             ; NULL terminator sur stack
    mov rdi, 0x68732f2f6e69622f  ; "/bin//sh" en little-endian
    push rdi
    mov rdi, rsp         ; RDI = pointeur vers "/bin//sh"
    xor rdx, rdx         ; RDX = 0 (envp)
    mov al, 59           ; RAX = 59 (execve)
    syscall
*/

unsigned char shellcode[] =
    "\x48\x31\xf6"                         // xor rsi, rsi
    "\x56"                                 // push rsi
    "\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"  // mov rdi, "/bin//sh"
    "\x57"                                 // push rdi
    "\x48\x89\xe7"                         // mov rdi, rsp
    "\x48\x31\xd2"                         // xor rdx, rdx
    "\xb0\x3b"                             // mov al, 59
    "\x0f\x05";                            // syscall
```

### 5.2 ROP Chain avec Appels de Fonction

```c
// Pour appeler mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC)
// On doit contrôler RDI, RSI, RDX avant le call

/*
ROP Chain Linux :
1. pop rdi; ret      → Charger adresse dans RDI
2. pop rsi; ret      → Charger taille dans RSI
3. pop rdx; ret      → Charger permissions dans RDX
4. call mprotect     → Appeler la fonction
*/

// Gadgets nécessaires :
// gadget1: pop rdi; ret
// gadget2: pop rsi; ret
// gadget3: pop rdx; ret

void *rop_chain[] = {
    gadget_pop_rdi,
    (void*)target_address,    // → RDI
    gadget_pop_rsi,
    (void*)0x1000,            // → RSI (taille)
    gadget_pop_rdx,
    (void*)7,                 // → RDX (RWX)
    mprotect_addr,
    shellcode_addr            // Retour vers shellcode
};
```

### 5.3 Identifier les Arguments en Reverse Engineering

```c
// En analysant un binaire, on peut reconstruire les prototypes

/*
Disassembly :
    mov edi, 2          ; arg1 = 2 (AF_INET)
    mov esi, 1          ; arg2 = 1 (SOCK_STREAM)
    xor edx, edx        ; arg3 = 0
    call socket

→ Prototype : socket(2, 1, 0)
→ Donc : socket(AF_INET, SOCK_STREAM, 0)
*/

// Pattern de reconnaissance :
// mov edi/rdi, X → Premier argument
// mov esi/rsi, X → Deuxième argument
// mov edx/rdx, X → Troisième argument
// call FONCTION  → Appel avec ces arguments
```

### 5.4 Appeler des Fonctions Windows depuis Shellcode

```c
// Windows x64 : Appeler WinExec("calc.exe", 0)
// Arguments : RCX = "calc.exe", RDX = 0

/*
    sub rsp, 40          ; Shadow space + alignement

    lea rcx, [rel cmd]   ; RCX = "calc.exe"
    xor rdx, rdx         ; RDX = 0 (SW_HIDE)

    mov rax, [WinExec]   ; Adresse de WinExec
    call rax

    add rsp, 40
    ret

cmd: db "calc.exe", 0
*/
```

---

## 6. Prologue et Épilogue de Fonction

### 6.1 Prologue Standard

```asm
; Prologue typique
fonction:
    push rbp            ; Sauvegarder ancien frame pointer
    mov rbp, rsp        ; Nouveau frame pointer
    sub rsp, 32         ; Allouer espace local (+ alignement)

    ; Sauvegarder registres callee-saved si utilisés
    push rbx
    push r12
    ; ...
```

### 6.2 Épilogue Standard

```asm
    ; Restaurer registres callee-saved
    pop r12
    pop rbx

    ; Épilogue
    mov rsp, rbp        ; ou: leave
    pop rbp
    ret
```

### 6.3 Fonction Leaf (sans appels)

```asm
; Fonction simple sans sous-appels
; Pas besoin de frame pointer
leaf_function:
    ; Utilise directement RSP
    mov rax, rdi        ; Travail avec arguments
    add rax, rsi
    ret                 ; Retour direct
```

---

## 7. Checklist

- [ ] Connaître les 6 registres d'arguments System V (RDI, RSI, RDX, RCX, R8, R9)
- [ ] Connaître les 4 registres d'arguments Windows (RCX, RDX, R8, R9)
- [ ] Comprendre le shadow space Windows (32 bytes)
- [ ] Savoir que R10 remplace RCX pour les syscalls Linux
- [ ] Identifier caller-saved vs callee-saved
- [ ] Construire des appels de fonction corrects en shellcode

---

## Exercices

Voir [exercice.md](exercice.md)

---

**Prochaine étape :** [Module 25 : Shellcode x64](../25_shellcode_basics/)
