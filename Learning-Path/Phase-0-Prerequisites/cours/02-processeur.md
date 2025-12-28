# Cours 02 : Le Processeur (CPU)

## Introduction

Le processeur (CPU - Central Processing Unit) est le "cerveau" de l'ordinateur. C'est lui qui exécute les instructions de vos programmes. Pour vraiment comprendre la programmation bas niveau et la sécurité offensive, vous devez comprendre comment il fonctionne.

---

## Architecture Simplifiée

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PROCESSEUR (CPU)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                        REGISTRES                                   │     │
│   │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ │     │
│   │  │ EAX │ │ EBX │ │ ECX │ │ EDX │ │ ESI │ │ EDI │ │ EBP │ │ ESP │ │     │
│   │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ │     │
│   │                     ┌─────┐ ┌───────────┐                         │     │
│   │                     │ EIP │ │  EFLAGS   │                         │     │
│   │                     └─────┘ └───────────┘                         │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                    │                                        │
│   ┌────────────────────────────────┼────────────────────────────────────┐   │
│   │            UNITÉ DE CONTRÔLE   │        UNITÉ ARITHMÉTIQUE          │   │
│   │          ┌─────────────────┐   │      ┌─────────────────────┐       │   │
│   │          │ Décode les      │   │      │ Effectue les        │       │   │
│   │          │ instructions    │◄──┼──────│ calculs (+, -, *, /) │       │   │
│   │          └─────────────────┘   │      │ et comparaisons     │       │   │
│   │                                │      └─────────────────────┘       │   │
│   └────────────────────────────────┼────────────────────────────────────┘   │
│                                    │                                        │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                               ┌─────┴─────┐
                               │    BUS    │
                               └─────┬─────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
               ┌────┴────┐     ┌─────┴─────┐    ┌─────┴─────┐
               │   RAM   │     │   Disque  │    │   I/O     │
               │(Mémoire)│     │   (SSD)   │    │(Clavier,  │
               └─────────┘     └───────────┘    │ Écran...) │
                                                └───────────┘
```

---

## Les Registres

Les registres sont des petites zones de mémoire **ultra-rapides** situées directement dans le CPU. C'est là que le processeur stocke les données sur lesquelles il travaille.

### Registres x86 (32 bits)

```
┌─────────────────────────────────────────────────────────────────┐
│                    REGISTRES GÉNÉRAUX                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EAX (Extended Accumulator)                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                          EAX (32 bits)                    │  │
│  │                    ┌──────────────────────────────────────┤  │
│  │                    │            AX (16 bits)              │  │
│  │                    │          ┌───────────┬──────────────┤  │
│  │                    │          │ AH (8b)   │  AL (8b)     │  │
│  └────────────────────┴──────────┴───────────┴──────────────┘  │
│                                                                 │
│  Utilisé pour : Résultats d'opérations, valeurs de retour     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EBX (Extended Base) - Souvent utilisé comme pointeur          │
│  ECX (Extended Counter) - Compteur pour les boucles            │
│  EDX (Extended Data) - Extension de EAX pour multiplication    │
│                                                                 │
│  Même structure : EBX → BX → BH/BL, etc.                       │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    REGISTRES D'INDEX                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ESI (Extended Source Index) - Source pour opérations chaîne   │
│  EDI (Extended Destination Index) - Destination                │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    REGISTRES SPÉCIAUX                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EBP (Extended Base Pointer) - Base de la stack frame          │
│  ESP (Extended Stack Pointer) - Sommet de la pile              │
│  EIP (Extended Instruction Pointer) - Adresse instruction      │
│  EFLAGS - Drapeaux d'état (résultats de comparaisons)         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Registres x64 (64 bits)

En mode 64 bits, les registres sont étendus et on en ajoute de nouveaux :

```
┌─────────────────────────────────────────────────────────────────┐
│  RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, RIP                   │
│  (Versions 64 bits des registres 32 bits)                       │
│                                                                 │
│  Nouveaux registres : R8, R9, R10, R11, R12, R13, R14, R15     │
│                                                                 │
│  RAX (64 bits)                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                         RAX                              │   │
│  │                    ┌─────────────────────────────────────┤   │
│  │                    │              EAX (32 bits)          │   │
│  │                    │         ┌───────────────────────────┤   │
│  │                    │         │      AX (16 bits)         │   │
│  │                    │         │      ┌────────┬───────────┤   │
│  │                    │         │      │AH (8b) │ AL (8b)   │   │
│  └────────────────────┴─────────┴──────┴────────┴───────────┘   │
│   63                  31        15      8        0               │
└─────────────────────────────────────────────────────────────────┘
```

### Le registre EFLAGS (Drapeaux)

Ce registre contient des "drapeaux" qui indiquent l'état du processeur après une opération :

```
┌─────────────────────────────────────────────────────────────────┐
│                         EFLAGS                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Bit   Nom    Description                                       │
│  ───────────────────────────────────────────────────────        │
│   0    CF     Carry Flag - Retenue (dépassement non signé)     │
│   2    PF     Parity Flag - Parité du résultat                 │
│   6    ZF     Zero Flag - Résultat = 0                         │
│   7    SF     Sign Flag - Résultat négatif                     │
│  11    OF     Overflow Flag - Dépassement signé                │
│                                                                 │
│  Exemple après "CMP EAX, EBX" (comparaison) :                  │
│  - ZF=1 si EAX == EBX                                          │
│  - SF=1 si EAX < EBX (signé)                                   │
│  - CF=1 si EAX < EBX (non signé)                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Le Cycle d'Exécution

Le processeur exécute les instructions en boucle selon ce cycle :

```
┌─────────────────────────────────────────────────────────────────┐
│                     CYCLE FETCH-DECODE-EXECUTE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                     ┌──────────────────┐                        │
│                     │     1. FETCH     │                        │
│                     │  Lire instruction│                        │
│                     │  à l'adresse EIP │                        │
│                     └────────┬─────────┘                        │
│                              │                                  │
│                              ▼                                  │
│                     ┌──────────────────┐                        │
│                     │    2. DECODE     │                        │
│                     │    Décoder       │                        │
│                     │   l'instruction  │                        │
│                     └────────┬─────────┘                        │
│                              │                                  │
│                              ▼                                  │
│                     ┌──────────────────┐                        │
│                     │    3. EXECUTE    │                        │
│                     │    Exécuter      │                        │
│                     │   l'opération    │                        │
│                     └────────┬─────────┘                        │
│                              │                                  │
│                              ▼                                  │
│                     ┌──────────────────┐                        │
│                     │  4. INCREMENT    │                        │
│                     │    EIP +=        │                        │
│                     │  taille_instr    │                        │
│                     └────────┬─────────┘                        │
│                              │                                  │
│                              └──────────────────────────────┐   │
│                                                             │   │
│                     (Retour à FETCH)   ◄────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Exemple Concret

Imaginons ce programme assembleur simple :

```nasm
; Programme qui calcule 5 + 3
mov eax, 5      ; Mettre 5 dans EAX
mov ebx, 3      ; Mettre 3 dans EBX
add eax, ebx    ; EAX = EAX + EBX
```

Exécution pas à pas :

```
┌─────────────────────────────────────────────────────────────────┐
│ Étape 1 : MOV EAX, 5                                           │
├─────────────────────────────────────────────────────────────────┤
│ Avant :  EAX = ????????   EIP = 0x00401000                     │
│ Après :  EAX = 00000005   EIP = 0x00401005                     │
├─────────────────────────────────────────────────────────────────┤
│ Étape 2 : MOV EBX, 3                                           │
├─────────────────────────────────────────────────────────────────┤
│ Avant :  EBX = ????????   EIP = 0x00401005                     │
│ Après :  EBX = 00000003   EIP = 0x0040100A                     │
├─────────────────────────────────────────────────────────────────┤
│ Étape 3 : ADD EAX, EBX                                         │
├─────────────────────────────────────────────────────────────────┤
│ Avant :  EAX = 00000005   EIP = 0x0040100A                     │
│ Après :  EAX = 00000008   EIP = 0x0040100C                     │
│          (5 + 3 = 8)                                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Les Instructions Assembleur de Base

L'assembleur est le langage le plus proche du processeur. Voici les instructions fondamentales :

### Mouvement de données

```nasm
mov dest, src    ; Copier src vers dest
                 ; mov eax, 42      → EAX = 42
                 ; mov eax, ebx     → EAX = EBX
                 ; mov eax, [ebx]   → EAX = mémoire[EBX]

push value       ; Empiler une valeur (sur la stack)
pop dest         ; Dépiler vers dest
```

### Arithmétique

```nasm
add dest, src    ; dest = dest + src
sub dest, src    ; dest = dest - src
mul src          ; EDX:EAX = EAX * src (non signé)
div src          ; EAX = EDX:EAX / src, EDX = reste
inc dest         ; dest = dest + 1
dec dest         ; dest = dest - 1
```

### Logique

```nasm
and dest, src    ; dest = dest AND src
or dest, src     ; dest = dest OR src
xor dest, src    ; dest = dest XOR src
not dest         ; dest = NOT dest
```

### Comparaison et sauts

```nasm
cmp a, b         ; Compare a et b (met à jour EFLAGS)
test a, b        ; AND logique sans stocker (met à jour EFLAGS)

jmp addr         ; Saut inconditionnel
je addr          ; Jump if Equal (ZF=1)
jne addr         ; Jump if Not Equal (ZF=0)
jg addr          ; Jump if Greater (signé)
jl addr          ; Jump if Less (signé)
ja addr          ; Jump if Above (non signé)
jb addr          ; Jump if Below (non signé)
```

### Appel de fonctions

```nasm
call addr        ; Appeler une fonction
                 ; 1. Push EIP (adresse retour)
                 ; 2. EIP = addr

ret              ; Retourner de la fonction
                 ; 1. Pop EIP
```

---

## Le Pipeline et l'Exécution Spéculative

Les processeurs modernes sont beaucoup plus complexes. Ils utilisent :

```
┌─────────────────────────────────────────────────────────────────┐
│                    PIPELINE SIMPLIFIÉ                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Temps →                                                        │
│                                                                 │
│  Cycle    1    2    3    4    5    6    7    8                 │
│  ───────────────────────────────────────────────               │
│  Instr 1  F    D    E    W                                     │
│  Instr 2       F    D    E    W                                │
│  Instr 3            F    D    E    W                           │
│  Instr 4                 F    D    E    W                      │
│  Instr 5                      F    D    E    W                 │
│                                                                 │
│  F = Fetch, D = Decode, E = Execute, W = Write-back           │
│                                                                 │
│  → Plusieurs instructions en cours simultanément !             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Exécution spéculative** : Le CPU "devine" le résultat des branchements et commence à exécuter avant de savoir si c'est le bon chemin.

> **Note sécurité** : Les vulnérabilités Spectre et Meltdown exploitent l'exécution spéculative pour lire de la mémoire normalement inaccessible.

---

## Modes d'Adressage

Comment le processeur accède-t-il aux données en mémoire ?

```
┌─────────────────────────────────────────────────────────────────┐
│                    MODES D'ADRESSAGE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Immédiat :     mov eax, 42                                     │
│                 └── La valeur est dans l'instruction           │
│                                                                 │
│  Registre :     mov eax, ebx                                    │
│                 └── Valeur dans un registre                    │
│                                                                 │
│  Direct :       mov eax, [0x00401000]                          │
│                 └── Adresse mémoire fixe                       │
│                                                                 │
│  Indirect :     mov eax, [ebx]                                  │
│                 └── Adresse dans un registre                   │
│                                                                 │
│  Base+Offset :  mov eax, [ebx + 8]                             │
│                 └── Registre + décalage                        │
│                                                                 │
│  Base+Index :   mov eax, [ebx + ecx*4]                         │
│                 └── Utilisé pour les tableaux                  │
│                                                                 │
│  Complet :      mov eax, [ebx + ecx*4 + 12]                    │
│                 └── Base + Index*Scale + Offset                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Conventions d'Appel (Calling Conventions)

Quand une fonction appelle une autre fonction, il faut des règles :

### cdecl (C declaration) - Linux/GCC par défaut

```
┌─────────────────────────────────────────────────────────────────┐
│                         CDECL                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • Arguments passés sur la pile (droite à gauche)              │
│  • L'appelant nettoie la pile après le retour                  │
│  • Valeur de retour dans EAX                                   │
│                                                                 │
│  Exemple : fonction(1, 2, 3)                                   │
│                                                                 │
│  push 3        ; Argument 3                                    │
│  push 2        ; Argument 2                                    │
│  push 1        ; Argument 1                                    │
│  call fonction                                                 │
│  add esp, 12   ; Nettoyer (3 args × 4 bytes)                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### x64 Linux (System V AMD64 ABI)

```
┌─────────────────────────────────────────────────────────────────┐
│                    x64 LINUX ABI                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • 6 premiers arguments entiers : RDI, RSI, RDX, RCX, R8, R9   │
│  • Arguments supplémentaires sur la pile                        │
│  • Valeur de retour dans RAX                                   │
│                                                                 │
│  Exemple : fonction(1, 2, 3)                                   │
│                                                                 │
│  mov rdi, 1    ; Argument 1                                    │
│  mov rsi, 2    ; Argument 2                                    │
│  mov rdx, 3    ; Argument 3                                    │
│  call fonction                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### x64 Windows

```
┌─────────────────────────────────────────────────────────────────┐
│                    x64 WINDOWS                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • 4 premiers arguments : RCX, RDX, R8, R9                     │
│  • "Shadow space" de 32 bytes réservé sur la pile              │
│  • Valeur de retour dans RAX                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Pertinence pour la Sécurité Offensive

### Comprendre les exploits

Pour exploiter un buffer overflow, vous devez comprendre :
- Comment EIP contrôle le flux d'exécution
- Comment la pile stocke les adresses de retour
- Comment écraser EIP pour rediriger l'exécution

```
┌─────────────────────────────────────────────────────────────────┐
│              BUFFER OVERFLOW SIMPLIFIÉ                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   PILE (avant overflow)         PILE (après overflow)          │
│   ┌────────────────┐            ┌────────────────┐              │
│   │    buffer      │            │ AAAAAAAAAAAAA  │              │
│   │    [64 bytes]  │            │ AAAAAAAAAAAAA  │              │
│   ├────────────────┤            ├────────────────┤              │
│   │    EBP sauvé   │            │ AAAAAAAAAAAAA  │              │
│   ├────────────────┤            ├────────────────┤              │
│   │    Adresse     │            │ 0xDEADBEEF     │ ← Contrôlé! │
│   │    de retour   │            │ (notre adresse)│              │
│   └────────────────┘            └────────────────┘              │
│                                                                 │
│   → EIP prend la valeur écrasée → Exécution redirigée          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Écriture de shellcode

Le shellcode doit utiliser directement les registres et les instructions :

```nasm
; Shellcode x86 Linux - execve("/bin/sh")
xor eax, eax       ; EAX = 0
push eax           ; NULL terminator
push 0x68732f2f    ; "//sh"
push 0x6e69622f    ; "/bin"
mov ebx, esp       ; EBX = pointer vers "/bin//sh"
push eax           ; NULL
push ebx           ; Pointeur vers args
mov ecx, esp       ; ECX = argv
xor edx, edx       ; EDX = NULL (envp)
mov al, 0xb        ; syscall execve = 11
int 0x80           ; Appel système
```

### Reverse engineering

Comprendre l'assembleur vous permet de :
- Analyser des malwares sans code source
- Comprendre ce qu'un programme fait réellement
- Trouver des vulnérabilités dans des binaires

---

## Résumé

```
┌─────────────────────────────────────────────────────────────────┐
│                        POINTS CLÉS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • Le CPU exécute des instructions en cycle fetch-decode-exec  │
│                                                                 │
│  • Les registres sont la mémoire la plus rapide                │
│                                                                 │
│  • EIP contient l'adresse de la prochaine instruction          │
│    → Contrôler EIP = contrôler l'exécution                     │
│                                                                 │
│  • ESP pointe vers le sommet de la pile                        │
│                                                                 │
│  • EFLAGS contient le résultat des comparaisons                │
│                                                                 │
│  • Les conventions d'appel définissent comment passer          │
│    les arguments aux fonctions                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [01 - Systèmes de Numération](01-systemes-numeration.md) | [03 - La Mémoire](03-memoire.md) |
