# Module : Opérations sur la Stack x64

## Objectifs d'apprentissage

À la fin de ce module, tu seras capable de :
- Comprendre l'organisation de la stack en x64
- Maîtriser PUSH, POP et la manipulation de RSP
- Analyser les stack frames et leur structure
- Identifier les vulnérabilités liées à la stack
- Exploiter les buffer overflows et comprendre ROP

---

## 1. La Stack - Concepts fondamentaux

### 1.1 Qu'est-ce que la stack ?

```
LA STACK EN MÉMOIRE :

Adresses hautes (0x7FFFFFFF...)
┌─────────────────────────────────┐
│         Arguments              │  ← Passés par le caller
├─────────────────────────────────┤
│       Return Address           │  ← Adresse de retour (CALL)
├─────────────────────────────────┤
│       Saved RBP                │  ← Frame pointer sauvegardé
├─────────────────────────────────┤
│       Variables locales        │  ← Espace alloué par la fonction
├─────────────────────────────────┤
│       Red Zone (128 bytes)     │  ← Zone protégée (System V ABI)
├─────────────────────────────────┤
│            ...                 │
│       (stack grandit vers le bas)
│            ↓                   │
└─────────────────────────────────┘
RSP → Adresses basses

POINT CLÉ : La stack grandit vers les adresses BASSES !
PUSH : RSP -= 8, puis stocke
POP  : charge, puis RSP += 8
```

### 1.2 Registres clés

```
REGISTRES DE LA STACK :
┌──────────┬────────────────────────────────────────────────────┐
│ RSP      │ Stack Pointer - pointe vers le sommet de la stack │
│ RBP      │ Base Pointer - pointe vers la base du frame       │
│ RIP      │ Instruction Pointer - adresse de retour sur stack │
└──────────┴────────────────────────────────────────────────────┘

RELATION RSP / RBP :
              ┌─────────────────┐
   RBP →     │   Saved RBP     │  Frame de la fonction courante
              ├─────────────────┤
              │   Local var 1   │
              ├─────────────────┤
              │   Local var 2   │
              ├─────────────────┤
   RSP →     │   (sommet)      │
              └─────────────────┘
```

---

## 2. Instructions PUSH et POP

### 2.1 PUSH - Empiler

```nasm
; PUSH effectue 2 opérations :
; 1. RSP = RSP - 8 (décrémente le stack pointer)
; 2. [RSP] = valeur (stocke la valeur au sommet)

push rax            ; Empile RAX (64 bits)
push rbx
push 0x12345678     ; Empile une constante
push qword [rbp-8]  ; Empile une valeur depuis la mémoire

; ÉQUIVALENT MANUEL :
sub rsp, 8
mov [rsp], rax
```

### 2.2 POP - Dépiler

```nasm
; POP effectue 2 opérations :
; 1. valeur = [RSP] (charge depuis le sommet)
; 2. RSP = RSP + 8 (incrémente le stack pointer)

pop rax             ; Dépile dans RAX
pop rbx
pop qword [rbp-8]   ; Dépile vers la mémoire

; ÉQUIVALENT MANUEL :
mov rax, [rsp]
add rsp, 8
```

### 2.3 Visualisation

```
AVANT PUSH RAX (RAX = 0xDEADBEEF) :
         ┌──────────────────┐
RSP →    │   0x11111111     │
         ├──────────────────┤
         │   0x22222222     │
         └──────────────────┘

APRÈS PUSH RAX :
         ┌──────────────────┐
         │   0x11111111     │
         ├──────────────────┤
RSP →    │   0xDEADBEEF     │  ← RAX pushé ici
         ├──────────────────┤
         │   0x22222222     │
         └──────────────────┘
```

---

## 3. Stack Frames

### 3.1 Structure d'un stack frame

```
STACK FRAME TYPIQUE (fonction avec 2 variables locales) :

Adresses hautes
┌─────────────────────────────┐
│    Argument 7+ (si besoin)  │  [RBP + 16 + n*8]
├─────────────────────────────┤
│    Return Address           │  [RBP + 8]
├─────────────────────────────┤
│    Saved RBP (caller)       │  [RBP] ← RBP pointe ici
├─────────────────────────────┤
│    Variable locale 1        │  [RBP - 8]
├─────────────────────────────┤
│    Variable locale 2        │  [RBP - 16]
├─────────────────────────────┤
│    (padding/alignement)     │  [RBP - 24]
├─────────────────────────────┤
│    Shadow space (Windows)   │  ← RSP (après prologue)
└─────────────────────────────┘
Adresses basses
```

### 3.2 Prologue et épilogue

```nasm
; ══════════════════════════════════════════════════
; PROLOGUE - Début de fonction
; ══════════════════════════════════════════════════
ma_fonction:
    push rbp            ; Sauvegarder l'ancien frame pointer
    mov rbp, rsp        ; Nouveau frame pointer = stack pointer
    sub rsp, 32         ; Allouer espace pour variables locales
                        ; (doit être multiple de 16 pour alignement)

    ; ... code de la fonction ...

; ══════════════════════════════════════════════════
; ÉPILOGUE - Fin de fonction
; ══════════════════════════════════════════════════
    mov rsp, rbp        ; Restaurer RSP (désallouer variables)
    pop rbp             ; Restaurer l'ancien frame pointer
    ret                 ; Retourner (pop RIP et jump)

; ALTERNATIVE AVEC LEAVE :
    leave               ; Équivalent à : mov rsp, rbp; pop rbp
    ret
```

### 3.3 Appel de fonction (CALL/RET)

```nasm
; CALL effectue :
; 1. PUSH de l'adresse de retour (RIP de l'instruction suivante)
; 2. JMP vers l'adresse de la fonction

call ma_fonction
; Équivalent à :
push rip_next          ; Sauvegarder l'adresse de retour
jmp ma_fonction

; RET effectue :
; 1. POP dans RIP
; 2. Continue l'exécution à cette adresse

ret
; Équivalent à :
pop rip                ; Charger l'adresse de retour
jmp rip                ; Y sauter
```

---

## 4. Alignement et conventions

### 4.1 Alignement de la stack

```
RÈGLE x64 : La stack doit être alignée sur 16 bytes AVANT un CALL

POURQUOI ?
- Instructions SSE/AVX nécessitent un alignement 16 bytes
- Performance optimale des accès mémoire

COMMENT VÉRIFIER :
RSP doit être divisible par 16 avant CALL
(RSP & 0xF) == 0

APRÈS CALL :
RSP n'est plus aligné (return address pushée = 8 bytes)
Le prologue doit réaligner si nécessaire
```

### 4.2 Red Zone (System V ABI - Linux/macOS)

```
RED ZONE : 128 bytes en dessous de RSP

┌─────────────────────────────┐
│       Stack normale         │
├─────────────────────────────┤
RSP →│                        │
├─────────────────────────────┤
│                             │
│    RED ZONE (128 bytes)     │  ← Peut être utilisée sans
│    Protégée des signaux     │    modifier RSP !
│                             │
└─────────────────────────────┘

USAGE :
- Fonctions "leaf" (qui n'appellent pas d'autres fonctions)
- Peuvent utiliser jusqu'à 128 bytes sous RSP
- Sans avoir besoin de modifier RSP (optimisation)

ATTENTION :
- N'existe PAS sur Windows !
- Les signal handlers ne l'écrasent pas
```

### 4.3 Shadow Space (Windows x64)

```
WINDOWS : 32 bytes de "shadow space" requis avant chaque CALL

┌─────────────────────────────┐
│    Argument 5+ (si besoin)  │
├─────────────────────────────┤
│    Shadow space (32 bytes)  │  ← Pour sauvegarder RCX, RDX, R8, R9
├─────────────────────────────┤
RSP →│    (aligné sur 16)    │
└─────────────────────────────┘

; Avant d'appeler une fonction sur Windows :
sub rsp, 40         ; 32 (shadow) + 8 (alignement)
call fonction
add rsp, 40
```

---

## 5. Applications offensives

### 5.1 Buffer Overflow - Principe

```
VULNÉRABILITÉ : Écriture au-delà d'un buffer sur la stack

STACK VULNÉRABLE :
┌─────────────────────────────┐
│    Return Address           │  ← CIBLE de l'attaque
├─────────────────────────────┤
│    Saved RBP                │
├─────────────────────────────┤
│    buffer[64]               │  ← Buffer vulnérable
│    ...                      │
│    buffer[0]                │  ← Début de l'écriture
└─────────────────────────────┘

EXPLOIT :
1. Écrire au-delà de buffer[]
2. Écraser Saved RBP (optionnel)
3. Écraser Return Address avec l'adresse voulue
4. Quand RET s'exécute → jump vers notre code
```

### 5.2 Stack Pivoting

```nasm
; STACK PIVOTING : Changer RSP vers une zone contrôlée

; Gadget typique :
xchg rax, rsp       ; Échanger RAX et RSP
ret                 ; Continuer sur la "fake stack"

; Ou :
leave               ; RSP = RBP, puis POP RBP
ret                 ; Si RBP est contrôlé, RSP l'est aussi

; Usage : Quand le buffer overflow est limité,
; pivoter vers un buffer plus grand qu'on contrôle
```

### 5.3 ROP (Return-Oriented Programming)

```
ROP : Chaîner des "gadgets" terminés par RET

GADGET : Séquence d'instructions terminée par RET
Exemple : pop rdi; ret

STACK ROP :
┌─────────────────────────────┐
│  Adresse gadget 1           │  → pop rdi; ret
├─────────────────────────────┤
│  Valeur pour RDI            │  → argument 1
├─────────────────────────────┤
│  Adresse gadget 2           │  → pop rsi; ret
├─────────────────────────────┤
│  Valeur pour RSI            │  → argument 2
├─────────────────────────────┤
│  Adresse de execve          │  → appel système final
└─────────────────────────────┘

EXÉCUTION :
1. Premier RET saute au gadget 1
2. pop rdi charge la valeur, ret saute au gadget 2
3. pop rsi charge la valeur, ret saute à execve
4. execve("/bin/sh", ...) → shell !
```

### 5.4 Trouver des gadgets

```bash
# Avec ROPgadget
ROPgadget --binary ./programme --only "pop|ret"

# Gadgets utiles :
pop rdi; ret              # Contrôler arg1 (Linux)
pop rsi; ret              # Contrôler arg2
pop rdx; ret              # Contrôler arg3
pop rax; ret              # Contrôler RAX (syscall number)
syscall; ret              # Effectuer le syscall
```

---

## 6. Protections de la stack

### 6.1 Stack Canary

```
STACK CANARY : Valeur aléatoire entre le buffer et l'adresse de retour

┌─────────────────────────────┐
│    Return Address           │
├─────────────────────────────┤
│    Saved RBP                │
├─────────────────────────────┤
│    CANARY (0x????????)      │  ← Vérifié avant RET
├─────────────────────────────┤
│    buffer[64]               │
└─────────────────────────────┘

Si le canary est modifié → crash (stack smashing detected)

CONTOURNEMENT :
- Leak du canary (format string, info disclosure)
- Brute force (si fork() conserve le canary)
- Écraser sans toucher le canary (write-what-where)
```

### 6.2 ASLR et PIE

```
ASLR : Adresses randomisées à chaque exécution
PIE  : Position Independent Executable

SANS ASLR :
Stack toujours à 0x7FFFFFFFE000 (exemple)
Code toujours à 0x400000

AVEC ASLR :
Stack à 0x7FFE12340000 (random)
Libc à 0x7F9876540000 (random)

CONTOURNEMENT :
- Info leak pour obtenir une adresse
- Partial overwrite (ne changer que les bits bas)
- Brute force (32 bits de randomisation = faisable)
```

---

## 7. Résumé

```
INSTRUCTIONS STACK ESSENTIELLES :
┌──────────────┬─────────────────────────────────────────────┐
│ PUSH reg     │ RSP -= 8; [RSP] = reg                       │
│ POP reg      │ reg = [RSP]; RSP += 8                       │
│ CALL addr    │ PUSH RIP_next; JMP addr                     │
│ RET          │ POP RIP (JMP to return address)             │
│ LEAVE        │ MOV RSP, RBP; POP RBP                       │
│ ENTER n, 0   │ PUSH RBP; MOV RBP, RSP; SUB RSP, n         │
└──────────────┴─────────────────────────────────────────────┘

EXPLOITATION :
- Buffer overflow → écraser return address
- ROP chains → chaîner des gadgets
- Stack pivoting → contrôler RSP
- Leak canary → contourner la protection
```

---

## Exercice pratique

Voir `exercice.md` pour mettre en pratique ces concepts.
