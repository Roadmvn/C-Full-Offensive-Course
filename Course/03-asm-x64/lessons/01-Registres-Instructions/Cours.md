# Module : Registres et Instructions x64

## Objectifs d'apprentissage

À la fin de ce module, tu seras capable de :
- Connaître tous les registres x64 et leurs rôles
- Comprendre les modes d'adressage
- Maîtriser les instructions fondamentales (MOV, ADD, SUB, etc.)
- Utiliser les instructions de comparaison et de saut
- Appliquer ces connaissances pour l'exploitation et le reverse engineering

---

## 1. Architecture x64 - Vue d'ensemble

### 1.1 Évolution des registres

```
ÉVOLUTION x86 → x64 :

32-bit (x86)          64-bit (x64)
┌──────────┐          ┌────────────────────┐
│   EAX    │    →     │        RAX         │
│ (32 bits)│          │     (64 bits)      │
└──────────┘          └────────────────────┘

DÉCOMPOSITION D'UN REGISTRE 64-BIT :
┌────────────────────────────────────────────────────────────────┐
│                            RAX (64 bits)                       │
├────────────────────────────┬───────────────────────────────────┤
│         (32 bits)          │             EAX (32 bits)         │
├────────────────────────────┼─────────────────┬─────────────────┤
│         (48 bits)          │    (8 bits)     │   AX (16 bits)  │
├────────────────────────────┼─────────────────┼────────┬────────┤
│         (48 bits)          │    (8 bits)     │AH (8b) │AL (8b) │
└────────────────────────────┴─────────────────┴────────┴────────┘
```

### 1.2 Les 16 registres généraux

```
REGISTRES GÉNÉRAUX x64 :
┌──────────┬──────────┬──────────────────────────────────────────┐
│ 64-bit   │ 32-bit   │ Usage typique                            │
├──────────┼──────────┼──────────────────────────────────────────┤
│ RAX      │ EAX      │ Accumulateur, retour de fonction         │
│ RBX      │ EBX      │ Base, callee-saved                       │
│ RCX      │ ECX      │ Compteur, 4e arg Windows                 │
│ RDX      │ EDX      │ Data, 3e arg Linux                       │
│ RSI      │ ESI      │ Source index, 2e arg Linux               │
│ RDI      │ EDI      │ Destination index, 1er arg Linux         │
│ RBP      │ EBP      │ Base pointer (frame pointer)             │
│ RSP      │ ESP      │ Stack pointer                            │
│ R8       │ R8D      │ 5e arg Linux, 5e arg Windows             │
│ R9       │ R9D      │ 6e arg Linux, 6e arg Windows             │
│ R10      │ R10D     │ Temporaire                               │
│ R11      │ R11D     │ Temporaire                               │
│ R12      │ R12D     │ Callee-saved                             │
│ R13      │ R13D     │ Callee-saved                             │
│ R14      │ R14D     │ Callee-saved                             │
│ R15      │ R15D     │ Callee-saved                             │
└──────────┴──────────┴──────────────────────────────────────────┘
```

### 1.3 Registres spéciaux

```
REGISTRES DE CONTRÔLE :
┌──────────┬─────────────────────────────────────────────────────┐
│ RIP      │ Instruction Pointer - adresse instruction courante │
│ RFLAGS   │ Flags (ZF, CF, SF, OF, etc.)                       │
└──────────┴─────────────────────────────────────────────────────┘

REGISTRES DE SEGMENTS (moins utilisés en x64) :
┌──────────┬─────────────────────────────────────────────────────┐
│ CS       │ Code Segment                                        │
│ DS       │ Data Segment                                        │
│ SS       │ Stack Segment                                       │
│ ES, FS   │ Extra Segments (FS utilisé pour TEB en Windows)    │
│ GS       │ Extra Segment (GS utilisé en Linux pour TLS)       │
└──────────┴─────────────────────────────────────────────────────┘
```

---

## 2. Le registre RFLAGS

### 2.1 Flags importants

```
STRUCTURE DE RFLAGS (bits importants) :
┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
│ OF │DF  │ IF │ TF │ SF │ ZF │    │ AF │    │ PF │    │ CF │
│ 11 │ 10 │ 9  │ 8  │ 7  │ 6  │ 5  │ 4  │ 3  │ 2  │ 1  │ 0  │
└────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘

FLAGS PRINCIPAUX :
┌──────┬──────────────────┬──────────────────────────────────────┐
│ Flag │ Nom              │ Description                          │
├──────┼──────────────────┼──────────────────────────────────────┤
│ ZF   │ Zero Flag        │ 1 si résultat = 0                    │
│ CF   │ Carry Flag       │ 1 si retenue (non-signé)             │
│ SF   │ Sign Flag        │ 1 si résultat négatif                │
│ OF   │ Overflow Flag    │ 1 si overflow (signé)                │
│ PF   │ Parity Flag      │ 1 si parité paire                    │
│ DF   │ Direction Flag   │ Direction pour string ops            │
└──────┴──────────────────┴──────────────────────────────────────┘
```

### 2.2 Comment les flags sont modifiés

```c
// Exemple : résultat d'une soustraction
mov rax, 5
sub rax, 5     ; RAX = 0
               ; ZF = 1 (résultat nul)
               ; SF = 0 (résultat positif)
               ; CF = 0 (pas de borrow)

mov rax, 3
sub rax, 5     ; RAX = -2 (0xFFFFFFFFFFFFFFFE)
               ; ZF = 0 (résultat non nul)
               ; SF = 1 (résultat négatif)
               ; CF = 1 (borrow)
```

---

## 3. Instructions de transfert de données

### 3.1 MOV - L'instruction fondamentale

```nasm
; Syntaxe : MOV destination, source

; Registre vers registre
mov rax, rbx        ; RAX = RBX

; Immédiat vers registre
mov rax, 0x1234     ; RAX = 0x1234

; Mémoire vers registre
mov rax, [rbx]      ; RAX = valeur à l'adresse RBX
mov rax, [rbx+8]    ; RAX = valeur à l'adresse RBX+8

; Registre vers mémoire
mov [rbx], rax      ; Mémoire[RBX] = RAX

; ATTENTION : MOV mémoire → mémoire IMPOSSIBLE !
; mov [rax], [rbx]  ; ERREUR !
```

### 3.2 Variantes de MOV

```nasm
; MOVZX - Move with Zero Extension
movzx rax, bl       ; RAX = BL (étendu avec des zéros)
movzx eax, word [rbx] ; EAX = 16 bits de [RBX], reste = 0

; MOVSX - Move with Sign Extension  
movsx rax, bl       ; RAX = BL (étendu avec le bit de signe)
movsxd rax, ebx     ; RAX = EBX (32→64 avec extension de signe)

; LEA - Load Effective Address (charge l'adresse, pas la valeur)
lea rax, [rbx+rcx*4+8]  ; RAX = RBX + RCX*4 + 8 (calcul d'adresse)
```

### 3.3 LEA vs MOV

```
DIFFÉRENCE CRUCIALE :

mov rax, [rbx+8]    ; Charge la VALEUR à l'adresse RBX+8
lea rax, [rbx+8]    ; Charge l'ADRESSE RBX+8 (sans accès mémoire)

UTILISATION DE LEA POUR LES CALCULS :
lea rax, [rbx+rbx*2]    ; RAX = RBX * 3 (plus rapide que MUL)
lea rax, [rbx+rcx]      ; RAX = RBX + RCX (sans modifier flags)
```

---

## 4. Instructions arithmétiques

### 4.1 Addition et soustraction

```nasm
; ADD - Addition
add rax, rbx        ; RAX = RAX + RBX
add rax, 10         ; RAX = RAX + 10
add [rbx], rax      ; [RBX] = [RBX] + RAX

; SUB - Soustraction
sub rax, rbx        ; RAX = RAX - RBX
sub rax, 10         ; RAX = RAX - 10

; INC / DEC - Incrémenter / Décrémenter
inc rax             ; RAX = RAX + 1
dec rbx             ; RBX = RBX - 1

; NEG - Négation (complément à 2)
neg rax             ; RAX = -RAX
```

### 4.2 Multiplication et division

```nasm
; MUL - Multiplication non signée
; Résultat dans RDX:RAX
mov rax, 5
mov rbx, 10
mul rbx             ; RDX:RAX = RAX * RBX = 50

; IMUL - Multiplication signée
imul rax, rbx       ; RAX = RAX * RBX (version 2 opérandes)
imul rax, rbx, 10   ; RAX = RBX * 10 (version 3 opérandes)

; DIV - Division non signée
; Divise RDX:RAX par l'opérande
; Quotient dans RAX, reste dans RDX
mov rdx, 0          ; IMPORTANT : initialiser RDX !
mov rax, 100
mov rbx, 7
div rbx             ; RAX = 14 (quotient), RDX = 2 (reste)

; IDIV - Division signée
; Même principe mais signé
```

---

## 5. Instructions logiques et de bits

### 5.1 Opérations logiques

```nasm
; AND - ET logique
and rax, rbx        ; RAX = RAX & RBX
and rax, 0xFF       ; Masque : garde les 8 bits bas

; OR - OU logique
or rax, rbx         ; RAX = RAX | RBX
or rax, 0x80        ; Met le bit 7 à 1

; XOR - OU exclusif
xor rax, rbx        ; RAX = RAX ^ RBX
xor rax, rax        ; RAX = 0 (très courant pour initialiser)

; NOT - Inversion de tous les bits
not rax             ; RAX = ~RAX
```

### 5.2 Décalages de bits

```nasm
; SHL / SAL - Shift Left (logique = arithmétique)
shl rax, 1          ; RAX = RAX << 1 (multiplication par 2)
shl rax, 4          ; RAX = RAX << 4 (multiplication par 16)
shl rax, cl         ; Décalage de CL positions

; SHR - Shift Right Logical (remplissage par zéros)
shr rax, 1          ; RAX = RAX >> 1 (division par 2, non signé)

; SAR - Shift Arithmetic Right (préserve le signe)
sar rax, 1          ; Division par 2, signé

; ROL / ROR - Rotations
rol rax, 1          ; Rotation à gauche
ror rax, 1          ; Rotation à droite
```

---

## 6. Instructions de comparaison et de saut

### 6.1 Comparaisons

```nasm
; CMP - Compare (fait une soustraction sans stocker le résultat)
cmp rax, rbx        ; Calcule RAX - RBX, met à jour les flags
cmp rax, 10         ; Compare RAX avec 10

; TEST - ET logique sans stocker le résultat
test rax, rax       ; Vérifie si RAX == 0 (ZF = 1 si nul)
test rax, 1         ; Vérifie si le bit 0 est mis (pair/impair)
```

### 6.2 Sauts conditionnels

```nasm
; Sauts basés sur les flags
jz  label           ; Jump if Zero (ZF = 1)
jnz label           ; Jump if Not Zero (ZF = 0)
je  label           ; Jump if Equal (= JZ)
jne label           ; Jump if Not Equal (= JNZ)

; Sauts pour comparaisons non signées
ja  label           ; Jump if Above (CF=0 et ZF=0)
jae label           ; Jump if Above or Equal (CF=0)
jb  label           ; Jump if Below (CF=1)
jbe label           ; Jump if Below or Equal (CF=1 ou ZF=1)

; Sauts pour comparaisons signées
jg  label           ; Jump if Greater (ZF=0 et SF=OF)
jge label           ; Jump if Greater or Equal (SF=OF)
jl  label           ; Jump if Less (SF≠OF)
jle label           ; Jump if Less or Equal (ZF=1 ou SF≠OF)

; Saut inconditionnel
jmp label           ; Toujours sauter
```

### 6.3 Exemple pratique

```nasm
; Équivalent de : if (rax > 10) { rbx = 1; } else { rbx = 0; }
cmp rax, 10
jle else_branch     ; Si RAX <= 10, aller à else
mov rbx, 1          ; RAX > 10
jmp end_if
else_branch:
mov rbx, 0          ; RAX <= 10
end_if:
```

---

## 7. Instructions de pile

### 7.1 PUSH et POP

```nasm
; PUSH - Empiler (décrémente RSP, puis stocke)
push rax            ; RSP -= 8; [RSP] = RAX
push rbx
push 0x1234         ; Push une constante

; POP - Dépiler (charge, puis incrémente RSP)
pop rax             ; RAX = [RSP]; RSP += 8
pop rbx

; ÉTAT DE LA PILE :
;                    ┌─────────────┐
; RSP avant push →   │   ancien    │
;                    ├─────────────┤
; RSP après push →   │    RAX      │ ← Valeur pushée
;                    └─────────────┘
```

### 7.2 Gestion de la stack frame

```nasm
; Prologue typique d'une fonction
push rbp            ; Sauvegarder l'ancien frame pointer
mov rbp, rsp        ; Nouveau frame pointer
sub rsp, 32         ; Allouer espace pour variables locales

; ... code de la fonction ...

; Épilogue
mov rsp, rbp        ; Restaurer RSP
pop rbp             ; Restaurer RBP
ret                 ; Retourner
```

---

## 8. Applications offensives

### 8.1 Identification de code dans un shellcode

```nasm
; Pattern courant : XOR pour décoder
xor_decoder:
    xor byte [rsi], 0x41    ; XOR chaque byte avec la clé
    inc rsi
    loop xor_decoder

; Pattern : Récupération de l'adresse courante (PIC)
call get_rip
get_rip:
pop rax                     ; RAX = adresse de l'instruction après call
```

### 8.2 Gadgets ROP courants

```nasm
; Gadgets utiles pour ROP
pop rdi; ret               ; Contrôler le 1er argument (Linux)
pop rsi; ret               ; Contrôler le 2e argument
pop rax; ret               ; Contrôler RAX pour syscall
mov rdi, rax; ret          ; Transférer une valeur
xchg rax, rdi; ret         ; Échanger des valeurs
```

---

## 9. Résumé des instructions essentielles

```
INSTRUCTIONS À CONNAÎTRE PAR CŒUR :
┌─────────────┬───────────────────────────────────────────────┐
│ Catégorie   │ Instructions                                  │
├─────────────┼───────────────────────────────────────────────┤
│ Transfert   │ mov, lea, movzx, movsx, push, pop             │
│ Arithmétique│ add, sub, inc, dec, mul, imul, div, idiv      │
│ Logique     │ and, or, xor, not, shl, shr, sar, rol, ror    │
│ Comparaison │ cmp, test                                      │
│ Saut        │ jmp, je, jne, jz, jnz, ja, jb, jg, jl, call   │
│ Pile        │ push, pop, ret                                 │
│ Système     │ syscall, int 0x80 (32-bit)                    │
└─────────────┴───────────────────────────────────────────────┘
```

---

## Exercice pratique

Voir `exercice.md` pour mettre en pratique ces concepts.
