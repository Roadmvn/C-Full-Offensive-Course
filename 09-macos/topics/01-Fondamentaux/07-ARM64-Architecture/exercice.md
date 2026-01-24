# EXERCICE : ARM64 ASSEMBLY


### OBJECTIF :
Maîtriser l'assembleur ARM64 et créer des programmes fonctionnels.

═══════════════════════════════════════════════════════════════

### PARTIE 1 : HELLO WORLD EN ARM64
═══════════════════════════════════════════════════════════════

Créer un programme qui affiche "Hello ARM64!" en utilisant syscalls.

SYSCALLS MacOS ARM64 :
- write: X16 = 0x2000004
- exit: X16 = 0x2000001


### REGISTRES :
- X0 = fd (1 = stdout)
- X1 = buffer address
- X2 = length


### EXEMPLE STRUCTURE :
.global _main
.align 2

_main:
    // Votre code ici
    mov x16, #0x2000004  // write syscall
    svc #0x80
    
    mov x16, #0x2000001  // exit syscall
    mov x0, #0
    svc #0x80

.data
msg: .ascii "Hello ARM64!\n"
len = . - msg

═══════════════════════════════════════════════════════════════

### PARTIE 2 : ADDITION ET SOUSTRACTION
═══════════════════════════════════════════════════════════════

Créer une fonction qui additionne deux nombres et retourne le résultat.


### FONCTION :
int add(int a, int b);


### REGISTRES :
- X0 = premier argument
- X1 = second argument
- X0 = valeur de retour

═══════════════════════════════════════════════════════════════

### PARTIE 3 : BOUCLE
═══════════════════════════════════════════════════════════════

Créer une boucle qui compte de 1 à 10 et affiche chaque nombre.


### INSTRUCTIONS UTILES :
- CBZ : Compare and Branch if Zero
- CBNZ : Compare and Branch if Not Zero
- B : Branch inconditionnel

═══════════════════════════════════════════════════════════════

### PARTIE 4 : CONDITION
═══════════════════════════════════════════════════════════════

Créer une fonction qui retourne le maximum de deux nombres.


### INSTRUCTIONS :
- CMP : Compare
- B.GT : Branch if Greater
- B.LT : Branch if Less
- B.EQ : Branch if Equal

═══════════════════════════════════════════════════════════════

### PARTIE 5 : STACK ET FRAME POINTER
═══════════════════════════════════════════════════════════════

Créer une fonction récursive pour calculer factorielle(n).


### GESTION DU STACK :
- STP : Store Pair (sauvegarder)
- LDP : Load Pair (restaurer)
- SP : Stack Pointer
- FP : Frame Pointer (X29)
- LR : Link Register (X30)

═══════════════════════════════════════════════════════════════

### EXERCICES BONUS
═══════════════════════════════════════════════════════════════

1. strlen() en ARM64
2. strcmp() en ARM64
3. Inverser une string
4. Fibonacci récursif
5. Appeler une fonction C depuis ARM64


### COMPILATION :
as -o prog.o prog.s
ld -o prog prog.o -lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path` -e _main -arch arm64


### OU :
clang -o prog prog.s

DÉSASSEMBLAGE :
otool -tv prog


