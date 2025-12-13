# SOLUTION : ARM64 ASSEMBLY


---

### PARTIE 1 : HELLO WORLD

---

.global _main
.align 2

_main:

```c
    // write(1, msg, len)
```
    mov x0, #1              // fd = stdout
    adrp x1, msg@PAGE
    add x1, x1, msg@PAGEOFF // buffer address
    mov x2, #13             // length
    mov x16, #0x2000004     // write syscall
    svc #0x80
    

```c
    // exit(0)
```
    mov x0, #0              // exit code
    mov x16, #0x2000001     // exit syscall
    svc #0x80

.data
msg: .ascii "Hello ARM64!\n"


---

### PARTIE 2 : ADDITION

---

.global _main
.align 2

_add:
    add x0, x0, x1          // X0 = X0 + X1
    ret

_main:
    mov x0, #10
    mov x1, #32
    bl _add                 // Appel fonction
    

```c
    // X0 contient maintenant 42
```
    mov x16, #0x2000001
    svc #0x80


---

### PARTIE 3 : BOUCLE (1 à 10)

---

.global _main
.align 2

_main:
    mov x0, #1              // Compteur

loop:

```c
    // Afficher X0 (simplifié - en réalité convertir en ASCII)
    // ... code d'affichage ...
```

    add x0, x0, #1          // Incrémenter
    cmp x0, #11
    b.lt loop               // Si < 11, continuer
    
    mov x0, #0
    mov x16, #0x2000001
    svc #0x80


---

### PARTIE 4 : MAXIMUM

---

.global _max
.align 2

_max:
    cmp x0, x1              // Compare X0 et X1
    b.gt return_x0          // Si X0 > X1, retourner X0
    mov x0, x1              // Sinon, X0 = X1
return_x0:
    ret

_main:
    mov x0, #42
    mov x1, #17
    bl _max                 // X0 = max(42, 17) = 42
    
    mov x16, #0x2000001
    svc #0x80


---

### PARTIE 5 : FACTORIELLE RÉCURSIVE

---

.global _factorial
.align 2

_factorial:

```c
    // Prologue : Sauvegarder FP et LR
```
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    

```c
    // Cas de base : if (n <= 1) return 1
```
    cmp x0, #1
    b.le base_case
    

```c
    // Cas récursif : n * factorial(n-1)
```
    stp x0, xzr, [sp, #-16]!  // Sauvegarder n
    sub x0, x0, #1            // n - 1
    bl _factorial             // factorial(n-1)
    ldp x1, xzr, [sp], #16    // Restaurer n dans X1
    mul x0, x0, x1            // n * factorial(n-1)
    b epilogue

base_case:
    mov x0, #1

epilogue:

```c
    // Épilogue : Restaurer FP et LR
```
    ldp x29, x30, [sp], #16
    ret

_main:
    mov x0, #5                // factorial(5)
    bl _factorial             // X0 = 120
    
    mov x16, #0x2000001
    svc #0x80


---
BONUS 1 : strlen()

---

.global _strlen
.align 2

_strlen:
    mov x1, x0              // Sauvegarder début
    
loop_strlen:
    ldrb w2, [x0]           // Charger byte
    cbz w2, end_strlen      // Si '\0', fin
    add x0, x0, #1          // Avancer
    b loop_strlen

end_strlen:
    sub x0, x0, x1          // Longueur = fin - début
    ret


---
BONUS 2 : strcmp()

---

.global _strcmp
.align 2

_strcmp:
loop_strcmp:
    ldrb w2, [x0], #1       // Charger s1[i++]
    ldrb w3, [x1], #1       // Charger s2[i++]
    
    cmp w2, w3              // Comparer
    b.ne not_equal          // Si différent
    
    cbz w2, equal           // Si '\0', égaux
    b loop_strcmp

not_equal:
    sub x0, x2, x3          // s1[i] - s2[i]
    ret

equal:
    mov x0, #0
    ret


---
BONUS 5 : APPELER FONCTION C

---


```c
// C code: int add_c(int a, int b) { return a + b; }
```

.global _main
.align 2

.extern _add_c              // Fonction C externe

_main:
    stp x29, x30, [sp, #-16]!
    
    mov x0, #10
    mov x1, #32
    bl _add_c               // Appel fonction C
    

```c
    // X0 = 42
```

    ldp x29, x30, [sp], #16
    
    mov x16, #0x2000001
    svc #0x80


---
COMPILATION

---


```bash
# Assembleur seul
```
clang -o prog prog.s
./prog
echo $?


```bash
# Avec fonction C
```
clang -o prog prog.s add.c
./prog


```bash
# Désassemblage
```
otool -tv prog


---
FIN DE LA SOLUTION

---


