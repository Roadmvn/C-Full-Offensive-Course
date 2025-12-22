# Module : Assembleur Inline en C (GCC/Clang)

## Objectifs d'apprentissage

À la fin de ce module, tu seras capable de :
- Maîtriser la syntaxe de l'assembleur inline GCC
- Comprendre les contraintes d'entrée/sortie
- Gérer les registres clobbered
- Écrire du code inline sûr et efficace
- Utiliser l'inline ASM pour l'exploitation

---

## 1. Introduction à l'assembleur inline

### 1.1 Pourquoi l'assembleur inline ?

```
USAGES DE L'ASSEMBLEUR INLINE :
┌─────────────────────────────────────────────────────────────┐
│ 1. Performance      │ Optimisations que le compilateur     │
│                     │ ne peut pas faire                     │
├─────────────────────┼───────────────────────────────────────┤
│ 2. Accès hardware   │ Instructions spéciales (CPUID, etc.) │
├─────────────────────┼───────────────────────────────────────┤
│ 3. Exploitation     │ Shellcode, ROP, injection            │
├─────────────────────┼───────────────────────────────────────┤
│ 4. Reverse eng.     │ Tester des séquences d'instructions  │
├─────────────────────┼───────────────────────────────────────┤
│ 5. Bypass défenses  │ Éviter les patterns détectés         │
└─────────────────────┴───────────────────────────────────────┘
```

### 1.2 Deux syntaxes

```c
// SYNTAXE AT&T (défaut GCC)
__asm__("movl %eax, %ebx");  // Source, Destination

// SYNTAXE INTEL (plus lisible)
__asm__("mov ebx, eax");     // Destination, Source

// Pour utiliser Intel avec GCC :
// gcc -masm=intel fichier.c
```

---

## 2. Syntaxe de base

### 2.1 Format général

```c
__asm__ [volatile] (
    "instructions assembleur"
    : outputs          // Opérandes de sortie
    : inputs           // Opérandes d'entrée
    : clobbers         // Registres modifiés
);

// Exemple simple
int result;
__asm__ (
    "mov %0, 42"       // Instruction : result = 42
    : "=r" (result)    // Output : result dans un registre
);
```

### 2.2 Le mot-clé volatile

```c
// SANS volatile : le compilateur peut optimiser/supprimer
__asm__("nop");                    // Peut être supprimé !

// AVEC volatile : jamais optimisé
__asm__ __volatile__("nop");       // Toujours exécuté

// QUAND utiliser volatile :
// - Effets de bord (accès mémoire, I/O)
// - Instructions de timing
// - Code qui ne doit jamais être supprimé
```

---

## 3. Contraintes d'opérandes

### 3.1 Contraintes de sortie (outputs)

```c
// FORMAT : "=contrainte" (variable_c)

// Contraintes communes :
// "=r" : n'importe quel registre général
// "=a" : RAX/EAX/AX/AL
// "=b" : RBX/EBX/BX/BL
// "=c" : RCX/ECX/CX/CL
// "=d" : RDX/EDX/DX/DL
// "=S" : RSI/ESI
// "=D" : RDI/EDI
// "=m" : emplacement mémoire

int val;
__asm__("mov %0, 100" : "=r"(val));  // val dans un registre
__asm__("mov %0, 100" : "=a"(val));  // val dans EAX spécifiquement
```

### 3.2 Contraintes d'entrée (inputs)

```c
// FORMAT : "contrainte" (expression_c)

int a = 5, b = 10, sum;

__asm__(
    "add %0, %2"           // %0 = %0 + %2
    : "=r" (sum)           // Output
    : "0" (a), "r" (b)     // Inputs : "0" = même registre que %0
);
// sum = a + b = 15
```

### 3.3 Contraintes spéciales

```c
// "+" : lecture ET écriture (input+output)
int x = 10;
__asm__("add %0, 5" : "+r"(x));  // x = x + 5

// "0", "1", etc. : même registre qu'un autre opérande
int a = 5, b;
__asm__("mov %0, %1" : "=r"(b) : "0"(a));  // b utilise même reg que a

// "i" : constante immédiate
__asm__("add %0, %1" : "+r"(x) : "i"(10));

// "m" : accès mémoire direct
int arr[10];
__asm__("mov dword ptr %0, 42" : "=m"(arr[0]));
```

---

## 4. Liste des clobbers

### 4.1 Registres clobbered

```c
// Indiquer les registres modifiés mais pas dans outputs
__asm__(
    "mov rax, 1\n\t"
    "mov rbx, 2\n\t"
    "add rax, rbx"          // RAX et RBX modifiés
    :                       // Pas d'output
    :                       // Pas d'input
    : "rax", "rbx"          // CLOBBERS : RAX et RBX modifiés
);
```

### 4.2 Clobbers spéciaux

```c
// "memory" : accès mémoire possibles (force flush des caches)
__asm__ __volatile__(
    "mfence"
    ::: "memory"
);

// "cc" : flags (condition codes) modifiés
__asm__(
    "add %0, 1"
    : "+r"(x)
    :: "cc"                 // L'ADD modifie les flags
);

// Exemple complet
__asm__ __volatile__(
    "xor rax, rax\n\t"
    "cpuid"
    ::: "rax", "rbx", "rcx", "rdx", "memory"
);
```

---

## 5. Instructions multiples

### 5.1 Plusieurs instructions

```c
// Utiliser \n\t pour séparer les instructions
__asm__(
    "push rax\n\t"
    "mov rax, %1\n\t"
    "add rax, %2\n\t"
    "mov %0, rax\n\t"
    "pop rax"
    : "=r" (result)
    : "r" (a), "r" (b)
);

// Ou avec des strings concaténées
__asm__(
    "push rax\n\t"
    "mov rax, %1\n\t"
    "add rax, %2\n\t"
    "mov %0, rax\n\t"
    "pop rax"
    : "=r" (result)
    : "r" (a), "r" (b)
);
```

### 5.2 Labels locaux

```c
// Utiliser des labels numériques pour éviter les conflits
__asm__(
    "cmp %1, 0\n\t"
    "je 1f\n\t"             // Jump forward to label 1
    "mov %0, 1\n\t"
    "jmp 2f\n\t"            // Jump forward to label 2
    "1:\n\t"                // Label 1
    "mov %0, 0\n\t"
    "2:"                    // Label 2
    : "=r" (result)
    : "r" (value)
    : "cc"
);
```

---

## 6. Exemples pratiques

### 6.1 Lecture de registres système

```c
// Lire le Time Stamp Counter (TSC)
uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__(
        "rdtsc"
        : "=a" (lo), "=d" (hi)
    );
    return ((uint64_t)hi << 32) | lo;
}

// Lire CPUID
void get_cpuid(uint32_t func, uint32_t *eax, uint32_t *ebx, 
               uint32_t *ecx, uint32_t *edx) {
    __asm__ __volatile__(
        "cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "a" (func)
    );
}
```

### 6.2 Opérations atomiques

```c
// Compare-and-swap atomique
int cas(int *ptr, int old_val, int new_val) {
    int result;
    __asm__ __volatile__(
        "lock cmpxchg %2, %1"
        : "=a" (result), "+m" (*ptr)
        : "r" (new_val), "0" (old_val)
        : "cc", "memory"
    );
    return result == old_val;
}

// Incrément atomique
void atomic_inc(int *ptr) {
    __asm__ __volatile__(
        "lock inc dword ptr %0"
        : "+m" (*ptr)
        :: "cc", "memory"
    );
}
```

### 6.3 Syscall direct (Linux x64)

```c
// Syscall Linux x64 : write(1, "Hello\n", 6)
void direct_write(void) {
    __asm__ __volatile__(
        "mov rax, 1\n\t"        // syscall number (write)
        "mov rdi, 1\n\t"        // fd = stdout
        "lea rsi, [rip + msg]\n\t"  // buffer
        "mov rdx, 6\n\t"        // count
        "syscall\n\t"
        "jmp end\n\t"
        "msg: .ascii \"Hello\\n\"\n\t"
        "end:"
        ::: "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
}

// Version avec paramètres
long syscall3(long num, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" (num), "D" (arg1), "S" (arg2), "d" (arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```

---

## 7. Applications offensives

### 7.1 XOR encoder inline

```c
void xor_encode(unsigned char *data, size_t len, unsigned char key) {
    __asm__ __volatile__(
        "1:\n\t"
        "test %1, %1\n\t"
        "jz 2f\n\t"
        "xor byte ptr [%0], %2\n\t"
        "inc %0\n\t"
        "dec %1\n\t"
        "jmp 1b\n\t"
        "2:"
        : "+r" (data), "+r" (len)
        : "r" (key)
        : "cc", "memory"
    );
}
```

### 7.2 Anti-debug technique

```c
int check_debugger(void) {
    int result;
    __asm__ __volatile__(
        "xor eax, eax\n\t"
        "mov al, 1\n\t"         // PTRACE_TRACEME
        "xor edi, edi\n\t"
        "xor esi, esi\n\t"
        "xor edx, edx\n\t"
        "mov r10d, edx\n\t"
        "mov eax, 101\n\t"      // sys_ptrace
        "syscall\n\t"
        "cmp rax, 0\n\t"
        "setl %0"               // result = 1 if debugged
        : "=r" (result)
        :
        : "rax", "rdi", "rsi", "rdx", "r10", "rcx", "r11", "cc"
    );
    return result;
}
```

### 7.3 Shellcode inline

```c
// Exécuter un shellcode depuis un buffer
void exec_shellcode(unsigned char *shellcode) {
    __asm__ __volatile__(
        "jmp *%0"
        :
        : "r" (shellcode)
    );
}

// Shellcode execve("/bin/sh") inline
void spawn_shell(void) {
    __asm__ __volatile__(
        "xor rdx, rdx\n\t"
        "push rdx\n\t"
        "mov rdi, 0x68732f6e69622f\n\t"  // /bin/sh
        "push rdi\n\t"
        "mov rdi, rsp\n\t"
        "push rdx\n\t"
        "push rdi\n\t"
        "mov rsi, rsp\n\t"
        "mov al, 59\n\t"                  // execve
        "syscall"
        ::: "rax", "rdi", "rsi", "rdx", "memory"
    );
}
```

---

## 8. Erreurs courantes

```c
// ERREUR 1 : Oublier les clobbers
__asm__("mov rax, 1");  // MAUVAIS : RAX modifié mais pas déclaré !

// CORRECT :
__asm__("mov rax, 1" ::: "rax");

// ERREUR 2 : Mauvais ordre des opérandes
// En syntaxe Intel : destination, source
// En syntaxe AT&T : source, destination

// ERREUR 3 : Oublier volatile pour les effets de bord
__asm__("mfence");  // Peut être optimisé !
__asm__ __volatile__("mfence" ::: "memory");  // CORRECT

// ERREUR 4 : Confondre les tailles de registres
int x;
__asm__("mov %0, rax" : "=r"(x));  // MAUVAIS : x est 32 bits !
__asm__("mov %0, eax" : "=r"(x));  // CORRECT
```

---

## Résumé

```
SYNTAXE :
__asm__ [volatile] ("instructions" : outputs : inputs : clobbers);

CONTRAINTES COMMUNES :
  "r" = registre général    "a" = RAX    "b" = RBX
  "c" = RCX                 "d" = RDX    "S" = RSI
  "D" = RDI                 "m" = mémoire
  "=" = write-only          "+" = read-write
  "0".."9" = même que opérande N

CLOBBERS SPÉCIAUX :
  "memory" = accès mémoire   "cc" = flags modifiés
```
