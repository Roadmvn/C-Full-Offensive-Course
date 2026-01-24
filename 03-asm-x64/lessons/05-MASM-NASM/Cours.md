# Module : MASM et NASM - Assembleurs standalone

## Objectifs

- Connaître les différences entre MASM et NASM
- Écrire des programmes assembleur standalone
- Créer des shellcodes avec NASM
- Linker assembleur avec C

---

## 1. NASM (Netwide Assembler)

### 1.1 Syntaxe de base

```nasm
; hello.asm - Linux x64
section .data
    msg db "Hello, World!", 10
    len equ $ - msg

section .text
    global _start

_start:
    mov rax, 1          ; syscall write
    mov rdi, 1          ; stdout
    mov rsi, msg        ; buffer
    mov rdx, len        ; length
    syscall
    
    mov rax, 60         ; syscall exit
    xor rdi, rdi        ; code 0
    syscall
```

### 1.2 Compilation NASM

```bash
# Assembler
nasm -f elf64 hello.asm -o hello.o

# Linker
ld hello.o -o hello

# Exécuter
./hello
```

---

## 2. MASM (Microsoft Macro Assembler)

### 2.1 Syntaxe Windows x64

```asm
; hello.asm - Windows x64
.code
main proc
    sub rsp, 28h        ; Shadow space + alignment
    
    mov rcx, -11        ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax        ; handle
    lea rdx, msg        ; buffer
    mov r8, 13          ; length
    lea r9, written     ; bytes written
    push 0              ; lpOverlapped
    call WriteConsoleA
    
    add rsp, 28h
    ret
main endp
end
```

---

## 3. Shellcode avec NASM

### 3.1 Shellcode execve Linux

```nasm
; shellcode.asm
BITS 64

global _start

_start:
    xor rdx, rdx        ; envp = NULL
    push rdx            ; null terminator
    mov rdi, '/bin//sh' ; string (8 bytes)
    push rdi
    mov rdi, rsp        ; pointer to string
    
    push rdx            ; NULL
    push rdi            ; argv[0]
    mov rsi, rsp        ; argv
    
    mov al, 59          ; execve syscall
    syscall
```

### 3.2 Extraire les bytes

```bash
nasm -f bin shellcode.asm -o shellcode.bin
xxd -i shellcode.bin
```

---

## 4. Comparaison NASM vs MASM

| Aspect | NASM | MASM |
|--------|------|------|
| Syntaxe | Intel (dest, src) | Intel (dest, src) |
| Tailles | `byte`, `word`, `dword`, `qword` | `BYTE PTR`, etc. |
| Sections | `section .text` | `.code` |
| OS | Multi-plateforme | Windows |
| Prix | Gratuit | Inclus Visual Studio |

---

## Exercice

Créer un shellcode qui appelle `exit(42)` en Linux x64.

## Solution

```nasm
BITS 64
xor rdi, rdi
mov dil, 42
mov al, 60
syscall
```
