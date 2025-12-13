# Solutions : MASM et NASM

## Solution 1 : Hello World NASM

```nasm
section .data
    msg db "Hello, World!", 10
    len equ $ - msg

section .text
    global _start

_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
```

## Solution 2 : Shellcode /bin/sh

```nasm
BITS 64
xor rdx, rdx
push rdx
mov rdi, 0x68732f6e69622f2f  ; //bin/sh
push rdi
mov rdi, rsp
push rdx
push rdi
mov rsi, rsp
mov al, 59
syscall
```

## Solution 3 : Multiply

```nasm
section .text
global multiply

multiply:
    mov rax, rdi
    imul rax, rsi
    ret
```
