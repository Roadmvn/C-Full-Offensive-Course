# Solution : Null-Free

```nasm
xor rax, rax    ; ou xor eax, eax
xor rdi, rdi    ; ou xor edi, edi
xor rsi, rsi
xor rdx, rdx

; Encore plus court :
xor eax, eax
cdq             ; RDX = sign-extend de EAX = 0
xor edi, edi
xor esi, esi
```
