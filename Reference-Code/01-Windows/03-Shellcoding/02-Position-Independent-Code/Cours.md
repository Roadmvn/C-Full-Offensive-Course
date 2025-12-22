# Module : Position Independent Code (PIC)

## Objectifs

- Comprendre pourquoi le shellcode doit être PIC
- Maîtriser les techniques pour éviter les adresses absolues
- Écrire du shellcode relocatable

---

## 1. Le problème des adresses absolues

```
SANS PIC :
mov rax, 0x401234    ; Adresse absolue codée en dur
                     ; Si le code est chargé ailleurs → CRASH !

AVEC PIC :
call get_rip
get_rip:
pop rax              ; RAX = adresse actuelle (dynamique)
```

---

## 2. Techniques PIC

### 2.1 Call/Pop pour obtenir l'adresse courante

```nasm
; Obtenir l'adresse de data dynamiquement
jmp get_data
got_data:
    pop rsi              ; RSI = adresse de "Hello"
    ; utiliser RSI...

get_data:
    call got_data
    db "Hello", 0
```

### 2.2 LEA avec RIP-relative (x64)

```nasm
; x64 supporte l'adressage RIP-relative
lea rsi, [rip + data]    ; Charge l'adresse relative à RIP
; ...
data: db "Hello", 0
```

### 2.3 Calcul d'offset

```nasm
call delta
delta:
    pop rbx              ; RBX = adresse de delta
    sub rbx, delta       ; RBX = base du shellcode
    lea rsi, [rbx + msg] ; Accès à msg de façon PIC
```

---

## 3. Exemple complet

```nasm
BITS 64

start:
    jmp call_shellcode

shellcode:
    pop rsi              ; RSI = adresse de "/bin/sh"
    xor rax, rax
    push rax
    push rsi
    mov rdi, rsi
    mov rsi, rsp
    xor rdx, rdx
    mov al, 59
    syscall

call_shellcode:
    call shellcode
    db "/bin/sh", 0
```

---

## Résumé

| Technique | Usage |
|-----------|-------|
| Call/Pop | Classique, fonctionne partout |
| RIP-relative | x64 uniquement, plus propre |
| Offset calcul | Pour structures complexes |
