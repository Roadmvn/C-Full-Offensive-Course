# Exercice : Position Independent Code

Convertir ce code NON-PIC en PIC :

```nasm
mov rsi, 0x402000  ; Adresse absolue de "Hello"
; ...
```

Objectif : Utiliser call/pop ou RIP-relative.
