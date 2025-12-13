# Solution : Position Independent Code

```nasm
jmp get_string
got_string:
    pop rsi           ; RSI = adresse de "Hello" (PIC!)
    ; ... utiliser rsi

get_string:
    call got_string
    db "Hello", 0
```

Ou avec RIP-relative (x64) :

```nasm
lea rsi, [rip + string]
; ...
string: db "Hello", 0
```
