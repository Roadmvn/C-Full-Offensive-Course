# Cours 01 : Systèmes de Numération

## Introduction

Avant même de parler de programmation, nous devons comprendre comment un ordinateur "pense". Et la réponse est simple : **en nombres**. Mais pas n'importe quels nombres.

Nous, humains, utilisons le système **décimal** (base 10) parce que nous avons 10 doigts. Les ordinateurs, eux, n'ont pas de doigts. Ils ont des transistors qui ne connaissent que deux états : **allumé** ou **éteint**, **1** ou **0**.

C'est de là que vient le **binaire** (base 2).

---

## Le Système Décimal (Base 10)

Commençons par ce que vous connaissez déjà, pour bien comprendre le principe.

### Comment fonctionne le décimal

Le nombre **1984** se décompose ainsi :

```
    1       9       8       4
    │       │       │       │
    │       │       │       └── 4 × 10⁰ = 4 × 1    = 4
    │       │       └────────── 8 × 10¹ = 8 × 10   = 80
    │       └────────────────── 9 × 10² = 9 × 100  = 900
    └────────────────────────── 1 × 10³ = 1 × 1000 = 1000
                                                   ──────
                                                    1984
```

**Principe clé** : Chaque position représente une puissance de 10.

```
Position :    3      2      1      0
Puissance :  10³    10²    10¹    10⁰
Valeur :    1000    100     10      1
```

Les symboles utilisés vont de 0 à 9 (10 symboles pour base 10).

---

## Le Système Binaire (Base 2)

### Pourquoi le binaire existe

Un transistor est comme un interrupteur microscopique :

```
    ÉTEINT                    ALLUMÉ
   ┌──────┐                  ┌──────┐
   │      │                  │ ████ │
   │  ○   │     ou           │  ●   │
   │      │                  │ ████ │
   └──────┘                  └──────┘
      0                         1
    (pas de courant)        (courant)
```

Un processeur moderne contient des **milliards** de ces transistors. Chaque transistor ne peut stocker qu'un **bit** (binary digit) : 0 ou 1.

### Comment compter en binaire

En décimal, quand on atteint 9, on remet à 0 et on ajoute 1 à gauche.
En binaire, c'est pareil, mais on remet à 0 dès qu'on atteint 1.

```
Décimal    Binaire     Explication
───────────────────────────────────────
   0         0         Zéro
   1         1         Un
   2        10         On remet à 0, on ajoute 1 à gauche
   3        11
   4       100         On remet tout à 0, on ajoute 1 à gauche
   5       101
   6       110
   7       111
   8      1000         Encore une fois
   9      1001
  10      1010
  ...
```

### Conversion Binaire → Décimal

Même principe que le décimal, mais avec des puissances de 2.

**Exemple : Convertir 1101 en décimal**

```
    1       1       0       1
    │       │       │       │
    │       │       │       └── 1 × 2⁰ = 1 × 1 = 1
    │       │       └────────── 0 × 2¹ = 0 × 2 = 0
    │       └────────────────── 1 × 2² = 1 × 4 = 4
    └────────────────────────── 1 × 2³ = 1 × 8 = 8
                                               ────
                                                13
```

**Donc 1101₂ = 13₁₀**

### Table des puissances de 2 (À MÉMORISER)

```
┌─────────────────────────────────────────────────────────┐
│  2⁰  =    1        2⁸  =   256       2¹⁶ = 65536       │
│  2¹  =    2        2⁹  =   512       2²⁰ = 1048576 (1M)│
│  2²  =    4        2¹⁰ =  1024 (1K)  2²⁴ = 16777216    │
│  2³  =    8        2¹¹ =  2048       2³² = 4294967296  │
│  2⁴  =   16        2¹² =  4096 (4K)                    │
│  2⁵  =   32        2¹³ =  8192                         │
│  2⁶  =   64        2¹⁴ = 16384                         │
│  2⁷  =  128        2¹⁵ = 32768                         │
└─────────────────────────────────────────────────────────┘
```

### Conversion Décimal → Binaire

**Méthode : Divisions successives par 2**

**Exemple : Convertir 42 en binaire**

```
42 ÷ 2 = 21  reste 0  ↑
21 ÷ 2 = 10  reste 1  │
10 ÷ 2 =  5  reste 0  │  Lire de bas en haut
 5 ÷ 2 =  2  reste 1  │
 2 ÷ 2 =  1  reste 0  │
 1 ÷ 2 =  0  reste 1  ↑
```

**Résultat : 42₁₀ = 101010₂**

Vérification : 32 + 8 + 2 = 42 ✓

---

## Bits et Bytes

### Définitions

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  BIT (b)   = 1 chiffre binaire (0 ou 1)                        │
│                                                                 │
│  BYTE (B)  = 8 bits = 1 octet                                  │
│              Peut stocker une valeur de 0 à 255                 │
│                                                                 │
│  NIBBLE    = 4 bits = 1/2 octet                                │
│              Peut stocker une valeur de 0 à 15                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Représentation visuelle d'un byte

```
         1 Byte (8 bits)
    ┌───┬───┬───┬───┬───┬───┬───┬───┐
    │ 1 │ 0 │ 1 │ 0 │ 0 │ 1 │ 1 │ 0 │  = 166 en décimal
    └───┴───┴───┴───┴───┴───┴───┴───┘
      7   6   5   4   3   2   1   0   ← Position du bit
     128  64  32  16   8   4   2   1  ← Valeur de la position
      ↑                           ↑
    MSB                         LSB
    (Most Significant Bit)     (Least Significant Bit)
    (Bit de poids fort)        (Bit de poids faible)
```

### Unités de mesure

```
1 Kilobyte (KB)  = 1024 bytes      = 2¹⁰ bytes
1 Megabyte (MB)  = 1024 KB         = 2²⁰ bytes
1 Gigabyte (GB)  = 1024 MB         = 2³⁰ bytes
1 Terabyte (TB)  = 1024 GB         = 2⁴⁰ bytes
```

**Note** : En marketing, on utilise parfois base 1000 (1 KB = 1000 bytes), mais en informatique technique, on utilise base 1024.

---

## Le Système Hexadécimal (Base 16)

### Pourquoi l'hexadécimal ?

Le binaire est parfait pour les ordinateurs, mais pénible pour les humains. Regardez :

```
Binaire :  11111111 10101010 00001111 11000011
```

C'est illisible. L'hexadécimal résout ce problème.

**Un chiffre hexadécimal = exactement 4 bits (un nibble)**

```
4 bits  →  1 chiffre hexa
8 bits  →  2 chiffres hexa
32 bits →  8 chiffres hexa
```

### Les symboles hexadécimaux

On a besoin de 16 symboles (0-15), mais on n'a que 10 chiffres. Solution : utiliser des lettres.

```
┌─────────────────────────────────────────────────────────────────┐
│  Décimal   Binaire    Hexa  │  Décimal   Binaire    Hexa       │
│  ─────────────────────────  │  ─────────────────────────       │
│     0       0000       0    │     8       1000       8         │
│     1       0001       1    │     9       1001       9         │
│     2       0010       2    │    10       1010       A         │
│     3       0011       3    │    11       1011       B         │
│     4       0100       4    │    12       1100       C         │
│     5       0101       5    │    13       1101       D         │
│     6       0110       6    │    14       1110       E         │
│     7       0111       7    │    15       1111       F         │
└─────────────────────────────────────────────────────────────────┘
```

### Notation hexadécimale

Plusieurs conventions existent pour indiquer qu'un nombre est en hexadécimal :

```
0xFF      ← Notation C/C++ (préfixe 0x)
FFh       ← Notation assembleur (suffixe h)
$FF       ← Notation anciens systèmes
#FF       ← Notation web (couleurs)
```

Dans ce cours, nous utiliserons principalement **0x** (notation C).

### Conversion Binaire ↔ Hexadécimal

C'est la conversion la plus simple : grouper par 4 bits.

**Binaire → Hexadécimal**

```
Binaire :   1111  1111  1010  1010  0000  1111  1100  0011
              ↓     ↓     ↓     ↓     ↓     ↓     ↓     ↓
Hexa :        F     F     A     A     0     F     C     3

Résultat : 0xFFAA0FC3
```

**Hexadécimal → Binaire**

```
Hexa :       D     E     A     D     B     E     E     F
             ↓     ↓     ↓     ↓     ↓     ↓     ↓     ↓
Binaire :  1101  1110  1010  1101  1011  1110  1110  1111

Résultat : 11011110101011011011111011101111
```

### Conversion Hexadécimal → Décimal

Même méthode que pour le binaire, avec puissances de 16.

**Exemple : 0x1A3 en décimal**

```
    1       A       3
    │       │       │
    │       │       └── 3  × 16⁰ = 3  × 1   = 3
    │       └────────── 10 × 16¹ = 10 × 16  = 160
    └────────────────── 1  × 16² = 1  × 256 = 256
                                            ─────
                                             419
```

**0x1A3 = 419₁₀**

### Conversion Décimal → Hexadécimal

Divisions successives par 16.

**Exemple : 1000 en hexadécimal**

```
1000 ÷ 16 = 62  reste 8   ↑
  62 ÷ 16 =  3  reste 14 (E)  │  Lire de bas en haut
   3 ÷ 16 =  0  reste 3   ↑
```

**1000₁₀ = 0x3E8**

---

## Application : Lecture de Dumps Mémoire

Dans le domaine de la sécurité, vous verrez souvent des "dumps" hexadécimaux. Voici comment les lire :

```
Adresse    Contenu hexadécimal                    ASCII
──────────────────────────────────────────────────────────
0x00401000: 48 65 6C 6C 6F 20 57 6F 72 6C 64 00   Hello World.
0x0040100C: 4D 5A 90 00 03 00 00 00               MZ......
```

### Comprendre cette représentation

```
       Adresse en mémoire (hexa)
              │
              ▼
       0x00401000: 48 65 6C 6C 6F 20 57 6F 72 6C 64 00
                    │                              │
                    └── Chaque paire = 1 byte ─────┘
                        48 = 'H' en ASCII
                        65 = 'e' en ASCII
                        etc.
```

### Table ASCII partielle (À connaître)

```
┌───────────────────────────────────────────────────────┐
│  Hexa   Car    Hexa   Car    Hexa   Car              │
│  ─────────────────────────────────────────────       │
│  0x00   NUL    0x30   '0'    0x41   'A'              │
│  0x0A   LF     0x31   '1'    0x42   'B'              │
│  0x0D   CR     ...           ...                     │
│  0x20   ' '    0x39   '9'    0x5A   'Z'              │
│  0x21   '!'    0x3A   ':'    0x61   'a'              │
│  ...           ...           0x7A   'z'              │
└───────────────────────────────────────────────────────┘

Règles rapides :
- '0' à '9' : 0x30 à 0x39
- 'A' à 'Z' : 0x41 à 0x5A
- 'a' à 'z' : 0x61 à 0x7A
```

---

## Application en Sécurité Offensive

### Shellcode

Un shellcode est une séquence d'instructions machine, souvent représentée en hexadécimal :

```c
// Shellcode pour exécuter /bin/sh sur Linux x86
char shellcode[] =
    "\x31\xc0"              // xor eax, eax
    "\x50"                  // push eax
    "\x68\x2f\x2f\x73\x68"  // push "//sh"
    "\x68\x2f\x62\x69\x6e"  // push "/bin"
    "\x89\xe3"              // mov ebx, esp
    "\x50"                  // push eax
    "\x53"                  // push ebx
    "\x89\xe1"              // mov ecx, esp
    "\xb0\x0b"              // mov al, 0x0b (execve)
    "\xcd\x80";             // int 0x80
```

Chaque `\x??` représente un byte en hexadécimal. Sans comprendre l'hexadécimal, ce code serait incompréhensible.

### Analyse de fichiers binaires

Les fichiers exécutables commencent par des "magic bytes" :

```
Windows EXE :  4D 5A           ("MZ" - Mark Zbikowski)
Linux ELF :    7F 45 4C 46     (".ELF")
PDF :          25 50 44 46     ("%PDF")
PNG :          89 50 4E 47     (.PNG)
```

---

## Opérations Bit à Bit (Aperçu)

Nous les reverrons en détail plus tard, mais voici un aperçu :

### AND (&) - Si les deux bits sont 1, résultat = 1

```
    1010
AND 1100
────────
    1000
```

### OR (|) - Si au moins un bit est 1, résultat = 1

```
    1010
 OR 1100
────────
    1110
```

### XOR (^) - Si les bits sont différents, résultat = 1

```
    1010
XOR 1100
────────
    0110
```

**Le XOR est fondamental en cryptographie et en sécurité !**

### NOT (~) - Inverse chaque bit

```
NOT 1010
────────
    0101
```

---

## Résumé

```
┌─────────────────────────────────────────────────────────────────┐
│                        POINTS CLÉS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • Binaire (base 2) : Le langage des ordinateurs               │
│                                                                 │
│  • Hexadécimal (base 16) : Représentation lisible du binaire   │
│                                                                 │
│  • 1 byte = 8 bits = 2 chiffres hexa                           │
│                                                                 │
│  • Conversion binaire ↔ hexa : grouper/dégrouper par 4 bits    │
│                                                                 │
│  • Les adresses mémoire sont en hexadécimal                    │
│                                                                 │
│  • Le shellcode et l'analyse binaire nécessitent l'hexa        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Exercices Recommandés

Avant de passer au cours suivant, assurez-vous de pouvoir :

1. Convertir n'importe quel nombre < 256 entre binaire, décimal et hexa
2. Lire une chaîne ASCII à partir de son dump hexadécimal
3. Identifier les "magic bytes" courants

→ Voir [exercices/exercice-01.md](../exercices/exercice-01.md)

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [README du Module](../README.md) | [02 - Le Processeur](02-processeur.md) |
