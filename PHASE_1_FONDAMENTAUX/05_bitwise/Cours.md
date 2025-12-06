# 05 - Opérations Bitwise

## 🎯 Ce que tu vas apprendre

- Ce que sont les opérations bit à bit (bitwise)
- Comment manipuler directement les bits en mémoire
- Les opérateurs AND, OR, XOR, NOT et shifts
- Les masques binaires et flags
- Applications cruciales en Red Team (XOR cipher, masking, etc.)

## 📚 Théorie

### Concept 1 : Pourquoi manipuler les bits ?

**C'est quoi ?**
Les opérations bitwise travaillent directement sur les bits individuels d'un nombre, au niveau le plus bas.

**Pourquoi ça existe ?**
Parce que c'est :
- **Rapide** : Les opérations sur bits sont les plus rapides du processeur
- **Compact** : Stocker plusieurs booléens dans un seul byte
- **Puissant** : Manipulation précise de données binaires, flags, permissions

**Comment ça marche ?**
Au lieu de manipuler le nombre entier, tu manipules chaque bit individuellement.

```
Nombre : 13

Représentation décimale : 13
Représentation binaire :  00001101
                          ||||||||
                          |||||||└─ Bit 0 (LSB) = 1
                          ||||||└── Bit 1 = 0
                          |||||└─── Bit 2 = 1
                          ||||└──── Bit 3 = 1
                          |||└───── Bit 4 à 7 = 0
                          ...
                          MSB (bit de poids fort)
```

### Concept 2 : Les opérateurs bitwise

| Opérateur | Nom | Description |
|-----------|-----|-------------|
| `&` | AND | 1 si les DEUX bits sont 1 |
| `\|` | OR | 1 si AU MOINS UN bit est 1 |
| `^` | XOR | 1 si les bits sont DIFFÉRENTS |
| `~` | NOT | Inverse TOUS les bits |
| `<<` | Left shift | Décale les bits vers la gauche |
| `>>` | Right shift | Décale les bits vers la droite |

### Concept 3 : AND bitwise (&)

**C'est quoi ?**
Retourne 1 seulement si les DEUX bits sont 1.

**Table de vérité** :
```
A  B  A & B
0  0    0
0  1    0
1  0    0
1  1    1    ← 1 seulement si les DEUX sont 1
```

**Exemple** :
```c
unsigned char a = 12;  // 0b00001100
unsigned char b = 10;  // 0b00001010
unsigned char c = a & b;

// Calcul bit par bit :
  00001100  (12)
& 00001010  (10)
-----------
  00001000  (8)
```

**Schéma détaillé** :
```
Bit 7  Bit 6  Bit 5  Bit 4  Bit 3  Bit 2  Bit 1  Bit 0
  0      0      0      0      1      1      0      0   (12)
  0      0      0      0      1      0      1      0   (10)
  ─      ─      ─      ─      ─      ─      ─      ─
  0      0      0      0      1      0      0      0   (8)
  │      │      │      │      │      │      │      │
  0&0    0&0    0&0    0&0    1&1    1&0    0&1    0&0
  =0     =0     =0     =0     =1     =0     =0     =0
```

**Application : Masquer des bits (extraire une partie)**

```c
// Extraire les 4 bits de droite (low nibble)
unsigned char value = 0b11010110;
unsigned char mask  = 0b00001111;
unsigned char low   = value & mask;  // 0b00000110

// Vérifier si un bit spécifique est activé
unsigned char flags = 0b00101000;
if (flags & 0b00001000) {  // Bit 3 activé ?
    printf("Bit 3 est à 1\n");
}
```

### Concept 4 : OR bitwise (|)

**C'est quoi ?**
Retourne 1 si AU MOINS UN des deux bits est 1.

**Table de vérité** :
```
A  B  A | B
0  0    0
0  1    1    ← 1 si au moins un est 1
1  0    1
1  1    1
```

**Exemple** :
```c
unsigned char a = 12;  // 0b00001100
unsigned char b = 10;  // 0b00001010
unsigned char c = a | b;

// Calcul bit par bit :
  00001100  (12)
| 00001010  (10)
-----------
  00001110  (14)
```

**Application : Activer des bits (set)**

```c
// Activer le bit 2
unsigned char flags = 0b00000000;
flags = flags | 0b00000100;  // flags = 0b00000100

// Raccourci :
flags |= (1 << 2);  // Shift 1 de 2 positions puis OR
```

### Concept 5 : XOR bitwise (^)

**C'est quoi ?**
Retourne 1 si les bits sont DIFFÉRENTS (OU exclusif).

**Table de vérité** :
```
A  B  A ^ B
0  0    0
0  1    1    ← 1 si différents
1  0    1
1  1    0    ← 0 si identiques
```

**Exemple** :
```c
unsigned char a = 12;  // 0b00001100
unsigned char b = 10;  // 0b00001010
unsigned char c = a ^ b;

// Calcul bit par bit :
  00001100  (12)
^ 00001010  (10)
-----------
  00000110  (6)
```

**Propriété MAGIQUE du XOR** :

```c
x ^ 0 = x      // XOR avec 0 : inchangé
x ^ x = 0      // XOR avec soi-même : 0
x ^ y ^ y = x  // XOR est réversible !
```

**Application 1 : Swap sans variable temporaire**

```c
int a = 5, b = 10;
a = a ^ b;  // a = 5 ^ 10
b = a ^ b;  // b = (5 ^ 10) ^ 10 = 5
a = a ^ b;  // a = (5 ^ 10) ^ 5 = 10
// Résultat : a=10, b=5
```

**Application 2 : Chiffrement XOR (cipher)**

```c
// Chiffrer
unsigned char data[] = "SECRET";
unsigned char key = 0xAA;
for (int i = 0; i < 6; i++) {
    data[i] ^= key;  // Chiffre
}

// Déchiffrer (même opération !)
for (int i = 0; i < 6; i++) {
    data[i] ^= key;  // Déchiffre
}
```

**Pourquoi ça marche ?**

```
Original : 'S' = 0x53
Clé :      0xAA

Chiffrement :
0x53 ^ 0xAA = 0xF9  (chiffré)

Déchiffrement :
0xF9 ^ 0xAA = 0x53  (original récupéré !)
```

### Concept 6 : NOT bitwise (~)

**C'est quoi ?**
Inverse TOUS les bits (0 devient 1, 1 devient 0).

**Exemple** :
```c
unsigned char a = 0b00001111;
unsigned char b = ~a;  // 0b11110000

// Attention avec signed :
unsigned char x = 5;   // 0b00000101
unsigned char y = ~x;  // 0b11111010 = 250

signed char z = 5;     // 0b00000101
signed char w = ~z;    // 0b11111010 = -6 (complément à 2)
```

**Application : Désactiver un bit (clear)**

```c
unsigned char flags = 0b00101100;
// Désactiver le bit 2
flags = flags & ~(1 << 2);
//              ↑ ~0b00000100 = 0b11111011
// flags & 0b11111011 → bit 2 mis à 0
```

### Concept 7 : Left Shift (<<)

**C'est quoi ?**
Décale tous les bits vers la GAUCHE, ajoute des 0 à droite.

**Effet** : Multiplication par 2^n

```c
unsigned char a = 5;  // 0b00000101
unsigned char b = a << 2;

  00000101  (5)
<<  2
-----------
  00010100  (20)
```

**Schéma** :
```
Shift de 2 positions vers la gauche :
Avant : 0 0 0 0 0 1 0 1  (5)
Après : 0 0 0 1 0 1 0 0  (20)
         ← ← décalage
             0 0 ajoutés à droite
```

**Résultat** : `5 << 2 = 5 * 2^2 = 5 * 4 = 20`

**Applications** :
```c
// Créer un masque avec le bit N activé
unsigned char mask = 1 << 3;  // 0b00001000

// Multiplication rapide par puissance de 2
int x = 10 << 3;  // 10 * 8 = 80
```

### Concept 8 : Right Shift (>>)

**C'est quoi ?**
Décale tous les bits vers la DROITE.

**Effet** : Division par 2^n (division entière)

```c
unsigned char a = 20;  // 0b00010100
unsigned char b = a >> 2;

  00010100  (20)
>>  2
-----------
  00000101  (5)
```

**Schéma** :
```
Shift de 2 positions vers la droite :
Avant : 0 0 0 1 0 1 0 0  (20)
Après : 0 0 0 0 0 1 0 1  (5)
        0 0 ajoutés    → →
             décalage
```

**Résultat** : `20 >> 2 = 20 / 2^2 = 20 / 4 = 5`

**Attention : Signed vs Unsigned**

```c
// Unsigned : ajoute des 0
unsigned char a = 0b10000000;  // 128
unsigned char b = a >> 2;      // 0b00100000 = 32

// Signed : préserve le signe (arithmetic shift)
signed char c = -128;          // 0b10000000
signed char d = c >> 2;        // 0b11100000 = -32
```

### Concept 9 : Masques et manipulation de flags

**C'est quoi un masque ?**
Un nombre binaire utilisé avec & ou | pour isoler ou modifier des bits spécifiques.

**Pattern : Vérifier un bit**
```c
#define BIT_SET(value, bit)   ((value) & (1 << (bit)))
#define BIT_CLEAR(value, bit) (!((value) & (1 << (bit))))

unsigned char flags = 0b00101000;
if (BIT_SET(flags, 3)) {
    printf("Bit 3 est activé\n");
}
```

**Pattern : Activer un bit**
```c
#define SET_BIT(value, bit)   ((value) |= (1 << (bit)))

unsigned char flags = 0b00000000;
SET_BIT(flags, 5);  // flags = 0b00100000
```

**Pattern : Désactiver un bit**
```c
#define CLEAR_BIT(value, bit) ((value) &= ~(1 << (bit)))

unsigned char flags = 0b00101000;
CLEAR_BIT(flags, 3);  // flags = 0b00100000
```

**Pattern : Toggle (inverser) un bit**
```c
#define TOGGLE_BIT(value, bit) ((value) ^= (1 << (bit)))

unsigned char flags = 0b00101000;
TOGGLE_BIT(flags, 5);  // flags = 0b00001000 (bit 5 : 1→0)
TOGGLE_BIT(flags, 5);  // flags = 0b00101000 (bit 5 : 0→1)
```

### Concept 10 : Flags et permissions (style Unix)

```c
// Définir les permissions
#define READ    0b100  // 4
#define WRITE   0b010  // 2
#define EXECUTE 0b001  // 1

// Combiner des permissions
unsigned char perms = READ | WRITE;  // 0b110 = 6 (rw-)

// Vérifier une permission
if (perms & EXECUTE) {
    printf("Exécution autorisée\n");
} else {
    printf("Pas de droit d'exécution\n");
}

// Ajouter une permission
perms |= EXECUTE;  // perms = 0b111 = 7 (rwx)

// Retirer une permission
perms &= ~WRITE;   // perms = 0b101 = 5 (r-x)
```

**Schéma Unix permissions** :
```
rwx r-x r--
│││ │││ │││
│││ │││ │└└─ Others: read
│││ │└└───── Group: read + execute
│└└────────── Owner: read + write + execute

Conversion :
Owner  : rwx = 111 = 7
Group  : r-x = 101 = 5
Others : r-- = 100 = 4
→ chmod 754
```

## 🔍 Visualisation : Extraction de nibbles

```c
unsigned char byte = 0b10110011;

// Extraire le high nibble (4 bits de gauche)
unsigned char high = (byte >> 4) & 0x0F;

// Extraire le low nibble (4 bits de droite)
unsigned char low = byte & 0x0F;
```

**Processus** :
```
Byte : 0b10110011

High nibble :
1. Shift right 4 : 0b10110011 >> 4 = 0b00001011
2. Masque 0x0F :   0b00001011 & 0b00001111 = 0b00001011 (11)

Low nibble :
1. Masque 0x0F :   0b10110011 & 0b00001111 = 0b00000011 (3)
```

## 🎯 Application Red Team

### 1. XOR Cipher - Encoding de shellcode

**Le cipher le plus simple et efficace** :

```c
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x31, 0xc0, 0x50, 0xff, 0xe4
};
unsigned char key = 0xAA;

// Encoder (avant envoi)
for (int i = 0; i < sizeof(shellcode); i++) {
    shellcode[i] ^= key;
}

// Décoder (au runtime)
for (int i = 0; i < sizeof(shellcode); i++) {
    shellcode[i] ^= key;
}
```

**Pourquoi c'est utilisé ?**
- Rapide
- Réversible (même opération pour encoder/décoder)
- Contourne la détection basique de signatures

### 2. Masking pour extraction de données

**Parser un header TCP/IP** :

```c
// Version IP (4 bits de gauche)
unsigned char ip_version = (header[0] >> 4) & 0x0F;

// IHL - Internet Header Length (4 bits de droite)
unsigned char ihl = header[0] & 0x0F;

// Flags TCP (3 bits)
unsigned char tcp_flags = tcp_header[13];
int syn = (tcp_flags >> 1) & 0x01;  // Bit SYN
int ack = (tcp_flags >> 4) & 0x01;  // Bit ACK
```

### 3. Bit manipulation pour permissions Linux

```c
// Vérifier les capabilities d'un processus
unsigned long caps = get_process_caps();
if (caps & CAP_NET_RAW) {
    // Peut créer des raw sockets
    create_raw_socket();
}
```

### 4. Shifts pour optimisation

**Multiplication/division rapide** :

```c
// Au lieu de :
int x = value * 16;  // Compile en plusieurs instructions

// Utiliser :
int x = value << 4;  // 1 instruction CPU
```

### 5. Encoding multi-byte XOR

```c
unsigned char data[] = "PAYLOAD";
unsigned char key[] = {0xDE, 0xAD, 0xBE, 0xEF};
int key_len = 4;

for (int i = 0; i < sizeof(data); i++) {
    data[i] ^= key[i % key_len];  // Rotation de clé
}
```

### 6. Checksums et hashing simple

```c
// XOR checksum
unsigned char checksum = 0;
for (int i = 0; i < len; i++) {
    checksum ^= data[i];
}
```

### 7. Obfuscation de constantes

```c
// Au lieu de :
int port = 4444;  // Détectable dans le binaire

// Obfusqué :
int port = (0x1000 | 0x15C);  // 4444 = 0x115C
port = (port << 1) >> 1;       // Operations inutiles pour confusion
```

### 8. Manipulation de couleurs (RGB)

```c
// Format : 0xRRGGBB
unsigned int color = 0xFF5733;

// Extraire les composantes
unsigned char red   = (color >> 16) & 0xFF;
unsigned char green = (color >> 8) & 0xFF;
unsigned char blue  = color & 0xFF;

// Reconstruire
unsigned int new_color = (red << 16) | (green << 8) | blue;
```

## 📝 Points clés à retenir

- `&` (AND) : masquer, extraire des bits
- `|` (OR) : activer des bits, combiner des flags
- `^` (XOR) : toggle, cipher réversible
- `~` (NOT) : inverser tous les bits
- `<<` : décale gauche = multiplication par 2^n
- `>>` : décale droite = division par 2^n
- XOR est réversible : `x ^ k ^ k = x`
- Les shifts sont plus rapides que * et /
- Les masques permettent d'isoler des bits spécifiques
- Les bitwise sont cruciaux pour parsing binaire, crypto, et optimisation

## ➡️ Prochaine étape

Maintenant que tu maîtrises les opérations sur bits, tu vas apprendre à contrôler le flux d'exécution avec les [conditions](../06_conditions/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
