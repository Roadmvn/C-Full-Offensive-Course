# Cours : Manipulation de Bits (Bit Manipulation)

## 1. Introduction

La manipulation de bits est l'art de travailler directement avec les **bits individuels** d'un nombre. C'est une compétence fondamentale en :
- **Optimisation** : Les opérations binaires sont extrêmement rapides
- **Cryptographie** : Chiffrement, hachage
- **Réseaux** : Masques IP, protocoles
- **Systèmes embarqués** : Contrôle de registres matériels
- **Exploitation** : Shellcode, ROP chains, obfuscation

En C, vous avez un contrôle **total** sur chaque bit, contrairement aux langages de haut niveau.

## 2. Visualisation : Représentation Binaire

```ascii
UN ENTIER (32 bits) : int x = 42;

┌─────────────────────────────────────────┐
│  Bit 31 (MSB - Most Significant Bit)   │
│     ↓                                    │
│  0000 0000 0000 0000 0000 0000 0010 1010│
│                                    ↑     │
│                  Bit 0 (LSB - Least Sig)│
└─────────────────────────────────────────┘

En décimal : 42
En binaire : 0b00101010
En hexa    : 0x0000002A

Bit indexing (de droite à gauche):
Bit 7: 0
Bit 6: 0
Bit 5: 1  ← (32)
Bit 4: 0
Bit 3: 1  ← (8)
Bit 2: 0
Bit 1: 1  ← (2)
Bit 0: 0
       ─────
       = 42
```

## 3. Opérateurs Binaires de Base

### 3.1 AND (`&`) - ET Binaire

Retourne 1 seulement si **les deux bits sont à 1**.

```c
int a = 0b1100;  // 12
int b = 0b1010;  // 10
int c = a & b;   // 0b1000 = 8

Détail :
  1100  (a)
& 1010  (b)
------
  1000  (c)
```

**Usage** : Masquer/Extraire des bits spécifiques.

```c
// Vérifier si un bit est activé
int flags = 0b10110;
if (flags & 0b00010) {  // Bit 1 actif ?
    printf("Bit 1 activé\n");
}

// Extraire les 4 bits de poids faible
int valeur = 0xABCD;
int lower_nibble = valeur & 0x000F;  // 0x000D
```

### 3.2 OR (`|`) - OU Binaire

Retourne 1 si **au moins un des bits est à 1**.

```c
int a = 0b1100;  // 12
int b = 0b1010;  // 10
int c = a | b;   // 0b1110 = 14

Détail :
  1100  (a)
| 1010  (b)
------
  1110  (c)
```

**Usage** : Activer des bits spécifiques.

```c
// Activer le bit 3
int flags = 0b00010;
flags = flags | 0b01000;  // flags = 0b01010

// Activer plusieurs bits à la fois
int permissions = 0b000;
permissions |= 0b100;  // READ
permissions |= 0b010;  // WRITE
// permissions = 0b110 (READ + WRITE)
```

### 3.3 XOR (`^`) - OU Exclusif

Retourne 1 si **les bits sont différents**.

```c
int a = 0b1100;  // 12
int b = 0b1010;  // 10
int c = a ^ b;   // 0b0110 = 6

Détail :
  1100  (a)
^ 1010  (b)
------
  0110  (c)
```

**Usage** : Toggle (inverser), swap sans variable temporaire, chiffrement simple.

```c
// Toggle (inverser) un bit
int flags = 0b1010;
flags ^= 0b0010;  // Toggle bit 1 → 0b1000

// Swap deux variables sans tmp
int a = 5, b = 10;
a ^= b;  // a = 5 ^ 10
b ^= a;  // b = 10 ^ (5 ^ 10) = 5
a ^= b;  // a = (5 ^ 10) ^ 5 = 10
// Résultat : a=10, b=5

// Chiffrement XOR basique
char message[] = "SECRET";
char cle = 0xAB;
for (int i = 0; message[i]; i++) {
    message[i] ^= cle;  // Chiffrement
}
// Pour déchiffrer, appliquer XOR à nouveau
for (int i = 0; message[i]; i++) {
    message[i] ^= cle;  // Déchiffrement
}
```

### 3.4 NOT (`~`) - Complément

Inverse **tous les bits** (0→1, 1→0).

```c
unsigned int a = 0b00001100;  // 12
unsigned int b = ~a;          // 0b11110011 (en 8 bits)

// Sur 32 bits :
int x = 0;
int y = ~x;  // 0xFFFFFFFF = -1 (complément à 2)
```

**Usage** : Créer des masques, complément binaire.

```c
// Désactiver un bit (mettre à 0)
int flags = 0b1111;
flags &= ~0b0010;  // Désactive bit 1 → 0b1101
```

## 4. Décalages de Bits (Shifts)

### 4.1 Décalage à Gauche (`<<`)

Déplace les bits vers la **gauche**, équivaut à **multiplier par 2^n**.

```c
int x = 5;       // 0b0101
int y = x << 1;  // 0b1010 = 10 (5 * 2)
int z = x << 2;  // 0b10100 = 20 (5 * 4)

Visualisation :
Original : 0000 0101 (5)
<< 1     : 0000 1010 (10)
<< 2     : 0001 0100 (20)
```

**Usage** : Multiplication rapide, création de masques.

```c
// Calculer 2^n
int puissance = 1 << 10;  // 2^10 = 1024

// Créer un masque pour le bit N
int masque_bit_5 = 1 << 5;  // 0b100000 = 32
```

### 4.2 Décalage à Droite (`>>`)

Déplace les bits vers la **droite**, équivaut à **diviser par 2^n**.

```c
int x = 20;      // 0b10100
int y = x >> 1;  // 0b01010 = 10 (20 / 2)
int z = x >> 2;  // 0b00101 = 5 (20 / 4)

Visualisation :
Original : 0001 0100 (20)
>> 1     : 0000 1010 (10)
>> 2     : 0000 0101 (5)
```

**⚠️ Attention** : Pour les nombres **signés négatifs**, le comportement dépend de l'implémentation (shift arithmétique vs logique).

```c
int x = -8;       // 0xFFFFFFF8 (complément à 2)
int y = x >> 1;   // Peut donner -4 ou un grand nombre positif
```

**Usage** : Division rapide, extraction de bits.

```c
// Extraire l'octet de poids fort (byte 3)
unsigned int valeur = 0x12345678;
unsigned int byte3 = (valeur >> 24) & 0xFF;  // 0x12
```

## 5. Techniques Courantes

### 5.1 Vérifier si un Bit est Activé

```c
int check_bit(int num, int pos) {
    return (num & (1 << pos)) != 0;
}

// Exemple
int flags = 0b1010;
if (check_bit(flags, 3)) {
    printf("Bit 3 est activé\n");
}
```

### 5.2 Activer un Bit

```c
int set_bit(int num, int pos) {
    return num | (1 << pos);
}

// Exemple
int flags = 0b0000;
flags = set_bit(flags, 2);  // flags = 0b0100
```

### 5.3 Désactiver un Bit

```c
int clear_bit(int num, int pos) {
    return num & ~(1 << pos);
}

// Exemple
int flags = 0b1111;
flags = clear_bit(flags, 2);  // flags = 0b1011
```

### 5.4 Toggle (Inverser) un Bit

```c
int toggle_bit(int num, int pos) {
    return num ^ (1 << pos);
}

// Exemple
int flags = 0b1010;
flags = toggle_bit(flags, 1);  // flags = 0b1000
```

### 5.5 Compter le Nombre de Bits à 1

```c
int count_bits(unsigned int n) {
    int count = 0;
    while (n) {
        count += n & 1;  // Ajoute le bit de poids faible
        n >>= 1;         // Décale d'une position
    }
    return count;
}

// Exemple
printf("%d\n", count_bits(0b1011));  // 3
```

### 5.6 Vérifier si une Puissance de 2

```c
int is_power_of_2(unsigned int n) {
    return n && !(n & (n - 1));
}

// Explication :
// 16 = 0b10000
// 15 = 0b01111
// 16 & 15 = 0 → C'est une puissance de 2
```

### 5.7 Inverser les Bits

```c
unsigned int reverse_bits(unsigned int n) {
    unsigned int result = 0;
    for (int i = 0; i < 32; i++) {
        result <<= 1;           // Décale le résultat
        result |= (n & 1);      // Ajoute le bit de poids faible de n
        n >>= 1;                // Passe au bit suivant de n
    }
    return result;
}
```

### 5.8 Swap de Nibbles (4 bits)

```c
unsigned char swap_nibbles(unsigned char x) {
    return ((x & 0x0F) << 4) | ((x & 0xF0) >> 4);
}

// Exemple : 0xAB → 0xBA
```

## 6. Applications en Cybersécurité

### 6.1 Permissions Unix

```c
#define READ    0b100  // 4
#define WRITE   0b010  // 2
#define EXECUTE 0b001  // 1

int permissions = READ | WRITE;  // 0b110 = 6 (rw-)

if (permissions & EXECUTE) {
    printf("Exécutable\n");
}
```

### 6.2 Flags dans un Shellcode

```c
// Flags pour un exploit
#define FLAG_DEP_BYPASS    (1 << 0)  // Bit 0
#define FLAG_ASLR_BYPASS   (1 << 1)  // Bit 1
#define FLAG_PIE_BYPASS    (1 << 2)  // Bit 2
#define FLAG_STACK_PIVOT   (1 << 3)  // Bit 3

int exploit_flags = 0;
exploit_flags |= FLAG_ASLR_BYPASS;
exploit_flags |= FLAG_PIE_BYPASS;

if (exploit_flags & FLAG_ASLR_BYPASS) {
    // Code pour bypass ASLR
}
```

### 6.3 Obfuscation Simple

```c
// Cacher une string avec XOR
char hidden[] = "\x12\x34\x56\x78";  // "SECRET" ^ 0x42
char key = 0x42;

for (int i = 0; i < strlen(hidden); i++) {
    hidden[i] ^= key;  // Révèle "SECRET"
}
```

### 6.4 Endianness Swap

```c
// Convertir entre Little Endian et Big Endian
uint32_t swap_endian(uint32_t x) {
    return ((x & 0x000000FF) << 24) |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0xFF000000) >> 24);
}

// Exemple : 0x12345678 → 0x78563412
```

## 7. Sous le Capot

### En Assembleur (x86-64)

```asm
; x = 5 | 3
mov eax, 5          ; EAX = 5
or  eax, 3          ; EAX = 5 | 3 = 7

; x = 8 << 2
mov eax, 8          ; EAX = 8
shl eax, 2          ; Shift Left de 2 bits → 32

; Vérifier bit 3 de x
mov eax, [x]
bt  eax, 3          ; Bit Test : met le bit dans CF (Carry Flag)
jc  bit_is_set      ; Jump if Carry
```

### Performance

Les opérations binaires sont **extrêmement rapides** (1 cycle CPU).

```c
// Lent (multiplication)
int x = n * 8;      // ~3-10 cycles

// Rapide (shift)
int x = n << 3;     // 1 cycle
```

## 8. Sécurité & Risques

### ⚠️ Shift sur Valeurs Négatives

```c
int x = -4;
int y = x >> 1;  // Comportement dépend de l'implémentation !
```

### ⚠️ Shift Supérieur à la Taille

```c
int x = 1 << 32;  // Comportement indéfini sur int 32 bits !
```

### ⚠️ Overflow

```c
int x = 1 << 31;  // Pour int signé : valeur la plus négative !
```

## 9. Bonnes Pratiques

1. **Utilisez `unsigned`** pour les opérations binaires
2. **Commentez** vos masques : `0x0F /* Lower nibble */`
3. **Définissez des constantes** au lieu de magic numbers
4. **Vérifiez** la taille des types (`sizeof`)
5. **Testez** sur différentes architectures (endianness)

## 10. Exercice Mental

Que vaut `x` ?
```c
unsigned int x = 0b1010;
x = (x >> 1) | (x << 3);
```

<details>
<summary>Réponse</summary>

**x = 0b1010101 = 85**

Étapes :
1. `x = 0b1010` (10)
2. `x >> 1 = 0b0101` (5)
3. `x << 3 = 0b1010000` (80)
4. `0b0101 | 0b1010000 = 0b1010101` (85)
</details>

## 11. Ressources Complémentaires

- [Bitwise operations](https://en.wikipedia.org/wiki/Bitwise_operation)
- [Bit manipulation tricks](https://graphics.stanford.edu/~seander/bithacks.html)
- [XOR encryption](https://en.wikipedia.org/wiki/XOR_cipher)
- [Two's complement](https://en.wikipedia.org/wiki/Two%27s_complement)

