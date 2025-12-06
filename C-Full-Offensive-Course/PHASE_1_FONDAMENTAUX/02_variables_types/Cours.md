# 02 - Variables et Types

## 🎯 Ce que tu vas apprendre

- Ce qu'est une variable et pourquoi elle existe
- Comment fonctionne la mémoire de ton ordinateur
- Les différents types de données en C
- La différence entre signed et unsigned
- L'endianness et la représentation en mémoire
- Comment déclarer et utiliser des variables

## 📚 Théorie

### Concept 1 : C'est quoi la mémoire RAM ?

**C'est quoi ?**
La RAM (Random Access Memory) est comme une gigantesque armoire avec des millions de petites cases numérotées. Chaque case peut stocker une petite quantité d'information.

**Pourquoi ça existe ?**
Ton programme a besoin d'un endroit pour stocker temporairement ses données pendant qu'il tourne : nombres, texte, résultats de calculs, etc.

**Comment ça marche ?**
```
┌─────────┬─────────┬─────────┬─────────┬─────────┐
│ Case 0  │ Case 1  │ Case 2  │ Case 3  │ Case 4  │  ...
├─────────┼─────────┼─────────┼─────────┼─────────┤
│ 0x00... │ 0x00... │ 0x00... │ 0x00... │ 0x00... │  Adresses
└─────────┴─────────┴─────────┴─────────┴─────────┘
```

- Chaque case a une **adresse unique** (comme un numéro de rue)
- Chaque case peut stocker **1 byte** (8 bits)
- Les adresses sont écrites en **hexadécimal** (base 16)

**Pourquoi hexadécimal ?**
Parce que c'est plus compact :
- Binaire : `11111111` (8 chiffres)
- Hexadécimal : `0xFF` (2 chiffres)

### Concept 2 : C'est quoi un byte ?

**C'est quoi ?**
Un byte (octet en français), c'est la plus petite unité de données que tu peux adresser en mémoire. 1 byte = 8 bits.

**Pourquoi 8 bits ?**
Parce que 8 bits permettent de représenter 256 valeurs différentes (2^8 = 256).

**Comment ça marche ?**
```
1 byte = 8 bits
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 0 │ 1 │ 1 │ 0 │ 0 │ 1 │ 0 │  = 178 en décimal
└───┴───┴───┴───┴───┴───┴───┴───┘
 128 64  32  16  8   4   2   1    (puissances de 2)

Calcul : 128 + 32 + 16 + 2 = 178
```

**Valeurs possibles pour 1 byte** :
- En binaire : `00000000` à `11111111`
- En décimal : `0` à `255`
- En hexadécimal : `0x00` à `0xFF`

### Concept 3 : C'est quoi une variable ?

**C'est quoi ?**
Une variable, c'est un nom que tu donnes à une ou plusieurs cases mémoire pour y stocker une valeur.

**Pourquoi ça existe ?**
Au lieu d'écrire "mets 42 à l'adresse 0x7fff5000", tu écris `int age = 42;`. C'est plus lisible et le compilateur gère les adresses pour toi.

**Comment ça marche ?**

```c
int age = 25;
```

Ce qui se passe en mémoire :
```
Nom : age
Type : int (4 bytes)
Valeur : 25

Mémoire :
Adresse    Contenu
0x1000  │  0x19  │ ┐
0x1001  │  0x00  │ │ 4 bytes pour stocker 25
0x1002  │  0x00  │ │ (en little endian)
0x1003  │  0x00  │ ┘
```

### Concept 4 : C'est quoi un type ?

**C'est quoi ?**
Un type, c'est une règle qui dit :
1. Combien de bytes réserver en mémoire
2. Comment interpréter ces bytes

**Pourquoi ça existe ?**
Sans type, l'ordinateur ne sait pas si `0x41` représente :
- Le nombre 65
- Le caractère 'A'
- Une partie d'un nombre plus grand

**Comment ça marche ?**
Le C est un langage **fortement typé** : tu dois déclarer le type de chaque variable.

### Concept 5 : Les types de base en C

#### Type char (1 byte)

**C'est quoi ?**
Le plus petit type, 1 byte. Utilisé pour les caractères ou les petits nombres.

```c
char letter = 'A';  // Stocke le code ASCII de 'A' = 65
```

**Représentation en mémoire** :
```
Adresse    Binaire        Hexa    Décimal    Caractère
0x1000  │ 01000001  │   0x41  │   65    │     'A'
```

**Plage de valeurs** :
- `char` (signed) : -128 à 127
- `unsigned char` : 0 à 255

**Pourquoi -128 à 127 ?**
Avec 8 bits en signed :
- 1 bit pour le signe (0 = positif, 1 = négatif)
- 7 bits pour la valeur
- Total : -2^7 à 2^7-1 = -128 à 127

```
Bit de signe
↓
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ S │   │   │   │   │   │   │   │
└───┴───┴───┴───┴───┴───┴───┴───┘
      7 bits de valeur
```

#### Type int (4 bytes)

**C'est quoi ?**
Le type standard pour les nombres entiers.

```c
int port = 4444;
```

**Représentation en mémoire** :
```
Adresse    Valeur (little endian)
0x1000  │  0x5C  │ ┐
0x1001  │  0x11  │ │ 4444 en hexa = 0x115C
0x1002  │  0x00  │ │ Ordre inversé (little endian)
0x1003  │  0x00  │ ┘
```

**Plage de valeurs** :
- `int` : -2,147,483,648 à 2,147,483,647 (-2^31 à 2^31-1)
- `unsigned int` : 0 à 4,294,967,295 (0 à 2^32-1)

**Pourquoi 4 bytes ?**
Compromis historique entre :
- Taille mémoire (plus petit = économie)
- Performance (alignement 32/64 bits)
- Plage de valeurs (suffisant pour la plupart des usages)

#### Type short (2 bytes)

**C'est quoi ?**
Un entier plus petit que int.

```c
short year = 2024;
```

**Plage de valeurs** :
- `short` : -32,768 à 32,767 (-2^15 à 2^15-1)
- `unsigned short` : 0 à 65,535 (0 à 2^16-1)

#### Type long (8 bytes)

**C'est quoi ?**
Un entier plus grand que int.

```c
long timestamp = 1701234567L;
```

**Plage de valeurs** :
- `long` : -2^63 à 2^63-1
- `unsigned long` : 0 à 2^64-1

#### Types float et double

**C'est quoi ?**
Types pour les nombres à virgule (décimaux).

```c
float pi = 3.14f;
double precise = 3.141592653589793;
```

**Différence** :
- `float` : 4 bytes, ~7 chiffres de précision
- `double` : 8 bytes, ~15 chiffres de précision

### Concept 6 : Tableau récapitulatif

| Type | Taille | Plage (signed) | Plage (unsigned) | Usage |
|------|--------|----------------|------------------|-------|
| `char` | 1 byte | -128 à 127 | 0 à 255 | Caractère, petit entier |
| `short` | 2 bytes | -32,768 à 32,767 | 0 à 65,535 | Petit entier |
| `int` | 4 bytes | -2^31 à 2^31-1 | 0 à 2^32-1 | Entier standard |
| `long` | 8 bytes | -2^63 à 2^63-1 | 0 à 2^64-1 | Grand entier |
| `float` | 4 bytes | ±3.4e±38 | N/A | Décimal simple |
| `double` | 8 bytes | ±1.7e±308 | N/A | Décimal précis |

### Concept 7 : Signed vs Unsigned

**C'est quoi la différence ?**

**Signed (avec signe)** :
- Peut être positif OU négatif
- Utilise 1 bit pour le signe
- Exemple : `int age = -5;` (possible)

**Unsigned (sans signe)** :
- Toujours positif ou zéro
- Tous les bits pour la valeur
- Exemple : `unsigned int count = 0;` (jamais négatif)

**Schéma comparatif pour 1 byte** :
```
SIGNED CHAR (-128 à 127) :
Bit de signe ↓
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ = -128
└───┴───┴───┴───┴───┴───┴───┴───┘

UNSIGNED CHAR (0 à 255) :
Tous les bits pour la valeur
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ = 128
└───┴───┴───┴───┴───┴───┴───┴───┘
```

**Exemple concret** :
```c
unsigned char byte = 255;  // OK
byte = byte + 1;           // Overflow : retourne à 0

char sbyte = 127;          // OK
sbyte = sbyte + 1;         // Overflow : -128
```

### Concept 8 : L'Endianness

**C'est quoi ?**
L'endianness définit l'ordre dans lequel les bytes d'un nombre multi-bytes sont stockés en mémoire.

**Pourquoi ça existe ?**
Différents processeurs ont choisi différentes conventions. Tu dois le savoir pour analyser la mémoire brute.

**Comment ça marche ?**

Prenons le nombre `0x12345678` (4 bytes) :

**Little Endian (x86, x64, ARM en général)** :
Le byte le moins significatif en premier.
```
int val = 0x12345678;

Mémoire (little endian) :
Adresse    Valeur
0x1000  │  0x78  │  ← Byte de poids faible (LSB)
0x1001  │  0x56  │
0x1002  │  0x34  │
0x1003  │  0x12  │  ← Byte de poids fort (MSB)
```

**Big Endian (réseau, anciennes architectures)** :
Le byte le plus significatif en premier.
```
Mémoire (big endian) :
Adresse    Valeur
0x1000  │  0x12  │  ← MSB
0x1001  │  0x34  │
0x1002  │  0x56  │
0x1003  │  0x78  │  ← LSB
```

**Schéma comparatif** :
```
Nombre : 0x12345678

Little Endian (x86/x64) :
┌──────┬──────┬──────┬──────┐
│ 0x78 │ 0x56 │ 0x34 │ 0x12 │
└──────┴──────┴──────┴──────┘
  ↑                        ↑
 LSB                      MSB

Big Endian (réseau) :
┌──────┬──────┬──────┬──────┐
│ 0x12 │ 0x34 │ 0x56 │ 0x78 │
└──────┴──────┴──────┴──────┘
  ↑                        ↑
 MSB                      LSB
```

**Pourquoi c'est important ?**
Quand tu lis un dump mémoire ou analyses un paquet réseau, tu dois savoir dans quel ordre lire les bytes.

### Concept 9 : Déclaration et initialisation

**Déclaration simple** :
```c
int age;  // Variable déclarée mais pas initialisée (valeur aléatoire)
```

**Déclaration avec initialisation** :
```c
int port = 4444;  // Déclaration ET initialisation
```

**Déclarations multiples** :
```c
int x = 10, y = 20, z = 30;
```

**Types unsigned** :
```c
unsigned int positive = 42;
unsigned char byte = 0xFF;
```

**Exemple concret avec commentaires** :
```c
#include <stdio.h>

int main() {
    // Déclarer des variables
    int age = 25;                    // Entier signé
    unsigned int port = 8080;        // Entier non signé
    char grade = 'A';                // Caractère
    float price = 19.99f;            // Décimal

    // Afficher les valeurs
    printf("Age: %d\n", age);
    printf("Port: %u\n", port);
    printf("Grade: %c\n", grade);
    printf("Price: %.2f\n", price);

    return 0;
}
```

### Concept 10 : sizeof() - Connaître la taille d'un type

**C'est quoi ?**
`sizeof()` est un opérateur qui retourne la taille en bytes d'un type ou d'une variable.

**Pourquoi c'est utile ?**
Pour savoir combien de mémoire occupe une variable, important pour l'allocation mémoire et les calculs d'offset.

**Exemple** :
```c
#include <stdio.h>

int main() {
    printf("Taille d'un char:   %lu bytes\n", sizeof(char));
    printf("Taille d'un short:  %lu bytes\n", sizeof(short));
    printf("Taille d'un int:    %lu bytes\n", sizeof(int));
    printf("Taille d'un long:   %lu bytes\n", sizeof(long));
    printf("Taille d'un float:  %lu bytes\n", sizeof(float));
    printf("Taille d'un double: %lu bytes\n", sizeof(double));
    printf("Taille d'un pointeur: %lu bytes\n", sizeof(void*));

    return 0;
}
```

Output typique sur x64 :
```
Taille d'un char:   1 bytes
Taille d'un short:  2 bytes
Taille d'un int:    4 bytes
Taille d'un long:   8 bytes
Taille d'un float:  4 bytes
Taille d'un double: 8 bytes
Taille d'un pointeur: 8 bytes
```

## 🔍 Visualisation en mémoire

Exemple complet avec plusieurs variables :

```c
int main() {
    char c = 'X';          // 1 byte
    short s = 1000;        // 2 bytes
    int i = 123456;        // 4 bytes
    long l = 9999999999L;  // 8 bytes
}
```

**Représentation en mémoire (little endian, x64)** :
```
┌─────────┬────────────────────────────────────┐
│ Adresse │ Contenu (hexa)                     │
├─────────┼────────────────────────────────────┤
│ 0x1000  │ 0x58                    │  char c  │
│         │ (padding pour alignement)          │
├─────────┼────────────────────────────────────┤
│ 0x1002  │ 0xE8 0x03               │ short s  │
│         │ (1000 = 0x03E8 inversé)            │
├─────────┼────────────────────────────────────┤
│ 0x1004  │ 0x40 0xE2 0x01 0x00     │  int i   │
│         │ (123456 = 0x0001E240)              │
├─────────┼────────────────────────────────────┤
│ 0x1008  │ 0xFF 0xC9 0x9A 0x3B     │ long l   │
│         │ 0x02 0x00 0x00 0x00     │          │
└─────────┴────────────────────────────────────┘

Note : Le compilateur peut ajouter du padding pour l'alignement mémoire.
```

## 🎯 Application Red Team

### 1. Taille des types et integer overflow

En exploitation, connaître les limites est crucial :

```c
unsigned char count = 255;
count++;  // Overflow : retourne à 0

// Exploit possible si le code fait :
if (count > 0) {
    // Accès à un buffer[count-1]
    // count = 0 → buffer[-1] → accès mémoire invalide
}
```

### 2. Unsigned pour manipuler des bytes bruts

Les shellcodes utilisent TOUJOURS `unsigned char` :

```c
// Shellcode = bytes bruts, jamais de valeurs négatives
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP sled
    0x31, 0xc0,              // xor eax, eax
    0x50,                    // push eax
    0xff, 0xe4               // jmp esp
};
```

Pourquoi pas `char` ? Parce que `0xFF` en signed char = `-1`, ce qui peut causer des bugs.

### 3. Types custom (typedef) - Style Windows API

```c
// Types Windows (style hongrois)
typedef unsigned char  BYTE;    // 1 byte
typedef unsigned short WORD;    // 2 bytes
typedef unsigned long  DWORD;   // 4 bytes
typedef void*          LPVOID;  // Pointeur

// Utilisation :
DWORD pid = GetCurrentProcessId();
LPVOID addr = VirtualAlloc(NULL, 1024, ...);
```

### 4. Endianness et exploitation réseau

Quand tu forges un paquet réseau (TCP/IP), tu dois inverser l'ordre des bytes :

```c
// Port 4444 en little endian (x86)
unsigned short port = 4444;  // 0x115C en mémoire : 5C 11

// Port 4444 en big endian (réseau)
unsigned short net_port = htons(4444);  // En mémoire : 11 5C
```

**Schéma** :
```
Ordinateur (little endian) :
port = 4444 → [0x5C][0x11]

Conversion htons() :
net_port = htons(4444) → [0x11][0x5C]

Réseau (big endian) :
Paquet TCP → [0x11][0x5C] → Port 4444
```

### 5. Analyse de dumps mémoire

Quand tu analyses un dump avec un debugger :

```
(gdb) x/4xb 0x7fffffffdc00
0x7fffffffdc00: 0x78  0x56  0x34  0x12

Interprétation :
- En little endian : 0x12345678
- En big endian : 0x78563412
```

### 6. Structure packing et exploitation

Le compilateur aligne les structures pour la performance, mais ça peut créer des failles :

```c
struct User {
    char name[8];   // 8 bytes
    int is_admin;   // 4 bytes
    // Total : 12 bytes
};

// Si tu overflow name, tu peux écraser is_admin
```

## 📝 Points clés à retenir

- Un byte = 8 bits = 256 valeurs possibles
- La mémoire RAM est un tableau géant de bytes avec des adresses
- Un type définit combien de bytes réserver et comment les interpréter
- `int` = 4 bytes, `char` = 1 byte, `long` = 8 bytes
- Signed = avec signe (+/-), unsigned = toujours positif
- Little endian (x86/x64) : byte de poids faible en premier
- Big endian (réseau) : byte de poids fort en premier
- `sizeof()` retourne la taille en bytes d'un type
- Les shellcodes utilisent `unsigned char` pour les bytes bruts
- L'endianness est crucial pour l'analyse mémoire et le réseau

## ➡️ Prochaine étape

Maintenant que tu sais stocker des données, tu vas apprendre à les afficher et les lire avec [printf et scanf](../03_printf_scanf/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
