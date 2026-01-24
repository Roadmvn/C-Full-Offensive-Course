# Solutions - Module 02 : Variables et Types

## Solution Exercice 1 : Tailles des types

```c
#include <stdio.h>

int main(void) {
    printf("=== Tailles des types ===\n\n");

    printf("Types entiers :\n");
    printf("  char      : %zu byte\n", sizeof(char));
    printf("  short     : %zu bytes\n", sizeof(short));
    printf("  int       : %zu bytes\n", sizeof(int));
    printf("  long      : %zu bytes\n", sizeof(long));
    printf("  long long : %zu bytes\n", sizeof(long long));

    printf("\nTypes flottants :\n");
    printf("  float     : %zu bytes\n", sizeof(float));
    printf("  double    : %zu bytes\n", sizeof(double));

    printf("\nPointeur :\n");
    printf("  void*     : %zu bytes → Architecture %zu-bit\n",
           sizeof(void*), sizeof(void*) * 8);

    return 0;
}
```

### Résultat typique (Linux x64)
```
=== Tailles des types ===

Types entiers :
  char      : 1 byte
  short     : 2 bytes
  int       : 4 bytes
  long      : 8 bytes
  long long : 8 bytes

Types flottants :
  float     : 4 bytes
  double    : 8 bytes

Pointeur :
  void*     : 8 bytes → Architecture 64-bit
```

### Réponses aux questions

1. **Taille de void*** : 8 bytes sur x64, 4 bytes sur x86
2. **Architecture** : 8 bytes × 8 bits = 64 bits
3. **Pourquoi important** : Pour calculer des offsets dans les exploits, parser des structures binaires, et comprendre le reverse engineering

---

## Solution Exercice 2 : Limites des types

```c
#include <stdio.h>
#include <limits.h>

int main(void) {
    printf("=== Limites des types ===\n\n");

    printf("char :\n");
    printf("  signed   : %d à %d\n", CHAR_MIN, CHAR_MAX);
    printf("  unsigned : 0 à %u\n", UCHAR_MAX);

    printf("\nshort :\n");
    printf("  signed   : %d à %d\n", SHRT_MIN, SHRT_MAX);
    printf("  unsigned : 0 à %u\n", USHRT_MAX);

    printf("\nint :\n");
    printf("  signed   : %d à %d\n", INT_MIN, INT_MAX);
    printf("  unsigned : 0 à %u\n", UINT_MAX);

    printf("\nlong :\n");
    printf("  signed   : %ld à %ld\n", LONG_MIN, LONG_MAX);
    printf("  unsigned : 0 à %lu\n", ULONG_MAX);

    return 0;
}
```

### Réponses aux questions

1. **Max unsigned char** : 255 (2^8 - 1)

2. **Pourquoi -128 à 127 ?**
   - 8 bits = 256 valeurs possibles
   - La moitié pour les négatifs : -128 à -1 (128 valeurs)
   - La moitié pour les positifs : 0 à 127 (128 valeurs)
   - Le 0 "prend" une place du côté positif

3. **Type pour un port réseau** : `unsigned short` (0 à 65535)

---

## Solution Exercice 3 : Signed vs Unsigned

```c
#include <stdio.h>

int main(void) {
    char s_byte = 0xFF;
    unsigned char u_byte = 0xFF;

    printf("signed char 0xFF   = %d\n", s_byte);
    printf("unsigned char 0xFF = %u\n", u_byte);

    printf("\nComparaisons avec 0 :\n");
    printf("signed 0xFF > 0   ? %s\n", (s_byte > 0) ? "OUI" : "NON");
    printf("unsigned 0xFF > 0 ? %s\n", (u_byte > 0) ? "OUI" : "NON");

    return 0;
}
```

### Résultat
```
signed char 0xFF   = -1
unsigned char 0xFF = 255

Comparaisons avec 0 :
signed 0xFF > 0   ? NON
unsigned 0xFF > 0 ? OUI
```

### Réponses aux questions

1. **Pourquoi 0xFF = -1 en signed ?**
   Le complément à deux :
   - Pour représenter -1, on inverse les bits de 1 (00000001 → 11111110) et on ajoute 1
   - Résultat : 11111111 = 0xFF
   - En signed, le bit de poids fort (1) indique un nombre négatif

2. **Problème avec shellcode** : Les bytes > 127 (comme 0xFF, 0xC0) seraient interprétés comme négatifs et les comparaisons `> 0` échoueraient

3. **Type à utiliser** : `unsigned char` ou `uint8_t` TOUJOURS pour les bytes bruts

---

## Solution Exercice 4 : Endianness

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t value = 0x12345678;
    unsigned char *bytes = (unsigned char*)&value;

    printf("Valeur : 0x%08X\n", value);
    printf("Bytes en mémoire : ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");

    if (bytes[0] == 0x78) {
        printf("Cette machine est LITTLE ENDIAN\n");
    } else {
        printf("Cette machine est BIG ENDIAN\n");
    }

    return 0;
}
```

### Résultat (sur x86/x64)
```
Valeur : 0x12345678
Bytes en mémoire : 78 56 34 12
Cette machine est LITTLE ENDIAN
```

### Réponses aux questions

1. **Ordre sur x86/x64** : Little endian (78 56 34 12)

2. **78 56 34 12 = ?** : 0x12345678 (on lit à l'envers)

3. **Pourquoi big endian pour le réseau ?**
   - Historique : les premiers protocoles utilisaient big endian
   - Plus "naturel" pour les humains (on lit de gauche à droite)
   - Standardisé pour éviter les problèmes d'interopérabilité

---

## Solution Exercice 5 : Integer Overflow

```c
#include <stdio.h>

int main(void) {
    // Overflow unsigned
    unsigned char u = 255;
    printf("unsigned char avant : %u\n", u);
    u = u + 1;
    printf("unsigned char après +1 : %u\n", u);

    // Overflow signed
    signed char s = 127;
    printf("\nsigned char avant : %d\n", s);
    s = s + 1;
    printf("signed char après +1 : %d\n", s);

    // Underflow
    unsigned char zero = 0;
    printf("\nunsigned char avant : %u\n", zero);
    zero = zero - 1;
    printf("unsigned char après -1 : %u\n", zero);

    return 0;
}
```

### Résultat
```
unsigned char avant : 255
unsigned char après +1 : 0

signed char avant : 127
signed char après +1 : -128

unsigned char avant : 0
unsigned char après -1 : 255
```

### Réponses aux questions

1. **255 + 1 unsigned** : 0 (wrap around)
2. **127 + 1 signed** : -128 (wrap around)
3. **Exploitation** :
   - Bypass de vérifications de taille : `if (len < MAX)` passe si len overflow vers 0
   - Allocation trop petite : `malloc(len * size)` où le produit overflow
   - Exemple CVE-2021-21300 (Git) : integer overflow dans le parsing

---

## Solution Exercice 6 : Types Windows

```c
#include <stdio.h>

typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef void*          LPVOID;

int main(void) {
    printf("=== Types Windows ===\n");
    printf("BYTE   : %zu byte(s)\n", sizeof(BYTE));
    printf("WORD   : %zu bytes\n", sizeof(WORD));
    printf("DWORD  : %zu bytes\n", sizeof(DWORD));
    printf("LPVOID : %zu bytes\n", sizeof(LPVOID));

    DWORD pid = 1337;
    WORD port = 4444;
    printf("\nPID   : %u\n", pid);
    printf("Port  : %u\n", port);

    return 0;
}
```

### Résultat
```
=== Types Windows ===
BYTE   : 1 byte(s)
WORD   : 2 bytes
DWORD  : 4 bytes
LPVOID : 8 bytes

PID   : 1337
Port  : 4444
```

### Réponses aux questions

1. **Pourquoi DWORD ?** : Pour garantir une taille fixe de 4 bytes, indépendamment de la plateforme. `int` peut varier selon les compilateurs/architectures.

2. **HANDLE sur x64** : 8 bytes (car c'est un `void*`)

3. **Machine dans PE header** : 2 bytes (WORD)

---

## Solution Exercice 7 : Écrire une adresse pour un exploit

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t target = 0x7fff1234;

    // Extraction byte par byte avec décalage et masque
    unsigned char exploit[4];
    exploit[0] = (target >> 0) & 0xFF;   // 0x34 - LSB
    exploit[1] = (target >> 8) & 0xFF;   // 0x12
    exploit[2] = (target >> 16) & 0xFF;  // 0xFF
    exploit[3] = (target >> 24) & 0xFF;  // 0x7F - MSB

    printf("Adresse cible : 0x%08X\n", target);
    printf("Bytes pour l'exploit : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02x", exploit[i]);
    }
    printf("\n");

    return 0;
}
```

### Résultat
```
Adresse cible : 0x7FFF1234
Bytes pour l'exploit : \x34\x12\xff\x7f
```

### Explication

```
target = 0x7FFF1234

Décalage bit à bit :
- target >> 0  = 0x7FFF1234 & 0xFF = 0x34
- target >> 8  = 0x007FFF12 & 0xFF = 0x12
- target >> 16 = 0x00007FFF & 0xFF = 0xFF
- target >> 24 = 0x0000007F & 0xFF = 0x7F

Little endian = LSB first = 34 12 FF 7F
```

---

## Solution Exercice 8 : Détecter un integer overflow

```c
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

// Méthode 1 : Vérification avant multiplication
int will_overflow(unsigned int a, unsigned int b) {
    // Si b est 0, pas d'overflow possible
    if (b == 0) return 0;

    // Si a > MAX / b, alors a * b > MAX = overflow
    return a > UINT_MAX / b;
}

// Méthode 2 : Vérification après (moins sûre car UB pour signed)
int will_overflow_v2(unsigned int a, unsigned int b) {
    unsigned int result = a * b;
    // Si overflow, result / b != a
    return (b != 0) && (result / b != a);
}

int main(void) {
    unsigned int sizes[] = {100, 1000000000, UINT_MAX};

    for (int i = 0; i < 3; i++) {
        unsigned int size = sizes[i];
        unsigned int element_size = 8;

        printf("size=%u, element_size=%u : ", size, element_size);

        if (will_overflow(size, element_size)) {
            printf("OVERFLOW DÉTECTÉ!\n");
        } else {
            printf("OK (total = %u)\n", size * element_size);
        }
    }

    return 0;
}
```

### Résultat
```
size=100, element_size=8 : OK (total = 800)
size=1000000000, element_size=8 : OVERFLOW DÉTECTÉ!
size=4294967295, element_size=8 : OVERFLOW DÉTECTÉ!
```

### Pourquoi c'est important ?

Ce pattern est utilisé dans le code sécurisé pour éviter les vulnérabilités :

```c
// Code VULNÉRABLE
void* alloc_array(size_t count, size_t size) {
    return malloc(count * size);  // Peut overflow !
}

// Code SÉCURISÉ
void* safe_alloc_array(size_t count, size_t size) {
    if (size != 0 && count > SIZE_MAX / size) {
        return NULL;  // Overflow détecté
    }
    return malloc(count * size);
}
```

---

## Solution Exercice 9 : Parser un header binaire

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    unsigned char raw_header[] = {
        0x4D, 0x5A,             // Magic "MZ"
        0x01, 0x00,             // Version 1
        0x00, 0x10, 0x00, 0x00  // Taille 0x1000 = 4096 bytes
    };

    // Méthode 1 : Cast de pointeur (attention à l'alignement !)
    uint16_t magic = *(uint16_t*)&raw_header[0];
    uint16_t version = *(uint16_t*)&raw_header[2];
    uint32_t size = *(uint32_t*)&raw_header[4];

    // Méthode 2 : Reconstruction manuelle (plus sûre, portable)
    // uint16_t magic = raw_header[0] | (raw_header[1] << 8);
    // uint16_t version = raw_header[2] | (raw_header[3] << 8);
    // uint32_t size = raw_header[4] | (raw_header[5] << 8) |
    //                (raw_header[6] << 16) | (raw_header[7] << 24);

    printf("Magic   : 0x%04X", magic);
    if (magic == 0x5A4D) printf(" (MZ - Executable DOS/Windows)");
    printf("\n");
    printf("Version : %u\n", version);
    printf("Taille  : %u bytes (0x%X)\n", size, size);

    return 0;
}
```

### Résultat
```
Magic   : 0x5A4D (MZ - Executable DOS/Windows)
Version : 1
Taille  : 4096 bytes (0x1000)
```

### Explication

**Pourquoi 0x5A4D et pas 0x4D5A ?**

Les bytes en mémoire sont `4D 5A` (dans cet ordre).
En little endian, quand on lit un uint16_t :
- Le premier byte (0x4D) devient le LSB
- Le second byte (0x5A) devient le MSB
- Résultat : 0x5A4D

C'est pourquoi le "magic number" MZ est stocké comme `4D 5A` dans le fichier mais lu comme `0x5A4D` en mémoire sur x86.

---

## Points clés à retenir

1. **Types et tailles** : Utilise `sizeof()` et `stdint.h` pour des tailles garanties

2. **Signed vs Unsigned** : TOUJOURS `unsigned char` / `uint8_t` pour les bytes bruts

3. **Endianness** : x86/x64 = little endian, réseau = big endian

4. **Integer overflow** : Vérifie AVANT les multiplications pour éviter les vulnérabilités

5. **Types Windows** : BYTE (1), WORD (2), DWORD (4), QWORD (8)

6. **Parsing binaire** : Attention à l'endianness et à l'alignement mémoire
