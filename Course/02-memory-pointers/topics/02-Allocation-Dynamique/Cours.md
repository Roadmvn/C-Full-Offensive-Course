# Module 20 : Integer Overflow

Bienvenue dans le monde des Integer Overflows. C'est une vulnérabilité SUBTILE mais DEVASTATRICE. Contrairement au buffer overflow qui est bruyant, l'integer overflow est silencieux et souvent invisible... jusqu'à ce qu'il cause un crash ou pire, une exploitation.

## 1. C'est quoi un Integer Overflow et Pourquoi c'est Dangereux ?

### 1.1 Le Problème Fondamental

```ascii
EN MATHÉMATIQUES :
1 + 1 = 2
999999 + 1 = 1000000
∞ + 1 = ∞ (nombres infinis)

EN C (ENTIERS LIMITÉS) :
char x = 127;     // Maximum signed char
x = x + 1;        // Résultat : -128 (!!)
                     ↓
              WRAPAROUND

┌──────────────────────────────────────┐
│  Signed char (8 bits) :              │
│  ┌─────────────────────────────────┐ │
│  │ -128 ... -1  0  1 ... 126  127 │ │
│  └─────────────────────────────────┘ │
│         ↑                       ↓    │
│         └───────OVERFLOW────────┘    │
│                                      │
│  127 + 1 = ? En maths : 128          │
│             En C : IMPOSSIBLE (char) │
│             → Wraparound à -128      │
└──────────────────────────────────────┘

= LES NOMBRES TOURNENT EN BOUCLE
= COMPORTEMENT IMPRÉVISIBLE
= VULNÉRABILITÉ EXPLOITABLE
```

### 1.2 Types d'Integer Issues

```ascii
┌──────────────────────────────────────────────┐
│  TYPE 1 : SIGNED OVERFLOW                    │
├──────────────────────────────────────────────┤
│  Range : -2147483648 à 2147483647 (int32)    │
│  Overflow : INT_MAX + 1 → INT_MIN            │
│  Exemple : 2147483647 + 1 = -2147483648      │
│  Danger : Nombres négatifs inattendus        │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  TYPE 2 : UNSIGNED OVERFLOW (Wraparound)     │
├──────────────────────────────────────────────┤
│  Range : 0 à 4294967295 (uint32)             │
│  Overflow : UINT_MAX + 1 → 0                 │
│  Underflow : 0 - 1 → UINT_MAX                │
│  Danger : Checks de sécurité bypassés        │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  TYPE 3 : TRUNCATION                         │
├──────────────────────────────────────────────┤
│  Conversion type large → type petit          │
│  long (64-bit) → int (32-bit)                │
│  Bits hauts PERDUS                           │
│  Danger : Valeur complètement changée        │
└──────────────────────────────────────────────┘
```

### 1.3 Visualisation Wraparound

```ascii
UNSIGNED INT (32-bit) :

      0x00000000
          ↓
  [─────────────────]
  ↑                 ↓
  │                 │
UINT_MIN         UINT_MAX
(0)          (4294967295)
  ↑                 ↓
  └─────WRAPAROUND──┘

0 - 1          = 4294967295
4294967295 + 1 = 0

SIGNED INT (32-bit) :

   -2147483648 ... -1  0  1 ... 2147483647
   ↑                                     ↓
   └──────────WRAPAROUND─────────────────┘

2147483647 + 1  = -2147483648
-2147483648 - 1 = 2147483647
```

## 2. Démonstration : Comprendre les Limites

### 2.1 Limites des Types Entiers

```c
#include <stdio.h>
#include <limits.h>
#include <stdint.h>

int main() {
    printf("=== LIMITES TYPES ENTIERS ===\n\n");

    // Signed char (8 bits)
    printf("signed char:\n");
    printf("  Min: %d\n", SCHAR_MIN);     // -128
    printf("  Max: %d\n", SCHAR_MAX);     //  127
    printf("  Size: %zu bytes\n\n", sizeof(signed char));

    // Unsigned char (8 bits)
    printf("unsigned char:\n");
    printf("  Min: 0\n");
    printf("  Max: %u\n", UCHAR_MAX);     // 255
    printf("  Size: %zu bytes\n\n", sizeof(unsigned char));

    // Signed int (32 bits)
    printf("signed int:\n");
    printf("  Min: %d\n", INT_MIN);       // -2147483648
    printf("  Max: %d\n", INT_MAX);       //  2147483647
    printf("  Size: %zu bytes\n\n", sizeof(int));

    // Unsigned int (32 bits)
    printf("unsigned int:\n");
    printf("  Min: 0\n");
    printf("  Max: %u\n", UINT_MAX);      // 4294967295
    printf("  Size: %zu bytes\n\n", sizeof(unsigned int));

    // Long long (64 bits)
    printf("signed long long:\n");
    printf("  Min: %lld\n", LLONG_MIN);
    printf("  Max: %lld\n", LLONG_MAX);
    printf("  Size: %zu bytes\n\n", sizeof(long long));

    return 0;
}
```

**Output** :

```
=== LIMITES TYPES ENTIERS ===

signed char:
  Min: -128
  Max: 127
  Size: 1 bytes

unsigned char:
  Min: 0
  Max: 255
  Size: 1 bytes

signed int:
  Min: -2147483648
  Max: 2147483647
  Size: 4 bytes

unsigned int:
  Min: 0
  Max: 4294967295
  Size: 4 bytes

signed long long:
  Min: -9223372036854775808
  Max: 9223372036854775807
  Size: 8 bytes
```

### 2.2 Overflow en Action

```c
#include <stdio.h>
#include <limits.h>

int main() {
    printf("=== SIGNED OVERFLOW ===\n\n");

    int x = INT_MAX;
    printf("x = INT_MAX = %d\n", x);
    printf("x + 1 = %d\n", x + 1);     // -2147483648 (!!)
    printf("x + 2 = %d\n\n", x + 2);   // -2147483647

    printf("=== UNSIGNED WRAPAROUND ===\n\n");

    unsigned int y = UINT_MAX;
    printf("y = UINT_MAX = %u\n", y);
    printf("y + 1 = %u\n", y + 1);     // 0
    printf("y + 2 = %u\n\n", y + 2);   // 1

    unsigned int z = 0;
    printf("z = 0\n");
    printf("z - 1 = %u\n", z - 1);     // 4294967295
    printf("z - 2 = %u\n\n", z - 2);   // 4294967294

    printf("=== MULTIPLICATION OVERFLOW ===\n\n");

    unsigned int a = 0x80000000;  // 2^31
    unsigned int b = 2;
    printf("a = 0x%08X (%u)\n", a, a);
    printf("b = %u\n", b);
    printf("a * b = 0x%08X (%u)\n", a * b, a * b);  // Overflow!

    return 0;
}
```

**Visualisation** :

```ascii
EXECUTION :

=== SIGNED OVERFLOW ===
x = INT_MAX = 2147483647
x + 1 = -2147483648    ← WRAPAROUND !
x + 2 = -2147483647

BINAIRE :
INT_MAX     = 0x7FFFFFFF = 0111 1111 1111 1111 1111 1111 1111 1111
INT_MAX + 1 = 0x80000000 = 1000 0000 0000 0000 0000 0000 0000 0000
                           ↑ Bit de signe devient 1 = nombre négatif

=== UNSIGNED WRAPAROUND ===
y = UINT_MAX = 4294967295
y + 1 = 0              ← Retour à zéro
y + 2 = 1

z = 0
z - 1 = 4294967295     ← Wraparound vers UINT_MAX
z - 2 = 4294967294
```

## 3. Exploitation : Bypass Allocation Check

### 3.1 Vulnérabilité Classique

**Code vulnérable** :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VULNÉRABLE : Integer overflow dans calcul taille
void* allocate_buffer(unsigned int count, unsigned int item_size) {
    // Calcul taille : count * item_size
    unsigned int total_size = count * item_size;

    printf("[DEBUG] Allocating %u items of size %u\n", count, item_size);
    printf("[DEBUG] Total size: %u bytes\n", total_size);

    // Check (insuffisant)
    if (total_size == 0) {
        printf("[ERROR] Invalid size\n");
        return NULL;
    }

    // Allocation
    void *buffer = malloc(total_size);
    if (!buffer) {
        printf("[ERROR] Malloc failed\n");
        return NULL;
    }

    printf("[SUCCESS] Buffer allocated at %p\n", buffer);
    return buffer;
}

int main() {
    printf("=== EXPLOITATION INTEGER OVERFLOW ===\n\n");

    // ATTAQUE : Provoquer overflow pour allouer petit buffer
    // mais écrire grande quantité de données

    // Objectif : Allouer seulement 16 bytes au lieu de beaucoup
    // 0x04000000 * 0x04 = 0x10000000 (NO overflow)
    // 0x40000000 * 0x04 = 0x100000000 → 0x00000000 (OVERFLOW!)

    // Tentative 1 : Normal (pas d'overflow)
    printf("--- Tentative 1 : Allocation normale ---\n");
    unsigned int count1 = 4;
    unsigned int size1 = 4;
    void *buf1 = allocate_buffer(count1, size1);
    if (buf1) free(buf1);

    printf("\n--- Tentative 2 : OVERFLOW ATTACK ---\n");
    // count * size = 0x40000001 * 4 = 0x100000004
    // Tronqué à 32-bit : 0x00000004 (seulement 4 bytes!)
    unsigned int count2 = 0x40000001;  // 1073741825
    unsigned int size2 = 4;
    void *buf2 = allocate_buffer(count2, size2);

    if (buf2) {
        printf("\n[EXPLOIT] Buffer alloué : seulement 4 bytes\n");
        printf("[EXPLOIT] Mais on va écrire %u bytes!\n", count2 * size2);

        // Écriture ÉNORME dans petit buffer → HEAP OVERFLOW
        // (Simulation, ne pas vraiment faire crash)
        printf("[EXPLOIT] Heap corruption possible!\n");

        free(buf2);
    }

    return 0;
}
```

**Analyse détaillée** :

```ascii
ATTAQUE :

CALCUL NORMAL :
count = 4
size = 4
total = 4 * 4 = 16 bytes
→ Allocation correcte de 16 bytes

CALCUL OVERFLOW :
count = 0x40000001 = 1073741825
size  = 4
total = 0x40000001 * 4 = 0x100000004
           ↓ Tronqué à 32-bit
        = 0x00000004 = 4 bytes (!!)

RÉSULTAT :
├─ malloc(4)        → Alloue 4 bytes
├─ Mais attaquant pense avoir 0x100000004 bytes
└─ Écriture au-delà → HEAP OVERFLOW

BINAIRE :
0x40000001 = 0100 0000 0000 0000 0000 0000 0000 0001
         * 4
──────────────────────────────────────────────────────
0x100000004 = 1 0000 0000 0000 0000 0000 0000 0000 0100
              ↑ Bit 33 (perdu sur 32-bit int)
Résultat 32-bit : 0x00000004
```

### 3.2 Exploitation Réelle

**Scénario** : Serveur traite requêtes réseau

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t num_items;
    uint32_t item_size;
} PacketHeader;

// VULNÉRABLE
void process_packet(PacketHeader *header, void *data) {
    printf("[SERVER] Processing packet\n");
    printf("[SERVER] Items: %u, Size: %u\n",
           header->num_items, header->item_size);

    // VULNÉRABILITÉ : Multiplication overflow
    uint32_t total_size = header->num_items * header->item_size;

    printf("[SERVER] Total size calculated: %u bytes\n", total_size);

    // Check naïf
    if (total_size > 1024 * 1024) {  // Max 1 MB
        printf("[SERVER] ERROR: Packet too large\n");
        return;
    }

    // Allocation basée sur calcul overflow
    void *buffer = malloc(total_size);
    if (!buffer) {
        printf("[SERVER] ERROR: Allocation failed\n");
        return;
    }

    printf("[SERVER] Buffer allocated: %u bytes at %p\n", total_size, buffer);

    // Copie données (DANGER)
    // Si overflow, total_size est petit mais data est grand!
    memcpy(buffer, data, total_size);

    printf("[SERVER] Data copied successfully\n");

    // Process data...

    free(buffer);
}

int main() {
    printf("=== SIMULATION ATTAQUE SERVEUR ===\n\n");

    // ATTAQUE : Craft packet malveillant
    PacketHeader malicious_header;

    // Objectif : Bypasser check "total_size > 1MB"
    // mais allouer très petit buffer

    // 0x40000001 * 64 = 0x1000000040
    // Tronqué : 0x40 = 64 bytes (< 1MB, check bypass!)
    malicious_header.num_items = 0x04000001;  // 67108865
    malicious_header.item_size = 64;

    uint64_t real_size = (uint64_t)malicious_header.num_items *
                         (uint64_t)malicious_header.item_size;
    printf("[ATTACKER] Crafting malicious packet\n");
    printf("[ATTACKER] Real size would be: %llu bytes (%.2f GB)\n",
           real_size, real_size / (1024.0 * 1024.0 * 1024.0));

    // Créer fausses données
    char fake_data[64];
    memset(fake_data, 'A', sizeof(fake_data));

    process_packet(&malicious_header, fake_data);

    printf("\n[RESULT] Check bypassed, heap overflow possible!\n");

    return 0;
}
```

## 4. Bypass Bounds Check

### 4.1 Underflow Attack

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

// VULNÉRABLE : Unsigned underflow
void copy_data(char *dest, size_t dest_size,
               const char *src, size_t offset, size_t length) {

    printf("[COPY] dest_size=%zu, offset=%zu, length=%zu\n",
           dest_size, offset, length);

    // VULNÉRABILITÉ : offset + length peut underflow/overflow
    if (offset + length <= dest_size) {
        printf("[COPY] Check passed, copying...\n");
        memcpy(dest + offset, src, length);
        printf("[COPY] Copy successful\n");
    } else {
        printf("[COPY] ERROR: Out of bounds\n");
    }
}

int main() {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    char payload[2048];
    memset(payload, 'A', sizeof(payload));

    printf("=== UNSIGNED UNDERFLOW ATTACK ===\n\n");

    // ATTAQUE 1 : offset + length wraparound
    printf("--- Attack 1: Overflow wraparound ---\n");
    size_t offset1 = 0x100;            // 256
    size_t length1 = SIZE_MAX - 0xFF;  // Énorme!

    printf("offset + length = 0x%zX + 0x%zX\n", offset1, length1);
    printf("              = 0x%zX\n", offset1 + length1);
    printf("Expected: Très grand nombre\n");
    printf("Actual (wraparound): %zu\n\n", offset1 + length1);

    // offset + length = 0x100 + 0xFFFFFFFFFFFFFF00
    //                 = 0x10000000000000000
    // Tronqué 64-bit : 0x0000000000000000 (!!)

    // Note: On ne fait pas vraiment l'attaque ici pour éviter crash

    // ATTAQUE 2 : offset très grand
    printf("--- Attack 2: Large offset ---\n");
    size_t offset2 = SIZE_MAX - 10;
    size_t length2 = 100;

    printf("offset=%zu, length=%zu\n", offset2, length2);
    printf("offset + length = %zu\n", offset2 + length2);
    printf("Wraparound bypasses check!\n\n");

    printf("[EXPLOIT] Ces valeurs bypassent le check bounds\n");
    printf("[EXPLOIT] → Écriture out-of-bounds possible\n");

    return 0;
}
```

**Visualisation** :

```ascii
UNSIGNED ARITHMETIC (size_t = 64-bit) :

ATTAQUE :
offset = 0x100
length = 0xFFFFFFFFFFFFFF00 (SIZE_MAX - 0xFF)

CHECK :
if (offset + length <= buffer_size)
   0x100 + 0xFFFFFFFFFFFFFF00 = ?

CALCUL :
  0x0000000000000100
+ 0xFFFFFFFFFFFFFF00
──────────────────────
  0x10000000000000000  ← 65 bits!
  ↓ Tronqué à 64-bit
  0x0000000000000000  = 0

RÉSULTAT :
0 <= 1024 → CHECK PASSE !
Mais en réalité :
memcpy(dest + 0x100, src, 0xFFFFFFFFFFFFFF00)
→ Copie ÉNORME quantité
→ BUFFER OVERFLOW massif
```

## 5. Truncation : Conversion de Types

### 5.1 Large to Small Conversion

```c
#include <stdio.h>
#include <stdint.h>

void process_data(int32_t size) {
    printf("[PROCESS] Size parameter: %d bytes\n", size);

    if (size <= 0) {
        printf("[ERROR] Invalid size\n");
        return;
    }

    // Allocation basée sur size
    void *buffer = malloc(size);
    printf("[PROCESS] Allocated %d bytes at %p\n", size, buffer);

    // Process...

    free(buffer);
}

int main() {
    printf("=== TRUNCATION ATTACK ===\n\n");

    // ATTAQUE : Passer grand nombre 64-bit
    // Tronqué en 32-bit devient petit/négatif

    int64_t large_value = 0x100000001;  // 4294967297

    printf("Original value (64-bit): 0x%llX = %lld\n",
           large_value, large_value);

    // Cast vers 32-bit
    int32_t truncated = (int32_t)large_value;

    printf("Truncated (32-bit): 0x%X = %d\n\n", truncated, truncated);

    // RÉSULTAT :
    // 0x100000001 → 0x00000001 = 1

    printf("--- Normal call ---\n");
    process_data(1024);

    printf("\n--- Truncated call ---\n");
    process_data(truncated);  // Passe 1 au lieu de 4294967297!

    printf("\n[EXPLOIT] Truncation change complètement la valeur\n");

    return 0;
}
```

**Binaire** :

```ascii
TRUNCATION :

Original 64-bit :
0x0000000100000001 = 0000 0000 0000 0000 0000 0000 0000 0001
                     0000 0000 0000 0000 0000 0000 0000 0001
                     ↑──────── High 32-bit ────────↑──── Low 32-bit ────↑

Cast vers int32_t :
Bits hauts PERDUS :
                     0000 0000 0000 0000 0000 0000 0000 0001
                     → 1

Autre exemple :
0x00000001FFFFFFFF → 0xFFFFFFFF = -1 (signed int32)
```

## 6. Protection et Mitigation

### 6.1 Code Sécurisé

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>

// SÉCURISÉ : Check overflow avant multiplication
bool safe_multiply(size_t a, size_t b, size_t *result) {
    // Check si a * b dépasserait SIZE_MAX
    if (a == 0 || b == 0) {
        *result = 0;
        return true;
    }

    // Check : a * b > SIZE_MAX
    // Équivalent : a > SIZE_MAX / b
    if (a > SIZE_MAX / b) {
        // Overflow détecté
        return false;
    }

    *result = a * b;
    return true;
}

// SÉCURISÉ : Check overflow addition
bool safe_add(size_t a, size_t b, size_t *result) {
    // Check : a + b > SIZE_MAX
    // Équivalent : a > SIZE_MAX - b
    if (a > SIZE_MAX - b) {
        return false;
    }

    *result = a + b;
    return true;
}

void* safe_allocate_buffer(size_t count, size_t item_size) {
    size_t total_size;

    printf("[SAFE] Allocating %zu items of size %zu\n", count, item_size);

    // Check multiplication overflow
    if (!safe_multiply(count, item_size, &total_size)) {
        printf("[ERROR] Integer overflow detected in size calculation\n");
        return NULL;
    }

    printf("[SAFE] Total size: %zu bytes (no overflow)\n", total_size);

    // Check limite raisonnable
    if (total_size > 1024 * 1024 * 100) {  // Max 100 MB
        printf("[ERROR] Size too large\n");
        return NULL;
    }

    void *buffer = malloc(total_size);
    if (!buffer) {
        printf("[ERROR] Allocation failed\n");
        return NULL;
    }

    printf("[SUCCESS] Buffer allocated safely at %p\n", buffer);
    return buffer;
}

int main() {
    printf("=== SAFE INTEGER OPERATIONS ===\n\n");

    // Test 1 : Allocation normale
    printf("--- Test 1: Normal allocation ---\n");
    void *buf1 = safe_allocate_buffer(100, 1024);
    if (buf1) {
        free(buf1);
    }

    // Test 2 : Tentative overflow
    printf("\n--- Test 2: Overflow attempt ---\n");
    void *buf2 = safe_allocate_buffer(0x40000001, 64);
    if (buf2) {
        free(buf2);
    }

    // Test 3 : Safe operations
    printf("\n--- Test 3: Safe arithmetic ---\n");
    size_t result;

    if (safe_multiply(1000, 1000, &result)) {
        printf("1000 * 1000 = %zu (safe)\n", result);
    }

    if (!safe_multiply(SIZE_MAX / 2, 3, &result)) {
        printf("(SIZE_MAX/2) * 3 = OVERFLOW (detected)\n");
    }

    if (safe_add(100, 200, &result)) {
        printf("100 + 200 = %zu (safe)\n", result);
    }

    if (!safe_add(SIZE_MAX, 1, &result)) {
        printf("SIZE_MAX + 1 = OVERFLOW (detected)\n");
    }

    return 0;
}
```

### 6.2 Bonnes Pratiques

```c
// ✅ RECOMMANDÉ : Utiliser types explicites
#include <stdint.h>
uint32_t count;
uint64_t total_size;

// ✅ Check overflow avant opération
if (a > SIZE_MAX - b) {
    // Overflow serait causé
    return ERROR;
}

// ✅ Utiliser types plus grands pour calculs
uint64_t total = (uint64_t)count * (uint64_t)size;
if (total > UINT32_MAX) {
    // Overflow détecté
    return ERROR;
}

// ✅ Compiler flags
// gcc -ftrapv  (trap sur signed overflow)
// gcc -fwrapv  (wraparound défini pour signed)
// clang -fsanitize=integer

// ❌ ÉVITER : Assumer pas d'overflow
size_t total = count * size;  // Peut overflow silencieusement

// ❌ ÉVITER : Checks après opération
size_t total = a + b;
if (total < a) {  // Trop tard si utilisé avant!
    return ERROR;
}
```

## 7. Red Team : Techniques d'Exploitation

### 7.1 Reconnaissance

```ascii
IDENTIFIER VULNÉRABILITÉS INTEGER OVERFLOW :

1. CHERCHER PATTERNS :
   ├─ malloc(count * size)
   ├─ if (offset + length < max)
   ├─ buffer[user_value]
   └─ Conversions de types (cast)

2. ANALYSER TYPES :
   ├─ signed vs unsigned
   ├─ Tailles (int 32-bit vs size_t 64-bit)
   └─ Résultat assez grand ?

3. INPUTS CONTRÔLÉS :
   ├─ Paramètres réseau
   ├─ Arguments ligne de commande
   ├─ Fichiers parsés
   └─ Données utilisateur

4. TESTER VALEURS LIMITES :
   ├─ 0, -1
   ├─ INT_MAX, INT_MIN
   ├─ UINT_MAX
   └─ SIZE_MAX
```

### 7.2 Payload Crafting

```c
// Exemple : Créer valeurs causant overflow

// Pour unsigned 32-bit wraparound à zéro :
uint32_t count = 0x40000000;  // 2^30
uint32_t size = 4;
// count * size = 0x100000000 → 0x00000000

// Pour underflow unsigned :
size_t offset = SIZE_MAX - 100;
size_t length = 200;
// offset + length wrappe à ~100

// Pour signed overflow :
int val = INT_MAX;
val = val + 1;  // → INT_MIN

// Calcul automatique :
// Trouver count tel que : count * size % (2^32) = petit_nombre
// count = (petit_nombre + k * 2^32) / size
// Exemple : Pour avoir résultat = 16
// 16 / 4 = 4 (pas d'overflow)
// (16 + 2^32) / 4 = 0x40000004 (overflow vers 16)
```

## 8. Détection et Analyse

### 8.1 Outils

```bash
# Compilation avec sanitizers
gcc -fsanitize=integer -fsanitize=undefined vuln.c -o vuln

# Exécution
./vuln
# Si overflow : runtime error détecté

# Analyse statique
clang --analyze vuln.c

# Fuzzing
afl-gcc vuln.c -o vuln
afl-fuzz -i inputs/ -o findings/ ./vuln @@
```

### 8.2 GDB/LLDB Detection

```bash
# Dans GDB
(gdb) break malloc
(gdb) run
# Examiner argument size
(gdb) print (unsigned long)$rdi
# Si très petit alors que logiquement devrait être grand → overflow

# Watchpoint sur calcul
(gdb) watch total_size
(gdb) continue
# Observer valeur après calcul
```

## Ressources

- CWE-190: Integer Overflow or Wraparound
- CWE-191: Integer Underflow
- CERT C Secure Coding Standard - INT30-C, INT32-C
- "Integer Overflow" - OWASP
- Compiler flags: -ftrapv, -fsanitize=integer
- Safe integer libraries: SafeInt (C++), checked arithmetic
