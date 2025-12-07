# Solutions - Module 03 : Opérateurs

## Solution Exercice 1 : Opérateurs arithmétiques

```c
#include <stdio.h>

int main(void) {
    int a = 17, b = 5;

    printf("a = %d, b = %d\n\n", a, b);

    printf("Addition       : %d + %d = %d\n", a, b, a + b);       // 22
    printf("Soustraction   : %d - %d = %d\n", a, b, a - b);       // 12
    printf("Multiplication : %d * %d = %d\n", a, b, a * b);       // 85
    printf("Division       : %d / %d = %d\n", a, b, a / b);       // 3
    printf("Modulo         : %d %% %d = %d\n", a, b, a % b);      // 2

    return 0;
}
```

### Résultat
```
a = 17, b = 5

Addition       : 17 + 5 = 22
Soustraction   : 17 - 5 = 12
Multiplication : 17 * 5 = 85
Division       : 17 / 5 = 3
Modulo         : 17 % 5 = 2
```

### Réponses aux questions

1. **17 / 5 = 3** (pas 3.4) car c'est une division entière. Quand on divise deux `int`, le résultat est un `int` (la partie décimale est tronquée).

2. **17 % 5 = 2** car : 17 = 5 × 3 + **2** (17 divisé par 5 = 3 reste 2)

3. Pour obtenir 3.4 : `float result = (float)a / b;` ou `float result = 17.0 / 5;`

---

## Solution Exercice 2 : Pré/Post incrémentation

```c
#include <stdio.h>

int main(void) {
    int x = 5;
    int a, b;

    a = ++x;  // x devient 6 d'abord, puis a reçoit 6
    printf("Après ++x : a = %d, x = %d\n", a, x);  // a = 6, x = 6

    x = 5;    // Reset
    b = x++;  // b reçoit 5 d'abord, puis x devient 6
    printf("Après x++ : b = %d, x = %d\n", b, x);  // b = 5, x = 6

    return 0;
}
```

### Résultat
```
Après ++x : a = 6, x = 6
Après x++ : b = 5, x = 6
```

### Réponses aux questions

1. **a = 6** car `++x` (pré-incrémentation) incrémente x EN PREMIER, puis retourne la nouvelle valeur.

2. **b = 5** car `x++` (post-incrémentation) retourne la valeur ACTUELLE de x, puis l'incrémente.

3. Dans une boucle `for(int i = 0; i < n; i++)`, ça ne change rien car on n'utilise pas la valeur retournée. Mais dans `arr[i++] = value`, c'est important : on accède à arr[i] puis i augmente.

---

## Solution Exercice 3 : Opérateurs de comparaison

```c
#include <stdio.h>

int main(void) {
    int a = 10, b = 20, c = 10;

    printf("a = %d, b = %d, c = %d\n\n", a, b, c);

    printf("a == b : %d\n", a == b);  // 0 (faux)
    printf("a == c : %d\n", a == c);  // 1 (vrai)
    printf("a != b : %d\n", a != b);  // 1 (vrai)
    printf("a < b  : %d\n", a < b);   // 1 (vrai)
    printf("a >= c : %d\n", a >= c);  // 1 (vrai)

    return 0;
}
```

### Réponses aux questions

1. **1** (vrai)
2. **0** (faux)
3. `=` est l'affectation (assigne une valeur), `==` est la comparaison.
   - `if (x = 5)` assigne 5 à x, puis teste si 5 != 0 → toujours vrai !
   - `if (x == 5)` compare x avec 5 sans modifier x

---

## Solution Exercice 4 : Opérateurs logiques

```c
#include <stdio.h>

int main(void) {
    int is_admin = 1;
    int is_logged = 0;
    int is_banned = 0;

    printf("is_admin = %d, is_logged = %d, is_banned = %d\n\n",
           is_admin, is_logged, is_banned);

    // 1. Admin ET connecté
    printf("is_admin && is_logged = %d\n", is_admin && is_logged);  // 0

    // 2. Admin OU connecté
    printf("is_admin || is_logged = %d\n", is_admin || is_logged);  // 1

    // 3. PAS banni
    printf("!is_banned = %d\n", !is_banned);  // 1

    // 4. (Admin ET connecté) ET (pas banni)
    printf("(is_admin && is_logged) && !is_banned = %d\n",
           (is_admin && is_logged) && !is_banned);  // 0

    return 0;
}
```

### Réponses aux questions

1. **Short-circuit evaluation** : le C évalue de gauche à droite et s'arrête dès que le résultat est déterminé.
   - AND : si le premier opérande est faux, le résultat est faux → le second n'est pas évalué
   - OR : si le premier opérande est vrai, le résultat est vrai → le second n'est pas évalué

2. Dans `if (ptr != NULL && ptr->value > 0)` :
   - Si ptr est NULL, `ptr != NULL` est faux
   - Grâce au short-circuit, `ptr->value` n'est JAMAIS évalué
   - Sans ça, on aurait un crash (déréférencement de NULL)

3. Anti-debug :
```c
if (IsDebuggerPresent() || check_timing() || check_breakpoints()) {
    exit(1);  // Dès qu'une vérification retourne vrai, on sort
}
```

---

## Solution Exercice 5 : AND bitwise - Masquage

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t value = 0xABCD1234;

    printf("Valeur originale : 0x%08X\n\n", value);

    // 1. Byte de poids faible
    uint8_t byte0 = value & 0xFF;
    printf("Byte 0 (LSB)     : 0x%02X\n", byte0);  // 0x34

    // 2. Second byte (décale de 8 bits, puis masque)
    uint8_t byte1 = (value >> 8) & 0xFF;
    printf("Byte 1           : 0x%02X\n", byte1);  // 0x12

    // 3. 4 bits de poids faible
    uint8_t low_nibble = value & 0x0F;
    printf("4 bits de poids faible : 0x%X\n", low_nibble);  // 0x4

    // 4. 4 bits de poids fort du premier byte
    uint8_t high_nibble = (value >> 4) & 0x0F;
    printf("4 bits de poids fort   : 0x%X\n", high_nibble);  // 0x3

    return 0;
}
```

### Explication visuelle

```
value = 0xABCD1234
      = 1010 1011 1100 1101 0001 0010 0011 0100

value & 0xFF :
      = .... .... .... .... .... .... 0011 0100
      = 0x34

(value >> 8) & 0xFF :
      = .... .... .... .... .... .... 0001 0010
      = 0x12

value & 0x0F :
      = .... .... .... .... .... .... .... 0100
      = 0x4

(value >> 4) & 0x0F :
      = .... .... .... .... .... .... .... 0011
      = 0x3
```

---

## Solution Exercice 6 : OR bitwise - Combinaison de flags

```c
#include <stdio.h>
#include <stdint.h>

#define FLAG_READ    0x01
#define FLAG_WRITE   0x02
#define FLAG_EXECUTE 0x04
#define FLAG_DELETE  0x08

// Fonction pour afficher les bits
void print_binary(uint8_t value) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (value >> i) & 1);
    }
}

int main(void) {
    uint8_t permissions = 0;

    printf("Permissions initiales : 0x%02X (", permissions);
    print_binary(permissions);
    printf(")\n\n");

    // 1. Ajouter FLAG_READ
    permissions |= FLAG_READ;
    printf("Après |= FLAG_READ    : 0x%02X (", permissions);
    print_binary(permissions);
    printf(")\n");

    // 2. Ajouter FLAG_WRITE
    permissions |= FLAG_WRITE;
    printf("Après |= FLAG_WRITE   : 0x%02X (", permissions);
    print_binary(permissions);
    printf(")\n\n");

    // 4. Vérifier FLAG_EXECUTE
    if (permissions & FLAG_EXECUTE) {
        printf("FLAG_EXECUTE est PRÉSENT\n");
    } else {
        printf("FLAG_EXECUTE est ABSENT\n");
    }

    // 5. Ajouter FLAG_EXECUTE
    permissions |= FLAG_EXECUTE;
    printf("\nAprès |= FLAG_EXECUTE : 0x%02X (", permissions);
    print_binary(permissions);
    printf(")\n");

    // 6. Vérifier à nouveau
    if (permissions & FLAG_EXECUTE) {
        printf("FLAG_EXECUTE est maintenant PRÉSENT\n");
    }

    return 0;
}
```

### Réponses aux questions

1. **OR (|)** pour ajouter : OR met le bit à 1 s'il ne l'est pas déjà, sans affecter les autres.
   ```
   permissions = 0000 0001  (FLAG_READ)
   FLAG_WRITE  = 0000 0010
   ──────────────────────
   Résultat    = 0000 0011  (les deux flags)
   ```

2. **AND (&)** pour vérifier : AND garde seulement les bits communs.
   - Si le flag est présent, le résultat est non-nul (vrai)
   - Si le flag est absent, le résultat est 0 (faux)

3. Pour retirer un flag : `permissions &= ~FLAG_TO_REMOVE;`
   - `~FLAG` inverse les bits du flag
   - `&` avec ce masque efface le bit correspondant

---

## Solution Exercice 7 : XOR - Propriété d'annulation

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Partie 1 : Un seul byte
    unsigned char original = 0x41;  // 'A'
    unsigned char key = 0x55;

    printf("=== XOR sur un byte ===\n\n");
    printf("Original : 0x%02X ('%c')\n", original, original);
    printf("Clé      : 0x%02X\n\n", key);

    // Chiffrement
    unsigned char encrypted = original ^ key;
    printf("Chiffré  : 0x%02X ^ 0x%02X = 0x%02X\n", original, key, encrypted);

    // Déchiffrement
    unsigned char decrypted = encrypted ^ key;
    printf("Déchiffré: 0x%02X ^ 0x%02X = 0x%02X ('%c')\n\n",
           encrypted, key, decrypted, decrypted);

    // Partie 2 : String "HELLO"
    printf("=== XOR sur une string ===\n\n");
    char message[] = "HELLO";
    unsigned char str_key = 0x55;

    printf("Original : %s\n", message);

    // Chiffrement
    for (size_t i = 0; i < strlen(message); i++) {
        message[i] ^= str_key;
    }
    printf("Chiffré  : ");
    for (size_t i = 0; i < strlen(message); i++) {
        printf("\\x%02x", (unsigned char)message[i]);
    }
    printf("\n");

    // Déchiffrement
    for (size_t i = 0; i < strlen(message); i++) {
        message[i] ^= str_key;
    }
    printf("Déchiffré: %s\n", message);

    return 0;
}
```

### Réponses aux questions

1. **Pourquoi A ^ B ^ B = A ?**
   ```
   A         = 0100 0001 (0x41)
   B         = 0101 0101 (0x55)
   ─────────────────────
   A ^ B     = 0001 0100 (0x14)

   (A ^ B)   = 0001 0100
   B         = 0101 0101
   ─────────────────────
   (A^B) ^ B = 0100 0001 = A !
   ```
   Chaque bit est XORé deux fois avec le même bit de B, ce qui l'annule.

2. **Sans la clé**, oui c'est difficile à retrouver directement, mais avec une clé d'1 byte il n'y a que 256 possibilités → brute force facile.

3. **Faiblesse du XOR 1 byte** :
   - Seulement 256 clés possibles
   - Analyse de fréquence facile (un 'e' sera toujours chiffré de la même façon)
   - `strings encrypted_file | grep pattern` peut révéler des motifs

---

## Solution Exercice 8 : Shift operators

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    // PARTIE 1 : Construction
    printf("=== Construction d'une valeur 32-bit ===\n\n");

    uint8_t b0 = 0x12, b1 = 0x34, b2 = 0x56, b3 = 0x78;

    // Construction en big endian order (0x12345678)
    uint32_t value = ((uint32_t)b0 << 24) |
                     ((uint32_t)b1 << 16) |
                     ((uint32_t)b2 << 8)  |
                     ((uint32_t)b3);

    printf("Bytes : 0x%02X, 0x%02X, 0x%02X, 0x%02X\n", b0, b1, b2, b3);
    printf("Valeur construite : 0x%08X\n\n", value);

    // PARTIE 2 : Extraction
    printf("=== Extraction des bytes ===\n\n");

    uint32_t data = 0xAABBCCDD;
    printf("Valeur : 0x%08X\n\n", data);

    uint8_t byte0 = (data >> 0) & 0xFF;   // LSB = 0xDD
    uint8_t byte1 = (data >> 8) & 0xFF;   // 0xCC
    uint8_t byte2 = (data >> 16) & 0xFF;  // 0xBB
    uint8_t byte3 = (data >> 24) & 0xFF;  // MSB = 0xAA

    printf("Byte 0 (LSB) : 0x%02X\n", byte0);
    printf("Byte 1       : 0x%02X\n", byte1);
    printf("Byte 2       : 0x%02X\n", byte2);
    printf("Byte 3 (MSB) : 0x%02X\n", byte3);

    return 0;
}
```

### Réponses aux questions

1. **5 << 2** = 5 × 2² = 5 × 4 = **20** (multiplication par puissance de 2)

2. **20 >> 2** = 20 ÷ 2² = 20 ÷ 4 = **5** (division par puissance de 2)

3. **Pourquoi plus rapide** : Les shifts sont des opérations CPU primitives (1 cycle), alors que la multiplication/division nécessite plusieurs cycles.

---

## Solution Exercice 9 : XOR Encryption d'une string

```c
#include <stdio.h>
#include <string.h>

void xor_encrypt(char *data, int len, char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;  // XOR chaque byte avec la clé
    }
}

int main(void) {
    char secret[] = "password123";
    char key = 0x42;

    printf("Original  : %s\n", secret);

    // Chiffre
    xor_encrypt(secret, strlen(secret), key);
    printf("Chiffré   : ");
    for (size_t i = 0; i < strlen(secret); i++) {
        printf("\\x%02x", (unsigned char)secret[i]);
    }
    printf("\n");

    // Déchiffre (même fonction !)
    xor_encrypt(secret, strlen(secret), key);
    printf("Déchiffré : %s\n", secret);

    return 0;
}
```

### Résultat
```
Original  : password123
Chiffré   : \x32\x23\x31\x31\x35\x2f\x30\x22\x71\x70\x71
Déchiffré : password123
```

---

## Solution Exercice 10 : XOR Encryption multi-clés

```c
#include <stdio.h>
#include <string.h>

void xor_multi_key(unsigned char *data, int data_len,
                   unsigned char *key, int key_len) {
    for (int i = 0; i < data_len; i++) {
        // key[i % key_len] fait cycler la clé
        // i=0 → key[0], i=1 → key[1], ..., i=4 → key[0], etc.
        data[i] ^= key[i % key_len];
    }
}

int main(void) {
    unsigned char secret[] = "TOPSECRET";
    unsigned char keys[] = {0x11, 0x22, 0x33, 0x44};

    printf("Original  : %s\n", secret);

    // Chiffre
    xor_multi_key(secret, strlen((char*)secret), keys, sizeof(keys));
    printf("Chiffré   : ");
    for (size_t i = 0; i < strlen((char*)secret); i++) {
        printf("\\x%02x", secret[i]);
    }
    printf("\n");

    // Déchiffre
    xor_multi_key(secret, strlen((char*)secret), keys, sizeof(keys));
    printf("Déchiffré : %s\n", secret);

    return 0;
}
```

### Réponses aux questions

1. **Pourquoi plus sécurisé** : Chaque byte est chiffré avec une clé différente, ce qui rend l'analyse de fréquence beaucoup plus difficile.

2. **Modulo (%)** : `i % key_len` retourne le reste de i / key_len.
   - i=0: 0%4=0, i=1: 1%4=1, i=2: 2%4=2, i=3: 3%4=3
   - i=4: 4%4=0, i=5: 5%4=1, ... (cycle recommence)

3. **Clé idéale** : Une clé de la même longueur que le message, générée aléatoirement, utilisée une seule fois = **One-Time Pad** (mathématiquement incassable).

---

## Solution Exercice 11 : Manipulation complète de flags

```c
#include <stdio.h>
#include <stdint.h>

#define FLAG_CONNECTED  (1 << 0)  // 0x01
#define FLAG_ADMIN      (1 << 1)  // 0x02
#define FLAG_VERIFIED   (1 << 2)  // 0x04
#define FLAG_PREMIUM    (1 << 3)  // 0x08

// Ajouter un flag : OR
void set_flag(uint8_t *flags, uint8_t flag) {
    *flags |= flag;
}

// Retirer un flag : AND avec NOT
void clear_flag(uint8_t *flags, uint8_t flag) {
    *flags &= ~flag;
}

// Inverser un flag : XOR
void toggle_flag(uint8_t *flags, uint8_t flag) {
    *flags ^= flag;
}

// Vérifier un flag : AND
int has_flag(uint8_t flags, uint8_t flag) {
    return (flags & flag) != 0;
}

// Afficher l'état
void print_flags(uint8_t flags) {
    printf("  Flags = 0x%02X\n", flags);
    printf("  CONNECTED : %s\n", has_flag(flags, FLAG_CONNECTED) ? "OUI" : "NON");
    printf("  ADMIN     : %s\n", has_flag(flags, FLAG_ADMIN) ? "OUI" : "NON");
    printf("  VERIFIED  : %s\n", has_flag(flags, FLAG_VERIFIED) ? "OUI" : "NON");
    printf("  PREMIUM   : %s\n", has_flag(flags, FLAG_PREMIUM) ? "OUI" : "NON");
}

int main(void) {
    uint8_t user_flags = 0;

    printf("État initial :\n");
    print_flags(user_flags);

    set_flag(&user_flags, FLAG_CONNECTED);
    printf("\nAprès set_flag(CONNECTED) :\n");
    print_flags(user_flags);

    set_flag(&user_flags, FLAG_VERIFIED);
    printf("\nAprès set_flag(VERIFIED) :\n");
    print_flags(user_flags);

    toggle_flag(&user_flags, FLAG_ADMIN);
    printf("\nAprès toggle_flag(ADMIN) :\n");
    print_flags(user_flags);

    clear_flag(&user_flags, FLAG_CONNECTED);
    printf("\nAprès clear_flag(CONNECTED) :\n");
    print_flags(user_flags);

    return 0;
}
```

### Réponses aux questions

1. **1 << n** crée un nombre avec un seul bit à 1 à la position n.
   - `1 << 0` = 0b00000001
   - `1 << 1` = 0b00000010
   - `1 << 7` = 0b10000000

2. **Effacer un flag** : `flags &= ~flag;`
   - `~flag` inverse les bits (le flag devient 0, le reste devient 1)
   - `&` avec ce masque garde tout sauf le flag

3. **Toggle** : `flags ^= flag;`
   - XOR avec 1 inverse le bit (0→1, 1→0)
   - XOR avec 0 ne change rien

---

## Solution Exercice 12 : Extraction d'adresse pour shellcode

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    // Adresse 32-bit
    uint32_t target_addr = 0x7FFFD234;

    unsigned char exploit_bytes[4];
    exploit_bytes[0] = (target_addr >> 0) & 0xFF;   // LSB = 0x34
    exploit_bytes[1] = (target_addr >> 8) & 0xFF;   // 0xD2
    exploit_bytes[2] = (target_addr >> 16) & 0xFF;  // 0xFF
    exploit_bytes[3] = (target_addr >> 24) & 0xFF;  // MSB = 0x7F

    printf("Adresse cible : 0x%08X\n", target_addr);
    printf("Format exploit : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02x", exploit_bytes[i]);
    }
    printf("\n\n");

    // BONUS : Adresse 64-bit
    uint64_t target64 = 0x00007FFFD2345678ULL;
    unsigned char exploit64[8];

    for (int i = 0; i < 8; i++) {
        exploit64[i] = (target64 >> (i * 8)) & 0xFF;
    }

    printf("Adresse 64-bit : 0x%016llX\n", (unsigned long long)target64);
    printf("Format exploit : ");
    for (int i = 0; i < 8; i++) {
        printf("\\x%02x", exploit64[i]);
    }
    printf("\n");

    return 0;
}
```

### Résultat
```
Adresse cible : 0x7FFFD234
Format exploit : \x34\xd2\xff\x7f

Adresse 64-bit : 0x00007FFFD2345678
Format exploit : \x78\x56\x34\xd2\xff\x7f\x00\x00
```

---

## Solution Exercice 13 : Reconstruction d'adresse depuis un dump

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    // Bytes lus depuis le dump (little endian)
    unsigned char dump[] = {0x78, 0x56, 0x34, 0x12};

    // Reconstruction : le premier byte est le LSB
    uint32_t address = (uint32_t)dump[0] |
                       ((uint32_t)dump[1] << 8) |
                       ((uint32_t)dump[2] << 16) |
                       ((uint32_t)dump[3] << 24);

    printf("Bytes dans le dump : ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", dump[i]);
    }
    printf("\n");

    printf("Adresse reconstruite : 0x%08X\n", address);

    return 0;
}
```

### Explication

```
dump[0] = 0x78 (LSB) → position 0 → shift de 0
dump[1] = 0x56       → position 1 → shift de 8
dump[2] = 0x34       → position 2 → shift de 16
dump[3] = 0x12 (MSB) → position 3 → shift de 24

0x78 | (0x56 << 8) | (0x34 << 16) | (0x12 << 24)
= 0x00000078 | 0x00005600 | 0x00340000 | 0x12000000
= 0x12345678
```

---

## Solution Exercice 14 : Opérateur ternaire

```c
#include <stdio.h>

int main(void) {
    int score = 75;

    // 1. PASS ou FAIL
    const char *result = (score >= 50) ? "PASS" : "FAIL";

    // 2. Maximum
    int max = (10 > 25) ? 10 : 25;

    // 3. Pair ou impair
    const char *parity = (score % 2 == 0) ? "pair" : "impair";

    printf("Score: %d → %s\n", score, result);
    printf("Max(10, 25) = %d\n", max);
    printf("Score est %s\n", parity);

    return 0;
}
```

### Résultat
```
Score: 75 → PASS
Max(10, 25) = 25
Score est impair
```

---

## Points clés à retenir

### Opérateurs arithmétiques
- Division entière : `7 / 3 = 2` (pas 2.33)
- Modulo : reste de division, utile pour rotation de clés

### Opérateurs logiques
- `&&`, `||`, `!` travaillent sur des valeurs booléennes
- Short-circuit : si le premier opérande détermine le résultat, le second n'est pas évalué

### Opérateurs bitwise
| Opérateur | Usage offensif |
|-----------|----------------|
| `&` (AND) | Masquage, extraction de bits, vérification de flags |
| `\|` (OR) | Combinaison de flags |
| `^` (XOR) | Chiffrement, toggle de bits |
| `~` (NOT) | Création de masques d'effacement |
| `<<` (Left shift) | Construction de valeurs, création de flags |
| `>>` (Right shift) | Extraction de bytes |

### Manipulation de flags
```c
set_flag:    flags |= FLAG;
clear_flag:  flags &= ~FLAG;
toggle_flag: flags ^= FLAG;
has_flag:    if (flags & FLAG)
```

### XOR Encryption
- Propriété magique : `A ^ B ^ B = A`
- Chiffrement et déchiffrement = même opération
- Multi-clés avec modulo pour rotation : `key[i % key_len]`

### Adresses little endian
- Extraction : `(addr >> (i*8)) & 0xFF`
- Reconstruction : `b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)`
