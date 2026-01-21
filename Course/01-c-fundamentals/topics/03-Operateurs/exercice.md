# Exercices - Module 03 : Opérateurs

## Exercice 1 : Opérateurs arithmétiques (Très facile)

**Objectif** : Maîtriser les opérations de base et le modulo.

### Instructions

Crée un programme qui :

```c
#include <stdio.h>

int main(void) {
    int a = 17, b = 5;

    // TODO: Affiche le résultat de chaque opération
    // - Addition
    // - Soustraction
    // - Multiplication
    // - Division (attention : division entière !)
    // - Modulo (reste de la division)

    return 0;
}
```

### Questions

1. Que donne `17 / 5` en C ? Pourquoi pas 3.4 ?
2. Que donne `17 % 5` ? Explique comment tu arrives à ce résultat.
3. Si tu voulais obtenir 3.4, comment ferais-tu ?

---

## Exercice 2 : Pré/Post incrémentation (Facile)

**Objectif** : Comprendre la différence entre `++x` et `x++`.

### Instructions

Prédis le résultat de ce code AVANT de l'exécuter, puis vérifie :

```c
#include <stdio.h>

int main(void) {
    int x = 5;
    int a, b;

    a = ++x;  // Qu'est-ce que a ? Qu'est-ce que x maintenant ?
    printf("Après ++x : a = %d, x = %d\n", a, x);

    x = 5;    // Reset
    b = x++;  // Qu'est-ce que b ? Qu'est-ce que x maintenant ?
    printf("Après x++ : b = %d, x = %d\n", b, x);

    return 0;
}
```

### Questions

1. Quelle est la valeur de `a` après `a = ++x` ?
2. Quelle est la valeur de `b` après `b = x++` ?
3. Pourquoi cette différence est importante dans une boucle `for` ?

---

## Exercice 3 : Opérateurs de comparaison (Facile)

**Objectif** : Comprendre les résultats des comparaisons (0 ou 1).

### Instructions

```c
#include <stdio.h>

int main(void) {
    int a = 10, b = 20, c = 10;

    // TODO: Affiche le résultat (0 ou 1) de chaque comparaison
    printf("a == b : %d\n", /* ... */);
    printf("a == c : %d\n", /* ... */);
    printf("a != b : %d\n", /* ... */);
    printf("a < b  : %d\n", /* ... */);
    printf("a >= c : %d\n", /* ... */);

    return 0;
}
```

### Questions

1. Que retourne une comparaison vraie en C ?
2. Que retourne une comparaison fausse ?
3. Quelle est la différence entre `=` et `==` ? Pourquoi c'est dangereux de les confondre ?

---

## Exercice 4 : Opérateurs logiques (Moyen)

**Objectif** : Maîtriser AND, OR, NOT et le short-circuit.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int is_admin = 1;
    int is_logged = 0;
    int is_banned = 0;

    // TODO: Évalue ces expressions
    // 1. L'utilisateur peut accéder s'il est admin ET connecté
    // 2. L'utilisateur peut accéder s'il est admin OU connecté
    // 3. L'utilisateur ne peut PAS accéder s'il est banni
    // 4. Accès autorisé si (admin ET connecté) ET (pas banni)

    return 0;
}
```

### Questions

1. Qu'est-ce que le "short-circuit evaluation" ?
2. Dans `if (ptr != NULL && ptr->value > 0)`, pourquoi le short-circuit est essentiel ?
3. Comment utiliserais-tu le short-circuit pour un anti-debug multi-checks ?

---

## Exercice 5 : AND bitwise - Masquage (Moyen)

**Objectif** : Utiliser AND pour extraire des bits spécifiques.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t value = 0xABCD1234;

    // TODO: Utilise AND (&) et des masques pour extraire :
    // 1. Le byte de poids faible (0x34)
    // 2. Le second byte (0x12)
    // 3. Les 4 bits de poids faible (0x4)
    // 4. Les 4 bits de poids fort du premier byte (0x3)

    return 0;
}
```

### Résultat attendu
```
Valeur originale : 0xABCD1234
Byte 0 (LSB)     : 0x34
Byte 1           : 0x12
4 bits de poids faible : 0x4
4 bits de poids fort   : 0x3
```

### Indice

- Pour le byte 0 : `value & 0xFF`
- Pour le byte 1 : décale d'abord avec `>>`, puis masque
- Pour les 4 bits : `& 0x0F` ou `& 0xF0`

---

## Exercice 6 : OR bitwise - Combinaison de flags (Moyen)

**Objectif** : Combiner des flags comme dans les API système.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

// Définition des flags (comme dans Windows API)
#define FLAG_READ    0x01   // 0b00000001
#define FLAG_WRITE   0x02   // 0b00000010
#define FLAG_EXECUTE 0x04   // 0b00000100
#define FLAG_DELETE  0x08   // 0b00001000

int main(void) {
    uint8_t permissions = 0;

    // TODO:
    // 1. Ajoute FLAG_READ avec OR
    // 2. Ajoute FLAG_WRITE avec OR
    // 3. Affiche les permissions en binaire (manuellement ou avec une boucle)
    // 4. Vérifie si FLAG_EXECUTE est présent (avec AND)
    // 5. Ajoute FLAG_EXECUTE
    // 6. Vérifie à nouveau

    return 0;
}
```

### Questions

1. Pourquoi utilise-t-on OR (|) pour ajouter un flag ?
2. Pourquoi utilise-t-on AND (&) pour vérifier un flag ?
3. Comment ferais-tu pour retirer un flag ?

---

## Exercice 7 : XOR - Propriété d'annulation (Moyen)

**Objectif** : Comprendre que XOR s'annule lui-même (A ^ B ^ B = A).

### Instructions

```c
#include <stdio.h>

int main(void) {
    unsigned char original = 0x41;  // 'A'
    unsigned char key = 0x55;

    // TODO:
    // 1. Chiffre 'original' avec XOR de 'key'
    // 2. Affiche la valeur chiffrée
    // 3. Déchiffre en appliquant XOR avec la même clé
    // 4. Vérifie que tu retrouves 'A'

    // Bonus : Fais la même chose avec une string "HELLO"

    return 0;
}
```

### Questions

1. Pourquoi `A ^ B ^ B = A` ? (Explique avec des bits)
2. Si quelqu'un voit le texte chiffré, peut-il retrouver le message sans la clé ?
3. Quelle est la faiblesse du XOR avec une clé d'un seul byte ?

---

## Exercice 8 : Shift operators - Construction de valeurs (Moyen)

**Objectif** : Utiliser les shifts pour construire et extraire des valeurs.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    // PARTIE 1 : Construction
    // Tu as 4 bytes : 0x12, 0x34, 0x56, 0x78
    // Construis la valeur 32-bit 0x12345678 (big endian order)
    uint8_t b0 = 0x12, b1 = 0x34, b2 = 0x56, b3 = 0x78;

    // TODO: uint32_t value = ... (utilise << et |)

    // PARTIE 2 : Extraction
    // Tu as la valeur 0xAABBCCDD
    // Extrais chaque byte

    uint32_t data = 0xAABBCCDD;
    // TODO: Extrais byte0, byte1, byte2, byte3 (utilise >> et &)

    return 0;
}
```

### Questions

1. `5 << 2` équivaut à quelle opération mathématique ?
2. `20 >> 2` équivaut à quelle opération mathématique ?
3. Pourquoi les shifts sont-ils plus rapides que la multiplication/division ?

---

## Exercice 9 : XOR Encryption d'une string (Challenge)

**Objectif** : Implémenter un chiffrement XOR simple sur une string.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO: Implémente cette fonction
void xor_encrypt(char *data, int len, char key) {
    // Applique XOR avec 'key' sur chaque byte de 'data'
}

int main(void) {
    char secret[] = "password123";
    char key = 0x42;

    printf("Original  : %s\n", secret);

    // Chiffre
    xor_encrypt(secret, strlen(secret), key);
    printf("Chiffré   : ");
    for (int i = 0; i < strlen(secret); i++) {
        printf("\\x%02x", (unsigned char)secret[i]);
    }
    printf("\n");

    // Déchiffre
    xor_encrypt(secret, strlen(secret), key);
    printf("Déchiffré : %s\n", secret);

    return 0;
}
```

### Résultat attendu
```
Original  : password123
Chiffré   : \x32\x23\x31\x31\x35\x2f\x30\x22\x71\x70\x71
Déchiffré : password123
```

---

## Exercice 10 : XOR Encryption multi-clés (Challenge)

**Objectif** : Améliorer le chiffrement XOR avec plusieurs clés.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO: Implémente cette fonction
void xor_multi_key(unsigned char *data, int data_len,
                   unsigned char *key, int key_len) {
    // Applique XOR avec une clé qui "cycle" : key[i % key_len]
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

### Questions

1. Pourquoi une clé multi-bytes est plus sécurisée ?
2. Comment fonctionne l'opérateur modulo (%) pour faire cycler la clé ?
3. Quelle serait la clé idéale pour un chiffrement XOR parfait ?

---

## Exercice 11 : Manipulation complète de flags (Challenge)

**Objectif** : Implémenter toutes les opérations sur les flags.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

#define FLAG_CONNECTED  (1 << 0)  // 0x01
#define FLAG_ADMIN      (1 << 1)  // 0x02
#define FLAG_VERIFIED   (1 << 2)  // 0x04
#define FLAG_PREMIUM    (1 << 3)  // 0x08

// TODO: Implémente ces fonctions
void set_flag(uint8_t *flags, uint8_t flag);     // Ajouter un flag
void clear_flag(uint8_t *flags, uint8_t flag);   // Retirer un flag
void toggle_flag(uint8_t *flags, uint8_t flag);  // Inverser un flag
int has_flag(uint8_t flags, uint8_t flag);       // Vérifier un flag

void print_flags(uint8_t flags);                 // Afficher l'état

int main(void) {
    uint8_t user_flags = 0;

    printf("État initial :\n");
    print_flags(user_flags);

    // Tests
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

### Questions

1. Pourquoi utilise-t-on `1 << n` pour définir les flags ?
2. Quelle est la formule pour effacer un flag spécifique ?
3. Comment toggle-t-on un flag (l'inverse) ?

---

## Exercice 12 : Extraction d'adresse pour shellcode (Challenge)

**Objectif** : Convertir une adresse en bytes little endian pour un exploit.

### Instructions

Tu as une adresse de retour à écraser : `0x7FFFD234`
Tu dois l'écrire en little endian dans un buffer.

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t target_addr = 0x7FFFD234;

    // TODO: Extrais les 4 bytes et stocke-les en little endian
    unsigned char exploit_bytes[4];

    // exploit_bytes[0] = byte de poids faible (LSB)
    // exploit_bytes[1] = ...
    // exploit_bytes[2] = ...
    // exploit_bytes[3] = byte de poids fort (MSB)

    // Affiche le format shellcode
    printf("Adresse cible : 0x%08X\n", target_addr);
    printf("Format exploit : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02x", exploit_bytes[i]);
    }
    printf("\n");

    return 0;
}
```

### Résultat attendu
```
Adresse cible : 0x7FFFD234
Format exploit : \x34\xd2\xff\x7f
```

### Bonus

Fais la même chose pour une adresse 64-bit : `0x00007FFFD2345678`

---

## Exercice 13 : Reconstruction d'adresse depuis un dump (Challenge)

**Objectif** : Reconstruire une adresse à partir de bytes en mémoire.

### Instructions

Tu analyses un dump mémoire et tu vois ces bytes (little endian) :
`78 56 34 12`

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    // Bytes lus depuis le dump (dans l'ordre du dump)
    unsigned char dump[] = {0x78, 0x56, 0x34, 0x12};

    // TODO: Reconstruis l'adresse 32-bit
    // Utilise << et | pour assembler les bytes

    uint32_t address = /* ... */;

    printf("Bytes dans le dump : ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", dump[i]);
    }
    printf("\n");

    printf("Adresse reconstruite : 0x%08X\n", address);

    return 0;
}
```

### Résultat attendu
```
Bytes dans le dump : 78 56 34 12
Adresse reconstruite : 0x12345678
```

---

## Exercice 14 : Opérateur ternaire (Facile)

**Objectif** : Utiliser l'opérateur ternaire pour un code plus concis.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int score = 75;

    // TODO: Utilise l'opérateur ternaire pour :

    // 1. Assigner "PASS" ou "FAIL" selon si score >= 50
    const char *result = /* ... */;

    // 2. Trouver le maximum entre 10 et 25
    int max = /* ... */;

    // 3. Afficher "pair" ou "impair" selon score % 2
    const char *parity = /* ... */;

    printf("Score: %d → %s\n", score, result);
    printf("Max(10, 25) = %d\n", max);
    printf("Score est %s\n", parity);

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Utiliser tous les opérateurs arithmétiques (+, -, *, /, %)
- [ ] Différencier `++x` (pré) et `x++` (post) incrémentation
- [ ] Comprendre les résultats des comparaisons (0 ou 1)
- [ ] Utiliser AND (&&), OR (||), NOT (!) logiques
- [ ] Expliquer le short-circuit evaluation
- [ ] Utiliser AND (&) bitwise pour masquer/extraire des bits
- [ ] Utiliser OR (|) bitwise pour combiner des flags
- [ ] Utiliser XOR (^) pour chiffrer/déchiffrer
- [ ] Utiliser les shifts (<< et >>) pour construire/extraire des valeurs
- [ ] Manipuler des flags (set, clear, toggle, check)
- [ ] Convertir une adresse en bytes little endian
- [ ] Reconstruire une adresse depuis des bytes

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.
