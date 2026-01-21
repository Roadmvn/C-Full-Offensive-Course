# Exercices - Module 02 : Variables et Types

## Exercice 1 : Tailles des types (Très facile)

**Objectif** : Comprendre combien de bytes occupe chaque type.

### Instructions

Crée un programme qui affiche la taille de tous les types de base :

```c
#include <stdio.h>

int main(void) {
    printf("=== Tailles des types ===\n");
    // Utilise sizeof() pour afficher la taille de :
    // - char, short, int, long, long long
    // - float, double
    // - void* (pointeur)

    return 0;
}
```

### Questions

1. Quelle est la taille d'un `void*` sur ta machine ?
2. Cela signifie que tu es sur une architecture combien de bits ?
3. Pourquoi est-ce important de connaître ces tailles ?

---

## Exercice 2 : Limites des types (Facile)

**Objectif** : Comprendre les valeurs min/max de chaque type.

### Instructions

Utilise `<limits.h>` pour afficher les limites :

```c
#include <stdio.h>
#include <limits.h>

int main(void) {
    printf("=== Limites des types ===\n");
    printf("char    : %d à %d\n", CHAR_MIN, CHAR_MAX);
    printf("uchar   : 0 à %u\n", UCHAR_MAX);
    // Continue pour short, int, long...

    return 0;
}
```

### Questions

1. Quelle est la valeur max d'un `unsigned char` ?
2. Pourquoi `signed char` va de -128 à 127 et pas de -128 à 128 ?
3. Un port réseau (0-65535) peut tenir dans quel type ?

---

## Exercice 3 : Signed vs Unsigned - Le bug classique (Moyen)

**Objectif** : Comprendre pourquoi on utilise `unsigned char` pour les shellcodes.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // Déclare les mêmes bytes, signed et unsigned
    char s_byte = 0xFF;
    unsigned char u_byte = 0xFF;

    // Affiche les valeurs
    printf("signed char 0xFF   = %d\n", s_byte);
    printf("unsigned char 0xFF = %u\n", u_byte);

    // Teste les comparaisons
    printf("\nComparaisons avec 0 :\n");
    printf("signed 0xFF > 0   ? %s\n", (s_byte > 0) ? "OUI" : "NON");
    printf("unsigned 0xFF > 0 ? %s\n", (u_byte > 0) ? "OUI" : "NON");

    return 0;
}
```

### Questions

1. Pourquoi `0xFF` vaut -1 en signed mais 255 en unsigned ?
2. Si tu parcours un shellcode avec `char` et testes `> 0`, que se passe-t-il pour les bytes > 127 ?
3. Quel type dois-tu TOUJOURS utiliser pour manipuler des bytes bruts ?

---

## Exercice 4 : Endianness - Lire un dump mémoire (Moyen)

**Objectif** : Comprendre comment les valeurs sont stockées en mémoire.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    uint32_t value = 0x12345678;

    // Accède aux bytes individuels
    unsigned char *bytes = (unsigned char*)&value;

    printf("Valeur : 0x%08X\n", value);
    printf("Bytes en mémoire : ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");

    // Détecte l'endianness
    if (bytes[0] == 0x78) {
        printf("Cette machine est LITTLE ENDIAN\n");
    } else {
        printf("Cette machine est BIG ENDIAN\n");
    }

    return 0;
}
```

### Questions

1. Dans quel ordre sont stockés les bytes sur ta machine ?
2. Si tu vois `78 56 34 12` dans un dump mémoire, quelle est la valeur réelle ?
3. Pourquoi les protocoles réseau utilisent-ils big endian ?

---

## Exercice 5 : Integer Overflow (Moyen)

**Objectif** : Comprendre le "wrap around" et ses implications en sécurité.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // Test overflow unsigned
    unsigned char u = 255;
    printf("unsigned char avant : %u\n", u);
    u = u + 1;
    printf("unsigned char après +1 : %u\n", u);

    // Test overflow signed
    signed char s = 127;
    printf("\nsigned char avant : %d\n", s);
    s = s + 1;
    printf("signed char après +1 : %d\n", s);

    // Test underflow
    unsigned char zero = 0;
    printf("\nunsigned char avant : %u\n", zero);
    zero = zero - 1;
    printf("unsigned char après -1 : %u\n", zero);

    return 0;
}
```

### Questions

1. Que vaut `255 + 1` pour un `unsigned char` ?
2. Que vaut `127 + 1` pour un `signed char` ?
3. Comment un attaquant pourrait exploiter un integer overflow ?

---

## Exercice 6 : Types Windows (Moyen)

**Objectif** : Connaître les types utilisés dans la programmation Windows.

### Instructions

Simule les types Windows et affiche leurs tailles :

```c
#include <stdio.h>

// Simule les types Windows
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

    // Exemple d'utilisation
    DWORD pid = 1337;
    WORD port = 4444;
    printf("\nPID   : %u\n", pid);
    printf("Port  : %u\n", port);

    return 0;
}
```

### Questions

1. Pourquoi Windows utilise `DWORD` au lieu de `unsigned int` ?
2. Un handle Windows est de type `HANDLE` (typedef de `void*`). Quelle taille sur x64 ?
3. Le champ `Machine` d'un header PE est de type `WORD`. Combien de bytes ?

---

## Exercice 7 : Écrire une adresse pour un exploit (Challenge)

**Objectif** : Apprendre à formater une adresse pour un buffer overflow.

### Contexte
Dans un exploit, tu dois écrire une adresse (ex: `0x7fff1234`) dans un buffer.
Sur x86/x64 (little endian), tu dois inverser l'ordre des bytes.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

int main(void) {
    // Adresse cible (exemple : adresse de retour à écraser)
    uint32_t target = 0x7fff1234;

    // TODO: Extrais chaque byte et stocke-les en little endian
    unsigned char exploit[4];
    exploit[0] = /* byte de poids faible */;
    exploit[1] = /* ... */;
    exploit[2] = /* ... */;
    exploit[3] = /* byte de poids fort */;

    printf("Adresse cible : 0x%08X\n", target);
    printf("Bytes pour l'exploit : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02x", exploit[i]);
    }
    printf("\n");

    return 0;
}
```

### Résultat attendu
```
Adresse cible : 0x7FFF1234
Bytes pour l'exploit : \x34\x12\xff\x7f
```

### Indice
Utilise les opérateurs de décalage `>>` et le masque `& 0xFF`.

---

## Exercice 8 : Détecter un integer overflow (Challenge)

**Objectif** : Écrire une fonction qui détecte un overflow avant qu'il ne se produise.

### Contexte
Tu écris du code qui alloue de la mémoire basée sur une taille fournie par l'utilisateur.
Tu dois détecter si `len * sizeof(element)` va overflow.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

// Retourne 1 si la multiplication overflow, 0 sinon
int will_overflow(unsigned int a, unsigned int b) {
    // TODO: Implémente la détection
    // Indice : si a * b overflow, alors (a * b) / b != a
    // Ou utilise : a > UINT_MAX / b
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

### Résultat attendu
```
size=100, element_size=8 : OK (total = 800)
size=1000000000, element_size=8 : OVERFLOW DÉTECTÉ!
size=4294967295, element_size=8 : OVERFLOW DÉTECTÉ!
```

---

## Exercice 9 : Parser un "header" binaire (Challenge)

**Objectif** : Lire une structure binaire en respectant les tailles et l'endianness.

### Contexte
Tu analyses un format binaire simplifié avec un header de 8 bytes :
- Bytes 0-1 : Magic number (WORD, 0x4D5A = "MZ")
- Bytes 2-3 : Version (WORD)
- Bytes 4-7 : Taille du fichier (DWORD)

### Instructions

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    // Header binaire brut (little endian)
    unsigned char raw_header[] = {
        0x4D, 0x5A,             // Magic "MZ"
        0x01, 0x00,             // Version 1
        0x00, 0x10, 0x00, 0x00  // Taille 0x1000 = 4096 bytes
    };

    // TODO: Parse le header
    uint16_t magic = /* Lis bytes 0-1 */;
    uint16_t version = /* Lis bytes 2-3 */;
    uint32_t size = /* Lis bytes 4-7 */;

    printf("Magic   : 0x%04X", magic);
    if (magic == 0x5A4D) printf(" (MZ - Executable DOS/Windows)");
    printf("\n");
    printf("Version : %u\n", version);
    printf("Taille  : %u bytes\n", size);

    return 0;
}
```

### Indice
Tu peux caster le pointeur ou lire byte par byte et reconstruire.
Attention à l'endianness !

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Utiliser `sizeof()` pour connaître la taille des types
- [ ] Expliquer la différence entre signed et unsigned
- [ ] Expliquer pourquoi utiliser `unsigned char` pour les shellcodes
- [ ] Lire un dump mémoire et interpréter l'endianness
- [ ] Détecter et comprendre un integer overflow
- [ ] Convertir une adresse en little endian pour un exploit
- [ ] Connaître les types Windows (BYTE, WORD, DWORD)

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.
