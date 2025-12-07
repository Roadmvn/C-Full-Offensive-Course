# Exercices - Module 09 : Pointeurs Fondamentaux

## Exercice 1 : Adresses et valeurs (Très facile)

**Objectif** : Comprendre la relation entre variables, adresses et pointeurs.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int a = 10;
    int b = 20;
    int c = 30;

    // TODO:
    // 1. Affiche la valeur de chaque variable
    // 2. Affiche l'adresse de chaque variable (utilise %p)
    // 3. Affiche la taille de chaque variable
    // 4. Crée des pointeurs vers chaque variable
    // 5. Affiche les valeurs via les pointeurs (déréférencement)

    return 0;
}
```

---

## Exercice 2 : Modification via pointeur (Très facile)

**Objectif** : Modifier des variables via des pointeurs.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int secret = 1234;
    int *ptr = &secret;

    printf("Valeur initiale : %d\n", secret);

    // TODO:
    // 1. Modifie secret à 9999 via ptr (sans toucher directement à secret)
    // 2. Affiche la nouvelle valeur
    // 3. Multiplie la valeur par 2 via ptr
    // 4. Affiche le résultat

    return 0;
}
```

---

## Exercice 3 : Passage par référence (Facile)

**Objectif** : Utiliser les pointeurs pour modifier des variables dans une fonction.

### Instructions

```c
#include <stdio.h>

// TODO: Implémente ces fonctions

// Multiplie x par 2 (modifie l'original)
void double_value(int *x) {
    // TODO
}

// Échange les valeurs de a et b
void swap(int *a, int *b) {
    // TODO
}

// Met x à zéro
void reset(int *x) {
    // TODO
}

int main(void) {
    int num = 25;
    printf("Avant double_value: %d\n", num);
    double_value(&num);
    printf("Après double_value: %d\n", num);  // Devrait être 50

    int x = 100, y = 200;
    printf("\nAvant swap: x=%d, y=%d\n", x, y);
    swap(&x, &y);
    printf("Après swap: x=%d, y=%d\n", x, y);  // x=200, y=100

    printf("\nAvant reset: num=%d\n", num);
    reset(&num);
    printf("Après reset: num=%d\n", num);  // 0

    return 0;
}
```

---

## Exercice 4 : Pointeurs et tableaux (Facile)

**Objectif** : Comprendre l'équivalence entre tableaux et pointeurs.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int ports[] = {21, 22, 80, 443, 3306, 3389, 8080};
    int size = 7;

    // TODO:
    // 1. Affiche l'adresse du tableau (arr et &arr[0])
    // 2. Crée un pointeur ptr vers le tableau
    // 3. Affiche chaque élément de 3 façons différentes:
    //    - arr[i]
    //    - *(arr + i)
    //    - *(ptr + i)
    // 4. Parcours le tableau avec un pointeur qui s'incrémente

    return 0;
}
```

---

## Exercice 5 : Arithmétique de pointeurs (Facile)

**Objectif** : Maîtriser l'arithmétique de pointeurs.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int values[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    int *start = values;
    int *end = &values[9];

    // TODO:
    // 1. Affiche l'adresse de start et end
    // 2. Calcule le nombre d'éléments entre start et end
    // 3. Avance start de 3 positions et affiche la valeur
    // 4. Recule end de 2 positions et affiche la valeur
    // 5. Affiche toutes les valeurs entre les nouveaux start et end

    return 0;
}
```

---

## Exercice 6 : Retourner plusieurs valeurs (Moyen)

**Objectif** : Utiliser les pointeurs pour retourner plusieurs valeurs d'une fonction.

### Instructions

```c
#include <stdio.h>

// TODO: Implémente cette fonction
// Elle doit retourner le min ET le max d'un tableau
void find_min_max(int arr[], int size, int *min, int *max) {
    // TODO
}

// BONUS: Retourne min, max ET moyenne
void array_stats(int arr[], int size, int *min, int *max, float *avg) {
    // TODO
}

int main(void) {
    int data[] = {42, 17, 89, 3, 56, 91, 23, 8, 67, 45};
    int size = 10;

    int min, max;
    find_min_max(data, size, &min, &max);
    printf("Min: %d, Max: %d\n", min, max);

    float avg;
    array_stats(data, size, &min, &max, &avg);
    printf("Min: %d, Max: %d, Moyenne: %.2f\n", min, max, avg);

    return 0;
}
```

---

## Exercice 7 : Hexdump simple (Moyen)

**Objectif** : Examiner la mémoire brute avec des pointeurs.

### Instructions

```c
#include <stdio.h>

// TODO: Implémente la fonction hexdump
// Elle affiche les bytes en hexadécimal avec leur offset
void hexdump(void *ptr, int size) {
    // Caste ptr en unsigned char*
    // Pour chaque byte:
    //   - Affiche l'offset tous les 16 bytes
    //   - Affiche le byte en hex (%02X)
    //   - Nouvelle ligne tous les 16 bytes
}

int main(void) {
    // Test 1: Un entier
    int x = 0x41424344;
    printf("Hexdump de int 0x41424344:\n");
    hexdump(&x, sizeof(x));
    printf("\n");

    // Test 2: Une string
    char msg[] = "ATTACK";
    printf("Hexdump de \"ATTACK\":\n");
    hexdump(msg, sizeof(msg));
    printf("\n");

    // Test 3: Un tableau de bytes
    unsigned char shellcode[] = {0x31, 0xC0, 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68};
    printf("Hexdump de shellcode:\n");
    hexdump(shellcode, sizeof(shellcode));

    return 0;
}
```

---

## Exercice 8 : XOR avec pointeurs (Moyen)

**Objectif** : Encoder/décoder des données avec XOR en utilisant des pointeurs.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO: Implémente ces fonctions avec des pointeurs (pas d'indexation [i])

// Encode/décode avec XOR single-byte
void xor_crypt(unsigned char *data, int len, unsigned char key) {
    // Utilise uniquement arithmétique de pointeurs
    // *ptr, ptr++, etc.
}

// Encode/décode avec XOR multi-byte (clé de plusieurs bytes)
void xor_crypt_multi(unsigned char *data, int len, unsigned char *key, int key_len) {
    // TODO
}

int main(void) {
    // Test 1: XOR simple
    char secret[] = "C2_SERVER_IP";
    unsigned char key = 0x42;

    printf("Original: %s\n", secret);

    xor_crypt((unsigned char*)secret, strlen(secret), key);
    printf("Encodé (hex): ");
    for (int i = 0; i < strlen(secret); i++) {
        printf("%02X ", (unsigned char)secret[i]);
    }
    printf("\n");

    xor_crypt((unsigned char*)secret, strlen(secret), key);
    printf("Décodé: %s\n\n", secret);

    // Test 2: XOR multi-byte
    char message[] = "ATTACK_AT_DAWN";
    unsigned char multi_key[] = {0xDE, 0xAD, 0xBE, 0xEF};

    printf("Original: %s\n", message);

    xor_crypt_multi((unsigned char*)message, strlen(message), multi_key, 4);
    printf("Encodé multi (hex): ");
    for (int i = 0; i < strlen(message); i++) {
        printf("%02X ", (unsigned char)message[i]);
    }
    printf("\n");

    xor_crypt_multi((unsigned char*)message, strlen(message), multi_key, 4);
    printf("Décodé: %s\n", message);

    return 0;
}
```

---

## Exercice 9 : Recherche de pattern (Moyen)

**Objectif** : Chercher un pattern de bytes dans une zone mémoire.

### Instructions

```c
#include <stdio.h>

// TODO: Implémente la recherche de pattern
// Retourne un pointeur vers la première occurrence, ou NULL si non trouvé
unsigned char* find_pattern(unsigned char *haystack, int hay_size,
                            unsigned char *needle, int needle_size) {
    // TODO
}

// BONUS: Trouve TOUTES les occurrences
int find_all_patterns(unsigned char *haystack, int hay_size,
                      unsigned char *needle, int needle_size,
                      unsigned char **results, int max_results) {
    // Stocke les pointeurs trouvés dans results[]
    // Retourne le nombre d'occurrences
}

int main(void) {
    // Simule une zone mémoire (comme un dump)
    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0x90, 0xCC,  // NOP sled + INT3
        0x31, 0xC0,                          // xor eax, eax
        0x50,                                // push eax
        0x68, 0x2F, 0x2F, 0x73, 0x68,        // push "//sh"
        0x31, 0xC0,                          // xor eax, eax (again)
        0xC3                                 // ret
    };
    int mem_size = sizeof(memory);

    // Cherche "xor eax, eax" (0x31 0xC0)
    unsigned char pattern[] = {0x31, 0xC0};

    unsigned char *found = find_pattern(memory, mem_size, pattern, 2);
    if (found) {
        printf("[+] Pattern trouvé à l'offset %ld\n", found - memory);
    } else {
        printf("[-] Pattern non trouvé\n");
    }

    // BONUS: Cherche toutes les occurrences
    unsigned char *results[10];
    int count = find_all_patterns(memory, mem_size, pattern, 2, results, 10);
    printf("[*] Trouvé %d occurrences:\n", count);
    for (int i = 0; i < count; i++) {
        printf("    Offset %ld\n", results[i] - memory);
    }

    return 0;
}
```

---

## Exercice 10 : Void pointer générique (Moyen)

**Objectif** : Utiliser void* pour créer des fonctions génériques.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO: Implémente une fonction de copie mémoire générique
void my_memcpy(void *dest, void *src, int size) {
    // Caste en unsigned char* et copie byte par byte
}

// TODO: Implémente une fonction de comparaison mémoire générique
int my_memcmp(void *ptr1, void *ptr2, int size) {
    // Retourne 0 si identiques, != 0 sinon
}

// TODO: Implémente une fonction de remplissage mémoire
void my_memset(void *ptr, unsigned char value, int size) {
    // Remplit size bytes avec value
}

int main(void) {
    // Test memcpy
    int src[] = {1, 2, 3, 4, 5};
    int dest[5];
    my_memcpy(dest, src, sizeof(src));
    printf("Copie de tableau: ");
    for (int i = 0; i < 5; i++) printf("%d ", dest[i]);
    printf("\n");

    // Test memcmp
    char str1[] = "HELLO";
    char str2[] = "HELLO";
    char str3[] = "WORLD";
    printf("memcmp(HELLO, HELLO) = %d\n", my_memcmp(str1, str2, 5));
    printf("memcmp(HELLO, WORLD) = %d\n", my_memcmp(str1, str3, 5));

    // Test memset
    unsigned char buffer[10];
    my_memset(buffer, 0x90, 10);  // NOP sled
    printf("Buffer après memset(0x90): ");
    for (int i = 0; i < 10; i++) printf("%02X ", buffer[i]);
    printf("\n");

    return 0;
}
```

---

## Exercice 11 : Pointeur comme retour de fonction (Challenge)

**Objectif** : Retourner des pointeurs de fonctions de manière sécurisée.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// DANGER: Cette fonction est INCORRECTE - explique pourquoi
char* dangerous_function(void) {
    char buffer[100] = "This is local data";
    return buffer;  // Que se passe-t-il ici?
}

// TODO: Implémente une version CORRECTE
// Option 1: Utilise un buffer passé en paramètre
char* safe_function_v1(char *buffer, int size) {
    // TODO: Copie "Safe data" dans buffer et retourne buffer
    return NULL;
}

// Option 2: Utilise une variable static
char* safe_function_v2(void) {
    // TODO: Utilise static char buffer[...]
    return NULL;
}

int main(void) {
    // Test de la fonction dangereuse (comportement indéfini!)
    // char *bad = dangerous_function();
    // printf("Dangerous: %s\n", bad);  // CRASH ou données corrompues

    // Test safe v1
    char buffer[100];
    char *result1 = safe_function_v1(buffer, 100);
    printf("Safe v1: %s\n", result1);

    // Test safe v2
    char *result2 = safe_function_v2();
    printf("Safe v2: %s\n", result2);

    return 0;
}
```

---

## Exercice 12 : Manipulation de shellcode (Challenge)

**Objectif** : Manipuler du shellcode avec des pointeurs.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// Shellcode encodé en XOR avec clé 0x55
unsigned char encoded_shellcode[] = {
    0x64, 0x95, 0x05, 0x3D, 0x7A, 0x7A, 0x26, 0x3D,  // "/bin/sh" XOR 0x55
    0x00
};

// TODO:
// 1. Affiche le shellcode encodé en hex
// 2. Décode le shellcode avec XOR 0x55
// 3. Affiche le shellcode décodé (comme string)
// 4. Génère le code C pour le shellcode encodé:
//    "unsigned char shellcode[] = {0xXX, 0xXX, ...};"

void print_hex(unsigned char *data, int len) {
    // TODO
}

void xor_decode(unsigned char *data, int len, unsigned char key) {
    // TODO
}

void generate_c_code(unsigned char *data, int len, const char *var_name) {
    // TODO: Génère une déclaration C
}

int main(void) {
    int len = sizeof(encoded_shellcode) - 1;  // Sans le null terminator

    printf("=== Manipulation de shellcode ===\n\n");

    printf("Shellcode encodé:\n");
    print_hex(encoded_shellcode, len);

    printf("\nDécodage avec clé 0x55...\n");
    xor_decode(encoded_shellcode, len, 0x55);

    printf("Shellcode décodé: \"%s\"\n\n", encoded_shellcode);

    // Ré-encode pour générer le code
    xor_decode(encoded_shellcode, len, 0x55);

    printf("Code C généré:\n");
    generate_c_code(encoded_shellcode, len, "shellcode");

    return 0;
}
```

---

## Exercice 13 : Tableau de pointeurs (Challenge)

**Objectif** : Gérer un tableau de pointeurs pour un système de commandes.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// Commandes C2 simulées
char *commands[] = {
    "whoami",
    "pwd",
    "ls -la",
    "cat /etc/passwd",
    "uname -a",
    NULL  // Sentinelle
};

// TODO:
// 1. Compte le nombre de commandes (jusqu'à NULL)
// 2. Affiche toutes les commandes avec leur index
// 3. Trouve une commande par son nom (retourne l'index ou -1)
// 4. Ajoute une nouvelle commande (dans un tableau modifiable)

int count_commands(char **cmds) {
    // TODO
    return 0;
}

void print_commands(char **cmds) {
    // TODO
}

int find_command(char **cmds, const char *name) {
    // TODO
    return -1;
}

int main(void) {
    printf("=== Système de commandes C2 ===\n\n");

    int count = count_commands(commands);
    printf("Nombre de commandes: %d\n\n", count);

    printf("Liste des commandes:\n");
    print_commands(commands);
    printf("\n");

    // Recherche
    const char *search = "cat /etc/passwd";
    int idx = find_command(commands, search);
    if (idx >= 0) {
        printf("Commande '%s' trouvée à l'index %d\n", search, idx);
    } else {
        printf("Commande '%s' non trouvée\n", search);
    }

    return 0;
}
```

---

## Exercice 14 : Memory patching (Challenge)

**Objectif** : Modifier du code machine en mémoire.

### Instructions

```c
#include <stdio.h>

// Simule une fonction avec une vérification de licence
unsigned char license_check[] = {
    0x55,                    // push rbp
    0x48, 0x89, 0xE5,        // mov rbp, rsp
    0x83, 0xFF, 0x01,        // cmp edi, 1
    0x75, 0x07,              // jne +7 (saute si pas égal à 1)
    0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (return 1 = licensed)
    0xC9,                    // leave
    0xC3,                    // ret
    0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0 (return 0 = not licensed)
    0xC9,                    // leave
    0xC3                     // ret
};

// TODO:
// 1. Affiche le code original en hex
// 2. Trouve l'instruction JNE (0x75)
// 3. Patch JNE -> JMP (0xEB) pour bypasser la vérification
// 4. Affiche le code patché
// 5. BONUS: Patch pour toujours retourner 1 (NOP le jump)

void hexdump_with_offset(unsigned char *data, int size) {
    // TODO
}

unsigned char* find_byte(unsigned char *data, int size, unsigned char target) {
    // TODO: Trouve la première occurrence de target
    return NULL;
}

void patch_byte(unsigned char *target, unsigned char new_value) {
    // TODO
}

int main(void) {
    int size = sizeof(license_check);

    printf("=== License Check Bypass ===\n\n");

    printf("Code original:\n");
    hexdump_with_offset(license_check, size);

    // Trouve JNE (0x75)
    unsigned char *jne = find_byte(license_check, size, 0x75);
    if (jne) {
        int offset = jne - license_check;
        printf("\n[+] JNE trouvé à l'offset %d\n", offset);

        // Patch: JNE -> JMP
        printf("[*] Patching JNE (0x75) -> JMP (0xEB)\n");
        patch_byte(jne, 0xEB);

        printf("\nCode patché:\n");
        hexdump_with_offset(license_check, size);

        printf("\n[+] Le check de licence est maintenant bypassé!\n");
    } else {
        printf("[-] JNE non trouvé\n");
    }

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Déclarer et initialiser des pointeurs
- [ ] Utiliser & pour obtenir une adresse
- [ ] Utiliser * pour déréférencer
- [ ] Passer des variables par référence à des fonctions
- [ ] Comprendre la relation tableaux/pointeurs
- [ ] Utiliser l'arithmétique de pointeurs
- [ ] Créer des fonctions avec void*
- [ ] Examiner la mémoire avec hexdump
- [ ] Encoder/décoder avec XOR via pointeurs
- [ ] Rechercher des patterns en mémoire
- [ ] Éviter les erreurs courantes (NULL, dangling pointers)

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.
