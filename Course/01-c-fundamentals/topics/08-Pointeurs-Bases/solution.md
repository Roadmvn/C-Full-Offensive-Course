# Solutions - Module 09 : Pointeurs Fondamentaux

## Solution Exercice 1 : Adresses et valeurs

```c
#include <stdio.h>

int main(void) {
    int a = 10;
    int b = 20;
    int c = 30;

    // 1. Affiche la valeur de chaque variable
    printf("=== Valeurs ===\n");
    printf("a = %d\n", a);
    printf("b = %d\n", b);
    printf("c = %d\n", c);

    // 2. Affiche l'adresse de chaque variable
    printf("\n=== Adresses ===\n");
    printf("&a = %p\n", (void*)&a);
    printf("&b = %p\n", (void*)&b);
    printf("&c = %p\n", (void*)&c);

    // 3. Affiche la taille de chaque variable
    printf("\n=== Tailles ===\n");
    printf("sizeof(a) = %lu bytes\n", sizeof(a));
    printf("sizeof(b) = %lu bytes\n", sizeof(b));
    printf("sizeof(c) = %lu bytes\n", sizeof(c));

    // 4. Crée des pointeurs vers chaque variable
    int *pa = &a;
    int *pb = &b;
    int *pc = &c;

    // 5. Affiche les valeurs via les pointeurs
    printf("\n=== Déréférencement ===\n");
    printf("*pa = %d\n", *pa);
    printf("*pb = %d\n", *pb);
    printf("*pc = %d\n", *pc);

    return 0;
}
```

**Explication** : Le pointeur stocke l'adresse, `*` permet d'accéder à la valeur à cette adresse.

---

## Solution Exercice 2 : Modification via pointeur

```c
#include <stdio.h>

int main(void) {
    int secret = 1234;
    int *ptr = &secret;

    printf("Valeur initiale : %d\n", secret);

    // 1. Modifie secret à 9999 via ptr
    *ptr = 9999;

    // 2. Affiche la nouvelle valeur
    printf("Après *ptr = 9999 : %d\n", secret);

    // 3. Multiplie la valeur par 2 via ptr
    *ptr = *ptr * 2;
    // ou: *ptr *= 2;

    // 4. Affiche le résultat
    printf("Après *ptr *= 2 : %d\n", secret);

    return 0;
}
```

**Sortie** :
```
Valeur initiale : 1234
Après *ptr = 9999 : 9999
Après *ptr *= 2 : 19998
```

---

## Solution Exercice 3 : Passage par référence

```c
#include <stdio.h>

void double_value(int *x) {
    *x = *x * 2;  // ou *x *= 2
}

void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void reset(int *x) {
    *x = 0;
}

int main(void) {
    int num = 25;
    printf("Avant double_value: %d\n", num);
    double_value(&num);
    printf("Après double_value: %d\n", num);

    int x = 100, y = 200;
    printf("\nAvant swap: x=%d, y=%d\n", x, y);
    swap(&x, &y);
    printf("Après swap: x=%d, y=%d\n", x, y);

    printf("\nAvant reset: num=%d\n", num);
    reset(&num);
    printf("Après reset: num=%d\n", num);

    return 0;
}
```

**Point clé** : L'opérateur `&` passe l'adresse, permettant à la fonction de modifier l'original.

---

## Solution Exercice 4 : Pointeurs et tableaux

```c
#include <stdio.h>

int main(void) {
    int ports[] = {21, 22, 80, 443, 3306, 3389, 8080};
    int size = 7;

    // 1. Affiche l'adresse du tableau
    printf("ports     = %p\n", (void*)ports);
    printf("&ports[0] = %p\n", (void*)&ports[0]);

    // 2. Crée un pointeur vers le tableau
    int *ptr = ports;
    printf("ptr       = %p\n\n", (void*)ptr);

    // 3. Affiche chaque élément de 3 façons
    printf("%-10s %-10s %-10s\n", "arr[i]", "*(arr+i)", "*(ptr+i)");
    printf("%-10s %-10s %-10s\n", "------", "--------", "--------");
    for (int i = 0; i < size; i++) {
        printf("%-10d %-10d %-10d\n", ports[i], *(ports + i), *(ptr + i));
    }

    // 4. Parcours avec pointeur qui s'incrémente
    printf("\nParcours avec pointeur:\n");
    int *p = ports;
    for (int i = 0; i < size; i++) {
        printf("Port: %d (adresse: %p)\n", *p, (void*)p);
        p++;
    }

    return 0;
}
```

**Explication** : `arr[i]` est strictement équivalent à `*(arr + i)`. Le nom du tableau est un pointeur vers le premier élément.

---

## Solution Exercice 5 : Arithmétique de pointeurs

```c
#include <stdio.h>

int main(void) {
    int values[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    int *start = values;
    int *end = &values[9];

    // 1. Affiche l'adresse de start et end
    printf("start = %p\n", (void*)start);
    printf("end   = %p\n", (void*)end);

    // 2. Calcule le nombre d'éléments
    printf("\nNombre d'éléments entre start et end: %ld\n", end - start);
    printf("(Différence en bytes: %ld)\n", (char*)end - (char*)start);

    // 3. Avance start de 3 positions
    start += 3;
    printf("\nAprès start += 3:\n");
    printf("  start = %p, *start = %d\n", (void*)start, *start);

    // 4. Recule end de 2 positions
    end -= 2;
    printf("Après end -= 2:\n");
    printf("  end = %p, *end = %d\n", (void*)end, *end);

    // 5. Affiche toutes les valeurs entre start et end
    printf("\nValeurs entre start et end:\n");
    for (int *p = start; p <= end; p++) {
        printf("  %d", *p);
    }
    printf("\n");

    return 0;
}
```

**Sortie** :
```
start = 0x7ffd...
end   = 0x7ffd...

Nombre d'éléments entre start et end: 9
(Différence en bytes: 36)

Après start += 3:
  start = 0x7ffd..., *start = 40
Après end -= 2:
  end = 0x7ffd..., *end = 80

Valeurs entre start et end:
  40  50  60  70  80
```

---

## Solution Exercice 6 : Retourner plusieurs valeurs

```c
#include <stdio.h>

void find_min_max(int arr[], int size, int *min, int *max) {
    if (size <= 0) return;

    *min = arr[0];
    *max = arr[0];

    for (int i = 1; i < size; i++) {
        if (arr[i] < *min) *min = arr[i];
        if (arr[i] > *max) *max = arr[i];
    }
}

void array_stats(int arr[], int size, int *min, int *max, float *avg) {
    if (size <= 0) return;

    *min = arr[0];
    *max = arr[0];
    int sum = 0;

    for (int i = 0; i < size; i++) {
        if (arr[i] < *min) *min = arr[i];
        if (arr[i] > *max) *max = arr[i];
        sum += arr[i];
    }

    *avg = (float)sum / size;
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

**Sortie** :
```
Min: 3, Max: 91
Min: 3, Max: 91, Moyenne: 44.10
```

---

## Solution Exercice 7 : Hexdump simple

```c
#include <stdio.h>

void hexdump(void *ptr, int size) {
    unsigned char *bytes = (unsigned char*)ptr;

    for (int i = 0; i < size; i++) {
        // Affiche l'offset tous les 16 bytes
        if (i % 16 == 0) {
            printf("%08X: ", i);
        }

        // Affiche le byte en hex
        printf("%02X ", bytes[i]);

        // Nouvelle ligne tous les 16 bytes
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    // Nouvelle ligne finale si pas multiple de 16
    if (size % 16 != 0) {
        printf("\n");
    }
}

int main(void) {
    // Test 1: Un entier
    int x = 0x41424344;
    printf("Hexdump de int 0x41424344:\n");
    hexdump(&x, sizeof(x));
    printf("(Little-endian: 44 43 42 41 = 'D' 'C' 'B' 'A')\n\n");

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

**Sortie** :
```
Hexdump de int 0x41424344:
00000000: 44 43 42 41
(Little-endian: 44 43 42 41 = 'D' 'C' 'B' 'A')

Hexdump de "ATTACK":
00000000: 41 54 54 41 43 4B 00

Hexdump de shellcode:
00000000: 31 C0 50 68 2F 2F 73 68
```

---

## Solution Exercice 8 : XOR avec pointeurs

```c
#include <stdio.h>
#include <string.h>

void xor_crypt(unsigned char *data, int len, unsigned char key) {
    unsigned char *end = data + len;

    while (data < end) {
        *data ^= key;
        data++;
    }
}

void xor_crypt_multi(unsigned char *data, int len, unsigned char *key, int key_len) {
    unsigned char *end = data + len;
    int key_idx = 0;

    while (data < end) {
        *data ^= key[key_idx];
        data++;
        key_idx = (key_idx + 1) % key_len;  // Rotation de clé
    }
}

int main(void) {
    // Test 1: XOR simple
    char secret[] = "C2_SERVER_IP";
    unsigned char key = 0x42;

    printf("Original: %s\n", secret);

    xor_crypt((unsigned char*)secret, strlen(secret), key);
    printf("Encodé (hex): ");
    for (size_t i = 0; i < strlen(secret); i++) {
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
    for (size_t i = 0; i < strlen(message); i++) {
        printf("%02X ", (unsigned char)message[i]);
    }
    printf("\n");

    xor_crypt_multi((unsigned char*)message, strlen(message), multi_key, 4);
    printf("Décodé: %s\n", message);

    return 0;
}
```

**Point clé** : En utilisant uniquement l'arithmétique de pointeurs (`*data`, `data++`), on évite l'indexation par tableau.

---

## Solution Exercice 9 : Recherche de pattern

```c
#include <stdio.h>

unsigned char* find_pattern(unsigned char *haystack, int hay_size,
                            unsigned char *needle, int needle_size) {
    for (int i = 0; i <= hay_size - needle_size; i++) {
        int match = 1;
        for (int j = 0; j < needle_size; j++) {
            if (haystack[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return &haystack[i];
        }
    }
    return NULL;
}

int find_all_patterns(unsigned char *haystack, int hay_size,
                      unsigned char *needle, int needle_size,
                      unsigned char **results, int max_results) {
    int count = 0;

    for (int i = 0; i <= hay_size - needle_size && count < max_results; i++) {
        int match = 1;
        for (int j = 0; j < needle_size; j++) {
            if (haystack[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            results[count++] = &haystack[i];
        }
    }
    return count;
}

int main(void) {
    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0x90, 0xCC,
        0x31, 0xC0,
        0x50,
        0x68, 0x2F, 0x2F, 0x73, 0x68,
        0x31, 0xC0,
        0xC3
    };
    int mem_size = sizeof(memory);

    unsigned char pattern[] = {0x31, 0xC0};

    // Première occurrence
    unsigned char *found = find_pattern(memory, mem_size, pattern, 2);
    if (found) {
        printf("[+] Pattern trouvé à l'offset %ld\n", found - memory);
    }

    // Toutes les occurrences
    unsigned char *results[10];
    int count = find_all_patterns(memory, mem_size, pattern, 2, results, 10);
    printf("[*] Trouvé %d occurrences:\n", count);
    for (int i = 0; i < count; i++) {
        printf("    Offset %ld\n", results[i] - memory);
    }

    return 0;
}
```

**Sortie** :
```
[+] Pattern trouvé à l'offset 6
[*] Trouvé 2 occurrences:
    Offset 6
    Offset 14
```

---

## Solution Exercice 10 : Void pointer générique

```c
#include <stdio.h>

void my_memcpy(void *dest, void *src, int size) {
    unsigned char *d = (unsigned char*)dest;
    unsigned char *s = (unsigned char*)src;

    for (int i = 0; i < size; i++) {
        d[i] = s[i];
    }
}

int my_memcmp(void *ptr1, void *ptr2, int size) {
    unsigned char *p1 = (unsigned char*)ptr1;
    unsigned char *p2 = (unsigned char*)ptr2;

    for (int i = 0; i < size; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

void my_memset(void *ptr, unsigned char value, int size) {
    unsigned char *p = (unsigned char*)ptr;

    for (int i = 0; i < size; i++) {
        p[i] = value;
    }
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
    my_memset(buffer, 0x90, 10);
    printf("Buffer après memset(0x90): ");
    for (int i = 0; i < 10; i++) printf("%02X ", buffer[i]);
    printf("\n");

    return 0;
}
```

**Point clé** : `void*` permet de créer des fonctions génériques qui travaillent avec n'importe quel type de données en les traitant comme des bytes.

---

## Solution Exercice 11 : Pointeur comme retour de fonction

```c
#include <stdio.h>
#include <string.h>

// DANGER: Cette fonction est INCORRECTE
// buffer est une variable locale, elle sera détruite à la fin de la fonction
// Le pointeur retourné pointe vers de la mémoire invalide (dangling pointer)
char* dangerous_function(void) {
    char buffer[100] = "This is local data";
    return buffer;  // DANGER: buffer n'existe plus après return!
}

// SOLUTION 1: Buffer passé en paramètre (appelant gère la mémoire)
char* safe_function_v1(char *buffer, int size) {
    const char *data = "Safe data from v1";
    int len = strlen(data);

    if (len >= size) {
        return NULL;  // Buffer trop petit
    }

    strcpy(buffer, data);
    return buffer;
}

// SOLUTION 2: Variable static (survit à la fonction)
char* safe_function_v2(void) {
    static char buffer[100] = "Safe data from v2";
    // static signifie que buffer existe pour toute la durée du programme
    return buffer;
}

int main(void) {
    // La fonction dangereuse causerait un comportement indéfini
    // char *bad = dangerous_function();
    // printf("Dangerous: %s\n", bad);

    // Test safe v1
    char buffer[100];
    char *result1 = safe_function_v1(buffer, 100);
    if (result1) {
        printf("Safe v1: %s\n", result1);
    }

    // Test safe v2
    char *result2 = safe_function_v2();
    printf("Safe v2: %s\n", result2);

    return 0;
}
```

**Explication du danger** : Les variables locales sont allouées sur la stack. Quand la fonction se termine, la stack frame est libérée. Le pointeur retourné pointe vers de la mémoire qui peut être réutilisée par d'autres fonctions.

---

## Solution Exercice 12 : Manipulation de shellcode

```c
#include <stdio.h>
#include <string.h>

unsigned char encoded_shellcode[] = {
    0x64, 0x95, 0x05, 0x3D, 0x7A, 0x7A, 0x26, 0x3D,
    0x00
};

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void xor_decode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void generate_c_code(unsigned char *data, int len, const char *var_name) {
    printf("unsigned char %s[] = {\n    ", var_name);
    for (int i = 0; i < len; i++) {
        printf("0x%02X", data[i]);
        if (i < len - 1) {
            printf(", ");
        }
        if ((i + 1) % 8 == 0 && i < len - 1) {
            printf("\n    ");
        }
    }
    printf("\n};\n");
}

int main(void) {
    int len = sizeof(encoded_shellcode) - 1;

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

**Sortie** :
```
=== Manipulation de shellcode ===

Shellcode encodé:
64 95 05 3D 7A 7A 26 3D

Décodage avec clé 0x55...
Shellcode décodé: "1bin/sh"

Code C généré:
unsigned char shellcode[] = {
    0x64, 0x95, 0x05, 0x3D, 0x7A, 0x7A, 0x26, 0x3D
};
```

---

## Solution Exercice 13 : Tableau de pointeurs

```c
#include <stdio.h>
#include <string.h>

char *commands[] = {
    "whoami",
    "pwd",
    "ls -la",
    "cat /etc/passwd",
    "uname -a",
    NULL
};

int count_commands(char **cmds) {
    int count = 0;
    while (cmds[count] != NULL) {
        count++;
    }
    return count;
}

void print_commands(char **cmds) {
    int i = 0;
    while (cmds[i] != NULL) {
        printf("  [%d] %s\n", i, cmds[i]);
        i++;
    }
}

int find_command(char **cmds, const char *name) {
    int i = 0;
    while (cmds[i] != NULL) {
        if (strcmp(cmds[i], name) == 0) {
            return i;
        }
        i++;
    }
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

    // Test recherche échouée
    search = "rm -rf /";
    idx = find_command(commands, search);
    if (idx >= 0) {
        printf("Commande '%s' trouvée à l'index %d\n", search, idx);
    } else {
        printf("Commande '%s' non trouvée\n", search);
    }

    return 0;
}
```

**Point clé** : Un tableau de pointeurs `char **` permet de stocker des strings de longueurs différentes. NULL sert de sentinelle pour marquer la fin.

---

## Solution Exercice 14 : Memory patching

```c
#include <stdio.h>

unsigned char license_check[] = {
    0x55,
    0x48, 0x89, 0xE5,
    0x83, 0xFF, 0x01,
    0x75, 0x07,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xC9,
    0xC3,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xC9,
    0xC3
};

void hexdump_with_offset(unsigned char *data, int size) {
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0) {
            printf("%04X: ", i);
        }
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 || i == size - 1) {
            printf("\n");
        }
    }
}

unsigned char* find_byte(unsigned char *data, int size, unsigned char target) {
    for (int i = 0; i < size; i++) {
        if (data[i] == target) {
            return &data[i];
        }
    }
    return NULL;
}

void patch_byte(unsigned char *target, unsigned char new_value) {
    *target = new_value;
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
        printf("\n[+] JNE (0x75) trouvé à l'offset %d\n", offset);

        // Patch: JNE -> JMP (0xEB)
        printf("[*] Patching JNE (0x75) -> JMP (0xEB)\n");
        patch_byte(jne, 0xEB);

        printf("\nCode patché:\n");
        hexdump_with_offset(license_check, size);

        printf("\n[+] Le check de licence est maintenant bypassé!\n");
        printf("    Avant: JNE +7 -> sautait SI license != 1\n");
        printf("    Après: JMP +7 -> saute TOUJOURS (bypass)\n");
    }

    // BONUS: Alternative - NOP le saut pour toujours exécuter le code "licensed"
    printf("\n=== BONUS: NOP le saut ===\n");

    // Restaure l'original
    license_check[7] = 0x75;

    // Remplace JNE par deux NOPs
    unsigned char *jump = find_byte(license_check, size, 0x75);
    if (jump) {
        printf("[*] Remplacement de JNE (2 bytes) par NOP NOP\n");
        patch_byte(jump, 0x90);      // Premier NOP
        patch_byte(jump + 1, 0x90);  // Deuxième NOP

        printf("\nCode après NOP:\n");
        hexdump_with_offset(license_check, size);

        printf("\n[+] Le saut est neutralisé, le code continue normalement.\n");
    }

    return 0;
}
```

**Sortie** :
```
=== License Check Bypass ===

Code original:
0000: 55 48 89 E5 83 FF 01 75 07 B8 01 00 00 00 C9 C3
0010: B8 00 00 00 00 C9 C3

[+] JNE (0x75) trouvé à l'offset 7
[*] Patching JNE (0x75) -> JMP (0xEB)

Code patché:
0000: 55 48 89 E5 83 FF 01 EB 07 B8 01 00 00 00 C9 C3
0010: B8 00 00 00 00 C9 C3

[+] Le check de licence est maintenant bypassé!
    Avant: JNE +7 -> sautait SI license != 1
    Après: JMP +7 -> saute TOUJOURS (bypass)

=== BONUS: NOP le saut ===
[*] Remplacement de JNE (2 bytes) par NOP NOP

Code après NOP:
0000: 55 48 89 E5 83 FF 01 90 90 B8 01 00 00 00 C9 C3
0010: B8 00 00 00 00 C9 C3

[+] Le saut est neutralisé, le code continue normalement.
```

---

## Résumé des patterns clés

| Pattern | Usage | Exemple |
|---------|-------|---------|
| `&variable` | Obtenir l'adresse | `int *p = &x;` |
| `*pointeur` | Déréférencer | `int val = *p;` |
| `ptr++` | Avancer d'un élément | Parcours de tableau |
| `ptr - base` | Calculer l'offset | `offset = found - memory;` |
| `void*` | Pointeur générique | `memcpy`, `hexdump` |
| `arr[i]` ≡ `*(arr+i)` | Équivalence | Accès tableau |
| Passage par pointeur | Modifier l'original | `void func(int *x)` |
| Retour pointeur | Buffer caller | `char* f(char *buf)` |
| `NULL` check | Sécurité | `if (ptr != NULL)` |

---

## Points clés à retenir

1. **Un pointeur stocke une adresse, pas une valeur**
2. **`&` obtient l'adresse, `*` accède à la valeur**
3. **Les tableaux sont des pointeurs vers leur premier élément**
4. **L'arithmétique de pointeurs tient compte de la taille du type**
5. **Toujours initialiser les pointeurs (NULL ou adresse valide)**
6. **Ne jamais retourner un pointeur vers une variable locale**
7. **`void*` permet des fonctions génériques mais nécessite un cast**
8. **En sécurité offensive : manipulation mémoire, patching, shellcode**
