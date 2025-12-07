/*
 * Module 09 : Pointeurs - Les Fondamentaux
 *
 * Description : Démonstration complète des pointeurs avec applications offensives
 * Compilation : gcc -o example example.c
 * Exécution  : ./example
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// DEMO 1 : Fondamentaux - Adresse et déréférencement
// ============================================================================
void demo_basics(void) {
    printf("=== DEMO 1 : Fondamentaux ===\n\n");

    int x = 42;
    int *ptr = &x;

    printf("Variable x :\n");
    printf("  Valeur    : %d\n", x);
    printf("  Adresse   : %p\n", (void*)&x);
    printf("  Taille    : %lu bytes\n\n", sizeof(x));

    printf("Pointeur ptr :\n");
    printf("  Valeur (adresse pointée) : %p\n", (void*)ptr);
    printf("  Adresse du pointeur      : %p\n", (void*)&ptr);
    printf("  Valeur déréférencée (*ptr) : %d\n", *ptr);
    printf("  Taille du pointeur       : %lu bytes\n\n", sizeof(ptr));

    // Modification via pointeur
    printf("[*] Modification via pointeur : *ptr = 99\n");
    *ptr = 99;
    printf("  Nouvelle valeur de x : %d\n\n", x);
}

// ============================================================================
// DEMO 2 : Types de pointeurs et tailles
// ============================================================================
void demo_pointer_types(void) {
    printf("=== DEMO 2 : Types de pointeurs ===\n\n");

    int i = 100;
    char c = 'A';
    float f = 3.14f;
    double d = 2.71828;

    int *pi = &i;
    char *pc = &c;
    float *pf = &f;
    double *pd = &d;
    void *pv = &i;

    printf("Tailles des pointeurs (tous identiques sur 64-bit) :\n");
    printf("  sizeof(int*)    : %lu bytes\n", sizeof(pi));
    printf("  sizeof(char*)   : %lu bytes\n", sizeof(pc));
    printf("  sizeof(float*)  : %lu bytes\n", sizeof(pf));
    printf("  sizeof(double*) : %lu bytes\n", sizeof(pd));
    printf("  sizeof(void*)   : %lu bytes\n\n", sizeof(pv));

    printf("Tailles des types pointés (différentes) :\n");
    printf("  sizeof(int)    : %lu bytes\n", sizeof(*pi));
    printf("  sizeof(char)   : %lu bytes\n", sizeof(*pc));
    printf("  sizeof(float)  : %lu bytes\n", sizeof(*pf));
    printf("  sizeof(double) : %lu bytes\n\n", sizeof(*pd));
}

// ============================================================================
// DEMO 3 : Arithmétique de pointeurs
// ============================================================================
void demo_pointer_arithmetic(void) {
    printf("=== DEMO 3 : Arithmétique de pointeurs ===\n\n");

    int arr[] = {10, 20, 30, 40, 50};
    int *ptr = arr;

    printf("Tableau : {10, 20, 30, 40, 50}\n");
    printf("Adresse de base : %p\n\n", (void*)ptr);

    printf("Parcours avec arithmétique de pointeur :\n");
    for (int i = 0; i < 5; i++) {
        printf("  ptr + %d = %p -> valeur = %d\n", i, (void*)(ptr + i), *(ptr + i));
    }
    printf("\n");

    // Différence entre pointeurs
    int *start = &arr[0];
    int *end = &arr[4];
    printf("Différence entre pointeurs :\n");
    printf("  end - start = %ld éléments\n", end - start);
    printf("  (en bytes : %ld)\n\n", (char*)end - (char*)start);
}

// ============================================================================
// DEMO 4 : Passage par référence
// ============================================================================
void increment_value(int x) {
    x++;
    printf("  [increment_value] x local = %d\n", x);
}

void increment_pointer(int *px) {
    (*px)++;
    printf("  [increment_pointer] *px = %d\n", *px);
}

void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void demo_pass_by_reference(void) {
    printf("=== DEMO 4 : Passage par référence ===\n\n");

    int num = 10;

    printf("1. Passage par valeur :\n");
    printf("  Avant : num = %d\n", num);
    increment_value(num);
    printf("  Après : num = %d (inchangé!)\n\n", num);

    printf("2. Passage par pointeur :\n");
    printf("  Avant : num = %d\n", num);
    increment_pointer(&num);
    printf("  Après : num = %d (modifié!)\n\n", num);

    printf("3. Fonction swap :\n");
    int a = 100, b = 200;
    printf("  Avant : a = %d, b = %d\n", a, b);
    swap(&a, &b);
    printf("  Après : a = %d, b = %d\n\n", a, b);
}

// ============================================================================
// DEMO 5 : Pointeurs et tableaux
// ============================================================================
void demo_pointers_and_arrays(void) {
    printf("=== DEMO 5 : Pointeurs et tableaux ===\n\n");

    int arr[] = {100, 200, 300, 400, 500};
    int *ptr = arr;

    printf("Équivalence tableau/pointeur :\n");
    printf("  arr      = %p\n", (void*)arr);
    printf("  &arr[0]  = %p\n", (void*)&arr[0]);
    printf("  ptr      = %p\n\n", (void*)ptr);

    printf("Accès équivalents :\n");
    for (int i = 0; i < 5; i++) {
        printf("  arr[%d] = %d, *(arr+%d) = %d, ptr[%d] = %d, *(ptr+%d) = %d\n",
               i, arr[i], i, *(arr + i), i, ptr[i], i, *(ptr + i));
    }
    printf("\n");

    // Parcours avec pointeur
    printf("Parcours avec pointeur itérant :\n  ");
    for (int *p = arr; p < arr + 5; p++) {
        printf("%d ", *p);
    }
    printf("\n\n");
}

// ============================================================================
// DEMO 6 : Void pointer (pointeur générique)
// ============================================================================
void print_value(void *ptr, char type) {
    switch (type) {
        case 'i':
            printf("  int: %d\n", *(int*)ptr);
            break;
        case 'f':
            printf("  float: %.2f\n", *(float*)ptr);
            break;
        case 'c':
            printf("  char: '%c'\n", *(char*)ptr);
            break;
        case 's':
            printf("  string: \"%s\"\n", (char*)ptr);
            break;
    }
}

void demo_void_pointer(void) {
    printf("=== DEMO 6 : Void pointer ===\n\n");

    int i = 42;
    float f = 3.14f;
    char c = 'X';
    char s[] = "Hello Hacker";

    void *generic;

    printf("Pointeur générique vers différents types :\n");

    generic = &i;
    print_value(generic, 'i');

    generic = &f;
    print_value(generic, 'f');

    generic = &c;
    print_value(generic, 'c');

    generic = s;
    print_value(generic, 's');

    printf("\n");
}

// ============================================================================
// DEMO 7 : Application offensive - Hexdump mémoire
// ============================================================================
void hexdump(void *ptr, int size) {
    unsigned char *bytes = (unsigned char*)ptr;

    for (int i = 0; i < size; i++) {
        if (i % 16 == 0) {
            printf("  %p: ", (void*)(bytes + i));
        }
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (size % 16 != 0) printf("\n");
}

void demo_hexdump(void) {
    printf("=== DEMO 7 : Hexdump mémoire ===\n\n");

    // Examiner un int
    int x = 0x41424344;
    printf("Hexdump de int x = 0x41424344 :\n");
    hexdump(&x, sizeof(x));
    printf("  Note: Little-endian -> bytes inversés\n\n");

    // Examiner une string
    char str[] = "ATTACK";
    printf("Hexdump de string \"ATTACK\" :\n");
    hexdump(str, sizeof(str));
    printf("\n");

    // Examiner une structure
    struct {
        int id;
        char name[8];
        int value;
    } data = {0x1234, "PAYLOAD", 0xDEAD};

    printf("Hexdump de structure :\n");
    hexdump(&data, sizeof(data));
    printf("\n");
}

// ============================================================================
// DEMO 8 : Application offensive - XOR decode avec pointeurs
// ============================================================================
void xor_decode(unsigned char *data, int len, unsigned char key) {
    unsigned char *ptr = data;
    unsigned char *end = data + len;

    while (ptr < end) {
        *ptr ^= key;
        ptr++;
    }
}

void demo_xor_decode(void) {
    printf("=== DEMO 8 : XOR decode avec pointeurs ===\n\n");

    // "PAYLOAD" XOR 0x42
    unsigned char encoded[] = {0x12, 0x03, 0x1B, 0x0E, 0x0D, 0x03, 0x06, 0x00};
    unsigned char key = 0x42;
    int len = 7;

    printf("Données encodées (hex) : ");
    for (int i = 0; i < len; i++) {
        printf("0x%02X ", encoded[i]);
    }
    printf("\n");

    printf("Clé XOR : 0x%02X\n", key);

    xor_decode(encoded, len, key);

    printf("Données décodées : \"%s\"\n\n", encoded);
}

// ============================================================================
// DEMO 9 : Application offensive - Recherche de pattern
// ============================================================================
unsigned char* find_pattern(unsigned char *memory, int mem_size,
                            unsigned char *pattern, int pat_size) {
    for (int i = 0; i <= mem_size - pat_size; i++) {
        int found = 1;
        for (int j = 0; j < pat_size; j++) {
            if (memory[i + j] != pattern[j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            return &memory[i];  // Retourne pointeur vers pattern trouvé
        }
    }
    return NULL;  // Non trouvé
}

void demo_pattern_search(void) {
    printf("=== DEMO 9 : Recherche de pattern ===\n\n");

    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0x90,  // NOP sled
        0xCC,                          // INT3 (breakpoint)
        0x31, 0xC0,                    // xor eax, eax
        0x50,                          // push eax
        0xC3,                          // ret
        0x00, 0x00
    };
    int mem_size = sizeof(memory);

    // Chercher "xor eax, eax" (0x31 0xC0)
    unsigned char pattern[] = {0x31, 0xC0};
    int pat_size = sizeof(pattern);

    printf("Mémoire :\n");
    hexdump(memory, mem_size);

    printf("Recherche du pattern {0x31, 0xC0} (xor eax, eax)...\n");

    unsigned char *found = find_pattern(memory, mem_size, pattern, pat_size);

    if (found) {
        int offset = found - memory;
        printf("[+] Pattern trouvé à l'offset %d (adresse %p)\n\n", offset, (void*)found);
    } else {
        printf("[-] Pattern non trouvé\n\n");
    }
}

// ============================================================================
// DEMO 10 : Application offensive - Modification de bytes
// ============================================================================
void patch_bytes(unsigned char *target, unsigned char *patch, int size) {
    for (int i = 0; i < size; i++) {
        target[i] = patch[i];
    }
}

void demo_memory_patching(void) {
    printf("=== DEMO 10 : Memory patching ===\n\n");

    // Simule du code avec une vérification
    unsigned char code[] = {
        0x83, 0xF8, 0x00,  // cmp eax, 0
        0x74, 0x05,        // je +5 (saute si égal)
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xC3               // ret
    };

    printf("Code original :\n");
    hexdump(code, sizeof(code));

    // Patch : changer JE (0x74) en JMP (0xEB) pour bypass
    printf("[*] Patching: JE (0x74) -> JMP (0xEB) à l'offset 3\n");

    unsigned char *target = &code[3];
    unsigned char patch[] = {0xEB};
    patch_bytes(target, patch, 1);

    printf("\nCode patché :\n");
    hexdump(code, sizeof(code));
    printf("  Le saut conditionnel est maintenant inconditionnel!\n\n");
}

// ============================================================================
// DEMO 11 : Pointeur NULL et sécurité
// ============================================================================
int safe_dereference(int *ptr) {
    if (ptr == NULL) {
        printf("  [!] Tentative de déréférencement NULL évitée!\n");
        return -1;
    }
    return *ptr;
}

void demo_null_safety(void) {
    printf("=== DEMO 11 : Pointeur NULL et sécurité ===\n\n");

    int value = 42;
    int *valid = &value;
    int *invalid = NULL;

    printf("Déréférencement sécurisé :\n");
    printf("  Pointeur valide : %d\n", safe_dereference(valid));
    printf("  Pointeur NULL   : ");
    safe_dereference(invalid);
    printf("\n");
}

// ============================================================================
// DEMO 12 : Constantes et pointeurs
// ============================================================================
void demo_const_pointers(void) {
    printf("=== DEMO 12 : Constantes et pointeurs ===\n\n");

    int x = 10, y = 20;

    // 1. Pointeur vers constante (ne peut pas modifier la valeur)
    const int *ptr1 = &x;
    printf("1. const int *ptr (pointeur vers constante) :\n");
    printf("   *ptr1 = %d\n", *ptr1);
    // *ptr1 = 100;  // ERREUR de compilation!
    ptr1 = &y;  // OK, peut changer l'adresse
    printf("   Après ptr1 = &y : *ptr1 = %d\n\n", *ptr1);

    // 2. Pointeur constant (ne peut pas changer d'adresse)
    int * const ptr2 = &x;
    printf("2. int * const ptr (pointeur constant) :\n");
    printf("   *ptr2 = %d\n", *ptr2);
    *ptr2 = 100;  // OK, peut modifier la valeur
    // ptr2 = &y;  // ERREUR de compilation!
    printf("   Après *ptr2 = 100 : x = %d\n\n", x);

    // 3. Les deux constants
    const int * const ptr3 = &y;
    printf("3. const int * const ptr (tout constant) :\n");
    printf("   *ptr3 = %d\n", *ptr3);
    // *ptr3 = 200;  // ERREUR!
    // ptr3 = &x;    // ERREUR!
    printf("   Rien ne peut être modifié\n\n");
}

// ============================================================================
// MAIN
// ============================================================================
int main(void) {
    printf("================================================================\n");
    printf("     MODULE 09 : POINTEURS FONDAMENTAUX - DEMONSTRATIONS\n");
    printf("================================================================\n\n");

    demo_basics();
    demo_pointer_types();
    demo_pointer_arithmetic();
    demo_pass_by_reference();
    demo_pointers_and_arrays();
    demo_void_pointer();
    demo_hexdump();
    demo_xor_decode();
    demo_pattern_search();
    demo_memory_patching();
    demo_null_safety();
    demo_const_pointers();

    printf("================================================================\n");
    printf("                  FIN DES DEMONSTRATIONS\n");
    printf("================================================================\n");

    return 0;
}
