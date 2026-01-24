# Module 10 : Pointeurs Avancés - Solutions

## Solution Exercice 1 : Allocation dynamique simple

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int *create_array(int size) {
    if (size <= 0) {
        return NULL;
    }

    int *arr = (int *)malloc(size * sizeof(int));
    if (arr == NULL) {
        return NULL;
    }

    // Initialiser à 0
    memset(arr, 0, size * sizeof(int));
    // Alternative : for (int i = 0; i < size; i++) arr[i] = 0;

    return arr;
}

void destroy_array(int *arr) {
    if (arr != NULL) {
        free(arr);
    }
}

int main(void) {
    int size = 10;

    int *arr = create_array(size);
    if (arr == NULL) {
        printf("[-] Échec d'allocation\n");
        return 1;
    }
    printf("[+] Tableau alloué avec succès\n");

    // Remplir avec 0 à 9
    for (int i = 0; i < size; i++) {
        arr[i] = i;
    }

    // Afficher
    printf("Contenu : ");
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    // Libérer
    destroy_array(arr);
    arr = NULL;  // Bonne pratique
    printf("[+] Mémoire libérée\n");

    return 0;
}
```

**Explication** :
- `malloc(size * sizeof(int))` alloue `size` entiers sur le heap
- Toujours vérifier si malloc retourne NULL
- `memset` initialise rapidement à 0
- `free` libère la mémoire, mais ne met pas le pointeur à NULL automatiquement

---

## Solution Exercice 2 : Redimensionnement dynamique

```c
#include <stdio.h>
#include <stdlib.h>

void print_array(int *arr, int size, const char *label) {
    printf("%s : ", label);
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main(void) {
    // Allocation initiale
    int initial_size = 5;
    int *arr = (int *)malloc(initial_size * sizeof(int));
    if (arr == NULL) {
        printf("[-] Échec malloc\n");
        return 1;
    }

    // Remplir
    arr[0] = 10; arr[1] = 20; arr[2] = 30; arr[3] = 40; arr[4] = 50;

    print_array(arr, initial_size, "Tableau initial (5 éléments)");

    // Redimensionner à 10
    int new_size = 10;
    int *temp = (int *)realloc(arr, new_size * sizeof(int));
    if (temp == NULL) {
        printf("[-] Échec realloc\n");
        free(arr);  // Libérer l'ancien si realloc échoue
        return 1;
    }
    arr = temp;  // realloc peut retourner une nouvelle adresse

    // Ajouter les nouveaux éléments
    arr[5] = 60; arr[6] = 70; arr[7] = 80; arr[8] = 90; arr[9] = 100;

    print_array(arr, new_size, "Tableau agrandi (10 éléments)");

    // Libérer
    free(arr);
    arr = NULL;

    return 0;
}
```

**Point important** : Toujours utiliser un pointeur temporaire pour realloc. Si realloc échoue, il retourne NULL mais l'ancien bloc reste valide. Sans pointeur temp, on perdrait la référence à l'ancien bloc (memory leak).

---

## Solution Exercice 3 : Pointeur de pointeur - Allocation dans fonction

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int allocate_buffer(unsigned char **buffer, int size) {
    if (buffer == NULL || size <= 0) {
        return -1;
    }

    *buffer = (unsigned char *)malloc(size);
    if (*buffer == NULL) {
        return -1;
    }

    // Initialiser à 0
    memset(*buffer, 0, size);

    return 0;
}

void free_buffer(unsigned char **buffer) {
    if (buffer != NULL && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;  // Met le pointeur original à NULL
    }
}

int main(void) {
    unsigned char *buf = NULL;
    int size = 256;

    // Allouer
    if (allocate_buffer(&buf, size) != 0) {
        printf("[-] Échec allocation\n");
        return 1;
    }
    printf("[+] Buffer alloué : %d bytes\n", size);

    // Remplir
    strcpy((char *)buf, "PAYLOAD_DATA");
    printf("Contenu : %s\n", buf);

    // Libérer
    free_buffer(&buf);
    printf("[+] Buffer libéré\n");

    // Vérifier que buf est NULL
    printf("Buffer après libération : %s\n", buf == NULL ? "NULL" : "NON NULL");

    return 0;
}
```

**Explication du int**** :
```
main()                     allocate_buffer()
┌─────────────┐           ┌─────────────┐
│ buf = NULL  │◄──────────│ *buffer     │  buffer pointe vers buf
│ &buf        │───────────│ buffer      │
└─────────────┘           └─────────────┘

Après *buffer = malloc():
┌─────────────┐           ┌─────────────┐    ┌──────────────┐
│ buf = 0x100 │◄──────────│ *buffer     │───→│ mémoire heap │
└─────────────┘           └─────────────┘    └──────────────┘
```

---

## Solution Exercice 4 : Matrice dynamique

```c
#include <stdio.h>
#include <stdlib.h>

int **create_matrix(int rows, int cols) {
    if (rows <= 0 || cols <= 0) {
        return NULL;
    }

    // Allouer le tableau de pointeurs (lignes)
    int **matrix = (int **)malloc(rows * sizeof(int *));
    if (matrix == NULL) {
        return NULL;
    }

    // Allouer chaque ligne
    for (int i = 0; i < rows; i++) {
        matrix[i] = (int *)malloc(cols * sizeof(int));
        if (matrix[i] == NULL) {
            // Échec : libérer ce qui a été alloué
            for (int j = 0; j < i; j++) {
                free(matrix[j]);
            }
            free(matrix);
            return NULL;
        }
    }

    return matrix;
}

void fill_matrix(int **matrix, int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = i * cols + j;
        }
    }
}

void print_matrix(int **matrix, int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
}

void destroy_matrix(int **matrix, int rows) {
    if (matrix == NULL) return;

    // Libérer chaque ligne d'abord
    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    // Puis le tableau de pointeurs
    free(matrix);
}

int main(void) {
    int rows = 3, cols = 4;

    int **matrix = create_matrix(rows, cols);
    if (matrix == NULL) {
        printf("[-] Échec création matrice\n");
        return 1;
    }

    fill_matrix(matrix, rows, cols);

    printf("Matrice %dx%d :\n", rows, cols);
    print_matrix(matrix, rows, cols);

    destroy_matrix(matrix, rows);

    return 0;
}
```

**Structure en mémoire** :
```
matrix (int**)
┌─────────┐
│ [0]     │────→ [0, 1, 2, 3]
├─────────┤
│ [1]     │────→ [4, 5, 6, 7]
├─────────┤
│ [2]     │────→ [8, 9, 10, 11]
└─────────┘
```

---

## Solution Exercice 5 : Tableau de strings dynamique

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char **create_string_array(int count) {
    if (count <= 0) return NULL;

    char **arr = (char **)malloc(count * sizeof(char *));
    if (arr == NULL) return NULL;

    // Initialiser tous à NULL
    for (int i = 0; i < count; i++) {
        arr[i] = NULL;
    }

    return arr;
}

int add_string(char **arr, int index, const char *str) {
    if (arr == NULL || str == NULL) return -1;

    // Libérer l'ancienne chaîne si elle existe
    if (arr[index] != NULL) {
        free(arr[index]);
    }

    // Allouer et copier
    arr[index] = (char *)malloc(strlen(str) + 1);
    if (arr[index] == NULL) return -1;

    strcpy(arr[index], str);
    return 0;
}

void free_string_array(char **arr, int count) {
    if (arr == NULL) return;

    for (int i = 0; i < count; i++) {
        if (arr[i] != NULL) {
            free(arr[i]);
        }
    }
    free(arr);
}

int main(void) {
    int count = 5;
    char **commands = create_string_array(count);
    if (commands == NULL) {
        printf("[-] Échec création tableau\n");
        return 1;
    }

    // Ajouter les commandes
    add_string(commands, 0, "whoami");
    add_string(commands, 1, "pwd");
    add_string(commands, 2, "ls -la");
    add_string(commands, 3, "cat /etc/passwd");
    add_string(commands, 4, "exit");

    // Afficher
    printf("=== Command List ===\n");
    for (int i = 0; i < count; i++) {
        printf("[%d] %s\n", i, commands[i]);
    }

    // Libérer
    free_string_array(commands, count);

    return 0;
}
```

---

## Solution Exercice 6 : Pointeur de fonction - Calculatrice

```c
#include <stdio.h>
#include <stdlib.h>

typedef int (*operation_t)(int, int);

int add(int a, int b) {
    return a + b;
}

int subtract(int a, int b) {
    return a - b;
}

int multiply(int a, int b) {
    return a * b;
}

int divide(int a, int b) {
    if (b == 0) return 0;  // Éviter division par zéro
    return a / b;
}

operation_t get_operation(char op) {
    switch (op) {
        case '+': return add;
        case '-': return subtract;
        case '*': return multiply;
        case '/': return divide;
        default:  return NULL;
    }
}

int main(void) {
    int a = 20, b = 5;
    char operators[] = {'+', '-', '*', '/'};

    for (int i = 0; i < 4; i++) {
        char op = operators[i];
        operation_t func = get_operation(op);

        if (func != NULL) {
            int result = func(a, b);
            printf("%d %c %d = %d\n", a, op, b, result);
        } else {
            printf("Opérateur inconnu: %c\n", op);
        }
    }

    return 0;
}
```

**Explication** : `get_operation` retourne un pointeur vers la bonne fonction. On peut ensuite appeler `func(a, b)` comme une fonction normale.

---

## Solution Exercice 7 : Callback - Traitement de données

```c
#include <stdio.h>
#include <string.h>

typedef void (*processor_t)(int *value);

void proc_double(int *value) {
    *value = *value * 2;
}

void proc_square(int *value) {
    *value = *value * *value;
}

void proc_negate(int *value) {
    *value = -*value;
}

void process_array(int *arr, int size, processor_t proc) {
    for (int i = 0; i < size; i++) {
        proc(&arr[i]);
    }
}

void print_array(int *arr, int size, const char *label) {
    printf("%s : ", label);
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main(void) {
    int original[] = {1, 2, 3, 4, 5};
    int size = 5;
    int arr[5];

    // Test double
    memcpy(arr, original, sizeof(original));
    print_array(arr, size, "Original");

    memcpy(arr, original, sizeof(original));
    process_array(arr, size, proc_double);
    print_array(arr, size, "Après double");

    // Test square
    memcpy(arr, original, sizeof(original));
    process_array(arr, size, proc_square);
    print_array(arr, size, "Après square");

    // Test negate
    memcpy(arr, original, sizeof(original));
    process_array(arr, size, proc_negate);
    print_array(arr, size, "Après negate");

    return 0;
}
```

---

## Solution Exercice 8 : Table de dispatch

```c
#include <stdio.h>
#include <string.h>

typedef void (*handler_t)(const char *arg);

typedef struct {
    const char *name;
    const char *description;
    handler_t handler;
} Command;

void cmd_help(const char *arg) {
    printf("Aide disponible\n");
}

void cmd_info(const char *arg) {
    printf("Système info...\n");
}

void cmd_echo(const char *arg) {
    printf("%s\n", arg ? arg : "");
}

void cmd_exit(const char *arg) {
    printf("Bye!\n");
}

// Table de commandes avec sentinelle
Command commands[] = {
    {"help", "Show help", cmd_help},
    {"info", "System information", cmd_info},
    {"echo", "Echo argument", cmd_echo},
    {"exit", "Exit program", cmd_exit},
    {NULL, NULL, NULL}  // Sentinelle
};

void dispatch(Command *cmds, const char *name, const char *arg) {
    for (int i = 0; cmds[i].name != NULL; i++) {
        if (strcmp(cmds[i].name, name) == 0) {
            cmds[i].handler(arg);
            return;
        }
    }
    printf("[-] Unknown command: %s\n", name);
}

int main(void) {
    printf("> help\n");
    dispatch(commands, "help", "");
    printf("\n");

    printf("> info\n");
    dispatch(commands, "info", "");
    printf("\n");

    printf("> echo Hello\n");
    dispatch(commands, "echo", "Hello");
    printf("\n");

    printf("> unknown\n");
    dispatch(commands, "unknown", "");
    printf("\n");

    printf("> exit\n");
    dispatch(commands, "exit", "");

    return 0;
}
```

---

## Solution Exercice 9 : Encodeur modulaire avec callbacks

```c
#include <stdio.h>
#include <string.h>

typedef void (*encoder_t)(unsigned char *data, int len, unsigned char key);

// XOR encoder/decoder (symétrique)
void xor_encode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// ADD encoder
void add_encode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] += key;
    }
}

// SUB decoder (inverse de ADD)
void sub_encode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] -= key;
    }
}

// ROL encoder (rotation à gauche)
void rol_encode(unsigned char *data, int len, unsigned char key) {
    key = key % 8;  // Limiter aux rotations valides
    for (int i = 0; i < len; i++) {
        data[i] = (data[i] << key) | (data[i] >> (8 - key));
    }
}

// ROR decoder (rotation à droite, inverse de ROL)
void ror_encode(unsigned char *data, int len, unsigned char key) {
    key = key % 8;
    for (int i = 0; i < len; i++) {
        data[i] = (data[i] >> key) | (data[i] << (8 - key));
    }
}

typedef struct {
    const char *name;
    encoder_t encode;
    encoder_t decode;
} Encoder;

Encoder encoders[] = {
    {"xor", xor_encode, xor_encode},      // XOR est son propre inverse
    {"add", add_encode, sub_encode},
    {"rol", rol_encode, ror_encode},
    {NULL, NULL, NULL}
};

Encoder *find_encoder(const char *name) {
    for (int i = 0; encoders[i].name != NULL; i++) {
        if (strcmp(encoders[i].name, name) == 0) {
            return &encoders[i];
        }
    }
    return NULL;
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char data[] = "ATTACK";
    int len = 6;  // Sans le null terminator
    unsigned char key = 0x42;

    printf("Original : %s\n", data);

    Encoder *enc = find_encoder("xor");
    if (enc == NULL) {
        printf("Encodeur non trouvé\n");
        return 1;
    }

    // Encoder
    enc->encode(data, len, key);
    printf("Encodé (XOR 0x%02X) : ", key);
    print_hex(data, len);

    // Décoder
    enc->decode(data, len, key);
    printf("Décodé : %s\n", data);

    return 0;
}
```

---

## Solution Exercice 10 : Buffer dynamique auto-extensible

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *data;
    int size;       // Taille utilisée
    int capacity;   // Taille allouée
} DynamicBuffer;

DynamicBuffer *buffer_create(int initial_capacity) {
    DynamicBuffer *buf = (DynamicBuffer *)malloc(sizeof(DynamicBuffer));
    if (buf == NULL) return NULL;

    buf->data = (unsigned char *)malloc(initial_capacity);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }

    buf->size = 0;
    buf->capacity = initial_capacity;

    return buf;
}

int buffer_append(DynamicBuffer *buf, unsigned char *data, int len) {
    if (buf == NULL || data == NULL) return -1;

    // Vérifier si on doit agrandir
    while (buf->size + len > buf->capacity) {
        int new_capacity = buf->capacity * 2;
        unsigned char *new_data = (unsigned char *)realloc(buf->data, new_capacity);
        if (new_data == NULL) return -1;

        buf->data = new_data;
        buf->capacity = new_capacity;
        printf("[+] Ajout %d bytes - Reallocation! (size: %d, capacity: %d)\n",
               len, buf->size + len, buf->capacity);
        return buffer_append(buf, data, len);  // Réessayer
    }

    // Copier les données
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;

    printf("[+] Ajout %d bytes (size: %d, capacity: %d)\n",
           len, buf->size, buf->capacity);

    return 0;
}

void buffer_print_hex(DynamicBuffer *buf) {
    if (buf == NULL || buf->data == NULL) return;

    printf("Contenu : ");
    for (int i = 0; i < buf->size; i++) {
        printf("%02X ", buf->data[i]);
    }
    printf("\n");
}

void buffer_destroy(DynamicBuffer *buf) {
    if (buf != NULL) {
        if (buf->data != NULL) {
            free(buf->data);
        }
        free(buf);
    }
}

int main(void) {
    DynamicBuffer *buf = buffer_create(8);
    if (buf == NULL) {
        printf("[-] Échec création buffer\n");
        return 1;
    }
    printf("[+] Buffer créé (capacité: %d)\n", buf->capacity);

    unsigned char data1[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00};
    unsigned char data2[] = {0xCA, 0xFE, 0xBA, 0xBE, 0x00};
    unsigned char data3[] = {0x41, 0x42, 0x43, 0x44, 0x00};

    buffer_append(buf, data1, 5);
    buffer_append(buf, data2, 5);
    buffer_append(buf, data3, 5);

    buffer_print_hex(buf);

    buffer_destroy(buf);

    return 0;
}
```

---

## Solution Exercice 11 : Shellcode Loader basique

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void *alloc_executable(int size) {
    void *mem = mmap(NULL, size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) {
        return NULL;
    }

    return mem;
}

void free_executable(void *mem, int size) {
    if (mem != NULL) {
        munmap(mem, size);
    }
}

int main(void) {
    // Shellcode minimal : juste "ret" (retourne immédiatement)
    unsigned char shellcode[] = {
        0xC3  // ret
    };
    int size = sizeof(shellcode);

    // Allouer mémoire exécutable
    void *mem = alloc_executable(size);
    if (mem == NULL) {
        printf("[-] Failed to allocate executable memory\n");
        return 1;
    }
    printf("[+] Allocated executable memory at %p\n", mem);

    // Copier le shellcode
    memcpy(mem, shellcode, size);
    printf("[+] Shellcode copied (%d bytes)\n", size);

    // Créer pointeur de fonction et exécuter
    printf("[*] Executing shellcode...\n");

    void (*func)(void) = (void (*)(void))mem;
    func();  // Exécute le shellcode

    printf("[+] Shellcode executed successfully!\n");

    // Libérer
    free_executable(mem, size);
    printf("[+] Memory freed\n");

    return 0;
}
```

**Note de sécurité** : Ce code est éducatif. Sur les systèmes modernes, W^X (Write XOR Execute) peut empêcher l'allocation de mémoire à la fois writable et executable.

---

## Solution Exercice 12 : Gestionnaire de hooks

```c
#include <stdio.h>
#include <string.h>

typedef int (*target_func_t)(int);

typedef struct {
    const char *name;
    target_func_t original;
    target_func_t hook;
    int is_hooked;
} Hook;

typedef struct {
    Hook hooks[10];
    int count;
} HookManager;

void hook_manager_init(HookManager *hm) {
    hm->count = 0;
    for (int i = 0; i < 10; i++) {
        hm->hooks[i].name = NULL;
        hm->hooks[i].original = NULL;
        hm->hooks[i].hook = NULL;
        hm->hooks[i].is_hooked = 0;
    }
}

int hook_register(HookManager *hm, const char *name, target_func_t original) {
    if (hm->count >= 10) return -1;

    hm->hooks[hm->count].name = name;
    hm->hooks[hm->count].original = original;
    hm->hooks[hm->count].hook = NULL;
    hm->hooks[hm->count].is_hooked = 0;
    hm->count++;

    return 0;
}

Hook *find_hook(HookManager *hm, const char *name) {
    for (int i = 0; i < hm->count; i++) {
        if (strcmp(hm->hooks[i].name, name) == 0) {
            return &hm->hooks[i];
        }
    }
    return NULL;
}

int hook_install(HookManager *hm, const char *name, target_func_t hook) {
    Hook *h = find_hook(hm, name);
    if (h == NULL) return -1;

    h->hook = hook;
    h->is_hooked = 1;
    printf("[+] Hook installed: %s\n", name);

    return 0;
}

int hook_remove(HookManager *hm, const char *name) {
    Hook *h = find_hook(hm, name);
    if (h == NULL) return -1;

    h->hook = NULL;
    h->is_hooked = 0;
    printf("[+] Hook removed: %s\n", name);

    return 0;
}

target_func_t hook_get_current(HookManager *hm, const char *name) {
    Hook *h = find_hook(hm, name);
    if (h == NULL) return NULL;

    return h->is_hooked ? h->hook : h->original;
}

// Fonctions cibles
int check_license(int key) {
    return (key == 12345);
}

int check_admin(int uid) {
    return (uid == 0);
}

// Hooks (bypass)
int hooked_license(int key) {
    return 1;  // Toujours valide
}

int hooked_admin(int uid) {
    return 1;  // Toujours admin
}

int main(void) {
    HookManager hm;
    hook_manager_init(&hm);

    // Enregistrer les fonctions
    hook_register(&hm, "check_license", check_license);
    hook_register(&hm, "check_admin", check_admin);

    // Avant hooks
    printf("=== Before Hooks ===\n");
    target_func_t f1 = hook_get_current(&hm, "check_license");
    target_func_t f2 = hook_get_current(&hm, "check_admin");
    printf("check_license(99999): %d (FAIL)\n", f1(99999));
    printf("check_admin(1000): %d (FAIL)\n", f2(1000));

    // Installer hooks
    printf("\n=== Installing Hooks ===\n");
    hook_install(&hm, "check_license", hooked_license);
    hook_install(&hm, "check_admin", hooked_admin);

    // Après hooks
    printf("\n=== After Hooks ===\n");
    f1 = hook_get_current(&hm, "check_license");
    f2 = hook_get_current(&hm, "check_admin");
    printf("check_license(99999): %d (BYPASSED!)\n", f1(99999));
    printf("check_admin(1000): %d (BYPASSED!)\n", f2(1000));

    // Retirer un hook
    printf("\n=== Removing Hooks ===\n");
    hook_remove(&hm, "check_license");

    // Après retrait
    printf("\n=== After Removal ===\n");
    f1 = hook_get_current(&hm, "check_license");
    f2 = hook_get_current(&hm, "check_admin");
    printf("check_license(99999): %d (ORIGINAL)\n", f1(99999));
    printf("check_admin(1000): %d (STILL HOOKED)\n", f2(1000));

    return 0;
}
```

---

## Solution Exercice 13 : Pool d'allocation

```c
#include <stdio.h>
#include <string.h>

#define POOL_SIZE 1024
#define BLOCK_SIZE 64
#define NUM_BLOCKS (POOL_SIZE / BLOCK_SIZE)

typedef struct {
    unsigned char memory[POOL_SIZE];
    int used[NUM_BLOCKS];
    int num_blocks;
} MemoryPool;

void pool_init(MemoryPool *pool) {
    memset(pool->memory, 0, POOL_SIZE);
    memset(pool->used, 0, sizeof(pool->used));
    pool->num_blocks = NUM_BLOCKS;
    printf("[+] Pool initialized: %d blocks of %d bytes\n\n",
           NUM_BLOCKS, BLOCK_SIZE);
}

void *pool_alloc(MemoryPool *pool) {
    for (int i = 0; i < pool->num_blocks; i++) {
        if (pool->used[i] == 0) {
            pool->used[i] = 1;
            void *ptr = &pool->memory[i * BLOCK_SIZE];
            return ptr;
        }
    }
    return NULL;  // Pool plein
}

void pool_free(MemoryPool *pool, void *ptr) {
    if (ptr == NULL) return;

    // Calculer l'offset
    unsigned char *p = (unsigned char *)ptr;
    int offset = p - pool->memory;

    // Vérifier que le pointeur est dans le pool
    if (offset < 0 || offset >= POOL_SIZE) {
        printf("[-] Invalid pointer (not in pool)\n");
        return;
    }

    // Vérifier l'alignement sur BLOCK_SIZE
    if (offset % BLOCK_SIZE != 0) {
        printf("[-] Invalid pointer (not aligned)\n");
        return;
    }

    int block_idx = offset / BLOCK_SIZE;
    pool->used[block_idx] = 0;
    printf("[+] Block freed at offset %d\n", offset);
}

void pool_stats(MemoryPool *pool) {
    int used_count = 0;
    for (int i = 0; i < pool->num_blocks; i++) {
        if (pool->used[i]) used_count++;
    }

    int percent = (used_count * 100) / pool->num_blocks;
    printf("Pool stats: %d/%d blocks used (%d%%)\n",
           used_count, pool->num_blocks, percent);
}

int main(void) {
    MemoryPool pool;
    pool_init(&pool);

    void *blocks[5];

    printf("Allocating 5 blocks...\n");
    for (int i = 0; i < 5; i++) {
        blocks[i] = pool_alloc(&pool);
        if (blocks[i]) {
            int offset = (unsigned char *)blocks[i] - pool.memory;
            printf("  Block %d: %p (pool+%d)\n", i, blocks[i], offset);
        }
    }

    printf("\nFreeing block 2...\n");
    pool_free(&pool, blocks[2]);

    printf("\nAllocating new block...\n");
    void *new_block = pool_alloc(&pool);
    if (new_block) {
        int offset = (unsigned char *)new_block - pool.memory;
        printf("  New block: %p (pool+%d) <- Reused!\n", new_block, offset);
    }

    printf("\n");
    pool_stats(&pool);

    return 0;
}
```

---

## Solution Exercice 14 : Implant C2 simplifié

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*cmd_handler_t)(const char *arg, char *response, int resp_size);

typedef struct {
    char *name;
    char *description;
    cmd_handler_t handler;
} ImplantCommand;

typedef struct {
    ImplantCommand *commands;
    int cmd_count;
    int cmd_capacity;
    unsigned char *recv_buffer;
    unsigned char *send_buffer;
    int buffer_size;
} Implant;

// Handlers
void cmd_id(const char *arg, char *response, int resp_size) {
    snprintf(response, resp_size, "implant-001");
}

void cmd_ping(const char *arg, char *response, int resp_size) {
    snprintf(response, resp_size, "PONG");
}

void cmd_echo(const char *arg, char *response, int resp_size) {
    snprintf(response, resp_size, "%s", arg ? arg : "");
}

void cmd_help(const char *arg, char *response, int resp_size);  // Forward declaration

// Implant functions
Implant *implant_create(int buffer_size) {
    Implant *imp = (Implant *)malloc(sizeof(Implant));
    if (imp == NULL) return NULL;

    imp->cmd_capacity = 10;
    imp->cmd_count = 0;
    imp->commands = (ImplantCommand *)calloc(imp->cmd_capacity, sizeof(ImplantCommand));
    if (imp->commands == NULL) {
        free(imp);
        return NULL;
    }

    imp->buffer_size = buffer_size;
    imp->recv_buffer = (unsigned char *)malloc(buffer_size);
    imp->send_buffer = (unsigned char *)malloc(buffer_size);

    if (imp->recv_buffer == NULL || imp->send_buffer == NULL) {
        free(imp->commands);
        free(imp->recv_buffer);
        free(imp->send_buffer);
        free(imp);
        return NULL;
    }

    return imp;
}

int implant_register_command(Implant *imp, const char *name, const char *desc, cmd_handler_t handler) {
    if (imp->cmd_count >= imp->cmd_capacity) {
        // Agrandir
        int new_cap = imp->cmd_capacity * 2;
        ImplantCommand *new_cmds = (ImplantCommand *)realloc(imp->commands,
                                                              new_cap * sizeof(ImplantCommand));
        if (new_cmds == NULL) return -1;
        imp->commands = new_cmds;
        imp->cmd_capacity = new_cap;
    }

    // Dupliquer les strings
    imp->commands[imp->cmd_count].name = strdup(name);
    imp->commands[imp->cmd_count].description = strdup(desc);
    imp->commands[imp->cmd_count].handler = handler;
    imp->cmd_count++;

    printf("[+] Command registered: %s\n", name);
    return 0;
}

int implant_execute(Implant *imp, const char *cmdline, char *response, int resp_size) {
    // Parser : extraire commande et argument
    char cmd_copy[256];
    strncpy(cmd_copy, cmdline, sizeof(cmd_copy) - 1);
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';

    char *cmd_name = strtok(cmd_copy, " ");
    char *arg = strtok(NULL, "");  // Le reste

    if (cmd_name == NULL) {
        snprintf(response, resp_size, "[-] Empty command");
        return -1;
    }

    // Chercher la commande
    for (int i = 0; i < imp->cmd_count; i++) {
        if (strcmp(imp->commands[i].name, cmd_name) == 0) {
            imp->commands[i].handler(arg, response, resp_size);
            return 0;
        }
    }

    snprintf(response, resp_size, "[-] Unknown command: %s", cmd_name);
    return -1;
}

void implant_destroy(Implant *imp) {
    if (imp == NULL) return;

    for (int i = 0; i < imp->cmd_count; i++) {
        free(imp->commands[i].name);
        free(imp->commands[i].description);
    }
    free(imp->commands);
    free(imp->recv_buffer);
    free(imp->send_buffer);
    free(imp);

    printf("[+] Implant destroyed\n");
}

// Help command (needs access to Implant)
static Implant *g_implant = NULL;  // Pour cmd_help

void cmd_help(const char *arg, char *response, int resp_size) {
    if (g_implant == NULL) {
        snprintf(response, resp_size, "Implant not initialized");
        return;
    }

    int offset = 0;
    offset += snprintf(response + offset, resp_size - offset, "\n");

    for (int i = 0; i < g_implant->cmd_count; i++) {
        offset += snprintf(response + offset, resp_size - offset,
                          "  %s - %s\n",
                          g_implant->commands[i].name,
                          g_implant->commands[i].description);
    }
}

int main(void) {
    printf("=== Implant C2 Simulator ===\n\n");

    Implant *imp = implant_create(1024);
    if (imp == NULL) {
        printf("[-] Failed to create implant\n");
        return 1;
    }
    printf("[+] Implant created\n");

    g_implant = imp;  // Pour cmd_help

    // Enregistrer les commandes
    implant_register_command(imp, "id", "Return implant ID", cmd_id);
    implant_register_command(imp, "ping", "Connectivity check", cmd_ping);
    implant_register_command(imp, "echo", "Echo back argument", cmd_echo);
    implant_register_command(imp, "help", "List commands", cmd_help);

    printf("\n");

    // Tests
    char response[512];
    const char *tests[] = {"id", "ping", "echo Hello from C2!", "help", "unknown"};

    for (int i = 0; i < 5; i++) {
        printf("> %s\n", tests[i]);
        implant_execute(imp, tests[i], response, sizeof(response));
        printf("Response: %s\n\n", response);
    }

    implant_destroy(imp);

    return 0;
}
```

---

## Résumé des concepts clés

| Exercice | Concept principal | Application offensive |
|----------|-------------------|----------------------|
| 1-2 | malloc/realloc/free | Allocation dynamique de payloads |
| 3 | int** | Allocation dans fonctions, output parameters |
| 4-5 | Structures 2D/strings | Gestion de listes de commandes |
| 6-7 | Function pointers | Calculatrice modulaire, callbacks |
| 8 | Dispatch table | Command & Control handlers |
| 9 | Encodeurs modulaires | Obfuscation de payloads |
| 10 | Buffer extensible | Réception de données réseau |
| 11 | Shellcode loader | Exécution de code arbitraire |
| 12 | Hook manager | Bypass de sécurité |
| 13 | Memory pool | Allocateur personnalisé |
| 14 | Implant complet | Architecture C2 |

---

## Points essentiels à retenir

1. **Toujours vérifier malloc** : `if (ptr == NULL) return -1;`
2. **Toujours free ce qui a été malloc** : évite les memory leaks
3. **Mettre à NULL après free** : `ptr = NULL;` évite use-after-free
4. **Libérer dans l'ordre inverse** : pour les structures imbriquées
5. **Utiliser realloc correctement** : avec pointeur temporaire
6. **int**** permet de modifier un pointeur depuis une fonction
7. **Les function pointers** : permettent le polymorphisme en C
8. **Les callbacks** : rendent le code modulaire et extensible
9. **mmap avec PROT_EXEC** : pour exécuter du code dynamique
10. **Les tables de dispatch** : pattern fondamental pour les implants
