# Module 10 : Pointeurs Avancés - Exercices

## Exercice 1 : Allocation dynamique simple (Facile)

**Objectif** : Maîtriser malloc et free.

**Instructions** :
1. Écrire une fonction `int *create_array(int size)` qui :
   - Alloue dynamiquement un tableau de `size` entiers
   - Vérifie que l'allocation a réussi
   - Initialise tous les éléments à 0
   - Retourne le pointeur (ou NULL si échec)

2. Écrire une fonction `void destroy_array(int *arr)` qui :
   - Libère la mémoire du tableau

3. Dans main :
   - Créer un tableau de 10 éléments
   - Remplir avec les valeurs 0 à 9
   - Afficher le contenu
   - Libérer la mémoire

**Sortie attendue** :
```
[+] Tableau alloué avec succès
Contenu : 0 1 2 3 4 5 6 7 8 9
[+] Mémoire libérée
```

---

## Exercice 2 : Redimensionnement dynamique (Facile)

**Objectif** : Utiliser realloc pour agrandir un tableau.

**Instructions** :
1. Allouer un tableau de 5 entiers
2. Remplir avec {10, 20, 30, 40, 50}
3. Afficher le tableau
4. Redimensionner à 10 éléments avec realloc
5. Ajouter {60, 70, 80, 90, 100} aux nouveaux éléments
6. Afficher le tableau complet
7. Libérer la mémoire

**Sortie attendue** :
```
Tableau initial (5 éléments) : 10 20 30 40 50
Tableau agrandi (10 éléments) : 10 20 30 40 50 60 70 80 90 100
```

---

## Exercice 3 : Pointeur de pointeur - Allocation dans fonction (Moyen)

**Objectif** : Comprendre int** pour modifier un pointeur via une fonction.

**Instructions** :
1. Écrire une fonction `int allocate_buffer(unsigned char **buffer, int size)` qui :
   - Alloue `size` bytes
   - Stocke le pointeur dans `*buffer`
   - Retourne 0 si succès, -1 si échec

2. Écrire une fonction `void free_buffer(unsigned char **buffer)` qui :
   - Libère la mémoire
   - Met `*buffer` à NULL

3. Dans main :
   - Déclarer `unsigned char *buf = NULL;`
   - Appeler allocate_buffer pour 256 bytes
   - Remplir avec "PAYLOAD_DATA"
   - Afficher le contenu
   - Libérer avec free_buffer
   - Vérifier que buf est NULL après libération

**Sortie attendue** :
```
[+] Buffer alloué : 256 bytes
Contenu : PAYLOAD_DATA
[+] Buffer libéré
Buffer après libération : NULL
```

---

## Exercice 4 : Matrice dynamique (Moyen)

**Objectif** : Allouer et gérer une matrice 2D dynamique.

**Instructions** :
1. Écrire `int **create_matrix(int rows, int cols)` qui :
   - Alloue un tableau de pointeurs (lignes)
   - Alloue chaque ligne
   - Gère les erreurs (libérer ce qui a été alloué en cas d'échec)

2. Écrire `void fill_matrix(int **matrix, int rows, int cols)` qui :
   - Remplit avec matrix[i][j] = i * cols + j

3. Écrire `void print_matrix(int **matrix, int rows, int cols)`

4. Écrire `void destroy_matrix(int **matrix, int rows)` qui :
   - Libère dans l'ordre inverse (lignes puis tableau de pointeurs)

5. Dans main : créer une matrice 3x4, remplir, afficher, libérer

**Sortie attendue** :
```
Matrice 3x4 :
  0  1  2  3
  4  5  6  7
  8  9 10 11
```

---

## Exercice 5 : Tableau de strings dynamique (Moyen)

**Objectif** : Gérer un tableau de chaînes allouées dynamiquement.

**Instructions** :
1. Créer une fonction `char **create_string_array(int count)` qui :
   - Alloue un tableau de `count` pointeurs char*
   - Initialise tous à NULL

2. Créer `int add_string(char **arr, int index, const char *str)` qui :
   - Alloue de la mémoire pour la chaîne
   - Copie la chaîne
   - Stocke dans arr[index]

3. Créer `void free_string_array(char **arr, int count)` qui :
   - Libère chaque chaîne
   - Libère le tableau

4. Dans main :
   - Créer un tableau de 5 strings
   - Ajouter : "whoami", "pwd", "ls -la", "cat /etc/passwd", "exit"
   - Afficher toutes les commandes
   - Libérer

**Sortie attendue** :
```
=== Command List ===
[0] whoami
[1] pwd
[2] ls -la
[3] cat /etc/passwd
[4] exit
```

---

## Exercice 6 : Pointeur de fonction - Calculatrice (Moyen)

**Objectif** : Utiliser des pointeurs de fonctions pour sélectionner des opérations.

**Instructions** :
1. Définir un typedef : `typedef int (*operation_t)(int, int);`

2. Implémenter 4 fonctions :
   - `int add(int a, int b)`
   - `int subtract(int a, int b)`
   - `int multiply(int a, int b)`
   - `int divide(int a, int b)` (retourne 0 si division par 0)

3. Créer une fonction `operation_t get_operation(char op)` qui :
   - Retourne le pointeur vers la bonne fonction selon '+', '-', '*', '/'
   - Retourne NULL si opérateur inconnu

4. Dans main :
   - Tester toutes les opérations avec 20 et 5
   - Afficher les résultats

**Sortie attendue** :
```
20 + 5 = 25
20 - 5 = 15
20 * 5 = 100
20 / 5 = 4
```

---

## Exercice 7 : Callback - Traitement de données (Moyen)

**Objectif** : Implémenter un système de callback pour traiter des données.

**Instructions** :
1. Définir : `typedef void (*processor_t)(int *value);`

2. Implémenter plusieurs processeurs :
   - `void proc_double(int *value)` - double la valeur
   - `void proc_square(int *value)` - met au carré
   - `void proc_negate(int *value)` - inverse le signe

3. Créer `void process_array(int *arr, int size, processor_t proc)` qui :
   - Applique le processeur à chaque élément

4. Dans main :
   - Créer un tableau {1, 2, 3, 4, 5}
   - Appliquer chaque processeur séparément
   - Afficher après chaque traitement

**Sortie attendue** :
```
Original : 1 2 3 4 5
Après double : 2 4 6 8 10
Après square : 1 4 9 16 25
Après negate : -1 -2 -3 -4 -5
```

---

## Exercice 8 : Table de dispatch (Difficile)

**Objectif** : Créer une table de commandes avec pointeurs de fonctions.

**Instructions** :
1. Définir une structure :
```c
typedef void (*handler_t)(const char *arg);

typedef struct {
    const char *name;
    const char *description;
    handler_t handler;
} Command;
```

2. Implémenter les handlers :
   - `cmd_help(arg)` - affiche "Aide disponible"
   - `cmd_info(arg)` - affiche "Système info..."
   - `cmd_echo(arg)` - affiche l'argument
   - `cmd_exit(arg)` - affiche "Bye!"

3. Créer un tableau de commandes avec sentinelle NULL

4. Créer `void dispatch(Command *cmds, const char *name, const char *arg)` qui :
   - Cherche la commande par nom
   - Exécute le handler
   - Affiche erreur si non trouvé

5. Tester avec "help", "info", "echo Hello", "unknown", "exit"

**Sortie attendue** :
```
> help
Aide disponible

> info
Système info...

> echo Hello
Hello

> unknown
[-] Unknown command: unknown

> exit
Bye!
```

---

## Exercice 9 : Encodeur modulaire avec callbacks (Difficile)

**Objectif** : Créer un système d'encodage/décodage modulaire.

**Instructions** :
1. Définir : `typedef void (*encoder_t)(unsigned char *data, int len, unsigned char key);`

2. Implémenter plusieurs encodeurs :
   - `xor_encode` - XOR avec la clé
   - `add_encode` - Ajoute la clé à chaque byte
   - `sub_encode` - Soustrait la clé de chaque byte
   - `rot_encode` - Rotation (ROL) de key bits

3. Créer une structure d'encodeur :
```c
typedef struct {
    const char *name;
    encoder_t encode;
    encoder_t decode;
} Encoder;
```

4. Créer un tableau d'encodeurs

5. Créer `void encode_payload(unsigned char *data, int len, const char *encoder_name, unsigned char key)`

6. Tester : encoder "ATTACK" avec XOR key=0x42, afficher hex, décoder, vérifier

**Sortie attendue** :
```
Original : ATTACK
Encodé (XOR 0x42) : 03 16 16 03 05 09
Décodé : ATTACK
```

---

## Exercice 10 : Buffer dynamique auto-extensible (Difficile)

**Objectif** : Implémenter un buffer qui s'agrandit automatiquement.

**Instructions** :
1. Définir une structure :
```c
typedef struct {
    unsigned char *data;
    int size;       // Taille utilisée
    int capacity;   // Taille allouée
} DynamicBuffer;
```

2. Implémenter :
   - `DynamicBuffer *buffer_create(int initial_capacity)`
   - `int buffer_append(DynamicBuffer *buf, unsigned char *data, int len)` - agrandit si nécessaire
   - `void buffer_print_hex(DynamicBuffer *buf)`
   - `void buffer_destroy(DynamicBuffer *buf)`

3. Dans main :
   - Créer un buffer de capacité 8
   - Ajouter 5 bytes : {0xDE, 0xAD, 0xBE, 0xEF, 0x00}
   - Ajouter 5 bytes : {0xCA, 0xFE, 0xBA, 0xBE, 0x00}
   - Ajouter 5 bytes : {0x41, 0x42, 0x43, 0x44, 0x00}
   - Afficher le contenu hex et la capacité finale

**Sortie attendue** :
```
[+] Buffer créé (capacité: 8)
[+] Ajout 5 bytes (size: 5, capacity: 8)
[+] Ajout 5 bytes - Reallocation! (size: 10, capacity: 16)
[+] Ajout 5 bytes (size: 15, capacity: 16)
Contenu : DE AD BE EF 00 CA FE BA BE 00 41 42 43 44 00
```

---

## Exercice 11 : Shellcode Loader basique (Difficile)

**Objectif** : Charger et exécuter du code en mémoire.

**Instructions** :
1. Créer un shellcode simple qui ne fait que retourner (juste `ret` = 0xC3)

2. Écrire une fonction `void *alloc_executable(int size)` qui :
   - Utilise mmap avec PROT_READ | PROT_WRITE | PROT_EXEC
   - Retourne le pointeur ou NULL si échec

3. Écrire une fonction `void free_executable(void *mem, int size)` qui :
   - Utilise munmap

4. Dans main :
   - Allouer de la mémoire exécutable
   - Copier le shellcode
   - Créer un pointeur de fonction et exécuter
   - Afficher "Shellcode executed successfully!" après l'exécution
   - Libérer la mémoire

**Sortie attendue** :
```
[+] Allocated executable memory at 0x7f...
[+] Shellcode copied (1 bytes)
[*] Executing shellcode...
[+] Shellcode executed successfully!
[+] Memory freed
```

**Note** : Sur certains systèmes, mmap avec PROT_EXEC peut être restreint.

---

## Exercice 12 : Gestionnaire de hooks (Challenge)

**Objectif** : Implémenter un système de hooking de fonctions.

**Instructions** :
1. Définir les structures :
```c
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
```

2. Implémenter :
   - `void hook_manager_init(HookManager *hm)`
   - `int hook_register(HookManager *hm, const char *name, target_func_t original)`
   - `int hook_install(HookManager *hm, const char *name, target_func_t hook)`
   - `int hook_remove(HookManager *hm, const char *name)`
   - `target_func_t hook_get_current(HookManager *hm, const char *name)`

3. Créer des fonctions cibles :
   - `int check_license(int key)` - retourne 1 si key == 12345
   - `int check_admin(int uid)` - retourne 1 si uid == 0

4. Créer des hooks :
   - `int hooked_license(int key)` - retourne toujours 1
   - `int hooked_admin(int uid)` - retourne toujours 1

5. Tester le flow complet

**Sortie attendue** :
```
=== Before Hooks ===
check_license(99999): 0 (FAIL)
check_admin(1000): 0 (FAIL)

=== Installing Hooks ===
[+] Hook installed: check_license
[+] Hook installed: check_admin

=== After Hooks ===
check_license(99999): 1 (BYPASSED!)
check_admin(1000): 1 (BYPASSED!)

=== Removing Hooks ===
[+] Hook removed: check_license

=== After Removal ===
check_license(99999): 0 (ORIGINAL)
check_admin(1000): 1 (STILL HOOKED)
```

---

## Exercice 13 : Pool d'allocation (Challenge)

**Objectif** : Implémenter un allocateur de mémoire simple.

**Instructions** :
1. Définir :
```c
#define POOL_SIZE 1024
#define BLOCK_SIZE 64

typedef struct {
    unsigned char memory[POOL_SIZE];
    int used[POOL_SIZE / BLOCK_SIZE];  // 0 = libre, 1 = utilisé
    int num_blocks;
} MemoryPool;
```

2. Implémenter :
   - `void pool_init(MemoryPool *pool)`
   - `void *pool_alloc(MemoryPool *pool)` - retourne un bloc de BLOCK_SIZE bytes
   - `void pool_free(MemoryPool *pool, void *ptr)`
   - `void pool_stats(MemoryPool *pool)` - affiche stats d'utilisation

3. Tester :
   - Allouer 5 blocs
   - Libérer le bloc 2
   - Allouer un nouveau bloc (devrait réutiliser l'emplacement)
   - Afficher les stats

**Sortie attendue** :
```
[+] Pool initialized: 16 blocks of 64 bytes

Allocating 5 blocks...
  Block 0: 0x... (pool+0)
  Block 1: 0x... (pool+64)
  Block 2: 0x... (pool+128)
  Block 3: 0x... (pool+192)
  Block 4: 0x... (pool+256)

Freeing block 2...
[+] Block freed at offset 128

Allocating new block...
  New block: 0x... (pool+128) <- Reused!

Pool stats: 5/16 blocks used (31%)
```

---

## Exercice 14 : Implant C2 simplifié (Challenge)

**Objectif** : Combiner tous les concepts dans un mini-implant.

**Instructions** :
1. Structures :
```c
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
```

2. Implémenter :
   - `Implant *implant_create(int buffer_size)`
   - `int implant_register_command(Implant *imp, const char *name, const char *desc, cmd_handler_t handler)`
   - `int implant_execute(Implant *imp, const char *cmdline, char *response, int resp_size)`
   - `void implant_destroy(Implant *imp)`

3. Commandes à implémenter :
   - `cmd_id` - retourne "implant-001"
   - `cmd_ping` - retourne "PONG"
   - `cmd_echo` - retourne l'argument
   - `cmd_help` - liste les commandes

4. Parser : extraire nom de commande et argument de "cmd arg1 arg2"

5. Tester avec plusieurs commandes

**Sortie attendue** :
```
=== Implant C2 Simulator ===

[+] Implant created
[+] Command registered: id
[+] Command registered: ping
[+] Command registered: echo
[+] Command registered: help

> id
Response: implant-001

> ping
Response: PONG

> echo Hello from C2!
Response: Hello from C2!

> help
Response:
  id - Return implant ID
  ping - Connectivity check
  echo - Echo back argument
  help - List commands

> unknown
Response: [-] Unknown command: unknown

[+] Implant destroyed
```

---

## Barème de difficulté

| Exercice | Difficulté | Concepts clés |
|----------|------------|---------------|
| 1 | Facile | malloc, free, NULL check |
| 2 | Facile | realloc |
| 3 | Moyen | int**, allocation dans fonction |
| 4 | Moyen | Matrice 2D dynamique |
| 5 | Moyen | Tableau de strings |
| 6 | Moyen | Pointeurs de fonctions, typedef |
| 7 | Moyen | Callbacks |
| 8 | Difficile | Table de dispatch |
| 9 | Difficile | Encodeurs modulaires |
| 10 | Difficile | Buffer auto-extensible |
| 11 | Difficile | Shellcode loader, mmap |
| 12 | Challenge | Système de hooks |
| 13 | Challenge | Pool d'allocation |
| 14 | Challenge | Implant C2 complet |

---

## Conseils

1. **Toujours vérifier malloc** : `if (ptr == NULL) return -1;`
2. **Libérer dans l'ordre inverse** : dernier alloué = premier libéré
3. **Mettre à NULL après free** : évite use-after-free
4. **Tester les cas limites** : taille 0, realloc échec, etc.
5. **Valgrind** : `valgrind ./programme` pour détecter les fuites

Bonne chance !
