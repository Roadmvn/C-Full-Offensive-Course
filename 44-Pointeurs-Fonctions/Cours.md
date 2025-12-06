# Module 44 : Pointeurs de Fonctions

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre ce qu'est un pointeur de fonction
- Déclarer et utiliser des pointeurs de fonctions
- Passer des fonctions en paramètres
- Créer des tables de dispatch
- Implémenter des callbacks
- Applications en Red Team (hooks, injection de code)

## 📚 Théorie

### C'est quoi un pointeur de fonction ?

Un **pointeur de fonction** est une variable qui stocke l'adresse mémoire d'une fonction. Comme les données, les fonctions ont une adresse en mémoire où leur code est stocké.

### Pourquoi utiliser des pointeurs de fonctions ?

1. **Flexibilité** : Changer le comportement à l'exécution
2. **Callbacks** : Passer des fonctions en paramètres
3. **Tables de dispatch** : Implémenter des systèmes de commandes
4. **Polymorphisme** : Simuler l'orienté objet en C
5. **Hooks** : Intercepter et modifier le comportement

### Comment déclarer un pointeur de fonction ?

```c
// Fonction normale
int add(int a, int b) {
    return a + b;
}

// Déclaration d'un pointeur de fonction
int (*func_ptr)(int, int);

// Assignment
func_ptr = add;

// Utilisation
int result = func_ptr(5, 3);  // Appelle add(5, 3)
```

### Syntaxe générale

```c
type_retour (*nom_pointeur)(type_param1, type_param2, ...);
```

### Différence entre pointeur de fonction et fonction

```c
int add(int a, int b);        // Déclaration de fonction
int (*ptr)(int, int);         // Déclaration de pointeur de fonction
```

## 🔍 Visualisation

### Mémoire et pointeurs de fonctions

```
┌─────────────────────────────────────────────┐
│           MÉMOIRE DU PROGRAMME              │
├─────────────────────────────────────────────┤
│                                             │
│  CODE SEGMENT (Instructions)               │
│  ┌─────────────────────────────┐           │
│  │ 0x08048000: add()           │           │
│  │   push ebp                  │           │
│  │   mov ebp, esp              │           │
│  │   mov eax, [ebp+8]          │           │
│  │   add eax, [ebp+12]         │           │
│  │   ...                       │◄──────┐   │
│  └─────────────────────────────┘       │   │
│                                         │   │
│  ┌─────────────────────────────┐       │   │
│  │ 0x08048020: subtract()      │       │   │
│  │   ...                       │       │   │
│  └─────────────────────────────┘       │   │
│                                         │   │
│  DATA SEGMENT (Variables)               │   │
│  ┌─────────────────────────────┐       │   │
│  │ func_ptr = 0x08048000 ──────┼───────┘   │
│  └─────────────────────────────┘           │
│                                             │
└─────────────────────────────────────────────┘
```

### Table de dispatch

```
┌────────────────────────────────────────┐
│      TABLE DE COMMANDES                │
├────────┬───────────────────────────────┤
│ Index  │  Pointeur de fonction         │
├────────┼───────────────────────────────┤
│   0    │  handle_help()    ───────────┼──► void handle_help()
│   1    │  handle_list()    ───────────┼──► void handle_list()
│   2    │  handle_execute() ───────────┼──► void handle_execute()
│   3    │  handle_exit()    ───────────┼──► void handle_exit()
└────────┴───────────────────────────────┘

Utilisation:
  command_table[2]();  // Appelle handle_execute()
```

### Callbacks en action

```
┌─────────────────────────────────────────────┐
│          SYSTÈME DE CALLBACKS               │
├─────────────────────────────────────────────┤
│                                             │
│  Fonction principale                        │
│  ┌────────────────────────┐                │
│  │ process_data(data,     │                │
│  │              callback) │                │
│  │   {                    │                │
│  │     // Traitement      │                │
│  │     ...                │                │
│  │     callback(result);  ├────┐           │
│  │   }                    │    │           │
│  └────────────────────────┘    │           │
│                                │           │
│                                │           │
│  Fonctions callback            ▼           │
│  ┌────────────────────────────────────┐    │
│  │ void log_result(int res) {         │    │
│  │   printf("Result: %d\n", res);     │    │
│  │ }                                  │    │
│  └────────────────────────────────────┘    │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │ void store_result(int res) {       │    │
│  │   database[index++] = res;         │    │
│  │ }                                  │    │
│  └────────────────────────────────────┘    │
│                                             │
└─────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Pointeurs de fonctions basiques

```c
#include <stdio.h>

// Fonctions arithmétiques
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
    if (b == 0) {
        printf("Erreur: division par zero\n");
        return 0;
    }
    return a / b;
}

int main() {
    // Déclaration d'un pointeur de fonction
    int (*operation)(int, int);

    int x = 10, y = 5;

    // Addition
    operation = add;
    printf("%d + %d = %d\n", x, y, operation(x, y));

    // Soustraction
    operation = subtract;
    printf("%d - %d = %d\n", x, y, operation(x, y));

    // Multiplication
    operation = multiply;
    printf("%d * %d = %d\n", x, y, operation(x, y));

    // Division
    operation = divide;
    printf("%d / %d = %d\n", x, y, operation(x, y));

    return 0;
}
```

### Exemple 2 : Table de dispatch (système de commandes)

```c
#include <stdio.h>
#include <string.h>

// Fonctions de commandes
void cmd_help() {
    printf("Commandes disponibles:\n");
    printf("  help   - Affiche cette aide\n");
    printf("  list   - Liste les fichiers\n");
    printf("  exec   - Execute une commande\n");
    printf("  exit   - Quitte le programme\n");
}

void cmd_list() {
    printf("Listing files...\n");
    printf("  file1.txt\n");
    printf("  file2.txt\n");
    printf("  secret.dat\n");
}

void cmd_exec() {
    printf("Executing command...\n");
    printf("Command executed successfully!\n");
}

void cmd_exit() {
    printf("Goodbye!\n");
}

// Structure pour associer commande et fonction
typedef struct {
    char *name;
    void (*function)();
} Command;

int main() {
    // Table de dispatch
    Command commands[] = {
        {"help", cmd_help},
        {"list", cmd_list},
        {"exec", cmd_exec},
        {"exit", cmd_exit},
        {NULL, NULL}  // Sentinelle
    };

    char input[50];

    printf("Système de commandes (tapez 'exit' pour quitter)\n");

    while (1) {
        printf("> ");
        scanf("%s", input);

        // Recherche de la commande
        int found = 0;
        for (int i = 0; commands[i].name != NULL; i++) {
            if (strcmp(input, commands[i].name) == 0) {
                commands[i].function();  // Appel via pointeur
                found = 1;

                if (strcmp(input, "exit") == 0) {
                    return 0;
                }
                break;
            }
        }

        if (!found) {
            printf("Commande inconnue: %s\n", input);
        }
    }

    return 0;
}
```

### Exemple 3 : Callbacks pour tri personnalisé

```c
#include <stdio.h>
#include <stdlib.h>

// Fonction de comparaison pour tri croissant
int compare_asc(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

// Fonction de comparaison pour tri décroissant
int compare_desc(const void *a, const void *b) {
    return (*(int*)b - *(int*)a);
}

// Tri personnalisé avec callback
void sort_array(int *arr, int size, int (*compare)(const void*, const void*)) {
    qsort(arr, size, sizeof(int), compare);
}

void print_array(int *arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main() {
    int numbers[] = {64, 34, 25, 12, 22, 11, 90};
    int size = sizeof(numbers) / sizeof(numbers[0]);

    printf("Tableau original: ");
    print_array(numbers, size);

    // Tri croissant
    sort_array(numbers, size, compare_asc);
    printf("Tri croissant:    ");
    print_array(numbers, size);

    // Réinitialisation
    int numbers2[] = {64, 34, 25, 12, 22, 11, 90};

    // Tri décroissant
    sort_array(numbers2, size, compare_desc);
    printf("Tri décroissant:  ");
    print_array(numbers2, size);

    return 0;
}
```

### Exemple 4 : Système de hooks (interception)

```c
#include <stdio.h>
#include <string.h>

// Fonction originale
void original_authenticate(const char *password) {
    if (strcmp(password, "secret123") == 0) {
        printf("[AUTH] Access granted!\n");
    } else {
        printf("[AUTH] Access denied!\n");
    }
}

// Hook malveillant
void hooked_authenticate(const char *password) {
    printf("[HOOK] Password intercepted: %s\n", password);

    // Log le mot de passe (attaque)
    FILE *f = fopen("stolen_passwords.txt", "a");
    if (f) {
        fprintf(f, "Password: %s\n", password);
        fclose(f);
    }

    // Appelle la fonction originale pour ne pas être détecté
    original_authenticate(password);
}

// Pointeur de fonction global
void (*authenticate)(const char*) = original_authenticate;

// Fonction pour installer le hook
void install_hook() {
    printf("[MALWARE] Installing authentication hook...\n");
    authenticate = hooked_authenticate;
}

int main() {
    printf("=== Authentification normale ===\n");
    authenticate("wrong_password");
    authenticate("secret123");

    printf("\n=== Installation du hook ===\n");
    install_hook();

    printf("\n=== Authentification hookée ===\n");
    authenticate("user_password");
    authenticate("secret123");

    return 0;
}
```

### Exemple 5 : Calculatrice avec pointeurs de fonctions

```c
#include <stdio.h>

// Fonctions d'opérations
double add(double a, double b) { return a + b; }
double subtract(double a, double b) { return a - b; }
double multiply(double a, double b) { return a * b; }
double divide(double a, double b) {
    if (b == 0) {
        printf("Erreur: division par zero\n");
        return 0;
    }
    return a / b;
}

// Type pour simplifier la syntaxe
typedef double (*operation_func)(double, double);

// Structure pour opération
typedef struct {
    char symbol;
    operation_func func;
    char *name;
} Operation;

int main() {
    // Table des opérations
    Operation operations[] = {
        {'+', add, "addition"},
        {'-', subtract, "soustraction"},
        {'*', multiply, "multiplication"},
        {'/', divide, "division"}
    };

    int num_ops = sizeof(operations) / sizeof(operations[0]);

    double a = 10, b = 5;
    char op;

    printf("Calculatrice simple\n");
    printf("Nombre 1: %.2f\n", a);
    printf("Nombre 2: %.2f\n", b);
    printf("\nOperations disponibles: + - * /\n");
    printf("Choisissez une operation: ");
    scanf(" %c", &op);

    // Recherche et exécution de l'opération
    int found = 0;
    for (int i = 0; i < num_ops; i++) {
        if (operations[i].symbol == op) {
            double result = operations[i].func(a, b);
            printf("\n%.2f %c %.2f = %.2f\n",
                   a, op, b, result);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("Operation invalide!\n");
    }

    return 0;
}
```

### Exemple 6 : Pointeur de fonction avancé (machine à états)

```c
#include <stdio.h>

// États possibles
typedef enum {
    STATE_IDLE,
    STATE_PROCESSING,
    STATE_COMPLETED,
    STATE_ERROR
} State;

// Type de fonction d'état
typedef State (*state_func)();

// Fonctions d'état
State idle_state() {
    printf("[IDLE] En attente...\n");
    printf("Voulez-vous commencer? (o/n): ");
    char choice;
    scanf(" %c", &choice);
    return (choice == 'o') ? STATE_PROCESSING : STATE_IDLE;
}

State processing_state() {
    printf("[PROCESSING] Traitement en cours...\n");
    static int progress = 0;
    progress += 25;

    printf("Progression: %d%%\n", progress);

    if (progress >= 100) {
        progress = 0;
        return STATE_COMPLETED;
    }
    return STATE_PROCESSING;
}

State completed_state() {
    printf("[COMPLETED] Traitement termine!\n");
    printf("Recommencer? (o/n): ");
    char choice;
    scanf(" %c", &choice);
    return (choice == 'o') ? STATE_IDLE : STATE_ERROR;
}

State error_state() {
    printf("[ERROR] Fin du programme\n");
    return STATE_ERROR;
}

int main() {
    // Table des états
    state_func state_table[] = {
        [STATE_IDLE] = idle_state,
        [STATE_PROCESSING] = processing_state,
        [STATE_COMPLETED] = completed_state,
        [STATE_ERROR] = error_state
    };

    State current_state = STATE_IDLE;

    printf("=== Machine a etats ===\n\n");

    // Boucle principale
    while (current_state != STATE_ERROR) {
        current_state = state_table[current_state]();
        printf("\n");
    }

    return 0;
}
```

## 🎯 Application Red Team

### 1. Hook de fonctions système

```c
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

// Pointeur vers la vraie fonction open
static int (*real_open)(const char *, int, ...) = NULL;

// Hook de open()
int open(const char *pathname, int flags, ...) {
    // Charge la vraie fonction si pas déjà fait
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }

    // Log tous les fichiers ouverts
    printf("[HOOK] Opening file: %s\n", pathname);

    // Interdit l'ouverture de fichiers sensibles
    if (strstr(pathname, "secret") != NULL) {
        printf("[HOOK] Blocked access to secret file!\n");
        return -1;
    }

    // Appelle la vraie fonction
    return real_open(pathname, flags);
}
```

### 2. Table de dispatch pour backdoor

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Commandes backdoor
void cmd_shell() {
    printf("[BACKDOOR] Spawning shell...\n");
    system("/bin/sh");
}

void cmd_download() {
    printf("[BACKDOOR] Downloading sensitive data...\n");
    system("tar czf /tmp/data.tar.gz /home/user/Documents/");
}

void cmd_keylog() {
    printf("[BACKDOOR] Starting keylogger...\n");
    // Code de keylogger ici
}

void cmd_elevate() {
    printf("[BACKDOOR] Attempting privilege escalation...\n");
    system("sudo su");
}

typedef struct {
    char *cmd;
    void (*handler)();
} BackdoorCommand;

int main() {
    BackdoorCommand commands[] = {
        {"shell", cmd_shell},
        {"download", cmd_download},
        {"keylog", cmd_keylog},
        {"elevate", cmd_elevate},
        {NULL, NULL}
    };

    char buffer[256];

    // Backdoor caché dans un programme légitime
    printf("System Diagnostic Tool v1.0\n");
    printf("Enter command: ");

    while (fgets(buffer, sizeof(buffer), stdin)) {
        buffer[strcspn(buffer, "\n")] = 0;

        for (int i = 0; commands[i].cmd != NULL; i++) {
            if (strcmp(buffer, commands[i].cmd) == 0) {
                commands[i].handler();
                break;
            }
        }

        printf("Enter command: ");
    }

    return 0;
}
```

### 3. Injection de callbacks malveillants

```c
#include <stdio.h>

// Callback légitime
void legit_callback(char *data) {
    printf("[LEGIT] Processing: %s\n", data);
}

// Callback malveillant
void malicious_callback(char *data) {
    printf("[MALICIOUS] Intercepted: %s\n", data);

    // Exfiltration de données
    FILE *f = fopen("/tmp/exfil.txt", "a");
    if (f) {
        fprintf(f, "%s\n", data);
        fclose(f);
    }

    // Appelle le callback légitime pour rester furtif
    legit_callback(data);
}

// Fonction qui utilise un callback
void process_data(char *data, void (*callback)(char*)) {
    printf("Processing data...\n");
    callback(data);
}

int main() {
    char *sensitive = "Password: admin123";

    printf("=== Mode normal ===\n");
    process_data(sensitive, legit_callback);

    printf("\n=== Mode compromis ===\n");
    process_data(sensitive, malicious_callback);

    return 0;
}
```

### 4. Table de dispatch polymorphe (évasion AV)

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Fonctions de chiffrement simple
void xor_encrypt(char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= 0xAA;
    }
}

void caesar_encrypt(char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] = (data[i] + 3) % 256;
    }
}

void reverse_encrypt(char *data, int len) {
    for (int i = 0; i < len / 2; i++) {
        char temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

typedef void (*encrypt_func)(char*, int);

int main() {
    // Table de fonctions de chiffrement
    encrypt_func encryptions[] = {
        xor_encrypt,
        caesar_encrypt,
        reverse_encrypt
    };

    int num_encryptions = sizeof(encryptions) / sizeof(encryptions[0]);

    char payload[] = "MALICIOUS PAYLOAD";
    int len = sizeof(payload) - 1;

    // Choix aléatoire pour éviter les signatures
    srand(time(NULL));
    int choice = rand() % num_encryptions;

    printf("Payload original: %s\n", payload);

    // Chiffrement polymorphe
    encryptions[choice](payload, len);

    printf("Payload chiffre (methode %d)\n", choice);

    // Transmission...

    // Déchiffrement (même fonction pour XOR et Caesar avec inverse)
    encryptions[choice](payload, len);

    printf("Payload dechiffre: %s\n", payload);

    return 0;
}
```

## 📝 Points clés à retenir

1. **Syntaxe** : `type_retour (*nom)(params)` pour déclarer un pointeur de fonction
2. **Flexibilité** : Permet de changer le comportement à l'exécution
3. **Tables de dispatch** : Association commande → fonction
4. **Callbacks** : Passer des fonctions en paramètres
5. **Typedef** : Simplifie la syntaxe des pointeurs de fonctions
6. **Hooks** : Technique puissante pour intercepter des appels
7. **Polymorphisme** : Simuler l'orienté objet en C pur

### Syntaxe à mémoriser

```c
// Déclaration simple
int (*func_ptr)(int, int);

// Avec typedef (plus lisible)
typedef int (*operation)(int, int);
operation op;

// Tableau de pointeurs de fonctions
void (*handlers[10])(void);

// Pointeur de fonction en paramètre
void execute(void (*callback)(int), int value);
```

### Pièges à éviter

1. **Parenthèses** : `int *func(int)` ≠ `int (*func)(int)`
2. **Initialisation** : Toujours initialiser avant utilisation
3. **NULL check** : Vérifier que le pointeur n'est pas NULL
4. **Prototype** : Le pointeur doit correspondre exactement à la signature

## ➡️ Prochaine étape

Maintenant que tu maîtrises les pointeurs de fonctions, tu es prêt pour le **Module 45 : Structures de Données Avancées**, où tu apprendras à créer des listes chaînées, arbres binaires et tables de hachage en utilisant ces concepts.

### Ce que tu as appris
- Déclarer et utiliser des pointeurs de fonctions
- Créer des tables de dispatch
- Implémenter des callbacks
- Hooker des fonctions système
- Créer des systèmes polymorphes

### Ce qui t'attend
- Structures de données dynamiques
- Listes chaînées
- Arbres binaires
- Tables de hachage
- Algorithmes avancés
