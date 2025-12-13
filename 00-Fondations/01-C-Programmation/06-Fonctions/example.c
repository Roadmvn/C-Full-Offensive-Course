/*
 * Module 06 : Fonctions (Functions)
 *
 * Description : Démonstration complète des fonctions avec applications offensives
 * Compilation : gcc -o example example.c
 * Exécution  : ./example
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// ============================================================================
// DEMO 1 : Fonctions de base - Déclaration et définition
// ============================================================================

// Prototypes (déclarations)
void greet(void);
int add(int a, int b);
float calculate_average(int values[], int size);

// Définitions
void greet(void) {
    printf("[+] Agent initialisé\n");
}

int add(int a, int b) {
    return a + b;
}

float calculate_average(int values[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += values[i];
    }
    return (float)sum / size;
}

void demo_basic_functions(void) {
    printf("=== DEMO 1 : Fonctions de base ===\n\n");

    // Fonction sans paramètre ni retour
    greet();

    // Fonction avec paramètres et retour
    int result = add(10, 25);
    printf("[*] 10 + 25 = %d\n", result);

    // Fonction avec tableau
    int ports[] = {22, 80, 443, 3306, 8080};
    float avg = calculate_average(ports, 5);
    printf("[*] Port moyen: %.1f\n\n", avg);
}

// ============================================================================
// DEMO 2 : Passage par valeur vs par pointeur
// ============================================================================

void increment_by_value(int x) {
    x++;  // Modifie la copie locale
    printf("    Dans la fonction (valeur): x = %d\n", x);
}

void increment_by_pointer(int *x) {
    (*x)++;  // Modifie l'original via le pointeur
    printf("    Dans la fonction (pointeur): *x = %d\n", *x);
}

void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void demo_pass_by(void) {
    printf("=== DEMO 2 : Passage par valeur vs pointeur ===\n\n");

    int value = 10;

    printf("[*] Passage par valeur:\n");
    printf("    Avant: value = %d\n", value);
    increment_by_value(value);
    printf("    Après: value = %d (inchangé!)\n\n", value);

    printf("[*] Passage par pointeur:\n");
    printf("    Avant: value = %d\n", value);
    increment_by_pointer(&value);
    printf("    Après: value = %d (modifié!)\n\n", value);

    // Swap
    int a = 100, b = 200;
    printf("[*] Swap:\n");
    printf("    Avant: a=%d, b=%d\n", a, b);
    swap(&a, &b);
    printf("    Après: a=%d, b=%d\n\n", a, b);
}

// ============================================================================
// DEMO 3 : Variables locales, globales et statiques
// ============================================================================

int global_counter = 0;  // Variable globale

void increment_global(void) {
    global_counter++;
}

int get_next_id(void) {
    static int id = 0;  // Conserve sa valeur entre appels
    return ++id;
}

int count_calls(void) {
    static int call_count = 0;  // Anti-sandbox: compte les exécutions
    call_count++;
    return call_count;
}

void demo_scope_and_lifetime(void) {
    printf("=== DEMO 3 : Scope et durée de vie ===\n\n");

    // Variable locale
    printf("[*] Variable locale:\n");
    for (int i = 0; i < 3; i++) {
        int local = 0;  // Réinitialisée à chaque itération
        local++;
        printf("    Itération %d: local = %d\n", i, local);
    }
    printf("\n");

    // Variable globale
    printf("[*] Variable globale:\n");
    printf("    Avant: global_counter = %d\n", global_counter);
    increment_global();
    increment_global();
    printf("    Après 2 appels: global_counter = %d\n\n", global_counter);

    // Variable statique
    printf("[*] Variable statique (conserve sa valeur):\n");
    for (int i = 0; i < 5; i++) {
        printf("    ID généré: %d\n", get_next_id());
    }
    printf("\n");

    // Application anti-sandbox
    printf("[*] Application: Compteur d'exécutions (anti-sandbox)\n");
    for (int i = 0; i < 3; i++) {
        int calls = count_calls();
        printf("    Appel #%d\n", calls);
    }
    printf("    [!] Si calls < seuil, environnement suspect\n\n");
}

// ============================================================================
// DEMO 4 : Récursion
// ============================================================================

unsigned long factorial(int n) {
    if (n <= 1) return 1;           // Cas de base
    return n * factorial(n - 1);    // Appel récursif
}

int fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Simulation parcours de répertoire récursif
void scan_directory(const char *path, int depth) {
    // Indentation selon la profondeur
    for (int i = 0; i < depth; i++) printf("  ");
    printf("[DIR] %s/\n", path);

    // Simule des fichiers trouvés
    if (depth < 2) {  // Limite la profondeur
        for (int i = 0; i < depth; i++) printf("  ");
        printf("  [FILE] document.docx\n");

        for (int i = 0; i < depth; i++) printf("  ");
        printf("  [FILE] data.xlsx\n");

        // Sous-répertoire récursif
        if (depth == 0) {
            scan_directory("Documents", depth + 1);
            scan_directory("Downloads", depth + 1);
        }
    }
}

void demo_recursion(void) {
    printf("=== DEMO 4 : Récursion ===\n\n");

    // Factorielle
    printf("[*] Factorielle:\n");
    for (int i = 1; i <= 6; i++) {
        printf("    %d! = %lu\n", i, factorial(i));
    }
    printf("\n");

    // Fibonacci
    printf("[*] Fibonacci:\n");
    printf("    Séquence: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", fibonacci(i));
    }
    printf("\n\n");

    // Parcours récursif
    printf("[*] Simulation scan récursif de fichiers:\n");
    scan_directory("C:\\Users\\Target", 0);
    printf("\n");
}

// ============================================================================
// DEMO 5 : Pointeurs de fonctions
// ============================================================================

// Définition de fonctions "commandes"
int cmd_whoami(void) {
    printf("    [+] Executing: whoami\n");
    printf("    -> DESKTOP-TARGET\\Admin\n");
    return 0;
}

int cmd_hostname(void) {
    printf("    [+] Executing: hostname\n");
    printf("    -> DESKTOP-TARGET\n");
    return 0;
}

int cmd_pwd(void) {
    printf("    [+] Executing: pwd\n");
    printf("    -> C:\\Users\\Admin\\Desktop\n");
    return 0;
}

int cmd_exit(void) {
    printf("    [+] Executing: exit\n");
    printf("    -> Terminating...\n");
    return -1;
}

// Type pointeur de fonction
typedef int (*CommandHandler)(void);

// Structure de commande
typedef struct {
    const char *name;
    CommandHandler handler;
} Command;

void demo_function_pointers(void) {
    printf("=== DEMO 5 : Pointeurs de fonctions ===\n\n");

    // Pointeur de fonction simple
    printf("[*] Pointeur de fonction simple:\n");
    int (*func_ptr)(void);
    func_ptr = cmd_whoami;
    func_ptr();  // Appel via pointeur
    printf("\n");

    // Table de dispatch (Command Dispatcher)
    printf("[*] Command Dispatcher (C2 pattern):\n");
    Command commands[] = {
        {"whoami", cmd_whoami},
        {"hostname", cmd_hostname},
        {"pwd", cmd_pwd},
        {"exit", cmd_exit}
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);

    // Simule réception de commandes
    const char *received[] = {"hostname", "pwd", "whoami"};
    int num_received = 3;

    for (int i = 0; i < num_received; i++) {
        printf("\n  [C2] Received: '%s'\n", received[i]);

        // Recherche et exécution
        int found = 0;
        for (int j = 0; j < num_commands; j++) {
            if (strcmp(received[i], commands[j].name) == 0) {
                commands[j].handler();  // Appel via table
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("    [-] Unknown command\n");
        }
    }
    printf("\n");
}

// ============================================================================
// DEMO 6 : Callbacks
// ============================================================================

// Type de callback pour encodage
typedef unsigned char (*Encoder)(unsigned char byte, unsigned char key);

// Implémentations d'encodeurs
unsigned char xor_encoder(unsigned char byte, unsigned char key) {
    return byte ^ key;
}

unsigned char add_encoder(unsigned char byte, unsigned char key) {
    return byte + key;
}

unsigned char rot_encoder(unsigned char byte, unsigned char key) {
    if (byte >= 'A' && byte <= 'Z') {
        return 'A' + (byte - 'A' + key) % 26;
    }
    if (byte >= 'a' && byte <= 'z') {
        return 'a' + (byte - 'a' + key) % 26;
    }
    return byte;
}

// Fonction générique qui utilise le callback
void encode_payload(unsigned char *data, int size, unsigned char key,
                    Encoder encoder, const char *name) {
    printf("  [%s] Key=0x%02X: ", name, key);
    for (int i = 0; i < size; i++) {
        data[i] = encoder(data[i], key);
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void demo_callbacks(void) {
    printf("=== DEMO 6 : Callbacks (Encodeurs modulaires) ===\n\n");

    unsigned char payload1[] = {'H', 'E', 'L', 'L', 'O'};
    unsigned char payload2[] = {'H', 'E', 'L', 'L', 'O'};
    unsigned char payload3[] = {'H', 'E', 'L', 'L', 'O'};

    printf("[*] Payload original: HELLO\n\n");

    encode_payload(payload1, 5, 0x42, xor_encoder, "XOR");
    encode_payload(payload2, 5, 0x10, add_encoder, "ADD");
    encode_payload(payload3, 5, 13, rot_encoder, "ROT");

    printf("\n[*] Avantage: même fonction, algorithmes différents!\n\n");
}

// ============================================================================
// DEMO 7 : Fonctions inline et macros
// ============================================================================

// Macro (remplacée à la compilation)
#define SQUARE_MACRO(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define XOR_BYTE(b, k) ((b) ^ (k))

// Fonction inline (suggestion au compilateur)
static inline int square_inline(int x) {
    return x * x;
}

void demo_inline_macros(void) {
    printf("=== DEMO 7 : Inline et Macros ===\n\n");

    printf("[*] Macro SQUARE:\n");
    printf("    SQUARE_MACRO(5) = %d\n", SQUARE_MACRO(5));

    printf("\n[*] Fonction inline square:\n");
    printf("    square_inline(5) = %d\n", square_inline(5));

    printf("\n[*] Macro MAX:\n");
    printf("    MAX(10, 25) = %d\n", MAX(10, 25));

    printf("\n[*] Macro XOR_BYTE:\n");
    unsigned char data = 0x41;  // 'A'
    unsigned char key = 0x42;
    printf("    0x%02X XOR 0x%02X = 0x%02X\n",
           data, key, XOR_BYTE(data, key));

    // Attention aux effets de bord avec les macros!
    printf("\n[!] Danger des macros - effets de bord:\n");
    int x = 5;
    printf("    x = 5\n");
    printf("    SQUARE_MACRO(x++) évalue x++ deux fois!\n");
    printf("    Résultat: %d (pas 25!)\n", SQUARE_MACRO(x++));
    printf("\n");
}

// ============================================================================
// DEMO 8 : Variadic functions (nombre variable d'arguments)
// ============================================================================

#include <stdarg.h>

// Fonction avec nombre variable d'arguments
void log_message(const char *level, const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[%s] ", level);
    vprintf(format, args);
    printf("\n");

    va_end(args);
}

// Somme de N nombres
int sum_all(int count, ...) {
    va_list args;
    va_start(args, count);

    int total = 0;
    for (int i = 0; i < count; i++) {
        total += va_arg(args, int);
    }

    va_end(args);
    return total;
}

void demo_variadic(void) {
    printf("=== DEMO 8 : Fonctions variadiques ===\n\n");

    printf("[*] Logger personnalisé:\n");
    log_message("INFO", "Agent started on port %d", 4444);
    log_message("DEBUG", "Target: %s", "192.168.1.100");
    log_message("ERROR", "Connection failed after %d attempts", 3);
    printf("\n");

    printf("[*] Somme de N nombres:\n");
    printf("    sum_all(3, 10, 20, 30) = %d\n", sum_all(3, 10, 20, 30));
    printf("    sum_all(5, 1, 2, 3, 4, 5) = %d\n", sum_all(5, 1, 2, 3, 4, 5));
    printf("\n");
}

// ============================================================================
// DEMO 9 : Simulation - Agent C2 modulaire
// ============================================================================

typedef struct {
    int (*init)(void);
    int (*beacon)(void);
    int (*execute)(const char *cmd);
    void (*cleanup)(void);
} AgentVTable;

int agent_init(void) {
    printf("  [*] Initializing agent...\n");
    printf("  [+] Agent ID: 0x%04X\n", rand() % 0xFFFF);
    return 0;
}

int agent_beacon(void) {
    static int beacon_count = 0;
    beacon_count++;
    printf("  [*] Beacon #%d sent\n", beacon_count);
    return 0;
}

int agent_execute(const char *cmd) {
    printf("  [*] Executing: %s\n", cmd);
    return 0;
}

void agent_cleanup(void) {
    printf("  [*] Cleaning up...\n");
    printf("  [+] Agent terminated\n");
}

void demo_modular_agent(void) {
    printf("=== DEMO 9 : Agent C2 modulaire ===\n\n");

    srand(time(NULL));

    // Table de fonctions virtuelles
    AgentVTable agent = {
        .init = agent_init,
        .beacon = agent_beacon,
        .execute = agent_execute,
        .cleanup = agent_cleanup
    };

    printf("[*] Agent lifecycle:\n\n");

    // Initialisation
    agent.init();
    printf("\n");

    // Boucle beacon (simulée)
    for (int i = 0; i < 3; i++) {
        agent.beacon();

        if (i == 1) {
            agent.execute("ipconfig /all");
        }
    }
    printf("\n");

    // Nettoyage
    agent.cleanup();
    printf("\n");
}

// ============================================================================
// MAIN
// ============================================================================
int main(void) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║        MODULE 06 : FONCTIONS (FUNCTIONS) - DÉMONSTRATIONS    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    demo_basic_functions();
    demo_pass_by();
    demo_scope_and_lifetime();
    demo_recursion();
    demo_function_pointers();
    demo_callbacks();
    demo_inline_macros();
    demo_variadic();
    demo_modular_agent();

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    FIN DES DÉMONSTRATIONS                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    return 0;
}
