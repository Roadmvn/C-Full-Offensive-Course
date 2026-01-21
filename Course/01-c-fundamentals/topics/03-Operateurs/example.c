/*
 * =============================================================================
 * Module 03 : Opérateurs - Démonstration complète
 * =============================================================================
 *
 * Ce fichier démontre TOUS les opérateurs essentiels pour la programmation
 * offensive : XOR encryption, manipulation de flags, extraction de bytes, etc.
 *
 * Compilation : gcc -Wall -Wextra example.c -o example
 * Exécution   : ./example
 *
 * =============================================================================
 * PRÉREQUIS : Avoir compris le Module 02 (Variables et Types)
 * =============================================================================
 */

#include <stdio.h>      // Pour printf()
#include <stdint.h>     // Pour uint8_t, uint32_t, etc.
#include <string.h>     // Pour strlen()

/* =============================================================================
 * DEMO 1 : Opérateurs arithmétiques
 *
 * POURQUOI C'EST IMPORTANT :
 * - Le modulo (%) est utilisé pour la rotation de clés de chiffrement
 * - La division entière est utilisée pour calculer des offsets
 * - L'incrémentation est partout dans le code
 * =============================================================================
 */
void demo_arithmetic(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 1 : OPÉRATEURS ARITHMÉTIQUES                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // Addition, soustraction, multiplication
    // -------------------------------------------------------------------------
    int a = 10, b = 3;

    printf("a = %d, b = %d\n\n", a, b);
    printf("Addition       : a + b = %d\n", a + b);       // 13
    printf("Soustraction   : a - b = %d\n", a - b);       // 7
    printf("Multiplication : a * b = %d\n", a * b);       // 30

    // -------------------------------------------------------------------------
    // Division entière - ATTENTION !
    // -------------------------------------------------------------------------
    printf("\n--- Division entière ---\n");
    printf("Division       : a / b = %d (pas 3.33 !)\n", a / b);  // 3

    // Pourquoi c'est important : calcul d'offsets dans un buffer
    // Si tu as un buffer de 100 bytes et tu veux le diviser en 3 parties
    int buffer_size = 100;
    int parts = 3;
    int part_size = buffer_size / parts;  // = 33, pas 33.33
    printf("Buffer 100 bytes / 3 parties = %d bytes par partie\n", part_size);

    // -------------------------------------------------------------------------
    // Modulo (%) - LE RESTE de la division
    // -------------------------------------------------------------------------
    printf("\n--- Modulo (reste de division) ---\n");
    printf("Modulo         : a %% b = %d (reste de 10/3)\n", a % b);  // 1

    // APPLICATION OFFENSIVE : Rotation de clés
    printf("\n[APPLICATION OFFENSIVE] Rotation de clés XOR :\n");
    unsigned char keys[] = {0x41, 0x42, 0x43, 0x44};  // 4 clés
    int key_count = 4;

    printf("Clés : ");
    for (int i = 0; i < key_count; i++) {
        printf("0x%02X ", keys[i]);
    }
    printf("\n");

    // Simulation de 10 itérations avec rotation
    printf("Indices : ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", i % key_count);  // 0, 1, 2, 3, 0, 1, 2, 3, 0, 1
    }
    printf(" (cycle à travers les clés)\n");

    // -------------------------------------------------------------------------
    // Incrémentation et décrémentation
    // -------------------------------------------------------------------------
    printf("\n--- Incrémentation/Décrémentation ---\n");
    int x = 5;

    printf("x initial = %d\n", x);
    printf("++x (pré)  = %d, x après = %d\n", ++x, x);  // x devient 6, retourne 6

    x = 5;  // Reset
    printf("x++ (post) = %d, x après = %d\n", x++, x);  // Retourne 5, puis x devient 6
}

/* =============================================================================
 * DEMO 2 : Opérateurs de comparaison
 *
 * POURQUOI C'EST IMPORTANT :
 * - Vérifications de conditions dans le code de sécurité
 * - Anti-debug checks
 * - Validation de données
 * =============================================================================
 */
void demo_comparison(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 2 : OPÉRATEURS DE COMPARAISON                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    int a = 5, b = 10;

    printf("a = %d, b = %d\n\n", a, b);

    // Chaque comparaison retourne 1 (vrai) ou 0 (faux)
    printf("a == b : %d (égal)\n", a == b);          // 0
    printf("a != b : %d (différent)\n", a != b);     // 1
    printf("a < b  : %d (inférieur)\n", a < b);      // 1
    printf("a > b  : %d (supérieur)\n", a > b);      // 0
    printf("a <= b : %d (inf ou égal)\n", a <= b);   // 1
    printf("a >= b : %d (sup ou égal)\n", a >= b);   // 0

    // ATTENTION : = vs ==
    printf("\n--- ERREUR CLASSIQUE : = vs == ---\n");
    int x = 0;

    // MAUVAIS : Ceci ASSIGNE 5 à x, puis teste si x != 0 (toujours vrai !)
    // if (x = 5) { }  // NE FAIS JAMAIS ÇA !

    // BON : Compare x avec 5
    // if (x == 5) { }

    printf("x = %d\n", x);
    printf("(x = 5) retourne %d et modifie x à %d (DANGEREUX !)\n", (x = 5), x);

    x = 0;  // Reset
    printf("(x == 5) retourne %d et x reste à %d (CORRECT)\n", (x == 5), x);

    // APPLICATION OFFENSIVE : Comparaison pour anti-debug
    printf("\n[APPLICATION OFFENSIVE] Vérifications de sécurité :\n");
    int debugger_detected = 0;  // Simulé
    int timing_anomaly = 0;     // Simulé

    if (debugger_detected == 0 && timing_anomaly == 0) {
        printf("  Aucune anomalie détectée - continuer exécution\n");
    } else {
        printf("  ALERTE - Analyse suspecte détectée !\n");
    }
}

/* =============================================================================
 * DEMO 3 : Opérateurs logiques (&&, ||, !)
 *
 * POURQUOI C'EST IMPORTANT :
 * - Combiner plusieurs conditions
 * - Short-circuit evaluation pour éviter les crashes
 * - Anti-debug avec multiples vérifications
 * =============================================================================
 */
void demo_logical(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 3 : OPÉRATEURS LOGIQUES (&&, ||, !)             ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    int is_admin = 1;
    int is_authenticated = 1;
    int is_banned = 0;

    printf("is_admin = %d, is_authenticated = %d, is_banned = %d\n\n",
           is_admin, is_authenticated, is_banned);

    // AND logique : les DEUX doivent être vrais
    printf("--- AND logique (&&) ---\n");
    printf("is_admin && is_authenticated = %d\n", is_admin && is_authenticated);  // 1
    printf("is_admin && is_banned = %d\n", is_admin && is_banned);                // 0

    // OR logique : AU MOINS UN doit être vrai
    printf("\n--- OR logique (||) ---\n");
    printf("is_admin || is_banned = %d\n", is_admin || is_banned);  // 1
    printf("is_banned || 0 = %d\n", is_banned || 0);                // 0

    // NOT logique : inverse la valeur
    printf("\n--- NOT logique (!) ---\n");
    printf("!is_admin = %d\n", !is_admin);          // 0
    printf("!is_banned = %d\n", !is_banned);        // 1
    printf("!!is_admin = %d (double négation)\n", !!is_admin);  // 1

    // Short-circuit evaluation
    printf("\n--- Short-circuit evaluation ---\n");
    printf("Avec AND (&&) : si le premier est FAUX, le second n'est PAS évalué\n");
    printf("Avec OR (||)  : si le premier est VRAI, le second n'est PAS évalué\n");

    // Exemple pratique : éviter un NULL pointer dereference
    int* ptr = NULL;

    // SÉCURISÉ grâce au short-circuit :
    // Si ptr est NULL, ptr != NULL est faux, donc *ptr n'est jamais évalué
    if (ptr != NULL && *ptr > 0) {
        printf("Valeur pointée : %d\n", *ptr);
    } else {
        printf("  ptr est NULL - accès évité grâce au short-circuit\n");
    }

    // APPLICATION OFFENSIVE : Multiple anti-debug checks
    printf("\n[APPLICATION OFFENSIVE] Anti-debug multi-checks :\n");
    int check1 = 0;  // IsDebuggerPresent() simulé
    int check2 = 0;  // Timing check simulé
    int check3 = 0;  // Breakpoint check simulé

    // Si UNE SEULE vérification échoue, on détecte le debugger
    if (check1 || check2 || check3) {
        printf("  Debugger détecté !\n");
    } else {
        printf("  Aucun debugger détecté - exécution normale\n");
    }
}

/* =============================================================================
 * DEMO 4 : Opérateurs bitwise - LE CŒUR DE L'OFFENSIVE
 *
 * POURQUOI C'EST IMPORTANT :
 * - XOR encryption / obfuscation
 * - Manipulation de flags (Windows API, permissions)
 * - Extraction de bytes pour shellcode
 * - Parsing de structures binaires
 * =============================================================================
 */
void demo_bitwise(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 4 : OPÉRATEURS BITWISE (LE PLUS IMPORTANT!)     ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Valeurs de test
    uint8_t a = 0b11001010;  // 202 en décimal
    uint8_t b = 0b10101100;  // 172 en décimal

    printf("a = 0b11001010 (202)\n");
    printf("b = 0b10101100 (172)\n\n");

    // -------------------------------------------------------------------------
    // AND bitwise (&) - Les DEUX bits doivent être 1
    // -------------------------------------------------------------------------
    printf("--- AND bitwise (&) ---\n");
    printf("    11001010\n");
    printf("  & 10101100\n");
    printf("  ----------\n");
    printf("    10001000 = %u\n\n", a & b);  // 136

    // APPLICATION : Masquage / Extraction de bits
    printf("[APPLICATION] Extraire le byte de poids faible :\n");
    uint32_t value32 = 0x12345678;
    uint8_t low_byte = value32 & 0xFF;
    printf("  0x%08X & 0xFF = 0x%02X\n\n", value32, low_byte);  // 0x78

    // -------------------------------------------------------------------------
    // OR bitwise (|) - AU MOINS UN bit doit être 1
    // -------------------------------------------------------------------------
    printf("--- OR bitwise (|) ---\n");
    printf("    11001010\n");
    printf("  | 10101100\n");
    printf("  ----------\n");
    printf("    11101110 = %u\n\n", a | b);  // 238

    // APPLICATION : Combiner des flags
    printf("[APPLICATION] Combiner des flags Windows :\n");
    #define MEM_COMMIT   0x00001000
    #define MEM_RESERVE  0x00002000
    uint32_t alloc_type = MEM_COMMIT | MEM_RESERVE;
    printf("  MEM_COMMIT | MEM_RESERVE = 0x%08X\n\n", alloc_type);

    // -------------------------------------------------------------------------
    // XOR bitwise (^) - Les bits doivent être DIFFÉRENTS
    // -------------------------------------------------------------------------
    printf("--- XOR bitwise (^) - LE PLUS IMPORTANT ! ---\n");
    printf("    11001010\n");
    printf("  ^ 10101100\n");
    printf("  ----------\n");
    printf("    01100110 = %u\n\n", a ^ b);  // 102

    // PROPRIÉTÉ MAGIQUE : XOR s'annule lui-même !
    printf("[PROPRIÉTÉ MAGIQUE] A ^ B ^ B = A\n");
    uint8_t original = 0x41;  // 'A'
    uint8_t key = 0xFF;
    uint8_t encrypted = original ^ key;
    uint8_t decrypted = encrypted ^ key;
    printf("  Original  : 0x%02X ('%c')\n", original, original);
    printf("  Chiffré   : 0x%02X ^ 0x%02X = 0x%02X\n", original, key, encrypted);
    printf("  Déchiffré : 0x%02X ^ 0x%02X = 0x%02X ('%c')\n\n",
           encrypted, key, decrypted, decrypted);

    // -------------------------------------------------------------------------
    // NOT bitwise (~) - Inverse TOUS les bits
    // -------------------------------------------------------------------------
    printf("--- NOT bitwise (~) ---\n");
    printf("  ~11001010 = 00110101 = %u (sur 8 bits)\n", (uint8_t)~a);

    // APPLICATION : Créer un masque pour effacer des bits
    printf("[APPLICATION] Effacer un flag spécifique :\n");
    uint8_t flags = 0xFF;
    uint8_t flag_to_remove = 0x02;
    flags = flags & ~flag_to_remove;
    printf("  0xFF & ~0x02 = 0x%02X (bit 1 effacé)\n\n", flags);

    // -------------------------------------------------------------------------
    // Shift Left (<<) - Décale les bits vers la gauche
    // -------------------------------------------------------------------------
    printf("--- Shift Left (<<) ---\n");
    printf("  5 << 2 = %d (5 * 4 = 20)\n", 5 << 2);
    printf("  1 << 0 = %d (bit 0)\n", 1 << 0);
    printf("  1 << 1 = %d (bit 1)\n", 1 << 1);
    printf("  1 << 7 = %d (bit 7)\n\n", 1 << 7);

    // APPLICATION : Construire une valeur à partir de bytes
    printf("[APPLICATION] Construire une adresse 32-bit :\n");
    uint8_t b0 = 0x78, b1 = 0x56, b2 = 0x34, b3 = 0x12;
    uint32_t addr = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    printf("  Bytes : 0x%02X, 0x%02X, 0x%02X, 0x%02X\n", b0, b1, b2, b3);
    printf("  Adresse construite : 0x%08X\n\n", addr);

    // -------------------------------------------------------------------------
    // Shift Right (>>) - Décale les bits vers la droite
    // -------------------------------------------------------------------------
    printf("--- Shift Right (>>) ---\n");
    printf("  20 >> 2 = %d (20 / 4 = 5)\n\n", 20 >> 2);

    // APPLICATION : Extraire des bytes
    printf("[APPLICATION] Extraire les bytes d'une valeur 32-bit :\n");
    uint32_t val = 0x12345678;
    printf("  Valeur : 0x%08X\n", val);
    printf("  Byte 0 : (val >> 0) & 0xFF  = 0x%02X\n", (val >> 0) & 0xFF);
    printf("  Byte 1 : (val >> 8) & 0xFF  = 0x%02X\n", (val >> 8) & 0xFF);
    printf("  Byte 2 : (val >> 16) & 0xFF = 0x%02X\n", (val >> 16) & 0xFF);
    printf("  Byte 3 : (val >> 24) & 0xFF = 0x%02X\n", (val >> 24) & 0xFF);
}

/* =============================================================================
 * DEMO 5 : XOR Encryption - L'application offensive principale
 *
 * POURQUOI C'EST IMPORTANT :
 * - Obfusquer des strings (éviter détection par 'strings' ou AV)
 * - Chiffrer des shellcodes
 * - Cacher des données sensibles
 * =============================================================================
 */
void demo_xor_encryption(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 5 : XOR ENCRYPTION (OFFENSIVE)                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // Exemple 1 : Chiffrement XOR simple (1 clé)
    // -------------------------------------------------------------------------
    printf("--- Chiffrement XOR simple (1 clé) ---\n\n");

    // String à chiffrer
    char message[] = "HELLO";
    unsigned char key = 0x42;

    printf("Message original : %s\n", message);
    printf("Clé             : 0x%02X\n\n", key);

    // Affiche les bytes originaux
    printf("Bytes originaux : ");
    for (size_t i = 0; i < strlen(message); i++) {
        printf("0x%02X ", (unsigned char)message[i]);
    }
    printf("\n");

    // Chiffrement : XOR chaque byte avec la clé
    printf("\nChiffrement (XOR avec clé) :\n");
    for (size_t i = 0; i < strlen(message); i++) {
        unsigned char original = message[i];
        unsigned char encrypted = original ^ key;
        printf("  '%c' (0x%02X) ^ 0x%02X = 0x%02X\n",
               original, original, key, encrypted);
        message[i] = encrypted;
    }

    // Affiche les bytes chiffrés
    printf("\nBytes chiffrés  : ");
    for (size_t i = 0; i < strlen(message); i++) {
        printf("0x%02X ", (unsigned char)message[i]);
    }
    printf("\n");

    // Déchiffrement : même opération !
    printf("\nDéchiffrement (même opération) :\n");
    for (size_t i = 0; i < strlen(message); i++) {
        message[i] ^= key;
    }
    printf("Message déchiffré : %s\n", message);

    // -------------------------------------------------------------------------
    // Exemple 2 : Chiffrement XOR multi-clés
    // -------------------------------------------------------------------------
    printf("\n--- Chiffrement XOR multi-clés (plus sécurisé) ---\n\n");

    unsigned char data[] = "SECRET";
    unsigned char keys[] = {0x11, 0x22, 0x33, 0x44};
    size_t data_len = strlen((char*)data);
    size_t key_len = sizeof(keys);

    printf("Data     : %s\n", data);
    printf("Clés     : ");
    for (size_t i = 0; i < key_len; i++) {
        printf("0x%02X ", keys[i]);
    }
    printf("\n\n");

    // Chiffrement avec clé cyclique
    printf("Chiffrement avec rotation de clés :\n");
    for (size_t i = 0; i < data_len; i++) {
        unsigned char original = data[i];
        unsigned char current_key = keys[i % key_len];
        data[i] = original ^ current_key;
        printf("  data[%zu] = 0x%02X ^ keys[%zu %% %zu] (0x%02X) = 0x%02X\n",
               i, original, i, key_len, current_key, data[i]);
    }

    printf("\nBytes chiffrés : ");
    for (size_t i = 0; i < data_len; i++) {
        printf("\\x%02x", data[i]);
    }
    printf("\n");

    // Déchiffrement
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= keys[i % key_len];
    }
    printf("Déchiffré      : %s\n", data);
}

/* =============================================================================
 * DEMO 6 : Manipulation de flags
 *
 * POURQUOI C'EST IMPORTANT :
 * - Windows API utilise des flags partout (VirtualAlloc, OpenProcess, etc.)
 * - Permissions Unix (chmod)
 * - Configuration de fonctionnalités
 * =============================================================================
 */
void demo_flags(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 6 : MANIPULATION DE FLAGS                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Définition de flags (chaque flag est un bit unique)
    #define FLAG_READ    (1 << 0)  // 0x01 = 0b00000001
    #define FLAG_WRITE   (1 << 1)  // 0x02 = 0b00000010
    #define FLAG_EXECUTE (1 << 2)  // 0x04 = 0b00000100
    #define FLAG_ADMIN   (1 << 3)  // 0x08 = 0b00001000

    printf("Définition des flags :\n");
    printf("  FLAG_READ    = 1 << 0 = 0x%02X = 0b00000001\n", FLAG_READ);
    printf("  FLAG_WRITE   = 1 << 1 = 0x%02X = 0b00000010\n", FLAG_WRITE);
    printf("  FLAG_EXECUTE = 1 << 2 = 0x%02X = 0b00000100\n", FLAG_EXECUTE);
    printf("  FLAG_ADMIN   = 1 << 3 = 0x%02X = 0b00001000\n\n", FLAG_ADMIN);

    unsigned char permissions = 0;

    // AJOUTER des flags (OR)
    printf("--- Ajouter des flags avec OR (|) ---\n");
    permissions |= FLAG_READ;
    printf("  permissions |= FLAG_READ    → 0x%02X\n", permissions);

    permissions |= FLAG_WRITE;
    printf("  permissions |= FLAG_WRITE   → 0x%02X\n", permissions);

    permissions |= FLAG_EXECUTE;
    printf("  permissions |= FLAG_EXECUTE → 0x%02X\n\n", permissions);

    // VÉRIFIER un flag (AND)
    printf("--- Vérifier un flag avec AND (&) ---\n");

    if (permissions & FLAG_READ) {
        printf("  FLAG_READ    est ACTIVÉ\n");
    }
    if (permissions & FLAG_WRITE) {
        printf("  FLAG_WRITE   est ACTIVÉ\n");
    }
    if (permissions & FLAG_EXECUTE) {
        printf("  FLAG_EXECUTE est ACTIVÉ\n");
    }
    if (permissions & FLAG_ADMIN) {
        printf("  FLAG_ADMIN   est ACTIVÉ\n");
    } else {
        printf("  FLAG_ADMIN   est DÉSACTIVÉ\n");
    }
    printf("\n");

    // RETIRER un flag (AND avec NOT)
    printf("--- Retirer un flag avec AND NOT (&= ~) ---\n");
    printf("  Avant : 0x%02X\n", permissions);
    permissions &= ~FLAG_WRITE;
    printf("  permissions &= ~FLAG_WRITE → 0x%02X\n\n", permissions);

    // TOGGLE un flag (XOR)
    printf("--- Toggle un flag avec XOR (^=) ---\n");
    printf("  Avant : 0x%02X (FLAG_ADMIN désactivé)\n", permissions);
    permissions ^= FLAG_ADMIN;
    printf("  permissions ^= FLAG_ADMIN → 0x%02X (FLAG_ADMIN activé)\n", permissions);
    permissions ^= FLAG_ADMIN;
    printf("  permissions ^= FLAG_ADMIN → 0x%02X (FLAG_ADMIN désactivé)\n", permissions);

    // APPLICATION OFFENSIVE : Flags Windows API
    printf("\n[APPLICATION OFFENSIVE] Flags Windows simulés :\n");
    #define PROCESS_VM_READ       0x0010
    #define PROCESS_VM_WRITE      0x0020
    #define PROCESS_VM_OPERATION  0x0008
    #define PROCESS_CREATE_THREAD 0x0002

    uint32_t access = PROCESS_VM_READ | PROCESS_VM_WRITE |
                      PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;

    printf("  PROCESS_VM_READ | PROCESS_VM_WRITE | ...\n");
    printf("  = 0x%04X (droits pour injection mémoire)\n", access);
}

/* =============================================================================
 * DEMO 7 : Extraction d'adresses pour shellcode
 *
 * POURQUOI C'EST IMPORTANT :
 * - Buffer overflow : écrire une adresse de retour en little endian
 * - Shellcode : injecter des adresses dans le payload
 * - Reverse engineering : parser des adresses depuis un dump
 * =============================================================================
 */
void demo_address_extraction(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 7 : EXTRACTION D'ADRESSES (SHELLCODE)           ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // Extraction de bytes d'une adresse 32-bit
    // -------------------------------------------------------------------------
    printf("--- Extraction d'une adresse 32-bit ---\n\n");

    uint32_t target_addr = 0x7FFF1234;
    printf("Adresse cible : 0x%08X\n\n", target_addr);

    // Extraction byte par byte
    unsigned char addr_bytes[4];
    addr_bytes[0] = (target_addr >> 0) & 0xFF;   // LSB (byte de poids faible)
    addr_bytes[1] = (target_addr >> 8) & 0xFF;
    addr_bytes[2] = (target_addr >> 16) & 0xFF;
    addr_bytes[3] = (target_addr >> 24) & 0xFF;  // MSB (byte de poids fort)

    printf("Extraction byte par byte :\n");
    printf("  Byte 0 (LSB) : (0x%08X >> 0)  & 0xFF = 0x%02X\n", target_addr, addr_bytes[0]);
    printf("  Byte 1       : (0x%08X >> 8)  & 0xFF = 0x%02X\n", target_addr, addr_bytes[1]);
    printf("  Byte 2       : (0x%08X >> 16) & 0xFF = 0x%02X\n", target_addr, addr_bytes[2]);
    printf("  Byte 3 (MSB) : (0x%08X >> 24) & 0xFF = 0x%02X\n\n", target_addr, addr_bytes[3]);

    // Format pour shellcode (little endian)
    printf("Format shellcode (little endian) : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02x", addr_bytes[i]);
    }
    printf("\n\n");

    // -------------------------------------------------------------------------
    // Extraction d'une adresse 64-bit
    // -------------------------------------------------------------------------
    printf("--- Extraction d'une adresse 64-bit ---\n\n");

    uint64_t target64 = 0x00007FFF12345678ULL;
    printf("Adresse cible : 0x%016llX\n\n", (unsigned long long)target64);

    unsigned char addr64_bytes[8];
    for (int i = 0; i < 8; i++) {
        addr64_bytes[i] = (target64 >> (i * 8)) & 0xFF;
    }

    printf("Format shellcode x64 (little endian) : ");
    for (int i = 0; i < 8; i++) {
        printf("\\x%02x", addr64_bytes[i]);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // Reconstruction depuis des bytes
    // -------------------------------------------------------------------------
    printf("\n--- Reconstruction depuis des bytes ---\n\n");

    // Bytes lus depuis un dump mémoire (little endian)
    unsigned char dump[] = {0x78, 0x56, 0x34, 0x12};

    printf("Bytes dans le dump : ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", dump[i]);
    }
    printf("\n");

    uint32_t reconstructed = dump[0] |
                             (dump[1] << 8) |
                             (dump[2] << 16) |
                             (dump[3] << 24);

    printf("Adresse reconstruite : 0x%08X\n", reconstructed);
}

/* =============================================================================
 * DEMO 8 : Opérateur ternaire
 *
 * POURQUOI C'EST IMPORTANT :
 * - Code plus compact
 * - Sélection conditionnelle de valeurs
 * =============================================================================
 */
void demo_ternary(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 8 : OPÉRATEUR TERNAIRE                          ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Syntaxe : condition ? valeur_si_vrai : valeur_si_faux

    int a = 10, b = 5;

    // Trouver le maximum
    int max = (a > b) ? a : b;
    printf("a = %d, b = %d\n", a, b);
    printf("max = (a > b) ? a : b = %d\n\n", max);

    // Équivalent avec if-else
    printf("Équivalent avec if-else :\n");
    printf("  if (a > b) max = a; else max = b;\n\n");

    // APPLICATION : Sélection conditionnelle
    int is_connected = 1;
    const char* status = is_connected ? "online" : "offline";
    printf("[APPLICATION] Status : %s\n", status);

    // Ternaire imbriqué (à éviter pour la lisibilité)
    int score = 75;
    const char* grade = (score >= 90) ? "A" :
                        (score >= 80) ? "B" :
                        (score >= 70) ? "C" :
                        (score >= 60) ? "D" : "F";
    printf("Score %d → Grade %s\n", score, grade);
}

/* =============================================================================
 * FONCTION PRINCIPALE
 * =============================================================================
 */
int main(void) {
    printf("\n");
    printf("███████████████████████████████████████████████████████████████████\n");
    printf("█                                                                 █\n");
    printf("█  MODULE 03 : OPÉRATEURS - DÉMONSTRATION COMPLÈTE                █\n");
    printf("█                                                                 █\n");
    printf("█  Focus : XOR Encryption, Bitwise, Flags                         █\n");
    printf("█                                                                 █\n");
    printf("███████████████████████████████████████████████████████████████████\n");

    // Exécute toutes les démos
    demo_arithmetic();
    demo_comparison();
    demo_logical();
    demo_bitwise();
    demo_xor_encryption();
    demo_flags();
    demo_address_extraction();
    demo_ternary();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  FIN DES DÉMONSTRATIONS\n");
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("Points clés à retenir :\n");
    printf("  1. XOR s'annule lui-même : A ^ B ^ B = A\n");
    printf("  2. Ajouter un flag   : flags |= FLAG\n");
    printf("  3. Vérifier un flag  : if (flags & FLAG)\n");
    printf("  4. Retirer un flag   : flags &= ~FLAG\n");
    printf("  5. Toggle un flag    : flags ^= FLAG\n");
    printf("  6. Extraire un byte  : (value >> (n*8)) & 0xFF\n");
    printf("  7. Construire une valeur : b0 | (b1 << 8) | (b2 << 16) | ...\n");
    printf("\n");

    return 0;
}
