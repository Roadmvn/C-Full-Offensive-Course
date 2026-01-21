/*
 * ═══════════════════════════════════════════════════════════════════════
 * MODULE 29 : OBFUSCATION DE CODE
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Description :
 *   Ce module démontre différentes techniques d'obfuscation de code en C.
 *   L'obfuscation rend le code difficile à comprendre et à analyser tout
 *   en préservant sa fonctionnalité.
 *
 * AVERTISSEMENT LÉGAL :
 *   Ces techniques sont présentées UNIQUEMENT à des fins éducatives.
 *   L'utilisateur est SEUL RESPONSABLE de l'usage qu'il en fait.
 *   Toute utilisation malveillante est STRICTEMENT INTERDITE.
 *
 * Techniques démontrées :
 *   1. XOR String Encryption Macro
 *   2. Control Flow Flattening
 *   3. Dead Code Insertion
 *   4. Opaque Predicates
 *   5. Junk Code Generation
 *
 * Compilation :
 *   gcc -O0 -o obfuscation main.c
 *   (Utilisez -O0 pour préserver l'obfuscation visible)
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 1 : STRING ENCRYPTION (XOR)
 * ═══════════════════════════════════════════════════════════════════════ */

#define XOR_KEY 0x42

// Fonction de déchiffrement XOR
void decrypt_xor(char* str, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Fonction de chiffrement XOR (identique au déchiffrement)
void encrypt_xor(char* str, size_t len, unsigned char key) {
    decrypt_xor(str, len, key);
}

// Démonstration du chiffrement de chaînes
void demo_string_encryption(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("1. CHIFFREMENT DE CHAÎNES (XOR)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    // Chaîne en clair (visible dans le binaire avec 'strings')
    char plain_string[] = "Ceci est visible en clair!";
    printf("Chaîne en clair : %s\n", plain_string);

    // Chaîne chiffrée au compile-time (moins visible)
    // En production, on utiliserait des macros pour chiffrer à la compilation
    char encrypted_string[] = {
        0x01, 0x27, 0x21, 0x2b, 0x00, 0x27, 0x33, 0x34, 0x00,
        0x21, 0x2a, 0x2b, 0x28, 0x28, 0x30, 0x27, 0x27, 0x00,
        0x43, 0x4f, 0x50, 0x00, 0x00
    };

    printf("Chaîne chiffrée (brut) : ");
    for (size_t i = 0; i < sizeof(encrypted_string) - 1; i++) {
        printf("\\x%02x", (unsigned char)encrypted_string[i]);
    }
    printf("\n");

    // Déchiffrement
    decrypt_xor(encrypted_string, sizeof(encrypted_string) - 1, XOR_KEY);
    printf("Après déchiffrement : %s\n", encrypted_string);
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 : CONTROL FLOW FLATTENING
 * ═══════════════════════════════════════════════════════════════════════ */

// Fonction normale (lisible)
int fonction_normale(int a, int b) {
    int result = 0;
    result = a + b;
    result *= 2;
    result -= 5;
    return result;
}

// Même fonction avec control flow flattening
int fonction_obfusquee(int a, int b) {
    int result = 0;
    int state = 0;

    // Machine à états qui cache le flux de contrôle
    while (1) {
        switch (state) {
            case 0:
                result = a + b;
                state = 1;
                break;

            case 1:
                result *= 2;
                state = 2;
                break;

            case 2:
                result -= 5;
                state = 3;
                break;

            case 3:
                return result;

            default:
                state = 0;
        }
    }

    return result;
}

void demo_control_flow_flattening(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("2. CONTROL FLOW FLATTENING\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int x = 10, y = 5;

    int normal = fonction_normale(x, y);
    int obfusque = fonction_obfusquee(x, y);

    printf("Résultat fonction normale : %d\n", normal);
    printf("Résultat fonction obfusquée : %d\n", obfusque);
    printf("Les deux fonctions produisent le même résultat : %s\n",
           normal == obfusque ? "OUI" : "NON");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 3 : OPAQUE PREDICATES
 * ═══════════════════════════════════════════════════════════════════════ */

// Prédicats opaques : conditions dont la valeur est connue mais difficile
// à déterminer par analyse statique

// Toujours vrai : (x * x) >= 0 pour tout entier x
int opaque_always_true(int x) {
    return (x * x) >= 0;
}

// Toujours faux : (x * (x + 1)) % 2 == 1
// Car x*(x+1) est toujours pair (produit de deux entiers consécutifs)
int opaque_always_false(int x) {
    return ((x * (x + 1)) % 2) == 1;
}

// Fonction utilisant des prédicats opaques
int fonction_avec_predicats_opaques(int a, int b) {
    int result = 0;
    int dummy = rand() % 100;

    // Prédicat opaque toujours vrai
    if (opaque_always_true(dummy)) {
        result = a + b;  // Code réel
    } else {
        result = a * b;  // Code mort (jamais exécuté)
    }

    // Prédicat opaque toujours faux
    if (opaque_always_false(dummy)) {
        result = 0;      // Code mort
    } else {
        result *= 2;     // Code réel
    }

    return result;
}

void demo_opaque_predicates(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("3. OPAQUE PREDICATES (PRÉDICATS OPAQUES)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int x = 15, y = 7;

    printf("Test de prédicats opaques avec x=%d\n", x);
    printf("  x² >= 0 ? %s (toujours vrai)\n",
           opaque_always_true(x) ? "VRAI" : "FAUX");
    printf("  (x*(x+1)) %% 2 == 1 ? %s (toujours faux)\n",
           opaque_always_false(x) ? "VRAI" : "FAUX");

    int result = fonction_avec_predicats_opaques(x, y);
    printf("\nRésultat avec prédicats opaques : %d\n", result);
    printf("Résultat attendu ((15+7)*2) : %d\n", (x + y) * 2);
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 4 : DEAD CODE INSERTION
 * ═══════════════════════════════════════════════════════════════════════ */

// Fonctions "mortes" qui ne sont jamais appelées
static void dead_function_1(void) {
    volatile int x = 42;
    volatile int y = x * 2 + 17;
    (void)y;
}

static void dead_function_2(void) {
    volatile char buffer[256];
    for (int i = 0; i < 256; i++) {
        buffer[i] = (char)(i ^ 0xAA);
    }
}

static int dead_function_3(int a, int b, int c) {
    return (a * b + c) ^ (a + b * c) | (a ^ b ^ c);
}

// Fonction avec du code mort inséré
int fonction_avec_dead_code(int input) {
    volatile int junk1 = rand() % 1000;
    volatile int junk2 = junk1 * 42;

    // Code réel
    int result = input * 2;

    // Code mort conditionnel (jamais exécuté)
    if (0) {
        dead_function_1();
        result = dead_function_3(junk1, junk2, input);
    }

    // Plus de junk code
    volatile int junk3 = junk2 ^ junk1;
    (void)junk3;

    // Code réel
    result += 10;

    // Encore du code mort
    if (opaque_always_false(input)) {
        dead_function_2();
        result = 0;
    }

    return result;
}

void demo_dead_code(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("4. DEAD CODE INSERTION (CODE MORT)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int value = 25;
    int result = fonction_avec_dead_code(value);

    printf("Entrée : %d\n", value);
    printf("Résultat : %d\n", result);
    printf("Attendu (25*2 + 10) : %d\n", value * 2 + 10);
    printf("\nNote : Le binaire contient du code mort invisible à l'exécution.\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 5 : JUNK CODE GENERATION
 * ═══════════════════════════════════════════════════════════════════════ */

#define JUNK_CODE_1 \
    do { \
        volatile int _junk = rand(); \
        _junk = _junk * _junk + _junk; \
        (void)_junk; \
    } while(0)

#define JUNK_CODE_2 \
    do { \
        volatile char _junk_buf[64]; \
        for (int _i = 0; _i < 64; _i++) \
            _junk_buf[_i] = (char)(_i ^ 0x55); \
    } while(0)

#define JUNK_CODE_3 \
    do { \
        volatile unsigned int _x = (unsigned int)time(NULL); \
        _x = (_x << 13) ^ _x; \
        _x = (_x >> 17) ^ _x; \
        _x = (_x << 5) ^ _x; \
    } while(0)

// Fonction avec beaucoup de junk code
int fonction_avec_junk_code(int a, int b) {
    JUNK_CODE_1;

    int result = a + b;

    JUNK_CODE_2;

    result *= 2;

    JUNK_CODE_3;
    JUNK_CODE_1;

    result -= 7;

    JUNK_CODE_2;

    return result;
}

void demo_junk_code(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("5. JUNK CODE GENERATION\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int x = 12, y = 8;
    int result = fonction_avec_junk_code(x, y);

    printf("Calcul : (%d + %d) * 2 - 7\n", x, y);
    printf("Résultat : %d\n", result);
    printf("Attendu : %d\n", (x + y) * 2 - 7);
    printf("\nNote : La fonction contient beaucoup de code inutile (junk).\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 6 : EXEMPLE COMBINÉ
 * ═══════════════════════════════════════════════════════════════════════ */

// Fonction hautement obfusquée combinant toutes les techniques
int super_obfuscated_function(int input) {
    // String encryption
    char msg[] = {0x2d, 0x21, 0x2a, 0x27, 0x2b, 0x34, 0x00}; // "Result"
    decrypt_xor(msg, sizeof(msg) - 1, XOR_KEY);

    int result = 0;
    int state = 0;
    volatile int junk = rand();

    JUNK_CODE_1;

    // Control flow flattening avec opaque predicates
    while (1) {
        switch (state) {
            case 0:
                if (opaque_always_true(junk)) {
                    result = input * 3;
                    state = 1;
                } else {
                    dead_function_1();
                    state = 99;
                }
                JUNK_CODE_2;
                break;

            case 1:
                JUNK_CODE_3;
                if (!opaque_always_false(input)) {
                    result += 15;
                    state = 2;
                } else {
                    result = 0;
                    state = 0;
                }
                break;

            case 2:
                result -= 5;
                state = 3;
                JUNK_CODE_1;
                break;

            case 3:
                if (opaque_always_true(result)) {
                    return result;
                } else {
                    dead_function_2();
                    state = 0;
                }
                break;

            case 99:
                dead_function_3(junk, input, result);
                state = 0;
                break;

            default:
                state = 0;
        }
    }

    return result;
}

void demo_combined_obfuscation(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("6. OBFUSCATION COMBINÉE (TOUTES LES TECHNIQUES)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int input = 10;
    int result = super_obfuscated_function(input);

    printf("Entrée : %d\n", input);
    printf("Résultat de la fonction hautement obfusquée : %d\n", result);
    printf("Calcul effectué : (10 * 3) + 15 - 5 = %d\n", (input * 3) + 15 - 5);
    printf("\nCette fonction combine :\n");
    printf("  - Chiffrement de chaînes\n");
    printf("  - Control flow flattening\n");
    printf("  - Prédicats opaques\n");
    printf("  - Code mort\n");
    printf("  - Junk code\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * FONCTION PRINCIPALE
 * ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    srand((unsigned int)time(NULL));

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          MODULE 29 : TECHNIQUES D'OBFUSCATION DE CODE         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\nAVERTISSEMENT LÉGAL :\n");
    printf("Ces techniques sont présentées à des fins ÉDUCATIVES uniquement.\n");
    printf("Toute utilisation malveillante est STRICTEMENT INTERDITE.\n");
    printf("L'utilisateur est SEUL RESPONSABLE de l'usage qu'il en fait.\n");

    // Exécution des démonstrations
    demo_string_encryption();
    demo_control_flow_flattening();
    demo_opaque_predicates();
    demo_dead_code();
    demo_junk_code();
    demo_combined_obfuscation();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("ANALYSE DU BINAIRE\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("Commandes utiles pour analyser l'obfuscation :\n");
    printf("  1. strings ./obfuscation | grep -i secret\n");
    printf("  2. objdump -d ./obfuscation > disasm.txt\n");
    printf("  3. nm ./obfuscation | grep dead\n");
    printf("  4. size ./obfuscation\n");

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Programme terminé avec succès.\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}
