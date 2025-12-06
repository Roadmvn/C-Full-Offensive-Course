/*
 * Module 16 : Préprocesseur et Macros
 * Exemples pratiques d'utilisation du préprocesseur
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// === 1. MACROS DE BASE ===

#define PI 3.14159
#define MAX_BUFFER 1024
#define VERSION "1.0.0"

// Macro fonctionnelle avec parenthèses (IMPORTANT!)
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

// === 2. COMPILATION CONDITIONNELLE ===

// Détecter l'OS à la compilation
#ifdef __APPLE__
    #define OS_NAME "macOS"
    #define SHELL "/bin/zsh"
#elif defined(__linux__)
    #define OS_NAME "Linux"
    #define SHELL "/bin/bash"
#elif defined(_WIN32)
    #define OS_NAME "Windows"
    #define SHELL "cmd.exe"
#else
    #define OS_NAME "Unknown"
    #define SHELL "unknown"
#endif

// Mode debug vs release
#ifdef DEBUG
    #define LOG(msg) printf("[DEBUG] %s:%d - %s\n", __FILE__, __LINE__, msg)
    #define ASSERT(cond) if(!(cond)) { \
        fprintf(stderr, "Assertion failed: %s\n", #cond); \
        exit(1); \
    }
#else
    #define LOG(msg) ((void)0)
    #define ASSERT(cond) ((void)0)
#endif

// === 3. OPÉRATEURS SPÉCIAUX ===

// Stringification (#)
#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

// Token pasting (##)
#define CONCAT(a, b) a##b
#define VAR_NAME(prefix, num) prefix##num

// Arguments variadiques
#define PRINT_ARGS(fmt, ...) printf(fmt, __VA_ARGS__)
#define DEBUG_PRINT(fmt, ...) printf("[%s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

// === 4. MACROS POUR OBFUSCATION ===

// XOR simple pour obfuscation
#define XOR_KEY 0x42
#define OBFUSCATE(str) obfuscate_string(str, XOR_KEY)
#define DEOBFUSCATE(str) obfuscate_string(str, XOR_KEY)  // XOR est symétrique

// Macro pour cacher des appels système
#define EXECUTE(cmd) system(cmd)
#define SHELL_EXEC(cmd) popen(cmd, "r")

// === 5. MACROS AVANCÉES POUR RED TEAM ===

// Détection d'architecture
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH "x64"
    #define PTR_SIZE 8
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARCH "ARM64"
    #define PTR_SIZE 8
#else
    #define ARCH "x86"
    #define PTR_SIZE 4
#endif

// Masquer les strings sensibles
#define HIDE_STR(s) ((void)0)  // No-op en production
#define ANTI_DEBUG() check_debugger()

// === FONCTIONS ===

void obfuscate_string(char *str, unsigned char key) {
    for (int i = 0; str[i] != '\0'; i++) {
        str[i] ^= key;
    }
}

void check_debugger(void) {
    // Placeholder pour détection de debugger
    LOG("Checking for debugger...");
}

void demo_basic_macros(void) {
    printf("\n=== MACROS DE BASE ===\n");
    printf("PI = %f\n", PI);
    printf("SQUARE(5) = %d\n", SQUARE(5));
    printf("MAX(10, 20) = %d\n", MAX(10, 20));
    printf("VERSION = %s\n", VERSION);
}

void demo_conditional_compilation(void) {
    printf("\n=== COMPILATION CONDITIONNELLE ===\n");
    printf("OS: %s\n", OS_NAME);
    printf("Shell: %s\n", SHELL);
    printf("Architecture: %s\n", ARCH);
    printf("Pointer size: %d bytes\n", PTR_SIZE);
}

void demo_predefined_macros(void) {
    printf("\n=== MACROS PRÉDÉFINIES ===\n");
    printf("File: %s\n", __FILE__);
    printf("Line: %d\n", __LINE__);
    printf("Date: %s\n", __DATE__);
    printf("Time: %s\n", __TIME__);
    printf("Function: %s\n", __func__);
}

void demo_stringify_concat(void) {
    printf("\n=== STRINGIFICATION & CONCATENATION ===\n");
    
    // Stringification
    printf("STRINGIFY(123) = %s\n", STRINGIFY(123));
    printf("TO_STRING(PI) = %s\n", TO_STRING(PI));
    
    // Token pasting
    int VAR_NAME(test, 1) = 100;
    int VAR_NAME(test, 2) = 200;
    printf("test1 = %d\n", test1);
    printf("test2 = %d\n", test2);
}

void demo_variadic_macros(void) {
    printf("\n=== MACROS VARIADIQUES ===\n");
    PRINT_ARGS("Value: %d, String: %s\n", 42, "test");
    DEBUG_PRINT("Starting function");
    DEBUG_PRINT("Value = %d", 123);
}

void demo_obfuscation(void) {
    printf("\n=== OBFUSCATION ===\n");
    
    // String obfuscation
    char secret[] = "SuperSecret123";
    printf("Original: %s\n", secret);
    
    OBFUSCATE(secret);
    printf("Obfuscated: %s\n", secret);
    
    DEOBFUSCATE(secret);
    printf("Deobfuscated: %s\n", secret);
}

void demo_conditional_code(void) {
    printf("\n=== CODE CONDITIONNEL ===\n");
    
    #ifdef DEBUG
        printf("Mode DEBUG actif\n");
        LOG("Ceci est un message de debug");
        ASSERT(1 == 1);  // OK
    #else
        printf("Mode RELEASE\n");
    #endif
    
    #if PTR_SIZE == 8
        printf("Système 64-bit détecté\n");
    #else
        printf("Système 32-bit détecté\n");
    #endif
}

// Démonstration de macros dangereuses (attention!)
void demo_dangerous_macros(void) {
    printf("\n=== MACROS DANGEREUSES (DEMO) ===\n");
    
    // MAUVAIS: Macro sans parenthèses
    #define BAD_SQUARE(x) x*x
    printf("BAD_SQUARE(1+2) = %d (devrait être 9, mais = 5!)\n", BAD_SQUARE(1+2));
    
    // BON: Avec parenthèses
    printf("SQUARE(1+2) = %d (correct!)\n", SQUARE(1+2));
    
    // MAUVAIS: Side-effects
    int i = 5;
    #define BAD_MAX(a,b) ((a)>(b)?(a):(b))
    // Ne pas faire: BAD_MAX(i++, 10) car i++ peut être évalué 2 fois
    
    #undef BAD_SQUARE
    #undef BAD_MAX
}

int main(void) {
    printf("=== MODULE 16: PRÉPROCESSEUR ET MACROS ===\n");
    printf("Compilé le %s à %s\n", __DATE__, __TIME__);
    
    demo_basic_macros();
    demo_conditional_compilation();
    demo_predefined_macros();
    demo_stringify_concat();
    demo_variadic_macros();
    demo_obfuscation();
    demo_conditional_code();
    demo_dangerous_macros();
    
    printf("\n=== FIN DES EXEMPLES ===\n");
    return 0;
}

/*
 * COMPILATION:
 * 
 * Mode normal:
 * gcc example.c -o example
 * 
 * Mode debug:
 * gcc -DDEBUG example.c -o example_debug
 * 
 * Voir le préprocesseur:
 * gcc -E example.c -o example.i
 * 
 * Avec optimisations:
 * gcc -O2 example.c -o example
 */
