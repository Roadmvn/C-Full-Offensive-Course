# Module 13 : Préprocesseur et Macros - Solutions

## Exercice 1 : Macros de base

```c
#include <stdio.h>

// TOUJOURS parenthéser les arguments!
#define CUBE(x) ((x) * (x) * (x))
#define ABS(x) ((x) < 0 ? -(x) : (x))
#define IS_EVEN(x) (((x) % 2) == 0)

int main(void) {
    printf("CUBE(3) = %d\n", CUBE(3));           // 27
    printf("CUBE(2+1) = %d\n", CUBE(2+1));       // 27 (pas 7!)
    printf("ABS(-5) = %d\n", ABS(-5));           // 5
    printf("IS_EVEN(4) = %d\n", IS_EVEN(4));     // 1 (vrai)
    printf("IS_EVEN(7) = %d\n", IS_EVEN(7));     // 0 (faux)
    return 0;
}
```

## Exercice 2 : Compilation conditionnelle multi-plateforme

```c
#include <stdio.h>
#include <stdlib.h>

// Détection OS
#ifdef _WIN32
    #define OS "Windows"
    #define CLEAR_SCREEN "cls"
    #define PATH_SEP "\\"
    #define NULL_DEVICE "NUL"
#elif __APPLE__
    #define OS "macOS"
    #define CLEAR_SCREEN "clear"
    #define PATH_SEP "/"
    #define NULL_DEVICE "/dev/null"
#elif __linux__
    #define OS "Linux"
    #define CLEAR_SCREEN "clear"
    #define PATH_SEP "/"
    #define NULL_DEVICE "/dev/null"
#endif

// Fonction spécifique à l'OS
void platform_specific(void) {
    #ifdef _WIN32
        printf("Windows-specific code\n");
        system("ver");
    #elif __APPLE__
        printf("macOS-specific code\n");
        system("sw_vers -productVersion");
    #elif __linux__
        printf("Linux-specific code\n");
        system("uname -r");
    #endif
}

int main(void) {
    printf("OS: %s\n", OS);
    printf("Path separator: %s\n", PATH_SEP);
    platform_specific();
    return 0;
}

// Compilation:
// gcc -DOS_CUSTOM solution2.c -o solution2
```

## Exercice 3 : Obfuscation de strings

```c
#include <stdio.h>
#include <string.h>

#define XOR_KEY 0x5A

// Obfuscation XOR
#define OBFUSCATE(str, key) do { \
    for (size_t i = 0; i < strlen(str); i++) { \
        str[i] ^= key; \
    } \
} while(0)

// Macro pour déclarer et obfusquer
#define SECURE_STRING(name, value) \
    char name[] = value; \
    OBFUSCATE(name, XOR_KEY)

int main(void) {
    // String obfusquée en mémoire
    SECURE_STRING(password, "SuperSecret123");
    
    printf("Obfuscated: ");
    for (size_t i = 0; i < strlen(password); i++) {
        printf("%02x ", (unsigned char)password[i]);
    }
    printf("\n");
    
    // Déobfuscation à l'utilisation
    OBFUSCATE(password, XOR_KEY);
    printf("Deobfuscated: %s\n", password);
    
    // Re-obfuscation immédiate
    OBFUSCATE(password, XOR_KEY);
    
    return 0;
}
```

## Exercice 4 : Logging conditionnel

```c
#include <stdio.h>
#include <time.h>

// Niveaux de log
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_ERROR 2

// Définir le niveau de compilation (par défaut INFO)
#ifndef CURRENT_LOG_LEVEL
    #define CURRENT_LOG_LEVEL LOG_LEVEL_INFO
#endif

// Macro pour timestamp
#define GET_TIME() ({ \
    time_t now = time(NULL); \
    char* time_str = ctime(&now); \
    time_str[strlen(time_str)-1] = '\0'; \
    time_str; \
})

// Macros de logging
#if CURRENT_LOG_LEVEL <= LOG_LEVEL_DEBUG
    #define LOG_DEBUG(fmt, ...) \
        printf("[DEBUG][%s][%s:%d] " fmt "\n", \
               GET_TIME(), __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#if CURRENT_LOG_LEVEL <= LOG_LEVEL_INFO
    #define LOG_INFO(fmt, ...) \
        printf("[INFO][%s] " fmt "\n", GET_TIME(), ##__VA_ARGS__)
#else
    #define LOG_INFO(fmt, ...) ((void)0)
#endif

#if CURRENT_LOG_LEVEL <= LOG_LEVEL_ERROR
    #define LOG_ERROR(fmt, ...) \
        fprintf(stderr, "[ERROR][%s][%s:%d] " fmt "\n", \
                GET_TIME(), __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define LOG_ERROR(fmt, ...) ((void)0)
#endif

int main(void) {
    LOG_DEBUG("Application démarrée");
    LOG_INFO("Traitement en cours...");
    LOG_ERROR("Erreur de connexion: %s", "timeout");
    return 0;
}

// Compilation:
// gcc -DCURRENT_LOG_LEVEL=0 solution4.c -o solution4_debug
// gcc -DCURRENT_LOG_LEVEL=2 solution4.c -o solution4_prod
```

## Exercice 5 : Token pasting avancé

```c
#include <stdio.h>

// Génération automatique de getters/setters
#define DEFINE_PROPERTY(type, name) \
    type _##name; \
    type get_##name(void) { return _##name; } \
    void set_##name(type val) { _##name = val; }

// Structure avec propriétés
struct Config {
    DEFINE_PROPERTY(int, timeout)
    DEFINE_PROPERTY(int, retries)
};

// Macro pour générer des fonctions de test
#define TEST_FUNCTION(name) \
    void test_##name(void) { \
        printf("Testing: %s\n", #name); \
    }

TEST_FUNCTION(connection)
TEST_FUNCTION(authentication)
TEST_FUNCTION(database)

int main(void) {
    struct Config cfg;
    
    // Utilisation des setters générés
    cfg.set_timeout(5000);
    cfg.set_retries(3);
    
    // Utilisation des getters générés
    printf("Timeout: %d\n", cfg.get_timeout());
    printf("Retries: %d\n", cfg.get_retries());
    
    // Appel des fonctions de test
    test_connection();
    test_authentication();
    test_database();
    
    return 0;
}
```

## Exercice 6 : Anti-debugging avec macros

```c
#include <stdio.h>
#include <stdlib.h>

#ifdef __APPLE__
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <unistd.h>
    
    #define CHECK_DEBUGGER() ({ \
        int mib[4]; \
        struct kinfo_proc info; \
        size_t size = sizeof(info); \
        mib[0] = CTL_KERN; \
        mib[1] = KERN_PROC; \
        mib[2] = KERN_PROC_PID; \
        mib[3] = getpid(); \
        sysctl(mib, 4, &info, &size, NULL, 0); \
        (info.kp_proc.p_flag & P_TRACED) != 0; \
    })
#elif __linux__
    #include <sys/ptrace.h>
    
    #define CHECK_DEBUGGER() (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
#else
    #define CHECK_DEBUGGER() 0
#endif

// Mode stealth : ne fait rien
#ifdef STEALTH_MODE
    #undef CHECK_DEBUGGER
    #define CHECK_DEBUGGER() 0
#endif

// Anti-debug action
#define ANTI_DEBUG_EXIT() do { \
    if (CHECK_DEBUGGER()) { \
        printf("Debugger detected!\n"); \
        exit(1); \
    } \
} while(0)

int main(void) {
    ANTI_DEBUG_EXIT();
    printf("No debugger detected, running normally\n");
    return 0;
}

// Compilation:
// gcc solution6.c -o solution6
// gcc -DSTEALTH_MODE solution6.c -o solution6_stealth
```

## Exercice 7 : Macros pour payload multiplateforme

```c
#include <stdio.h>
#include <stdint.h>

// Détection architecture
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH "x64"
    #define SHELLCODE_SIZE 64
    // Shellcode x64 Linux: execve("/bin/sh")
    #define SHELLCODE { \
        0x48, 0x31, 0xd2, 0x52, 0x48, 0xb8, 0x2f, 0x62, \
        0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x50, 0x48, \
        0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x48, \
        0x31, 0xc0, 0xb0, 0x3b, 0x0f, 0x05 \
    }
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARCH "ARM64"
    #define SHELLCODE_SIZE 32
    // Shellcode ARM64 (exemple simplifié)
    #define SHELLCODE { \
        0x20, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0x14 \
    }
#else
    #define ARCH "x86"
    #define SHELLCODE_SIZE 32
    #define SHELLCODE { 0x90, 0x90, 0x90, 0x90 } // NOPs
#endif

// Macro de fallback
#ifndef SHELLCODE
    #define SHELLCODE { 0x00 }
#endif

int main(void) {
    unsigned char payload[] = SHELLCODE;
    
    printf("Architecture: %s\n", ARCH);
    printf("Shellcode size: %d bytes\n", SHELLCODE_SIZE);
    printf("Payload: ");
    
    for (size_t i = 0; i < sizeof(payload); i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
    
    return 0;
}
```

## Exercice 8 : Optimisation et inline

```c
#include <stdio.h>
#include <time.h>

// Version macro
#define MACRO_SQUARE(x) ((x) * (x))

// Version inline
static inline int inline_square(int x) {
    return x * x;
}

// Version fonction normale
int function_square(int x) {
    return x * x;
}

#define ITERATIONS 100000000

double benchmark(int (*func)(int)) {
    clock_t start = clock();
    volatile int result;
    
    for (int i = 0; i < ITERATIONS; i++) {
        result = func(i % 1000);
    }
    
    clock_t end = clock();
    return (double)(end - start) / CLOCKS_PER_SEC;
}

int main(void) {
    double time_func = benchmark(function_square);
    double time_inline = benchmark(inline_square);
    
    printf("=== BENCHMARK ===\n");
    printf("Function: %.3f seconds\n", time_func);
    printf("Inline:   %.3f seconds\n", time_inline);
    
    // Test macro
    clock_t start = clock();
    volatile int result;
    for (int i = 0; i < ITERATIONS; i++) {
        result = MACRO_SQUARE(i % 1000);
    }
    clock_t end = clock();
    double time_macro = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("Macro:    %.3f seconds\n", time_macro);
    
    printf("\nConclusion:\n");
    printf("- Macro: Le plus rapide (inline au préprocesseur)\n");
    printf("- Inline: Très rapide (optimisé par le compilateur)\n");
    printf("- Function: Plus lent (call overhead)\n");
    
    return 0;
}

// Voir l'assembleur généré:
// gcc -S -O2 solution8.c
// cat solution8.s
```

## BONUS : Système complet d'obfuscation

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Base64 encoding table
#define B64_TABLE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// Obfuscation de noms de fonctions
#define OBFUSCATE_NAME(name) _##name##_obf

// Anti-analysis checks
#define ANTI_ANALYSIS() do { \
    CHECK_DEBUGGER_PROC(); \
    CHECK_VM(); \
    CHECK_SANDBOX(); \
} while(0)

#define CHECK_DEBUGGER_PROC() ((void)0)  // Implémenter selon OS
#define CHECK_VM() ((void)0)              // Détecter VM
#define CHECK_SANDBOX() ((void)0)         // Détecter sandbox

// XOR multi-clés
#define XOR_ENCRYPT(data, len, key) do { \
    for (size_t i = 0; i < len; i++) { \
        data[i] ^= key[i % sizeof(key)]; \
    } \
} while(0)

// Exemple complet
void OBFUSCATE_NAME(sensitive_function)(void) {
    ANTI_ANALYSIS();
    
    // String obfusquée
    char secret[] = {0x3f, 0x1a, 0x5c, 0x2e, 0x00};
    XOR_ENCRYPT(secret, strlen(secret), "\xAB\xCD");
    
    printf("Secret: %s\n", secret);
}

int main(void) {
    _sensitive_function_obf();
    return 0;
}
```

NOTES IMPORTANTES:
- Toujours tester les macros avec des expressions complexes
- Utiliser gcc -E pour voir l'expansion
- Attention aux side-effects (i++, appels de fonctions)
- Préférer inline pour logique complexe
- Documenter les macros obscures
