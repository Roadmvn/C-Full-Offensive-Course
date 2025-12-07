// inject.c - Dylib injectable simple
#include <stdio.h>
#include <dlfcn.h>
#include <stdarg.h>

// Hook printf
static int (*original_printf)(const char*, ...) = NULL;

int printf(const char *format, ...) {
    if (!original_printf) {
        original_printf = dlsym(RTLD_NEXT, "printf");
    }
    
    // Préfixe
    original_printf("[HOOKED] ");
    
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    
    return ret;
}

// Constructeur : appelé au chargement
__attribute__((constructor))
static void on_load() {
    fprintf(stderr, "\n=== DYLIB INJECTED ===\n");
    fprintf(stderr, "Library loaded successfully!\n");
    fprintf(stderr, "All printf calls will now be hooked.\n\n");
}

// Destructeur : appelé au déchargement
__attribute__((destructor))
static void on_unload() {
    fprintf(stderr, "\n=== DYLIB UNLOADED ===\n");
}

