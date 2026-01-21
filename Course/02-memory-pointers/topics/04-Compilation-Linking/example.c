/*
 * Module 17 : Compilation et Linking
 * Démonstration des concepts de compilation et linking
 */

#include <stdio.h>
#include <stdlib.h>

// === SECTION 1: CODE ===

// Fonction dans .text section
void text_section_function(void) {
    printf("Je suis dans la section .text\n");
}

// === SECTION 2: DATA ===

// .data : données initialisées
int initialized_data = 42;
char initialized_string[] = "Hello, .data section!";

// .rodata : données read-only
const char *read_only_data = "Je suis en read-only (.rodata)";
const int constant_value = 100;

// .bss : données non-initialisées (initialisées à 0)
int uninitialized_data;
char uninitialized_array[1024];

// === SECTION 3: SYMBOLES ===

// Symbole global (visible partout)
int global_symbol = 123;

// Symbole static (visible seulement dans ce fichier)
static int local_symbol = 456;

// Symbole externe (défini ailleurs)
extern void external_function(void);  // Sera undefined si non lié

// === SECTION 4: WEAK SYMBOLS ===

// Weak symbol: peut être overridé par un symbole fort
__attribute__((weak)) void weak_function(void) {
    printf("Version faible de la fonction\n");
}

// === FONCTIONS DE DÉMONSTRATION ===

void demo_sections(void) {
    printf("\n=== DÉMONSTRATION DES SECTIONS ===\n");
    
    printf("\n.text section (code):\n");
    text_section_function();
    
    printf("\n.data section:\n");
    printf("initialized_data = %d\n", initialized_data);
    printf("initialized_string = %s\n", initialized_string);
    
    printf("\n.rodata section:\n");
    printf("read_only_data = %s\n", read_only_data);
    printf("constant_value = %d\n", constant_value);
    
    printf("\n.bss section:\n");
    printf("uninitialized_data = %d (devrait être 0)\n", uninitialized_data);
    printf("uninitialized_array[0] = %d (devrait être 0)\n", uninitialized_array[0]);
}

void demo_symbols(void) {
    printf("\n=== DÉMONSTRATION DES SYMBOLES ===\n");
    
    printf("global_symbol = %d (symbole global)\n", global_symbol);
    printf("local_symbol = %d (symbole static)\n", local_symbol);
    
    // Afficher adresses pour voir les différences
    printf("\nAdresses mémoire:\n");
    printf("&text_section_function: %p (.text)\n", (void*)text_section_function);
    printf("&initialized_data: %p (.data)\n", (void*)&initialized_data);
    printf("&read_only_data: %p (.rodata)\n", (void*)&read_only_data);
    printf("&uninitialized_data: %p (.bss)\n", (void*)&uninitialized_data);
}

void demo_linking(void) {
    printf("\n=== DÉMONSTRATION DU LINKING ===\n");
    
    // Appel de fonction faible
    weak_function();
    
    // Note: external_function() causerait une erreur de linking
    // si elle n'est pas définie ailleurs
}

// === FONCTION POUR DEMO COMPILATION FLAGS ===

void demo_optimization(void) {
    printf("\n=== EFFETS DE L'OPTIMISATION ===\n");
    
    // Code qui sera optimisé différemment selon -O
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) {
        x = i * 2;
    }
    printf("Résultat: %d\n", x);
}

#ifdef DEBUG
void debug_only_function(void) {
    printf("Cette fonction n'existe qu'en mode DEBUG\n");
}
#endif

void demo_conditional_compilation(void) {
    printf("\n=== COMPILATION CONDITIONNELLE ===\n");
    
    #ifdef DEBUG
        printf("Mode DEBUG activé\n");
        debug_only_function();
    #else
        printf("Mode RELEASE\n");
    #endif
    
    #ifdef CUSTOM_FLAG
        printf("CUSTOM_FLAG est défini\n");
    #endif
}

// === MAIN ===

int main(int argc, char *argv[]) {
    printf("=== MODULE 17: COMPILATION ET LINKING ===\n");
    
    demo_sections();
    demo_symbols();
    demo_linking();
    demo_optimization();
    demo_conditional_compilation();
    
    printf("\n=== INFORMATIONS DE COMPILATION ===\n");
    printf("Compilé le %s à %s\n", __DATE__, __TIME__);
    
    #ifdef __OPTIMIZE__
        printf("Optimisations activées\n");
    #else
        printf("Pas d'optimisation (DEBUG)\n");
    #endif
    
    #ifdef __PIE__
        printf("PIE (Position Independent Executable) activé\n");
    #endif
    
    printf("\n=== COMMANDES POUR ANALYSER CE BINAIRE ===\n");
    printf("1. Voir les sections:\n");
    printf("   readelf -S %s (Linux)\n", argv[0]);
    printf("   otool -l %s (macOS)\n", argv[0]);
    
    printf("\n2. Voir les symboles:\n");
    printf("   nm %s\n", argv[0]);
    printf("   readelf -s %s (Linux)\n", argv[0]);
    
    printf("\n3. Voir les dépendances:\n");
    printf("   ldd %s (Linux)\n", argv[0]);
    printf("   otool -L %s (macOS)\n", argv[0]);
    
    printf("\n4. Désassembler:\n");
    printf("   objdump -d %s\n", argv[0]);
    printf("   otool -tV %s (macOS)\n", argv[0]);
    
    return 0;
}

/*
 * EXEMPLES DE COMPILATION:
 * 
 * 1. Compilation normale:
 *    gcc example.c -o example
 * 
 * 2. Voir les étapes:
 *    gcc -E example.c -o example.i      # Préprocesseur
 *    gcc -S example.c -o example.s      # Assembleur
 *    gcc -c example.c -o example.o      # Objet
 *    gcc example.o -o example           # Linking
 * 
 * 3. Avec optimisations:
 *    gcc -O0 example.c -o example_O0    # Pas d'optimisation
 *    gcc -O2 example.c -o example_O2    # Optimisations
 *    gcc -Os example.c -o example_Os    # Optimiser taille
 * 
 * 4. Debug vs Release:
 *    gcc -g -DDEBUG example.c -o example_debug
 *    gcc -O2 -s example.c -o example_release
 * 
 * 5. Avec protections de sécurité:
 *    gcc -fstack-protector-all -D_FORTIFY_SOURCE=2 \
 *        -fPIE -pie example.c -o example_secure
 * 
 * 6. Sans protections (pour exploitation):
 *    gcc -fno-stack-protector -z execstack -no-pie \
 *        example.c -o example_vuln
 * 
 * 7. Linking statique:
 *    gcc -static example.c -o example_static
 * 
 * 8. Vérifier les protections:
 *    checksec --file=example
 * 
 * 9. Comparer tailles:
 *    size example_O0 example_O2 example_Os
 * 
 * 10. Stripping:
 *     strip example -o example_stripped
 *     strip --strip-all example
 */
