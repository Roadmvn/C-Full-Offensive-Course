/*
 * Exemple : Inline Assembly ARM64 dans du C
 *
 * Pour compiler : gcc example.c -o example
 * (Sur un Mac M1/M2/M3 uniquement)
 */

#include <stdio.h>

int main() {
    #if defined(__aarch64__)
        long value = 10;
        long result = 0;

        printf("Avant l'assembleur : value = %ld\n", value);

        // Bloc d'assembleur inline
        // On va ajouter 5 à 'value' et mettre le résultat dans 'result'
        __asm__(
            "add %0, %1, #5"  // Instruction : add Operande0, Operande1, #5
            : "=r" (result)   // Output : %0 est lié à la variable 'result' (write-only)
            : "r" (value)     // Input  : %1 est lié à la variable 'value' (read-only)
        );

        printf("Après l'assembleur (value + 5) : result = %ld\n", result);
    #else
        printf("Cet exemple nécessite un processeur ARM64 (Apple Silicon).\n");
        printf("Sur Intel (x86_64), l'assembleur est différent.\n");
    #endif

    return 0;
}

