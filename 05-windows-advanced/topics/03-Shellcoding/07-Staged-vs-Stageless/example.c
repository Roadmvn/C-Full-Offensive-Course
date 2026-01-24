/**
 * Staged vs Stageless - Concepts
 */
#include <stdio.h>

int main(void) {
    printf("=== STAGED ===\n");
    printf("1. Petit loader (~100 bytes)\n");
    printf("2. Connecte au C2\n");
    printf("3. Télécharge payload complet\n");
    printf("4. Exécute en mémoire\n\n");
    
    printf("=== STAGELESS ===\n");
    printf("1. Payload complet inclus (~500+ bytes)\n");
    printf("2. Autonome, pas besoin de C2\n");
    printf("3. Plus gros mais plus fiable\n");
    
    return 0;
}
