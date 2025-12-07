/*
 * ⚠️ AVERTISSEMENT : Code éducatif avec vulnérabilités INTENTIONNELLES
 * Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.
 *
 * Démonstration d'exploitation du heap.
 * Compilation : gcc example.c -o example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void demo_use_after_free() {
    printf("\n=== Démonstration : Use-After-Free ===\n");
    
    char *ptr1 = malloc(100);
    strcpy(ptr1, "Données originales");
    printf("ptr1 : %s\n", ptr1);
    
    free(ptr1);
    printf("ptr1 libéré.\n");
    
    // Réallocation
    char *ptr2 = malloc(100);
    strcpy(ptr2, "Nouvelles données");
    printf("ptr2 (même adresse?) : %s\n", ptr2);
    
    // UAF : utilisation de ptr1 après free
    printf("ptr1 (UAF) : %s\n", ptr1);  // VULNÉRABLE
    
    free(ptr2);
}

void demo_double_free() {
    printf("\n=== Démonstration : Double-Free ===\n");
    
    char *ptr = malloc(100);
    strcpy(ptr, "Data");
    printf("Alloué : %s\n", ptr);
    
    free(ptr);
    printf("Libéré une fois.\n");
    
    // VULNÉRABLE : double-free crash ou corruption
    printf("Tentative de double-free...\n");
    // free(ptr);  // Décommente pour crash
    printf("(Double-free commenté pour éviter le crash)\n");
}

void demo_heap_overflow() {
    printf("\n=== Démonstration : Heap Overflow ===\n");
    
    char *buf1 = malloc(64);
    char *buf2 = malloc(64);
    
    strcpy(buf1, "Buffer 1");
    strcpy(buf2, "Buffer 2");
    
    printf("buf1 @ %p : %s\n", buf1, buf1);
    printf("buf2 @ %p : %s\n", buf2, buf2);
    
    // Overflow de buf1 vers buf2
    memset(buf1, 'A', 128);  // VULNÉRABLE
    
    printf("\nAprès overflow:\n");
    printf("buf1 : %.64s\n", buf1);
    printf("buf2 : %.64s\n", buf2);
    
    free(buf1);
    free(buf2);
}

int main() {
    int choice;
    char input[16];

    printf("⚠️  CODE ÉDUCATIF - HEAP EXPLOITATION\n\n");

    while (1) {
        printf("\n1. Use-After-Free\n2. Double-Free\n3. Heap Overflow\n0. Quit\nChoix : ");

        if (fgets(input, sizeof(input), stdin) == NULL) break;
        choice = atoi(input);

        switch (choice) {
            case 1: demo_use_after_free(); break;
            case 2: demo_double_free(); break;
            case 3: demo_heap_overflow(); break;
            case 0: return 0;
            default: printf("Choix invalide.\n");
        }
    }
    return 0;
}
