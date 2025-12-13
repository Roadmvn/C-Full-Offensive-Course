/*
 * ⚠️ AVERTISSEMENT : Code éducatif avec vulnérabilités INTENTIONNELLES
 * Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.
 *
 * Démonstration de vulnérabilités format string.
 * Compilation : gcc -fno-stack-protector -no-pie -Wno-format-security example.c -o example
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int secret = 0xDEADBEEF;
char global_buffer[64] = "SECRET_FLAG{format_str1ng}";

void demo_leak_stack() {
    printf("\n=== Démonstration 1 : Leak de la stack ===\n");
    char input[100];
    
    printf("Entrez format string (ex: %%x %%x %%x) : ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    
    printf("Output : ");
    printf(input);  // VULNÉRABLE
    printf("\n");
}

void demo_leak_memory() {
    printf("\n=== Démonstration 2 : Leak de mémoire ===\n");
    char input[100];
    
    printf("Adresse de secret : %p (valeur: 0x%x)\n", &secret, secret);
    printf("Adresse de global_buffer : %p\n", global_buffer);
    
    printf("\nEntrez format string : ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    
    printf(input);  // VULNÉRABLE
    printf("\n");
}

void demo_write_memory() {
    printf("\n=== Démonstration 3 : Écriture en mémoire avec %%n ===\n");
    
    int target = 0;
    char input[200];
    
    printf("target avant : %d\n", target);
    printf("Adresse de target : %p\n", &target);
    
    printf("\nEntrez format string (utilise %%n) : ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    
    printf(input);  // VULNÉRABLE
    printf("\n");
    
    printf("target après : %d\n", target);
}

void vulnerable_printf() {
    printf("\n=== Programme vulnérable ===\n");
    char buffer[200];
    
    printf("Entrez votre nom : ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    
    printf("Bonjour ");
    printf(buffer);  // VULNÉRABLE
    printf("!\n");
}

int main() {
    int choice;
    char input[16];

    printf("⚠️  CODE ÉDUCATIF - FORMAT STRING VULNÉRABLE\n");
    printf("Compilation : gcc -Wno-format-security example.c -o example\n\n");

    while (1) {
        printf("\n1. Leak stack\n2. Leak memory\n3. Write with %%n\n");
        printf("4. Vulnerable printf\n0. Quit\nChoix : ");

        if (fgets(input, sizeof(input), stdin) == NULL) break;
        choice = atoi(input);

        switch (choice) {
            case 1: demo_leak_stack(); break;
            case 2: demo_leak_memory(); break;
            case 3: demo_write_memory(); break;
            case 4: vulnerable_printf(); break;
            case 0: return 0;
            default: printf("Choix invalide.\n");
        }
    }
    return 0;
}
