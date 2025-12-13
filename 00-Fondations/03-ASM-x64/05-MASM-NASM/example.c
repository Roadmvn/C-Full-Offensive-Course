/**
 * Exemple : Appeler du code NASM depuis C
 * 
 * 1. Créer add.asm avec la fonction add_numbers
 * 2. nasm -f elf64 add.asm -o add.o
 * 3. gcc example.c add.o -o example
 */

#include <stdio.h>

// Déclaration de la fonction assembleur externe
extern int add_numbers(int a, int b);

/*
 * Contenu de add.asm :
 * 
 * section .text
 * global add_numbers
 * 
 * add_numbers:
 *     mov eax, edi
 *     add eax, esi
 *     ret
 */

int main(void) {
    // Exemple d'appel si add.asm est linké
    // int result = add_numbers(5, 3);
    // printf("5 + 3 = %d\n", result);
    
    printf("Voir les commentaires pour l'exemple NASM\n");
    return 0;
}
