/*
 * ============================================================================
 * LESSON 02 : Arithmetique des pointeurs
 * ============================================================================
 *
 * OBJECTIF : Naviguer en memoire avec les pointeurs
 * PREREQUIS : Lesson 01 (pointeurs basics)
 * COMPILE  : cl 02-pointer-arithmetic.c
 *
 * ============================================================================
 * ANALOGIE :
 *
 * Imagine une rue avec des maisons numerotees :
 * - Maison 100, 101, 102, 103...
 *
 * Si tu es a la maison 100 et tu fais "+1", tu vas a 101
 * MAIS en C, ca depend de la TAILLE de ce que tu pointes !
 *
 * Si chaque "maison" fait 4 metres (int = 4 bytes) :
 *   pointeur + 1 = adresse + 4 bytes
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    printf("=== ARITHMETIQUE DES POINTEURS ===\n\n");

    // ========================================================================
    // PARTIE 1 : TAILLE DES TYPES
    // ========================================================================

    printf("--- PARTIE 1 : Taille des types ---\n\n");

    printf("sizeof(char)   = %zu bytes\n", sizeof(char));    // 1
    printf("sizeof(short)  = %zu bytes\n", sizeof(short));   // 2
    printf("sizeof(int)    = %zu bytes\n", sizeof(int));     // 4
    printf("sizeof(float)  = %zu bytes\n", sizeof(float));   // 4
    printf("sizeof(double) = %zu bytes\n", sizeof(double));  // 8
    printf("sizeof(void*)  = %zu bytes\n", sizeof(void*));   // 8 (64-bit)

    // Quand tu fais ptr + 1, le compilateur ajoute sizeof(*ptr) bytes


    // ========================================================================
    // PARTIE 2 : POINTEUR + 1
    // ========================================================================

    printf("\n--- PARTIE 2 : Pointeur + 1 ---\n\n");

    int tableau[] = {10, 20, 30, 40, 50};
    int* ptr = tableau;  // Pointe vers le premier element

    printf("Tableau : ");
    for (int i = 0; i < 5; i++)
    {
        printf("%d ", tableau[i]);
    }
    printf("\n\n");

    // ptr pointe vers tableau[0]
    printf("ptr       = %p -> valeur = %d\n", ptr, *ptr);

    // ptr + 1 pointe vers tableau[1]
    printf("ptr + 1   = %p -> valeur = %d\n", ptr + 1, *(ptr + 1));

    // ptr + 2 pointe vers tableau[2]
    printf("ptr + 2   = %p -> valeur = %d\n", ptr + 2, *(ptr + 2));

    // Remarque les adresses : elles augmentent de 4 bytes (sizeof(int))


    // ========================================================================
    // PARTIE 3 : PARCOURIR AVEC UN POINTEUR
    // ========================================================================

    printf("\n--- PARTIE 3 : Parcours avec pointeur ---\n\n");

    printf("Parcours classique (index) :\n");
    for (int i = 0; i < 5; i++)
    {
        printf("  tableau[%d] = %d\n", i, tableau[i]);
    }

    printf("\nParcours avec pointeur :\n");
    int* p = tableau;
    for (int i = 0; i < 5; i++)
    {
        printf("  *(p + %d) = %d\n", i, *(p + i));
    }

    printf("\nParcours avec increment :\n");
    p = tableau;  // Reset au debut
    for (int i = 0; i < 5; i++)
    {
        printf("  *p = %d (adresse %p)\n", *p, p);
        p++;  // Avance au prochain element
    }

    // IMPORTANT : tableau[i] est equivalent a *(tableau + i)


    // ========================================================================
    // PARTIE 4 : DIFFERENCE ENTRE POINTEURS
    // ========================================================================

    printf("\n--- PARTIE 4 : Difference ---\n\n");

    int* debut = &tableau[0];
    int* fin = &tableau[4];

    // La difference donne le NOMBRE D'ELEMENTS, pas de bytes
    printf("debut = %p\n", debut);
    printf("fin   = %p\n", fin);
    printf("fin - debut = %td elements\n", fin - debut);  // 4

    // Pour avoir la difference en bytes :
    printf("Difference en bytes = %td\n", (char*)fin - (char*)debut);


    // ========================================================================
    // PARTIE 5 : COMPARAISON DE POINTEURS
    // ========================================================================

    printf("\n--- PARTIE 5 : Comparaison ---\n\n");

    int* a = &tableau[1];
    int* b = &tableau[3];

    if (a < b)
    {
        printf("a (%p) est AVANT b (%p) en memoire\n", a, b);
    }

    // Utile pour verifier qu'on ne depasse pas la fin d'un buffer


    // ========================================================================
    // PARTIE 6 : ATTENTION AUX TYPES
    // ========================================================================

    printf("\n--- PARTIE 6 : Types differents ---\n\n");

    char str[] = "HELLO";
    char* pc = str;

    printf("String : %s\n\n", str);

    // Avec char*, +1 ajoute 1 byte (sizeof(char) = 1)
    for (int i = 0; i < 5; i++)
    {
        printf("  pc + %d = %p -> '%c'\n", i, pc + i, *(pc + i));
    }

    // Compare avec int* : +1 ajoute 4 bytes
    // C'est pour ca que le TYPE du pointeur est important !


    return 0;
}

/*
 * ============================================================================
 * RESUME :
 *
 * ptr + n   -> avance de n * sizeof(*ptr) bytes
 * ptr - n   -> recule de n * sizeof(*ptr) bytes
 * ptr++     -> avance d'un element
 * ptr--     -> recule d'un element
 *
 * ptr1 - ptr2 -> nombre d'elements entre les deux
 *
 * EQUIVALENCES :
 *   tableau[i]    ==  *(tableau + i)
 *   &tableau[i]   ==  tableau + i
 *
 * ============================================================================
 * MALDEV USAGE :
 *
 * Arithmetique de pointeurs = essentiel pour :
 *
 * 1. Parser des headers binaires (PE, ELF)
 *    BYTE* base = ...;
 *    DWORD offset = header->e_lfanew;
 *    NT_HEADERS* nt = (NT_HEADERS*)(base + offset);
 *
 * 2. Parcourir du shellcode
 *    BYTE* shellcode = ...;
 *    for (int i = 0; i < len; i++)
 *        shellcode[i] ^= key;  // XOR decode
 *
 * 3. Manipulation de memoire
 *    memcpy(dest, src, len);  // Copie byte par byte
 *
 * ============================================================================
 */
