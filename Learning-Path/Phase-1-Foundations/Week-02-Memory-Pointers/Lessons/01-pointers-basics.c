/*
 * ============================================================================
 * LESSON 01 : Pointeurs - Les adresses memoire
 * ============================================================================
 *
 * OBJECTIF : Comprendre ce qu'est un pointeur et comment l'utiliser
 * PREREQUIS : Semaine 1 (variables, fonctions)
 * COMPILE  : cl 01-pointers-basics.c
 *
 * ============================================================================
 * ANALOGIE ENFANT 5 ANS :
 *
 * Imagine un grand immeuble avec des appartements :
 * - Chaque appartement a un NUMERO (adresse)
 * - Chaque appartement contient quelque chose (valeur)
 *
 * Une VARIABLE = un appartement avec son contenu
 * Un POINTEUR = un papier avec le numero d'un appartement ecrit dessus
 *
 * Avec le pointeur, tu peux :
 * - Savoir ou est l'appartement (l'adresse)
 * - Aller voir ce qu'il y a dedans (la valeur)
 * - Changer ce qu'il y a dedans !
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    printf("=== POINTEURS - LES BASES ===\n\n");

    // ========================================================================
    // PARTIE 1 : ADRESSE D'UNE VARIABLE
    // ========================================================================

    printf("--- PARTIE 1 : Adresses ---\n\n");

    int age = 25;

    // Chaque variable a une ADRESSE en memoire
    // L'operateur & ("adresse de") donne cette adresse

    printf("Valeur de age    : %d\n", age);
    printf("Adresse de age   : %p\n", &age);  // %p = pointer format

    // L'adresse est un nombre hexadecimal (ex: 0x7ffd5c8b3a4c)
    // C'est l'emplacement en RAM ou est stockee la variable


    // ========================================================================
    // PARTIE 2 : DECLARER UN POINTEUR
    // ========================================================================

    printf("\n--- PARTIE 2 : Declaration ---\n\n");

    // Un pointeur est une variable qui STOCKE UNE ADRESSE
    // Syntaxe : type* nom;
    //           Le * indique "pointeur vers"

    int* ptr;      // ptr est un "pointeur vers int"
                   // Il peut stocker l'adresse d'un int

    ptr = &age;    // ptr contient maintenant l'adresse de age

    printf("age vaut         : %d\n", age);
    printf("&age (adresse)   : %p\n", &age);
    printf("ptr contient     : %p\n", ptr);    // Meme adresse !
    printf("ptr pointe vers  : %d\n", *ptr);   // Valeur a cette adresse

    // * devant un pointeur = "valeur a cette adresse" (dereferencement)


    // ========================================================================
    // PARTIE 3 : MODIFIER VIA LE POINTEUR
    // ========================================================================

    printf("\n--- PARTIE 3 : Modification ---\n\n");

    printf("Avant : age = %d\n", age);

    *ptr = 30;  // Change la valeur A L'ADRESSE pointee

    printf("Apres *ptr = 30 : age = %d\n", age);

    // On a modifie 'age' sans utiliser directement 'age' !
    // C'est le pouvoir des pointeurs


    // ========================================================================
    // PARTIE 4 : POURQUOI C'EST UTILE ?
    // ========================================================================

    printf("\n--- PARTIE 4 : Utilite ---\n\n");

    // Probleme : une fonction ne peut pas modifier une variable externe

    int nombre = 10;
    printf("Avant fonction : nombre = %d\n", nombre);

    // Si on passait 'nombre' directement, la fonction recoit une COPIE
    // Avec un pointeur, elle recoit L'ADRESSE = peut modifier l'original

    // Voir fonction ajouter_dix() ci-dessous


    // ========================================================================
    // PARTIE 5 : POINTEUR NULL
    // ========================================================================

    printf("\n--- PARTIE 5 : Pointeur NULL ---\n\n");

    int* ptr_null = NULL;  // Pointeur qui ne pointe vers rien

    printf("ptr_null = %p\n", ptr_null);  // Affiche 0 ou (nil)

    // TOUJOURS initialiser les pointeurs !
    // Un pointeur non initialise contient une adresse ALEATOIRE
    // = crash ou comportement imprevisible

    // Avant d'utiliser un pointeur, verifier qu'il n'est pas NULL :
    if (ptr_null != NULL)
    {
        printf("ptr_null pointe vers : %d\n", *ptr_null);
    }
    else
    {
        printf("ptr_null est NULL, on ne peut pas le dereferencer\n");
    }


    // ========================================================================
    // PARTIE 6 : RESUME VISUEL
    // ========================================================================

    printf("\n--- PARTIE 6 : Resume visuel ---\n\n");

    int x = 42;
    int* p = &x;

    printf("       VARIABLE          POINTEUR\n");
    printf("       ┌─────┐           ┌─────┐\n");
    printf("   x   │ %3d │  <──────  │  *  │  p\n", x);
    printf("       └─────┘           └─────┘\n");
    printf("       %p     %p\n", (void*)&x, (void*)&p);
    printf("\n");
    printf("   x   = %d (valeur)\n", x);
    printf("   &x  = %p (adresse de x)\n", &x);
    printf("   p   = %p (contenu de p = adresse de x)\n", p);
    printf("   *p  = %d (valeur a l'adresse stockee dans p)\n", *p);
    printf("   &p  = %p (adresse du pointeur lui-meme)\n", &p);


    return 0;
}

/*
 * ============================================================================
 * RESUME :
 *
 * OPERATEURS :
 *   &variable  -> donne l'ADRESSE de la variable
 *   *pointeur  -> donne la VALEUR a l'adresse (dereferencement)
 *
 * DECLARATION :
 *   int* ptr;     -> pointeur vers int
 *   float* ptr;   -> pointeur vers float
 *   char* ptr;    -> pointeur vers char
 *
 * INITIALISATION :
 *   ptr = &variable;  -> ptr pointe vers variable
 *   ptr = NULL;       -> ptr ne pointe vers rien (securite)
 *
 * UTILISATION :
 *   *ptr = 10;        -> modifie la valeur pointee
 *   x = *ptr;         -> lit la valeur pointee
 *
 * ============================================================================
 * MALDEV PREVIEW :
 *
 * En maldev, les pointeurs sont PARTOUT :
 * - Shellcode = tableau de bytes, manipule via pointeur
 * - VirtualAlloc retourne un pointeur vers la memoire allouee
 * - Les structures Windows sont manipulees via pointeurs
 * - Injection = ecrire a une adresse dans un autre processus
 *
 * ============================================================================
 */
