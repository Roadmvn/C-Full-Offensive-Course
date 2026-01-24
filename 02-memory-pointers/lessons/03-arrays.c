/*
 * ============================================================================
 * LESSON 03 : Tableaux et pointeurs
 * ============================================================================
 *
 * OBJECTIF : Comprendre la relation entre tableaux et pointeurs
 * PREREQUIS : Lessons 01-02
 * COMPILE  : cl 03-arrays.c
 *
 * ============================================================================
 * CONCEPT CLE :
 *
 * En C, un tableau EST (presque) un pointeur vers son premier element.
 * Cette equivalence est fondamentale pour comprendre le C bas niveau.
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    printf("=== TABLEAUX ET POINTEURS ===\n\n");

    // ========================================================================
    // PARTIE 1 : TABLEAU = POINTEUR VERS PREMIER ELEMENT
    // ========================================================================

    printf("--- PARTIE 1 : Equivalence tableau/pointeur ---\n\n");

    int tab[5] = {10, 20, 30, 40, 50};

    // Le nom du tableau EST l'adresse du premier element
    printf("tab      = %p\n", tab);
    printf("&tab[0]  = %p\n", &tab[0]);
    printf("Egal ? %s\n", (tab == &tab[0]) ? "OUI" : "NON");

    printf("\n");

    // On peut assigner un tableau a un pointeur
    int* ptr = tab;  // Pas besoin de & car tab est deja une adresse

    printf("ptr      = %p\n", ptr);
    printf("*ptr     = %d (premier element)\n", *ptr);


    // ========================================================================
    // PARTIE 2 : NOTATION [] VS *
    // ========================================================================

    printf("\n--- PARTIE 2 : Notations equivalentes ---\n\n");

    // Ces deux notations sont STRICTEMENT equivalentes
    printf("tab[0] = %d    |    *tab = %d\n", tab[0], *tab);
    printf("tab[1] = %d    |    *(tab+1) = %d\n", tab[1], *(tab+1));
    printf("tab[2] = %d    |    *(tab+2) = %d\n", tab[2], *(tab+2));

    // En fait, tab[i] est syntaxiquement transforme en *(tab + i)

    // Et meme... ca marche dans l'autre sens !
    printf("\n2[tab] = %d (bizarre mais valide !)\n", 2[tab]);
    // Car 2[tab] = *(2 + tab) = *(tab + 2) = tab[2]


    // ========================================================================
    // PARTIE 3 : DIFFERENCE TABLEAU VS POINTEUR
    // ========================================================================

    printf("\n--- PARTIE 3 : Differences ---\n\n");

    // DIFFERENCE 1 : sizeof

    printf("sizeof(tab) = %zu (taille totale du tableau)\n", sizeof(tab));
    printf("sizeof(ptr) = %zu (taille d'un pointeur)\n", sizeof(ptr));

    // Le tableau "connait" sa taille, le pointeur non

    // Nombre d'elements :
    int nb_elements = sizeof(tab) / sizeof(tab[0]);
    printf("Nombre d'elements = %d\n", nb_elements);


    // DIFFERENCE 2 : On ne peut pas reassigner un tableau

    // tab = ptr;  // ERREUR ! tab n'est pas modifiable
    ptr = tab;     // OK, ptr peut pointer ailleurs


    // ========================================================================
    // PARTIE 4 : TABLEAUX DE BYTES (pour shellcode)
    // ========================================================================

    printf("\n--- PARTIE 4 : Tableau de bytes ---\n\n");

    // En maldev, on manipule souvent des tableaux de bytes
    unsigned char shellcode[] = {0x90, 0x90, 0x90, 0xCC, 0xC3};
    //                           NOP   NOP   NOP   INT3  RET

    printf("Shellcode (%zu bytes) :\n", sizeof(shellcode));

    for (int i = 0; i < sizeof(shellcode); i++)
    {
        printf("  [%d] 0x%02X\n", i, shellcode[i]);
    }

    // Manipulation via pointeur
    unsigned char* sc_ptr = shellcode;

    printf("\nVia pointeur :\n");
    printf("  Premier byte : 0x%02X\n", *sc_ptr);
    printf("  Dernier byte : 0x%02X\n", *(sc_ptr + sizeof(shellcode) - 1));


    // ========================================================================
    // PARTIE 5 : TABLEAUX 2D
    // ========================================================================

    printf("\n--- PARTIE 5 : Tableaux 2D ---\n\n");

    int matrice[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };

    printf("Matrice 3x4 :\n");
    for (int i = 0; i < 3; i++)
    {
        printf("  ");
        for (int j = 0; j < 4; j++)
        {
            printf("%3d ", matrice[i][j]);
        }
        printf("\n");
    }

    // En memoire, c'est stocke de facon CONTIGUE (ligne par ligne)
    printf("\nEn memoire (continu) :\n  ");

    int* flat = (int*)matrice;  // Cast en pointeur simple
    for (int i = 0; i < 12; i++)
    {
        printf("%d ", flat[i]);
    }
    printf("\n");

    // matrice[i][j] = *(*(matrice + i) + j)
    // Ou simplement : matrice[i][j] = flat[i * 4 + j]


    // ========================================================================
    // PARTIE 6 : PASSER UN TABLEAU A UNE FONCTION
    // ========================================================================

    printf("\n--- PARTIE 6 : Tableaux et fonctions ---\n\n");

    // Quand on passe un tableau a une fonction, on passe son ADRESSE
    // Le tableau "decay" en pointeur

    void afficher_tableau(int* arr, int taille);  // Declaration

    printf("Appel de fonction :\n");
    afficher_tableau(tab, 5);

    // ATTENTION : dans la fonction, sizeof(arr) = sizeof(int*)
    // On doit TOUJOURS passer la taille separement !


    return 0;
}

// Fonction qui recoit un tableau (= pointeur)
void afficher_tableau(int* arr, int taille)
{
    printf("  Dans la fonction : ");
    for (int i = 0; i < taille; i++)
    {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

/*
 * ============================================================================
 * RESUME :
 *
 * EQUIVALENCES :
 *   tab[i]     ==  *(tab + i)
 *   &tab[i]    ==  tab + i
 *   tab        ==  &tab[0]
 *
 * DIFFERENCES :
 *   sizeof(tableau)  = taille totale
 *   sizeof(pointeur) = taille d'une adresse (8 bytes sur 64-bit)
 *
 *   tableau = ...;   // INTERDIT
 *   pointeur = ...;  // OK
 *
 * ============================================================================
 * MALDEV USAGE :
 *
 * 1. Shellcode stocke dans un tableau :
 *    unsigned char sc[] = "\x90\x90\xCC\xC3";
 *    void (*func)() = (void(*)())sc;
 *    func();  // Execute le shellcode
 *
 * 2. Buffer pour donnees recues :
 *    char buffer[4096];
 *    recv(socket, buffer, sizeof(buffer), 0);
 *
 * 3. Parsing de structures en memoire :
 *    BYTE data[] = { ... };
 *    HEADER* hdr = (HEADER*)data;
 *
 * ============================================================================
 */
