/*
 * ============================================================================
 * LESSON 04 : Allocation dynamique - malloc et free
 * ============================================================================
 *
 * OBJECTIF : Allouer de la memoire pendant l'execution
 * PREREQUIS : Lessons 01-03
 * COMPILE  : cl 04-malloc-free.c
 *
 * ============================================================================
 * POURQUOI L'ALLOCATION DYNAMIQUE ?
 *
 * Probleme : les tableaux ont une taille FIXE a la compilation
 *   int tab[100];  // Toujours 100, meme si on en utilise 3
 *
 * Solution : demander de la memoire AU MOMENT OU ON EN A BESOIN
 *   int* tab = malloc(n * sizeof(int));  // n decide a l'execution
 *
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>  // Pour malloc, free, realloc
#include <string.h>  // Pour memset

int main()
{
    printf("=== ALLOCATION DYNAMIQUE ===\n\n");

    // ========================================================================
    // PARTIE 1 : STACK VS HEAP
    // ========================================================================

    printf("--- PARTIE 1 : Stack vs Heap ---\n\n");

    // STACK (pile) : variables locales, taille fixe, automatique
    int stack_var = 42;
    int stack_array[10];

    printf("Variable stack : %p\n", &stack_var);
    printf("Tableau stack  : %p\n", stack_array);

    // HEAP (tas) : allocation dynamique, taille variable, manuel
    int* heap_var = malloc(sizeof(int));
    int* heap_array = malloc(10 * sizeof(int));

    printf("Variable heap  : %p\n", heap_var);
    printf("Tableau heap   : %p\n", heap_array);

    // Remarque : les adresses heap sont tres differentes des stack


    // ========================================================================
    // PARTIE 2 : MALLOC - Allouer de la memoire
    // ========================================================================

    printf("\n--- PARTIE 2 : malloc ---\n\n");

    // malloc(taille_en_bytes) retourne un pointeur vers la memoire allouee
    // Retourne NULL si l'allocation echoue

    int n = 5;
    int* tableau = malloc(n * sizeof(int));

    // TOUJOURS verifier si malloc a reussi !
    if (tableau == NULL)
    {
        printf("Erreur : allocation echouee !\n");
        return 1;
    }

    printf("Alloue %zu bytes pour %d entiers\n", n * sizeof(int), n);
    printf("Adresse : %p\n", tableau);

    // Utiliser comme un tableau normal
    for (int i = 0; i < n; i++)
    {
        tableau[i] = (i + 1) * 10;
    }

    printf("Contenu : ");
    for (int i = 0; i < n; i++)
    {
        printf("%d ", tableau[i]);
    }
    printf("\n");


    // ========================================================================
    // PARTIE 3 : CALLOC - Allouer et initialiser a zero
    // ========================================================================

    printf("\n--- PARTIE 3 : calloc ---\n\n");

    // calloc(nombre, taille_element) = malloc + memset(0)
    // La memoire est initialisee a zero

    int* zeros = calloc(5, sizeof(int));

    if (zeros == NULL)
    {
        printf("Erreur : allocation echouee !\n");
        free(tableau);
        return 1;
    }

    printf("calloc : ");
    for (int i = 0; i < 5; i++)
    {
        printf("%d ", zeros[i]);  // Tout est 0
    }
    printf("(initialise a zero)\n");


    // ========================================================================
    // PARTIE 4 : FREE - Liberer la memoire
    // ========================================================================

    printf("\n--- PARTIE 4 : free ---\n\n");

    // TRES IMPORTANT : liberer la memoire quand on n'en a plus besoin
    // Sinon = MEMORY LEAK (fuite memoire)

    free(tableau);
    free(zeros);

    printf("Memoire liberee.\n");

    // Apres free, le pointeur contient encore l'ancienne adresse
    // Mais cette memoire n'est plus valide !

    // Bonne pratique : mettre le pointeur a NULL apres free
    tableau = NULL;
    zeros = NULL;


    // ========================================================================
    // PARTIE 5 : REALLOC - Redimensionner
    // ========================================================================

    printf("\n--- PARTIE 5 : realloc ---\n\n");

    // realloc permet d'agrandir ou reduire une allocation

    int* data = malloc(3 * sizeof(int));
    data[0] = 1;
    data[1] = 2;
    data[2] = 3;

    printf("Avant realloc (%zu bytes) : ", 3 * sizeof(int));
    for (int i = 0; i < 3; i++) printf("%d ", data[i]);
    printf("\n");

    // Agrandir a 6 elements
    int* new_data = realloc(data, 6 * sizeof(int));

    if (new_data == NULL)
    {
        printf("Erreur realloc !\n");
        free(data);
        return 1;
    }

    data = new_data;  // Peut avoir change d'adresse !

    // Les nouvelles cases ne sont PAS initialisees
    data[3] = 4;
    data[4] = 5;
    data[5] = 6;

    printf("Apres realloc (%zu bytes) : ", 6 * sizeof(int));
    for (int i = 0; i < 6; i++) printf("%d ", data[i]);
    printf("\n");

    free(data);


    // ========================================================================
    // PARTIE 6 : ERREURS COURANTES
    // ========================================================================

    printf("\n--- PARTIE 6 : Erreurs courantes ---\n\n");

    printf("1. Oublier de free() = memory leak\n");
    printf("2. free() deux fois = crash (double free)\n");
    printf("3. Utiliser apres free() = undefined behavior (use after free)\n");
    printf("4. Depasser la taille allouee = buffer overflow\n");
    printf("5. Ne pas verifier si malloc retourne NULL\n");


    // ========================================================================
    // PARTIE 7 : EXEMPLE MALDEV - Buffer pour shellcode
    // ========================================================================

    printf("\n--- PARTIE 7 : Exemple maldev ---\n\n");

    // Simuler l'allocation pour un shellcode
    size_t shellcode_size = 256;

    unsigned char* shellcode = malloc(shellcode_size);
    if (!shellcode)
    {
        printf("Allocation failed\n");
        return 1;
    }

    // Remplir avec des NOP (0x90)
    memset(shellcode, 0x90, shellcode_size);

    // Ajouter INT3 a la fin (breakpoint)
    shellcode[shellcode_size - 1] = 0xCC;

    printf("Shellcode buffer alloue : %zu bytes\n", shellcode_size);
    printf("Premier byte : 0x%02X (NOP)\n", shellcode[0]);
    printf("Dernier byte : 0x%02X (INT3)\n", shellcode[shellcode_size - 1]);

    free(shellcode);
    shellcode = NULL;

    printf("\nMemoire nettoyee.\n");

    // Liberation des allocations du debut
    free(heap_var);
    free(heap_array);

    return 0;
}

/*
 * ============================================================================
 * RESUME :
 *
 * malloc(size)           -> alloue size bytes, non initialise
 * calloc(n, size)        -> alloue n*size bytes, initialise a 0
 * realloc(ptr, new_size) -> redimensionne l'allocation
 * free(ptr)              -> libere la memoire
 *
 * REGLES D'OR :
 * 1. Toujours verifier si malloc/calloc retourne NULL
 * 2. Toujours free() ce qu'on a malloc()
 * 3. Mettre le pointeur a NULL apres free()
 * 4. Ne jamais utiliser un pointeur apres free()
 *
 * ============================================================================
 * MALDEV USAGE :
 *
 * 1. Allouer un buffer pour shellcode :
 *    LPVOID buffer = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_RWX);
 *    // VirtualAlloc = version Windows de malloc avec controle des permissions
 *
 * 2. Buffer pour donnees recues du C2 :
 *    char* data = malloc(content_length);
 *    recv(socket, data, content_length, 0);
 *
 * 3. Construire des structures dynamiquement :
 *    CONFIG* cfg = malloc(sizeof(CONFIG));
 *    cfg->server = strdup("evil.com");
 *
 * ============================================================================
 */
