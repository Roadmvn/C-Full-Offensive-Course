#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("=== Malloc et Free - Allocation Dynamique ===\n\n");

    // 1. malloc basique
    printf("1. malloc() basique:\n");
    int *ptr = malloc(sizeof(int));
    if (ptr == NULL) {
        printf("Erreur d'allocation\n");
        return 1;
    }
    *ptr = 42;
    printf("Valeur allouée: %d\n", *ptr);
    printf("Adresse: %p\n\n", (void*)ptr);
    free(ptr);

    // 2. malloc pour un tableau
    printf("2. Tableau dynamique:\n");
    int taille = 10;
    int *tableau = malloc(taille * sizeof(int));

    if (tableau == NULL) {
        printf("Erreur d'allocation\n");
        return 1;
    }

    for (int i = 0; i < taille; i++) {
        tableau[i] = i * i;
    }

    printf("Tableau: ");
    for (int i = 0; i < taille; i++) {
        printf("%d ", tableau[i]);
    }
    printf("\n\n");
    free(tableau);

    // 3. calloc (initialise à zéro)
    printf("3. calloc() - Initialisation à zéro:\n");
    int *tab_zero = calloc(5, sizeof(int));

    if (tab_zero == NULL) {
        printf("Erreur d'allocation\n");
        return 1;
    }

    printf("Contenu après calloc: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", tab_zero[i]);
    }
    printf("\n\n");
    free(tab_zero);

    // 4. realloc (redimensionner)
    printf("4. realloc() - Redimensionnement:\n");
    int *dynamic = malloc(3 * sizeof(int));
    if (dynamic == NULL) return 1;

    for (int i = 0; i < 3; i++) {
        dynamic[i] = i + 1;
    }

    printf("Avant realloc (3 éléments): ");
    for (int i = 0; i < 3; i++) {
        printf("%d ", dynamic[i]);
    }
    printf("\n");

    // Agrandir à 6 éléments
    int *temp = realloc(dynamic, 6 * sizeof(int));
    if (temp == NULL) {
        free(dynamic);
        return 1;
    }
    dynamic = temp;

    for (int i = 3; i < 6; i++) {
        dynamic[i] = i + 1;
    }

    printf("Après realloc (6 éléments): ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", dynamic[i]);
    }
    printf("\n\n");
    free(dynamic);

    // 5. Allocation de chaîne dynamique
    printf("5. Chaîne de caractères dynamique:\n");
    char *message = malloc(50 * sizeof(char));
    if (message == NULL) return 1;

    strcpy(message, "Bonjour le monde!");
    printf("Message: %s\n", message);
    printf("Taille allouée: 50 bytes\n\n");
    free(message);

    // 6. Tableau de pointeurs (tableau de chaînes)
    printf("6. Tableau de chaînes dynamique:\n");
    int nb_noms = 4;
    char **noms = malloc(nb_noms * sizeof(char*));
    if (noms == NULL) return 1;

    noms[0] = malloc(20 * sizeof(char));
    noms[1] = malloc(20 * sizeof(char));
    noms[2] = malloc(20 * sizeof(char));
    noms[3] = malloc(20 * sizeof(char));

    strcpy(noms[0], "Alice");
    strcpy(noms[1], "Bob");
    strcpy(noms[2], "Charlie");
    strcpy(noms[3], "Diana");

    for (int i = 0; i < nb_noms; i++) {
        printf("%d. %s\n", i+1, noms[i]);
    }
    printf("\n");

    // Libération en ordre inverse
    for (int i = 0; i < nb_noms; i++) {
        free(noms[i]);
    }
    free(noms);

    // 7. Vérification NULL
    printf("7. Gestion d'erreur:\n");
    int *test = malloc(0);  // Comportement dépend du système
    if (test == NULL) {
        printf("malloc(0) a retourné NULL\n");
    } else {
        printf("malloc(0) a retourné une adresse: %p\n", (void*)test);
        free(test);
    }
    printf("\n");

    // 8. Memory leak évité
    printf("8. Éviter les memory leaks:\n");
    int *leak_test = malloc(100 * sizeof(int));
    if (leak_test == NULL) return 1;

    printf("Mémoire allouée: %zu bytes\n", 100 * sizeof(int));
    printf("IMPORTANT: Toujours free() ce que vous malloc()\n");
    free(leak_test);
    leak_test = NULL;  // Bonne pratique
    printf("Mémoire libérée et pointeur mis à NULL\n\n");

    // 9. Stack vs Heap
    printf("9. Stack vs Heap:\n");
    int stack_var = 42;  // Sur la stack
    int *heap_var = malloc(sizeof(int));  // Sur le heap
    if (heap_var == NULL) return 1;
    *heap_var = 42;

    printf("Variable stack: %d (adresse: %p)\n", stack_var, (void*)&stack_var);
    printf("Variable heap: %d (adresse: %p)\n", *heap_var, (void*)heap_var);
    printf("La stack est souvent à des adresses plus hautes\n");
    free(heap_var);

    printf("\n=== Programme terminé sans memory leaks ===\n");
    return 0;
}
