#include <stdio.h>
#include <string.h>

// Fonction qui inverse un tableau avec l'arithmétique de pointeurs
void inverser_tableau(int *debut, int *fin) {
    while (debut < fin) {
        int temp = *debut;
        *debut = *fin;
        *fin = temp;
        debut++;
        fin--;
    }
}

// Fonction qui recherche un élément dans un tableau
int* chercher(int *tableau, int taille, int valeur) {
    int *ptr = tableau;
    int *fin = tableau + taille;

    while (ptr < fin) {
        if (*ptr == valeur) {
            return ptr;  // Retourne l'adresse de l'élément trouvé
        }
        ptr++;
    }
    return NULL;  // Élément non trouvé
}

int main() {
    printf("=== Arithmétique de Pointeurs ===\n\n");

    // 1. Addition et soustraction
    int tab[5] = {10, 20, 30, 40, 50};
    int *ptr = tab;

    printf("Tableau initial: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", tab[i]);
    }
    printf("\n\n");

    printf("Parcours avec arithmétique:\n");
    printf("*ptr = %d (adresse: %p)\n", *ptr, (void*)ptr);
    printf("*(ptr+1) = %d (adresse: %p)\n", *(ptr+1), (void*)(ptr+1));
    printf("*(ptr+2) = %d (adresse: %p)\n", *(ptr+2), (void*)(ptr+2));
    printf("*(ptr+4) = %d (adresse: %p)\n", *(ptr+4), (void*)(ptr+4));
    printf("\n");

    // 2. Incrémentation et décrémentation
    printf("=== Incrémentation de Pointeurs ===\n\n");
    ptr = tab;
    printf("Parcours avec ptr++:\n");
    for (int i = 0; i < 5; i++) {
        printf("*ptr = %d\n", *ptr);
        ptr++;
    }
    printf("\n");

    // 3. Différence entre deux pointeurs
    int *debut = &tab[0];
    int *fin = &tab[4];
    printf("=== Différence de Pointeurs ===\n");
    printf("Adresse debut: %p\n", (void*)debut);
    printf("Adresse fin: %p\n", (void*)fin);
    printf("Différence (fin - debut): %ld éléments\n", fin - debut);
    printf("Différence en bytes: %ld bytes\n\n", (char*)fin - (char*)debut);

    // 4. Relation tableau et pointeur
    printf("=== Équivalences Tableau/Pointeur ===\n");
    printf("tab[2] = %d\n", tab[2]);
    printf("*(tab+2) = %d\n", *(tab+2));
    printf("2[tab] = %d (syntaxe bizarre mais valide!)\n\n", 2[tab]);

    // 5. Pointeurs de pointeurs
    printf("=== Pointeurs de Pointeurs ===\n\n");
    int valeur = 42;
    int *ptr1 = &valeur;
    int **ptr2 = &ptr1;
    int ***ptr3 = &ptr2;

    printf("Valeur originale: %d\n", valeur);
    printf("Via ptr1: %d\n", *ptr1);
    printf("Via ptr2: %d\n", **ptr2);
    printf("Via ptr3: %d\n\n", ***ptr3);

    printf("Adresses:\n");
    printf("&valeur = %p\n", (void*)&valeur);
    printf("ptr1 = %p (pointe vers valeur)\n", (void*)ptr1);
    printf("&ptr1 = %p\n", (void*)&ptr1);
    printf("ptr2 = %p (pointe vers ptr1)\n", (void*)ptr2);
    printf("&ptr2 = %p\n", (void*)&ptr2);
    printf("ptr3 = %p (pointe vers ptr2)\n\n", (void*)ptr3);

    // 6. Tableau de pointeurs
    printf("=== Tableau de Pointeurs ===\n\n");
    char *noms[] = {
        "Alice",
        "Bob",
        "Charlie",
        "Diana"
    };

    int nb_noms = sizeof(noms) / sizeof(noms[0]);
    printf("Liste de noms:\n");
    for (int i = 0; i < nb_noms; i++) {
        printf("%d. %s (adresse du pointeur: %p)\n",
               i+1, noms[i], (void*)&noms[i]);
    }
    printf("\n");

    // 7. Fonction avec pointeurs
    printf("=== Inversion de Tableau ===\n");
    int nombres[6] = {1, 2, 3, 4, 5, 6};

    printf("Avant inversion: ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", nombres[i]);
    }
    printf("\n");

    inverser_tableau(nombres, nombres + 5);

    printf("Après inversion: ");
    for (int i = 0; i < 6; i++) {
        printf("%d ", nombres[i]);
    }
    printf("\n\n");

    // 8. Recherche avec retour de pointeur
    printf("=== Recherche dans un Tableau ===\n");
    int data[] = {15, 23, 8, 42, 16, 4, 99};
    int taille = sizeof(data) / sizeof(data[0]);

    int valeur_cherchee = 42;
    int *resultat = chercher(data, taille, valeur_cherchee);

    if (resultat != NULL) {
        printf("Trouvé %d à l'adresse %p\n", valeur_cherchee, (void*)resultat);
        printf("Index dans le tableau: %ld\n", resultat - data);
    } else {
        printf("%d non trouvé\n", valeur_cherchee);
    }
    printf("\n");

    // 9. Tableau 2D et pointeurs
    printf("=== Tableau 2D ===\n");
    int matrice[3][3] = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9}
    };

    // Accès via pointeur
    int *ptr_mat = (int*)matrice;
    printf("Parcours linéaire de la matrice:\n");
    for (int i = 0; i < 9; i++) {
        printf("%d ", *(ptr_mat + i));
        if ((i + 1) % 3 == 0) printf("\n");
    }
    printf("\n");

    // 10. Comparaison de pointeurs
    printf("=== Comparaison de Pointeurs ===\n");
    int arr[] = {5, 10, 15, 20, 25};
    int *p1 = &arr[1];
    int *p2 = &arr[3];

    if (p1 < p2) {
        printf("p1 est avant p2 en mémoire\n");
    }
    if (p2 > p1) {
        printf("p2 est après p1 en mémoire\n");
    }
    printf("Distance: %ld éléments\n", p2 - p1);

    return 0;
}
