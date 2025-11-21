#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 1. Structure basique
struct Point {
    int x;
    int y;
};

// 2. Structure avec typedef
typedef struct {
    char nom[50];
    int age;
    float salaire;
} Employe;

// 3. Structure avec pointeur
typedef struct {
    char titre[100];
    char auteur[50];
    int annee;
    float prix;
} Livre;

// 4. Structure imbriquée
typedef struct {
    char rue[100];
    char ville[50];
    int code_postal;
} Adresse;

typedef struct {
    char nom[50];
    int age;
    Adresse adresse;  // Structure dans une structure
} Personne;

// 5. Structure avec tableau
typedef struct {
    char nom[50];
    int notes[5];
    float moyenne;
} Etudiant;

// Fonction qui calcule la moyenne
void calculer_moyenne(Etudiant *e) {
    int somme = 0;
    for (int i = 0; i < 5; i++) {
        somme += e->notes[i];
    }
    e->moyenne = somme / 5.0;
}

// Fonction qui affiche un point
void afficher_point(struct Point p) {
    printf("Point(%d, %d)\n", p.x, p.y);
}

// Fonction avec pointeur vers structure
void vieillir(Personne *p, int annees) {
    p->age += annees;
}

int main() {
    printf("=== Structures en C ===\n\n");

    // 1. Structure basique
    printf("1. Structure basique:\n");
    struct Point p1;
    p1.x = 10;
    p1.y = 20;
    printf("p1: ");
    afficher_point(p1);

    struct Point p2 = {30, 40};  // Initialisation directe
    printf("p2: ");
    afficher_point(p2);
    printf("\n");

    // 2. Typedef
    printf("2. Avec typedef:\n");
    Employe emp1;
    strcpy(emp1.nom, "Alice Dupont");
    emp1.age = 30;
    emp1.salaire = 45000.0;

    printf("Employé: %s\n", emp1.nom);
    printf("Age: %d ans\n", emp1.age);
    printf("Salaire: %.2f€\n\n", emp1.salaire);

    // 3. Pointeur vers structure
    printf("3. Pointeur vers structure:\n");
    Livre livre1;
    strcpy(livre1.titre, "Le Seigneur des Anneaux");
    strcpy(livre1.auteur, "J.R.R. Tolkien");
    livre1.annee = 1954;
    livre1.prix = 25.99;

    Livre *ptr_livre = &livre1;
    printf("Titre: %s\n", ptr_livre->titre);
    printf("Auteur: %s\n", ptr_livre->auteur);
    printf("Année: %d\n", ptr_livre->annee);
    printf("Prix: %.2f€\n\n", ptr_livre->prix);

    // 4. Structure imbriquée
    printf("4. Structure imbriquée:\n");
    Personne personne1;
    strcpy(personne1.nom, "Bob Martin");
    personne1.age = 25;
    strcpy(personne1.adresse.rue, "123 Rue de la Paix");
    strcpy(personne1.adresse.ville, "Paris");
    personne1.adresse.code_postal = 75001;

    printf("Nom: %s\n", personne1.nom);
    printf("Age: %d ans\n", personne1.age);
    printf("Adresse: %s, %s %d\n\n",
           personne1.adresse.rue,
           personne1.adresse.ville,
           personne1.adresse.code_postal);

    // 5. Fonction modifiant une structure
    printf("5. Modification via fonction:\n");
    printf("Avant: %s a %d ans\n", personne1.nom, personne1.age);
    vieillir(&personne1, 5);
    printf("Après vieillissement: %s a %d ans\n\n", personne1.nom, personne1.age);

    // 6. Tableau dans structure
    printf("6. Tableau dans structure:\n");
    Etudiant etudiant1;
    strcpy(etudiant1.nom, "Charlie Brown");
    etudiant1.notes[0] = 15;
    etudiant1.notes[1] = 17;
    etudiant1.notes[2] = 14;
    etudiant1.notes[3] = 16;
    etudiant1.notes[4] = 18;

    calculer_moyenne(&etudiant1);

    printf("Étudiant: %s\n", etudiant1.nom);
    printf("Notes: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", etudiant1.notes[i]);
    }
    printf("\nMoyenne: %.2f\n\n", etudiant1.moyenne);

    // 7. Tableau de structures
    printf("7. Tableau de structures:\n");
    Employe equipe[3] = {
        {"Alice", 30, 45000},
        {"Bob", 25, 38000},
        {"Charlie", 35, 52000}
    };

    printf("Équipe:\n");
    for (int i = 0; i < 3; i++) {
        printf("%d. %s - %d ans - %.0f€\n",
               i+1, equipe[i].nom, equipe[i].age, equipe[i].salaire);
    }
    printf("\n");

    // 8. Allocation dynamique de structure
    printf("8. Allocation dynamique:\n");
    Livre *livre_dynamic = malloc(sizeof(Livre));
    if (livre_dynamic == NULL) {
        printf("Erreur d'allocation\n");
        return 1;
    }

    strcpy(livre_dynamic->titre, "1984");
    strcpy(livre_dynamic->auteur, "George Orwell");
    livre_dynamic->annee = 1949;
    livre_dynamic->prix = 15.50;

    printf("Livre alloué dynamiquement:\n");
    printf("Titre: %s\n", livre_dynamic->titre);
    printf("Auteur: %s\n", livre_dynamic->auteur);

    free(livre_dynamic);
    printf("Mémoire libérée\n\n");

    // 9. Copie de structure
    printf("9. Copie de structure:\n");
    struct Point original = {100, 200};
    struct Point copie = original;  // Copie membre par membre

    printf("Original: ");
    afficher_point(original);
    printf("Copie: ");
    afficher_point(copie);

    copie.x = 999;
    printf("Après modification de la copie:\n");
    printf("Original: ");
    afficher_point(original);
    printf("Copie: ");
    afficher_point(copie);
    printf("\n");

    // 10. sizeof structure
    printf("10. Taille des structures:\n");
    printf("sizeof(struct Point): %zu bytes\n", sizeof(struct Point));
    printf("sizeof(Employe): %zu bytes\n", sizeof(Employe));
    printf("sizeof(Livre): %zu bytes\n", sizeof(Livre));
    printf("sizeof(Personne): %zu bytes\n", sizeof(Personne));

    return 0;
}
