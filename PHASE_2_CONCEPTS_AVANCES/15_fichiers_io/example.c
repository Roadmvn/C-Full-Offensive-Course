#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Structure pour démonstration fichier binaire
typedef struct {
    char nom[50];
    int age;
    float salaire;
} Employe;

int main() {
    printf("=== Manipulation de Fichiers en C ===\n\n");

    // 1. Écriture texte simple
    printf("1. Écriture dans un fichier texte:\n");
    FILE *fichier = fopen("exemple.txt", "w");

    if (fichier == NULL) {
        printf("Erreur d'ouverture en écriture\n");
        return 1;
    }

    fprintf(fichier, "Première ligne\n");
    fprintf(fichier, "Deuxième ligne\n");
    fprintf(fichier, "Troisième ligne\n");

    fclose(fichier);
    printf("Fichier 'exemple.txt' créé\n\n");

    // 2. Lecture texte ligne par ligne
    printf("2. Lecture du fichier:\n");
    fichier = fopen("exemple.txt", "r");

    if (fichier == NULL) {
        printf("Erreur d'ouverture en lecture\n");
        return 1;
    }

    char ligne[256];
    int numero_ligne = 1;
    while (fgets(ligne, sizeof(ligne), fichier)) {
        printf("Ligne %d: %s", numero_ligne, ligne);
        numero_ligne++;
    }
    printf("\n");

    fclose(fichier);

    // 3. Append (ajout à la fin)
    printf("3. Ajout à la fin du fichier (mode 'a'):\n");
    fichier = fopen("exemple.txt", "a");

    if (fichier == NULL) {
        printf("Erreur d'ouverture en append\n");
        return 1;
    }

    fprintf(fichier, "Ligne ajoutée\n");
    fprintf(fichier, "Encore une ligne\n");

    fclose(fichier);
    printf("Lignes ajoutées\n\n");

    // 4. Lecture caractère par caractère
    printf("4. Lecture caractère par caractère:\n");
    fichier = fopen("exemple.txt", "r");

    if (fichier == NULL) return 1;

    int compteur = 0;
    int c;
    while ((c = fgetc(fichier)) != EOF) {
        compteur++;
    }

    fclose(fichier);
    printf("Le fichier contient %d caractères\n\n", compteur);

    // 5. Fichier binaire - écriture
    printf("5. Écriture fichier binaire:\n");
    Employe employes[3] = {
        {"Alice Dupont", 30, 45000.0},
        {"Bob Martin", 25, 38000.0},
        {"Charlie Durand", 35, 52000.0}
    };

    FILE *fichier_bin = fopen("employes.dat", "wb");

    if (fichier_bin == NULL) {
        printf("Erreur création fichier binaire\n");
        return 1;
    }

    size_t written = fwrite(employes, sizeof(Employe), 3, fichier_bin);
    fclose(fichier_bin);

    printf("%zu employés écrits dans 'employes.dat'\n\n", written);

    // 6. Fichier binaire - lecture
    printf("6. Lecture fichier binaire:\n");
    fichier_bin = fopen("employes.dat", "rb");

    if (fichier_bin == NULL) {
        printf("Erreur lecture fichier binaire\n");
        return 1;
    }

    Employe employes_lus[3];
    size_t read_count = fread(employes_lus, sizeof(Employe), 3, fichier_bin);
    fclose(fichier_bin);

    printf("%zu employés lus:\n", read_count);
    for (int i = 0; i < 3; i++) {
        printf("%d. %s - %d ans - %.2f€\n",
               i+1, employes_lus[i].nom,
               employes_lus[i].age, employes_lus[i].salaire);
    }
    printf("\n");

    // 7. Vérifier si un fichier existe
    printf("7. Vérifier existence d'un fichier:\n");
    FILE *test = fopen("fichier_inexistant.txt", "r");

    if (test == NULL) {
        printf("Le fichier n'existe pas\n");
    } else {
        printf("Le fichier existe\n");
        fclose(test);
    }
    printf("\n");

    // 8. Position dans le fichier (fseek/ftell)
    printf("8. Navigation dans un fichier:\n");
    fichier = fopen("exemple.txt", "r");

    if (fichier == NULL) return 1;

    // Aller à la fin
    fseek(fichier, 0, SEEK_END);
    long taille = ftell(fichier);
    printf("Taille du fichier: %ld bytes\n", taille);

    // Retour au début
    fseek(fichier, 0, SEEK_SET);
    char premiere_ligne[256];
    fgets(premiere_ligne, sizeof(premiere_ligne), fichier);
    printf("Première ligne: %s\n", premiere_ligne);

    fclose(fichier);

    // 9. Copie de fichier
    printf("9. Copie de fichier:\n");
    FILE *source = fopen("exemple.txt", "r");
    FILE *destination = fopen("copie.txt", "w");

    if (source == NULL || destination == NULL) {
        printf("Erreur lors de la copie\n");
        if (source) fclose(source);
        if (destination) fclose(destination);
        return 1;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), source)) {
        fputs(buffer, destination);
    }

    fclose(source);
    fclose(destination);
    printf("Fichier copié vers 'copie.txt'\n\n");

    // 10. Suppression de fichier
    printf("10. Suppression de fichiers temporaires:\n");
    if (remove("copie.txt") == 0) {
        printf("'copie.txt' supprimé\n");
    }
    if (remove("employes.dat") == 0) {
        printf("'employes.dat' supprimé\n");
    }

    printf("\n=== Programme terminé ===\n");
    printf("Fichier 'exemple.txt' conservé pour inspection\n");

    return 0;
}
