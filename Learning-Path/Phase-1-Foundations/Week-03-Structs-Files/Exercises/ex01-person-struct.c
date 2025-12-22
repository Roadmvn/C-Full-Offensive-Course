/*
 * =============================================================================
 * EXERCICE 01 : CRÉER UNE STRUCTURE PERSONNE
 * =============================================================================
 *
 * OBJECTIF :
 *   Pratiquer la création et manipulation de structures.
 *   Créer une structure Person avec plusieurs membres et des fonctions
 *   pour l'afficher et la modifier.
 *
 * INSTRUCTIONS :
 *   1. Complète la structure Person avec les membres demandés
 *   2. Implémente les fonctions printPerson() et updateAge()
 *   3. Crée un tableau de 3 personnes
 *   4. Affiche toutes les personnes
 *   5. Modifie l'âge d'une personne via pointeur
 *   6. Affiche à nouveau pour voir le changement
 *
 * COMPILATION :
 *   cl ex01-person-struct.c
 *   .\ex01-person-struct.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <string.h>

/*
 * =============================================================================
 * TODO 1 : Compléter la structure Person
 * =============================================================================
 *
 * Ajoute les membres suivants :
 * - char prenom[50]      : Prénom de la personne
 * - char nom[50]         : Nom de famille
 * - int age              : Age en années
 * - float taille         : Taille en mètres
 * - int estActif         : 1 si actif, 0 sinon (comme un booléen)
 */

typedef struct {
    char prenom[50];
    char nom[50];
    int age;
    float taille;
    int estActif;
} Person;

/*
 * =============================================================================
 * TODO 2 : Implémenter la fonction printPerson
 * =============================================================================
 *
 * Cette fonction doit afficher toutes les informations d'une personne.
 *
 * Format attendu :
 *   [Actif] Prenom Nom - 25 ans - 1.75m
 * ou
 *   [Inactif] Prenom Nom - 30 ans - 1.68m
 *
 * ASTUCE : Utilise p->membre pour accéder aux membres via pointeur
 */

void printPerson(Person* p) {
    // Ta solution ici :
    printf("   [%s] %s %s - %d ans - %.2fm\n",
           p->estActif ? "Actif" : "Inactif",
           p->prenom,
           p->nom,
           p->age,
           p->taille);
}

/*
 * =============================================================================
 * TODO 3 : Implémenter la fonction updateAge
 * =============================================================================
 *
 * Cette fonction doit modifier l'âge d'une personne.
 *
 * ASTUCE : Comme c'est un pointeur, la modification sera permanente !
 */

void updateAge(Person* p, int newAge) {
    // Ta solution ici :
    p->age = newAge;
    printf("   Age de %s mis a jour : %d -> %d ans\n",
           p->prenom, p->age - (newAge - p->age), newAge);
}

/*
 * =============================================================================
 * TODO 4 : Implémenter la fonction findOldest
 * =============================================================================
 *
 * Cette fonction doit trouver la personne la plus âgée dans un tableau.
 * Retourne un pointeur vers la personne la plus âgée.
 *
 * ASTUCE :
 * - Parcours le tableau
 * - Compare les âges
 * - Garde un pointeur vers la personne la plus âgée
 */

Person* findOldest(Person* people, int count) {
    // Ta solution ici :
    Person* oldest = &people[0];

    for (int i = 1; i < count; i++) {
        if (people[i].age > oldest->age) {
            oldest = &people[i];
        }
    }

    return oldest;
}

/*
 * =============================================================================
 * TODO 5 : Implémenter la fonction countActive
 * =============================================================================
 *
 * Cette fonction doit compter le nombre de personnes actives.
 *
 * ASTUCE : Parcours le tableau et compte celles où estActif == 1
 */

int countActive(Person* people, int count) {
    // Ta solution ici :
    int activeCount = 0;

    for (int i = 0; i < count; i++) {
        if (people[i].estActif == 1) {
            activeCount++;
        }
    }

    return activeCount;
}

/*
 * =============================================================================
 * FONCTION MAIN : TESTS
 * =============================================================================
 */

int main() {
    printf("=== EXERCICE 01 : STRUCTURE PERSONNE ===\n\n");

    // -------------------------------------------------------------------------
    // TEST 1 : Créer un tableau de 3 personnes
    // -------------------------------------------------------------------------
    printf("[1] Creation du tableau de personnes\n");

    Person equipe[3] = {
        {"Alice", "Dupont", 25, 1.65f, 1},
        {"Bob", "Martin", 32, 1.78f, 1},
        {"Charlie", "Bernard", 28, 1.72f, 0}
    };

    printf("   3 personnes creees\n\n");

    // -------------------------------------------------------------------------
    // TEST 2 : Afficher toutes les personnes
    // -------------------------------------------------------------------------
    printf("[2] Affichage de toutes les personnes\n");

    for (int i = 0; i < 3; i++) {
        printf("   [%d] ", i);
        printPerson(&equipe[i]);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 3 : Modifier l'âge via pointeur
    // -------------------------------------------------------------------------
    printf("[3] Modification de l'age d'Alice\n");

    Person* ptrAlice = &equipe[0];
    updateAge(ptrAlice, 26);
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 4 : Afficher après modification
    // -------------------------------------------------------------------------
    printf("[4] Affichage apres modification\n");

    printf("   ");
    printPerson(&equipe[0]);
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 5 : Trouver la personne la plus âgée
    // -------------------------------------------------------------------------
    printf("[5] Recherche de la personne la plus agee\n");

    Person* oldest = findOldest(equipe, 3);
    printf("   Personne la plus agee : %s %s (%d ans)\n\n",
           oldest->prenom, oldest->nom, oldest->age);

    // -------------------------------------------------------------------------
    // TEST 6 : Compter les personnes actives
    // -------------------------------------------------------------------------
    printf("[6] Comptage des personnes actives\n");

    int activeCount = countActive(equipe, 3);
    printf("   Nombre de personnes actives : %d / 3\n\n", activeCount);

    // -------------------------------------------------------------------------
    // TEST 7 : Modifier le statut actif
    // -------------------------------------------------------------------------
    printf("[7] Activation de Charlie\n");

    equipe[2].estActif = 1;
    printf("   ");
    printPerson(&equipe[2]);
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 8 : Recompter les actifs
    // -------------------------------------------------------------------------
    printf("[8] Recomptage des personnes actives\n");

    activeCount = countActive(equipe, 3);
    printf("   Nombre de personnes actives : %d / 3\n\n", activeCount);

    /*
     * =========================================================================
     * DÉFI BONUS (OPTIONNEL) :
     * =========================================================================
     *
     * 1. Ajoute une fonction calculateAverageHeight() qui calcule la taille
     *    moyenne de toutes les personnes.
     *
     * 2. Ajoute une fonction sortByAge() qui trie le tableau par âge
     *    (du plus jeune au plus âgé).
     *
     * 3. Ajoute un champ "char email[100]" à la structure Person et modifie
     *    les fonctions en conséquence.
     *
     * 4. Crée une fonction savePerson() qui sauvegarde une Person dans un
     *    fichier binaire.
     *
     * =========================================================================
     */

    printf("=== EXERCICE 01 TERMINE ===\n");
    printf("Bravo ! Tu maitrises les structures !\n");
    printf("Passe maintenant a ex02-config-parser.c\n");

    return 0;
}

/*
 * =============================================================================
 * NOTES POUR L'APPRENTISSAGE :
 * =============================================================================
 *
 * 1. STRUCTURES = Grouper des données liées
 *    - Plus facile à maintenir qu'un tas de variables séparées
 *    - Permet de passer toutes les infos d'un coup à une fonction
 *
 * 2. POINTEURS VERS STRUCTURES :
 *    - Très courant en C
 *    - Évite de copier toute la structure (plus rapide)
 *    - Permet de modifier la structure originale
 *
 * 3. ACCÈS AUX MEMBRES :
 *    - Avec variable : person.age
 *    - Avec pointeur : person->age (équivalent à (*person).age)
 *
 * 4. TABLEAUX DE STRUCTURES :
 *    - Très utile pour gérer des collections
 *    - Exemple : liste de processus, liste de threads, etc.
 *
 * 5. MALDEV :
 *    - En maldev, on manipule BEAUCOUP de structures
 *    - Exemple : PROCESS_INFORMATION, STARTUPINFO, etc.
 *    - Comprendre les structures est ESSENTIEL !
 *
 * =============================================================================
 */
