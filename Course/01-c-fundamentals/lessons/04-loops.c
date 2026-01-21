/*
 * ============================================================================
 * LESSON 04 : Boucles - Repeter des actions
 * ============================================================================
 *
 * OBJECTIF : Faire repeter des instructions sans copier-coller
 * PREREQUIS : Lesson 03 (If/Else)
 * COMPILE  : cl 04-loops.c
 *
 * ============================================================================
 * ANALOGIE ENFANT 5 ANS :
 *
 * Imagine que tu dois colorier 10 cases :
 *
 * SANS boucle : "colorie case 1, colorie case 2, colorie case 3..."
 *               (tu dois ecrire 10 fois la meme chose)
 *
 * AVEC boucle : "repete 10 fois : colorie la case suivante"
 *               (une seule instruction, executee 10 fois)
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    // ========================================================================
    // PARTIE 1 : LA BOUCLE FOR (quand on connait le nombre de repetitions)
    // ========================================================================

    printf("=== BOUCLE FOR ===\n\n");

    // Structure :
    // for (initialisation; condition; increment) { instructions }
    //
    // 1. initialisation : execute UNE fois au debut
    // 2. condition : testee AVANT chaque tour
    // 3. increment : execute APRES chaque tour

    printf("Compter de 1 a 5 :\n");

    for (int i = 1; i <= 5; i++)
    {
        printf("  Tour numero %d\n", i);
    }

    // Deroulement :
    // i = 1 -> 1 <= 5 ? OUI -> affiche "Tour 1" -> i++ -> i = 2
    // i = 2 -> 2 <= 5 ? OUI -> affiche "Tour 2" -> i++ -> i = 3
    // i = 3 -> 3 <= 5 ? OUI -> affiche "Tour 3" -> i++ -> i = 4
    // i = 4 -> 4 <= 5 ? OUI -> affiche "Tour 4" -> i++ -> i = 5
    // i = 5 -> 5 <= 5 ? OUI -> affiche "Tour 5" -> i++ -> i = 6
    // i = 6 -> 6 <= 5 ? NON -> FIN DE BOUCLE


    printf("\nCompter de 10 a 0 (decompte) :\n");

    for (int i = 10; i >= 0; i--)
    {
        printf("  %d...\n", i);
    }
    printf("  DECOLLAGE !\n");


    printf("\nCompter de 2 en 2 :\n");

    for (int i = 0; i <= 10; i += 2)  // i += 2 au lieu de i++
    {
        printf("  %d\n", i);
    }


    // ========================================================================
    // PARTIE 2 : LA BOUCLE WHILE (tant que...)
    // ========================================================================

    printf("\n=== BOUCLE WHILE ===\n\n");

    // Structure :
    // while (condition) { instructions }
    //
    // Tant que la condition est vraie, on repete
    // ATTENTION : il faut modifier la condition dans la boucle !

    printf("Diviser par 2 jusqu'a 1 :\n");

    int nombre = 128;

    while (nombre > 1)
    {
        printf("  %d\n", nombre);
        nombre = nombre / 2;  // IMPORTANT : modifie la condition
    }
    printf("  %d (fin)\n", nombre);

    // Si on oublie de modifier 'nombre', boucle INFINIE !


    printf("\nSimulation de mot de passe (max 3 essais) :\n");

    int essais = 0;
    int max_essais = 3;
    int mot_de_passe = 1234;
    int saisie = 0000;  // Simule une mauvaise saisie

    while (essais < max_essais && saisie != mot_de_passe)
    {
        essais++;
        printf("  Essai %d/%d : ", essais, max_essais);

        // En vrai on lirait l'entree utilisateur, ici on simule
        if (essais == 3)
        {
            saisie = 1234;  // Bon mot de passe au 3eme essai
            printf("1234 -> CORRECT !\n");
        }
        else
        {
            saisie = 0000;
            printf("0000 -> Incorrect\n");
        }
    }


    // ========================================================================
    // PARTIE 3 : DO...WHILE (faire au moins une fois)
    // ========================================================================

    printf("\n=== BOUCLE DO...WHILE ===\n\n");

    // Structure :
    // do { instructions } while (condition);
    //
    // Difference avec while :
    // - while : teste AVANT -> peut ne jamais executer
    // - do...while : teste APRES -> execute au moins UNE fois

    printf("Menu (do...while) :\n");

    int choix = 0;
    int tour = 0;

    do
    {
        tour++;
        printf("  [Tour %d] Choix (1-3, 0 pour quitter) : ", tour);

        // Simulation : on quitte au 3eme tour
        if (tour == 3)
        {
            choix = 0;
            printf("0\n");
        }
        else
        {
            choix = tour;
            printf("%d\n", choix);
        }

    } while (choix != 0);  // ATTENTION au point-virgule !

    printf("  Sorti du menu.\n");


    // ========================================================================
    // PARTIE 4 : BREAK ET CONTINUE
    // ========================================================================

    printf("\n=== BREAK ET CONTINUE ===\n\n");

    // break : sort IMMEDIATEMENT de la boucle
    // continue : saute au tour SUIVANT

    printf("Break (sortir si on trouve 5) :\n");

    for (int i = 1; i <= 10; i++)
    {
        if (i == 5)
        {
            printf("  Trouve 5 ! On sort.\n");
            break;  // Sort de la boucle
        }
        printf("  %d\n", i);
    }


    printf("\nContinue (sauter les multiples de 3) :\n");

    for (int i = 1; i <= 10; i++)
    {
        if (i % 3 == 0)  // Si i est multiple de 3
        {
            continue;  // Saute au tour suivant
        }
        printf("  %d\n", i);
    }


    // ========================================================================
    // PARTIE 5 : BOUCLES IMBRIQUEES
    // ========================================================================

    printf("\n=== BOUCLES IMBRIQUEES ===\n\n");

    printf("Table de multiplication (1-3) :\n\n");

    for (int i = 1; i <= 3; i++)
    {
        for (int j = 1; j <= 3; j++)
        {
            printf("  %d x %d = %d\n", i, j, i * j);
        }
        printf("\n");  // Ligne vide entre chaque table
    }


    return 0;
}

/*
 * ============================================================================
 * RESUME :
 *
 * FOR : Quand on sait combien de fois repeter
 *       for (int i = 0; i < N; i++) { ... }
 *
 * WHILE : Tant qu'une condition est vraie
 *         while (condition) { ... }
 *
 * DO...WHILE : Au moins une fois, puis tant que...
 *              do { ... } while (condition);
 *
 * BREAK : Sort de la boucle immediatement
 * CONTINUE : Passe au tour suivant
 *
 * ============================================================================
 * PIEGES :
 *
 * 1. Boucle infinie :
 *    while (1) { }  // Tourne pour toujours !
 *    for (;;) { }   // Pareil
 *
 * 2. Oublier d'incrementer dans while :
 *    int i = 0;
 *    while (i < 5) { printf("%d", i); }  // i ne change jamais = infini
 *
 * 3. Mauvaise condition de fin :
 *    for (int i = 0; i <= 10; i++)  // 11 tours (0 a 10 inclus)
 *    for (int i = 0; i < 10; i++)   // 10 tours (0 a 9)
 *
 * ============================================================================
 */
