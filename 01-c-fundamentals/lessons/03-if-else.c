/*
 * ============================================================================
 * LESSON 03 : If/Else - Prendre des decisions
 * ============================================================================
 *
 * OBJECTIF : Faire executer du code selon des conditions
 * PREREQUIS : Lesson 02 (Variables)
 * COMPILE  : cl 03-if-else.c
 *
 * ============================================================================
 * ANALOGIE ENFANT 5 ANS :
 *
 * C'est comme un carrefour avec des panneaux :
 *
 * SI (if) il pleut :
 *     -> Prendre le parapluie
 * SINON (else) :
 *     -> Mettre les lunettes de soleil
 *
 * L'ordinateur ne fait qu'UN seul chemin, jamais les deux !
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    // ========================================================================
    // PARTIE 1 : IF SIMPLE
    // ========================================================================

    printf("=== IF SIMPLE ===\n\n");

    int age = 20;

    // Structure : if (condition) { instructions }
    // La condition est VRAIE ou FAUSSE

    if (age >= 18)
    {
        printf("Tu es majeur !\n");
        printf("Tu peux voter.\n");
    }

    // Les instructions dans { } ne s'executent QUE si la condition est vraie
    // Si age = 15, rien ne s'affiche


    // ========================================================================
    // PARTIE 2 : LES OPERATEURS DE COMPARAISON
    // ========================================================================

    printf("\n=== OPERATEURS DE COMPARAISON ===\n\n");

    int a = 10;
    int b = 20;

    // ==  : egal a (ATTENTION : deux signes =)
    // !=  : different de
    // >   : superieur a
    // <   : inferieur a
    // >=  : superieur ou egal
    // <=  : inferieur ou egal

    printf("a = %d, b = %d\n\n", a, b);

    if (a == b)  printf("a == b : VRAI\n");
    if (a != b)  printf("a != b : VRAI\n");
    if (a > b)   printf("a > b  : VRAI\n");
    if (a < b)   printf("a < b  : VRAI\n");
    if (a >= 10) printf("a >= 10: VRAI\n");
    if (b <= 20) printf("b <= 20: VRAI\n");

    // PIEGE MORTEL : Ecrire = au lieu de ==
    // if (a = 5) -> ASSIGNE 5 a 'a' et est toujours VRAI !
    // if (a == 5) -> COMPARE a avec 5


    // ========================================================================
    // PARTIE 3 : IF / ELSE
    // ========================================================================

    printf("\n=== IF / ELSE ===\n\n");

    int temperature = 15;

    if (temperature > 25)
    {
        printf("Il fait chaud ! Mets un t-shirt.\n");
    }
    else
    {
        printf("Il fait frais. Prends une veste.\n");
    }

    // L'ordinateur execute SOIT le bloc if, SOIT le bloc else
    // Jamais les deux, jamais aucun des deux


    // ========================================================================
    // PARTIE 4 : IF / ELSE IF / ELSE (plusieurs conditions)
    // ========================================================================

    printf("\n=== IF / ELSE IF / ELSE ===\n\n");

    int note = 75;

    printf("Note : %d/100\n", note);

    if (note >= 90)
    {
        printf("Grade : A - Excellent !\n");
    }
    else if (note >= 80)
    {
        printf("Grade : B - Tres bien\n");
    }
    else if (note >= 70)
    {
        printf("Grade : C - Bien\n");
    }
    else if (note >= 60)
    {
        printf("Grade : D - Passable\n");
    }
    else
    {
        printf("Grade : F - Echec\n");
    }

    // L'ordinateur teste les conditions DE HAUT EN BAS
    // Il s'arrete a la PREMIERE condition vraie
    // Si aucune n'est vraie, il execute le bloc else final


    // ========================================================================
    // PARTIE 5 : COMBINER LES CONDITIONS (ET, OU)
    // ========================================================================

    printf("\n=== COMBINER CONDITIONS ===\n\n");

    int heure = 14;
    int jour_semaine = 1;  // 1 = Lundi, 7 = Dimanche

    // && = ET (les deux conditions doivent etre vraies)
    if (heure >= 9 && heure <= 18)
    {
        printf("C'est les heures de bureau (9h-18h)\n");
    }

    // || = OU (au moins une condition doit etre vraie)
    if (jour_semaine == 6 || jour_semaine == 7)
    {
        printf("C'est le weekend !\n");
    }
    else
    {
        printf("C'est un jour de semaine.\n");
    }

    // ! = NON (inverse la condition)
    int est_connecte = 0;  // 0 = faux, 1 = vrai

    if (!est_connecte)  // Si PAS connecte
    {
        printf("Tu dois te connecter.\n");
    }


    // ========================================================================
    // PARTIE 6 : CONDITIONS IMBRIQUEES
    // ========================================================================

    printf("\n=== CONDITIONS IMBRIQUEES ===\n\n");

    int age_utilisateur = 25;
    int a_permis = 1;  // 1 = vrai

    if (age_utilisateur >= 18)
    {
        printf("Tu es majeur.\n");

        if (a_permis)
        {
            printf("Tu peux conduire !\n");
        }
        else
        {
            printf("Tu dois passer le permis.\n");
        }
    }
    else
    {
        printf("Tu es mineur. Attends encore %d ans.\n", 18 - age_utilisateur);
    }


    return 0;
}

/*
 * ============================================================================
 * RESUME :
 *
 * Structure de base :
 *
 *     if (condition) {
 *         // Code si VRAI
 *     } else {
 *         // Code si FAUX
 *     }
 *
 * Operateurs :
 *     ==  egal            !=  different
 *     >   superieur       <   inferieur
 *     >=  sup ou egal     <=  inf ou egal
 *     &&  ET              ||  OU
 *     !   NON
 *
 * ============================================================================
 * VALEURS VRAIES ET FAUSSES EN C :
 *
 * FAUX = 0 (zero)
 * VRAI = tout ce qui n'est pas 0 (1, -5, 42, etc.)
 *
 * C'est pourquoi :
 *     if (x)   signifie "si x est different de 0"
 *     if (!x)  signifie "si x est egal a 0"
 *
 * ============================================================================
 */
