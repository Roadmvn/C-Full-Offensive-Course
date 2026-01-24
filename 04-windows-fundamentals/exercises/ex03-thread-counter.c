/*
 * EXERCICE 03: Thread Counter
 *
 * OBJECTIF:
 * Creer 3 threads qui incrementent chacun un compteur global,
 * puis afficher le resultat final.
 *
 * TACHES:
 * 1. Declarer un compteur global initialise a 0
 * 2. Creer une fonction thread qui incremente le compteur 1000 fois
 * 3. Lancer 3 threads qui executent cette fonction
 * 4. Attendre que tous les threads se terminent
 * 5. Afficher la valeur finale du compteur
 * 6. Verifier si le resultat est correct (3000)
 *
 * BONUS:
 * - Augmenter le nombre d'iterations pour observer les race conditions
 * - Ajouter un ID unique a chaque thread
 * - Afficher des messages pendant l'execution de chaque thread
 * - Mesurer le temps d'execution total
 */

#include <windows.h>
#include <stdio.h>

// TODO: Declarer le compteur global


// TODO: Fonction thread qui incremente le compteur
DWORD WINAPI increment_counter(LPVOID lpParam) {
    // TODO: Recuperer l'ID du thread passe en parametre


    // TODO: Boucle pour incrementer le compteur N fois


    // TODO: Retourner 0
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         EXERCICE 03: COMPTEUR AVEC 3 THREADS             ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    // TODO: Definir le nombre de threads et d'iterations


    // TODO: Declarer un tableau de handles de threads


    // TODO: Declarer un tableau d'IDs pour les threads


    // TODO: Creer les threads dans une boucle


    // TODO: Afficher un message indiquant que les threads sont lances


    // TODO: Attendre que tous les threads se terminent (WaitForMultipleObjects)


    // TODO: Afficher la valeur finale du compteur


    // TODO: Verifier si le resultat est correct


    // TODO: Fermer tous les handles


    printf("\n[*] Programme termine\n");
    return 0;
}

/*
 * CONSEILS:
 *
 * 1. Compteur global:
 *    int global_counter = 0;
 *
 * 2. Fonction thread:
 *    DWORD WINAPI thread_func(LPVOID lpParam) {
 *        int id = *(int*)lpParam;
 *        for (int i = 0; i < 1000; i++) {
 *            global_counter++;
 *        }
 *        return 0;
 *    }
 *
 * 3. Creer thread:
 *    threads[i] = CreateThread(
 *        NULL, 0,
 *        thread_func,
 *        &threadIDs[i],
 *        0, NULL
 *    );
 *
 * 4. Attendre tous:
 *    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
 *
 * 5. Race condition:
 *    Si le resultat n'est pas 3000, c'est une race condition!
 *    Plusieurs threads modifient la meme variable simultanement.
 */
