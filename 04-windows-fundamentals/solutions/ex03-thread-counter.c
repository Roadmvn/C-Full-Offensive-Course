/*
 * SOLUTION EXERCICE 03: Thread Counter
 */

#include <windows.h>
#include <stdio.h>

int global_counter = 0;

DWORD WINAPI increment_counter(LPVOID lpParam) {
    int id = *(int*)lpParam;

    printf("[Thread %d] Demarre (TID: %lu)\n", id, GetCurrentThreadId());

    for (int i = 0; i < 1000; i++) {
        global_counter++;

        if ((i + 1) % 250 == 0) {
            printf("[Thread %d] Progression: %d/1000\n", id, i + 1);
        }
    }

    printf("[Thread %d] Termine!\n", id);
    return 0;
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║       SOLUTION 03: COMPTEUR AVEC 3 THREADS               ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    const int NUM_THREADS = 3;
    const int ITERATIONS_PER_THREAD = 1000;

    HANDLE threads[NUM_THREADS];
    int threadIDs[NUM_THREADS];

    printf("[*] Configuration:\n");
    printf("    Nombre de threads: %d\n", NUM_THREADS);
    printf("    Iterations par thread: %d\n", ITERATIONS_PER_THREAD);
    printf("    Valeur attendue: %d\n\n", NUM_THREADS * ITERATIONS_PER_THREAD);

    printf("[*] Creation des threads...\n\n");

    DWORD startTime = GetTickCount();

    for (int i = 0; i < NUM_THREADS; i++) {
        threadIDs[i] = i + 1;

        threads[i] = CreateThread(
            NULL,
            0,
            increment_counter,
            &threadIDs[i],
            0,
            NULL
        );

        if (threads[i] == NULL) {
            printf("[-] Echec creation thread %d: %lu\n", i + 1, GetLastError());
            return 1;
        }

        printf("[Main] Thread %d cree\n", i + 1);
    }

    printf("\n[Main] Tous les threads sont lances!\n");
    printf("[Main] Attente de la fin de tous les threads...\n\n");

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    DWORD endTime = GetTickCount();
    DWORD elapsed = endTime - startTime;

    printf("\n[Main] Tous les threads sont termines!\n\n");

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║                      RESULTATS                            ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    printf("Valeur attendue: %d\n", NUM_THREADS * ITERATIONS_PER_THREAD);
    printf("Valeur obtenue:  %d\n", global_counter);
    printf("Difference:      %d\n\n", (NUM_THREADS * ITERATIONS_PER_THREAD) - global_counter);

    if (global_counter == NUM_THREADS * ITERATIONS_PER_THREAD) {
        printf("[+] RESULTAT CORRECT!\n");
        printf("    Par chance, aucune race condition cette fois.\n");
    } else {
        printf("[!] RACE CONDITION DETECTEE!\n");
        printf("    %d increments ont ete perdus!\n",
            (NUM_THREADS * ITERATIONS_PER_THREAD) - global_counter);
        printf("\n");
        printf("EXPLICATION:\n");
        printf("  L'operation 'global_counter++' n'est pas atomique:\n");
        printf("    1. Lire la valeur\n");
        printf("    2. Incrementer\n");
        printf("    3. Ecrire la nouvelle valeur\n");
        printf("\n");
        printf("  Quand 2 threads executent ces 3 etapes en meme temps,\n");
        printf("  certains increments peuvent etre perdus.\n");
        printf("\n");
        printf("SOLUTION:\n");
        printf("  Utiliser InterlockedIncrement() ou des mutex\n");
        printf("  pour proteger l'acces concurrent.\n");
    }

    printf("\nTemps d'execution: %lu ms\n", elapsed);

    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(threads[i]);
    }

    printf("\n[*] Handles fermes\n");
    printf("[*] Programme termine\n");

    return 0;
}

/*
 * EXPLICATIONS:
 *
 * 1. Compteur global:
 *    - Variable partagee par tous les threads
 *    - DANGER: acces concurrent non synchronise
 *
 * 2. CreateThread:
 *    - Chaque thread execute la meme fonction
 *    - lpParam permet de passer un ID unique
 *
 * 3. WaitForMultipleObjects:
 *    - Attend que TOUS les threads se terminent
 *    - TRUE = attendre tous (AND), FALSE = n'importe lequel (OR)
 *
 * 4. Race Condition:
 *    - Comportement non deterministe
 *    - Resultat peut varier a chaque execution
 *    - Plus d'iterations = plus de chances de collision
 *
 * 5. Solution (non implementee ici):
 *    InterlockedIncrement(&global_counter);
 *    // Au lieu de global_counter++
 *
 * BONUS IMPLEMENTES:
 * - ID unique par thread
 * - Messages de progression
 * - Mesure du temps d'execution
 * - Explication detaillee de la race condition
 */
