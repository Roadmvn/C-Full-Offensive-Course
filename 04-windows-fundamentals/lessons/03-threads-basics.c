/*
 * LESSON 03: Threads Basics
 *
 * OBJECTIFS:
 * - Comprendre ce qu'est un thread
 * - Creer des threads avec CreateThread
 * - Synchroniser des threads
 * - Gerer le cycle de vie des threads
 *
 * CONCEPTS CLES:
 * - Thread: Unite d'execution au sein d'un processus
 * - Fonction thread: Point d'entree du thread
 * - WaitForSingleObject: Synchronisation
 * - Thread ID et Handle
 */

#include <windows.h>
#include <stdio.h>

/*
 * QU'EST-CE QU'UN THREAD ?
 *
 * Un thread est une unite d'execution independante au sein d'un processus.
 * - Chaque processus a au moins 1 thread (le thread principal)
 * - Les threads d'un meme processus partagent la meme memoire
 * - Chaque thread a sa propre pile (stack)
 * - Les threads peuvent s'executer en parallele (multi-core)
 */

void demonstrate_thread_concept() {
    printf("=== CONCEPT DE THREAD ===\n\n");

    printf("Thread principal:\n");
    printf("  Process ID: %lu\n", GetCurrentProcessId());
    printf("  Thread ID: %lu\n", GetCurrentThreadId());
    printf("\nUn processus peut avoir plusieurs threads qui s'executent\n");
    printf("en parallele et partagent la meme memoire.\n\n");
}

/*
 * FONCTION THREAD SIMPLE
 *
 * Une fonction thread doit avoir la signature:
 * DWORD WINAPI ThreadFunction(LPVOID lpParam)
 */
DWORD WINAPI simple_thread_function(LPVOID lpParam) {
    int threadNum = *(int*)lpParam;

    printf("[Thread %d] Demarre (TID: %lu)\n", threadNum, GetCurrentThreadId());

    // Simuler un travail
    for (int i = 1; i <= 5; i++) {
        printf("[Thread %d] Travail en cours... %d/5\n", threadNum, i);
        Sleep(500);  // Pause de 500ms
    }

    printf("[Thread %d] Termine!\n", threadNum);
    return 0;
}

void create_simple_thread() {
    printf("=== CREATION DE THREAD SIMPLE ===\n\n");

    int threadNum = 1;

    // Creer le thread
    HANDLE hThread = CreateThread(
        NULL,                       // Securite par defaut
        0,                          // Taille de pile par defaut
        simple_thread_function,     // Fonction thread
        &threadNum,                 // Parametre passe au thread
        0,                          // Flags de creation (0 = demarre immediatement)
        NULL                        // Thread ID (NULL = pas besoin)
    );

    if (hThread == NULL) {
        printf("[-] CreateThread echoue: %lu\n", GetLastError());
        return;
    }

    printf("[Main] Thread cree! Handle: 0x%p\n\n", hThread);

    // Attendre que le thread se termine
    printf("[Main] Attente de la fin du thread...\n");
    WaitForSingleObject(hThread, INFINITE);

    printf("[Main] Thread termine!\n");

    // Obtenir le code de retour
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[Main] Code de retour: %lu\n\n", exitCode);

    CloseHandle(hThread);
}

/*
 * THREADS MULTIPLES
 *
 * Creer plusieurs threads qui s'executent en parallele.
 */
DWORD WINAPI worker_thread(LPVOID lpParam) {
    int id = *(int*)lpParam;

    printf("[Worker %d] TID: %lu - Debut\n", id, GetCurrentThreadId());

    // Travail different selon l'ID
    for (int i = 0; i < 3; i++) {
        printf("[Worker %d] Iteration %d\n", id, i + 1);
        Sleep(300 * id);  // Delai different pour chaque thread
    }

    printf("[Worker %d] Fin\n", id);
    return id * 100;  // Code de retour unique
}

void create_multiple_threads() {
    printf("=== THREADS MULTIPLES ===\n\n");

    const int NUM_THREADS = 3;
    HANDLE threads[NUM_THREADS];
    int threadIDs[NUM_THREADS];

    printf("[Main] Creation de %d threads...\n\n", NUM_THREADS);

    // Creer les threads
    for (int i = 0; i < NUM_THREADS; i++) {
        threadIDs[i] = i + 1;

        threads[i] = CreateThread(
            NULL,
            0,
            worker_thread,
            &threadIDs[i],
            0,
            NULL
        );

        if (threads[i] == NULL) {
            printf("[-] Echec creation thread %d\n", i);
        } else {
            printf("[Main] Thread %d cree\n", i + 1);
        }
    }

    printf("\n[Main] Tous les threads sont lances!\n");
    printf("[Main] Attente de la fin de tous les threads...\n\n");

    // Attendre tous les threads
    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    printf("\n[Main] Tous les threads sont termines!\n");

    // Recuperer les codes de retour
    printf("\nCodes de retour:\n");
    for (int i = 0; i < NUM_THREADS; i++) {
        DWORD exitCode;
        GetExitCodeThread(threads[i], &exitCode);
        printf("  Thread %d: %lu\n", i + 1, exitCode);
        CloseHandle(threads[i]);
    }
    printf("\n");
}

/*
 * PASSAGE DE PARAMETRES
 *
 * Differentes manieres de passer des donnees aux threads.
 */
struct ThreadData {
    int id;
    char message[100];
    int iterations;
};

DWORD WINAPI thread_with_struct(LPVOID lpParam) {
    struct ThreadData* data = (struct ThreadData*)lpParam;

    printf("[Thread %d] Message: %s\n", data->id, data->message);

    for (int i = 0; i < data->iterations; i++) {
        printf("[Thread %d] %d/%d\n", data->id, i + 1, data->iterations);
        Sleep(200);
    }

    return 0;
}

void demonstrate_parameter_passing() {
    printf("=== PASSAGE DE PARAMETRES COMPLEXES ===\n\n");

    struct ThreadData data1 = {
        .id = 1,
        .message = "Premier thread avec structure",
        .iterations = 3
    };

    struct ThreadData data2 = {
        .id = 2,
        .message = "Deuxieme thread avec structure",
        .iterations = 4
    };

    HANDLE threads[2];

    threads[0] = CreateThread(NULL, 0, thread_with_struct, &data1, 0, NULL);
    threads[1] = CreateThread(NULL, 0, thread_with_struct, &data2, 0, NULL);

    WaitForMultipleObjects(2, threads, TRUE, INFINITE);

    CloseHandle(threads[0]);
    CloseHandle(threads[1]);

    printf("\n");
}

/*
 * CREATION FLAGS
 *
 * Options de creation de threads.
 */
DWORD WINAPI delayed_thread(LPVOID lpParam) {
    printf("[Delayed] Thread demarre apres ResumeThread!\n");
    return 0;
}

void demonstrate_creation_flags() {
    printf("=== FLAGS DE CREATION ===\n\n");

    printf("Flags disponibles:\n");
    printf("  0 (par defaut) - Demarre immediatement\n");
    printf("  CREATE_SUSPENDED (0x%08X) - Demarre suspendu\n", CREATE_SUSPENDED);
    printf("  STACK_SIZE_PARAM_IS_A_RESERVATION - Taille pile reservee\n\n");

    printf("[Main] Creation d'un thread SUSPENDU\n");

    HANDLE hThread = CreateThread(
        NULL,
        0,
        delayed_thread,
        NULL,
        CREATE_SUSPENDED,  // Thread suspendu
        NULL
    );

    printf("[Main] Thread cree mais pas encore execute\n");
    printf("[Main] Attente de 2 secondes...\n");
    Sleep(2000);

    printf("[Main] Demarrage du thread avec ResumeThread\n");
    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("\n");
}

/*
 * SYNCHRONISATION BASIQUE
 *
 * WaitForSingleObject et WaitForMultipleObjects.
 */
DWORD WINAPI long_running_thread(LPVOID lpParam) {
    int seconds = *(int*)lpParam;

    printf("[Long Thread] Execution pendant %d secondes...\n", seconds);

    for (int i = 0; i < seconds; i++) {
        printf("[Long Thread] %d/%d\n", i + 1, seconds);
        Sleep(1000);
    }

    return 0;
}

void demonstrate_synchronization() {
    printf("=== SYNCHRONISATION DES THREADS ===\n\n");

    int duration = 3;

    HANDLE hThread = CreateThread(NULL, 0, long_running_thread, &duration, 0, NULL);

    printf("[Main] Thread lance, attente avec timeout...\n");

    // Attendre 2 secondes
    DWORD result = WaitForSingleObject(hThread, 2000);

    if (result == WAIT_TIMEOUT) {
        printf("[Main] Timeout! Le thread est encore en cours...\n");
        printf("[Main] Attente de la fin reelle...\n");
        WaitForSingleObject(hThread, INFINITE);
    } else if (result == WAIT_OBJECT_0) {
        printf("[Main] Thread termine avant le timeout\n");
    }

    CloseHandle(hThread);
    printf("\n");
}

/*
 * PROBLEMES DE CONCURRENCE (RACE CONDITION)
 *
 * Demonstration d'un probleme classique sans synchronisation.
 */
int global_counter = 0;

DWORD WINAPI increment_thread(LPVOID lpParam) {
    int iterations = *(int*)lpParam;

    for (int i = 0; i < iterations; i++) {
        global_counter++;  // DANGER: Race condition!
    }

    return 0;
}

void demonstrate_race_condition() {
    printf("=== RACE CONDITION (PROBLEME) ===\n\n");

    global_counter = 0;
    const int NUM_THREADS = 5;
    const int ITERATIONS = 10000;
    HANDLE threads[NUM_THREADS];
    int iterations = ITERATIONS;

    printf("[Main] Lancement de %d threads\n", NUM_THREADS);
    printf("[Main] Chaque thread incremente un compteur %d fois\n", ITERATIONS);
    printf("[Main] Valeur attendue: %d\n\n", NUM_THREADS * ITERATIONS);

    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i] = CreateThread(NULL, 0, increment_thread, &iterations, 0, NULL);
    }

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(threads[i]);
    }

    printf("[Main] Valeur obtenue: %d\n", global_counter);

    if (global_counter != NUM_THREADS * ITERATIONS) {
        printf("[!] RACE CONDITION DETECTEE!\n");
        printf("[!] Des increments ont ete perdus a cause de l'acces concurrent\n");
    } else {
        printf("[*] Par chance, pas de perte cette fois\n");
    }

    printf("\n");
}

/*
 * TERMINAISON DE THREAD
 *
 * Differentes manieres de terminer un thread.
 */
DWORD WINAPI terminating_thread(LPVOID lpParam) {
    printf("[Thread] Debut\n");
    Sleep(100);

    // Methode 1: return
    printf("[Thread] Fin normale avec return\n");
    return 42;

    // Methode 2: ExitThread (jamais atteint ici)
    // ExitThread(42);
}

void demonstrate_thread_termination() {
    printf("=== TERMINAISON DE THREAD ===\n\n");

    printf("Manieres de terminer un thread:\n");
    printf("  1. return dans la fonction thread (RECOMMANDE)\n");
    printf("  2. ExitThread() (OK)\n");
    printf("  3. TerminateThread() (DANGEREUX - eviter!)\n\n");

    HANDLE hThread = CreateThread(NULL, 0, terminating_thread, NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[Main] Code de retour: %lu\n", exitCode);

    CloseHandle(hThread);
    printf("\n");
}

/*
 * BONNES PRATIQUES
 */
void show_best_practices() {
    printf("=== BONNES PRATIQUES ===\n\n");

    printf("1. TOUJOURS fermer les handles de threads avec CloseHandle\n");
    printf("2. TOUJOURS attendre la fin des threads avant de quitter\n");
    printf("3. Eviter TerminateThread (pas de cleanup)\n");
    printf("4. Utiliser return pour terminer un thread normalement\n");
    printf("5. Attention aux race conditions sur donnees partagees\n");
    printf("6. Passer des structures pour parametres complexes\n");
    printf("7. Verifier le retour de CreateThread\n\n");
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         LESSON 03: THREADS BASICS - WINDOWS API          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    demonstrate_thread_concept();
    create_simple_thread();

    printf("[*] Appuie sur Entree pour continuer...\n");
    getchar();

    create_multiple_threads();
    demonstrate_parameter_passing();
    demonstrate_creation_flags();
    demonstrate_synchronization();
    demonstrate_race_condition();
    demonstrate_thread_termination();
    show_best_practices();

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║                    FIN DE LA LESSON                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}
