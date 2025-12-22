/*
 * ═══════════════════════════════════════════════════════════════════════════
 * Module 21 : Processus et Threads
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Démonstration de :
 * - fork() et exec() (Linux)
 * - CreateProcess() (Windows)
 * - POSIX Threads (pthread)
 * - Windows Threads
 * - Communication inter-processus (IPC)
 * - Mémoire partagée
 *
 * Compilation :
 *   Linux   : gcc main.c -o main -pthread -lrt
 *   Windows : gcc main.c -o main.exe
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <pthread.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <semaphore.h>
#endif

// ═══════════════════════════════════════════════════════════════════════════
// STRUCTURES ET TYPES
// ═══════════════════════════════════════════════════════════════════════════

typedef struct {
    int thread_id;
    int iterations;
    char message[64];
} ThreadData;

typedef struct {
    int counter;
    char buffer[256];
} SharedData;

// Variables globales pour synchronisation
#ifdef _WIN32
    HANDLE g_mutex;
    SharedData *g_shared_data = NULL;
#else
    pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
    SharedData *g_shared_data = NULL;
#endif

// ═══════════════════════════════════════════════════════════════════════════
// FONCTIONS THREADS
// ═══════════════════════════════════════════════════════════════════════════

#ifdef _WIN32
DWORD WINAPI thread_function(LPVOID param) {
    ThreadData *data = (ThreadData *)param;

    for (int i = 0; i < data->iterations; i++) {
        WaitForSingleObject(g_mutex, INFINITE);

        printf("[Thread Windows %d] Iteration %d : %s\n",
               data->thread_id, i, data->message);

        if (g_shared_data) {
            g_shared_data->counter++;
            snprintf(g_shared_data->buffer, sizeof(g_shared_data->buffer),
                    "Thread %d iteration %d", data->thread_id, i);
        }

        ReleaseMutex(g_mutex);
        Sleep(100);
    }

    return 0;
}
#else
void *thread_function(void *param) {
    ThreadData *data = (ThreadData *)param;

    for (int i = 0; i < data->iterations; i++) {
        pthread_mutex_lock(&g_mutex);

        printf("[Thread POSIX %d] Iteration %d : %s\n",
               data->thread_id, i, data->message);

        if (g_shared_data) {
            g_shared_data->counter++;
            snprintf(g_shared_data->buffer, sizeof(g_shared_data->buffer),
                    "Thread %d iteration %d", data->thread_id, i);
        }

        pthread_mutex_unlock(&g_mutex);
        usleep(100000);
    }

    return NULL;
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION PROCESSUS LINUX
// ═══════════════════════════════════════════════════════════════════════════

#ifndef _WIN32
void demo_fork_exec() {
    printf("\n═══ Démonstration fork() et exec() ═══\n\n");

    // Exemple 1 : fork simple
    printf("[1] Fork simple\n");
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        return;
    } else if (pid == 0) {
        // Processus enfant
        printf("  [Enfant] PID=%d, PPID=%d\n", getpid(), getppid());
        printf("  [Enfant] Je vais dormir 1 seconde...\n");
        sleep(1);
        printf("  [Enfant] Terminé!\n");
        exit(0);
    } else {
        // Processus parent
        printf("  [Parent] PID=%d, Enfant PID=%d\n", getpid(), pid);
        int status;
        waitpid(pid, &status, 0);
        printf("  [Parent] Enfant terminé avec status %d\n",
               WEXITSTATUS(status));
    }

    // Exemple 2 : exec
    printf("\n[2] Fork + exec\n");
    pid = fork();

    if (pid == 0) {
        // Exécuter la commande 'ls -l'
        printf("  [Enfant] Exécution de 'ls -l'\n");
        execlp("ls", "ls", "-l", NULL);
        // Si exec réussit, ce code n'est jamais atteint
        perror("  [Enfant] exec failed");
        exit(1);
    } else {
        int status;
        waitpid(pid, &status, 0);
        printf("  [Parent] Commande terminée\n");
    }
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION PROCESSUS WINDOWS
// ═══════════════════════════════════════════════════════════════════════════

#ifdef _WIN32
void demo_create_process() {
    printf("\n═══ Démonstration CreateProcess() ═══\n\n");

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Créer un processus pour exécuter 'cmd /c dir'
    char cmd[] = "cmd.exe /c dir";

    printf("[CreateProcess] Lancement de : %s\n", cmd);

    if (!CreateProcessA(
            NULL,           // Nom du module
            cmd,            // Ligne de commande
            NULL,           // Attributs processus
            NULL,           // Attributs thread
            FALSE,          // Héritage handles
            0,              // Flags création
            NULL,           // Environnement
            NULL,           // Répertoire courant
            &si,            // STARTUPINFO
            &pi             // PROCESS_INFORMATION
        )) {
        printf("  [Erreur] CreateProcess failed (%lu)\n", GetLastError());
        return;
    }

    printf("  [Parent] Processus créé, PID=%lu\n", pi.dwProcessId);
    printf("  [Parent] Attente de la fin...\n");

    // Attendre que le processus se termine
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    printf("  [Parent] Processus terminé avec code %lu\n", exit_code);

    // Fermer les handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION THREADS
// ═══════════════════════════════════════════════════════════════════════════

void demo_threads() {
    printf("\n═══ Démonstration Threads ═══\n\n");

    const int NUM_THREADS = 3;
    ThreadData thread_data[NUM_THREADS];

#ifdef _WIN32
    HANDLE threads[NUM_THREADS];
    g_mutex = CreateMutex(NULL, FALSE, NULL);

    // Créer les threads Windows
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i + 1;
        thread_data[i].iterations = 3;
        snprintf(thread_data[i].message, sizeof(thread_data[i].message),
                "Message du thread %d", i + 1);

        threads[i] = CreateThread(
            NULL,                   // Attributs sécurité
            0,                      // Taille stack
            thread_function,        // Fonction
            &thread_data[i],        // Paramètre
            0,                      // Flags
            NULL                    // ID thread
        );

        if (threads[i] == NULL) {
            printf("Erreur création thread %d\n", i + 1);
        }
    }

    // Attendre tous les threads
    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    // Nettoyer
    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(threads[i]);
    }
    CloseHandle(g_mutex);

#else
    pthread_t threads[NUM_THREADS];

    // Créer les threads POSIX
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i + 1;
        thread_data[i].iterations = 3;
        snprintf(thread_data[i].message, sizeof(thread_data[i].message),
                "Message du thread %d", i + 1);

        if (pthread_create(&threads[i], NULL, thread_function,
                          &thread_data[i]) != 0) {
            printf("Erreur création thread %d\n", i + 1);
        }
    }

    // Attendre tous les threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&g_mutex);
#endif

    printf("\n[Threads] Tous les threads ont terminé\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION IPC : PIPES
// ═══════════════════════════════════════════════════════════════════════════

#ifndef _WIN32
void demo_pipes() {
    printf("\n═══ Démonstration Pipes (IPC) ═══\n\n");

    int pipefd[2];
    pid_t pid;
    char buffer[256];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return;
    }

    pid = fork();

    if (pid < 0) {
        perror("fork");
        return;
    } else if (pid == 0) {
        // Processus enfant : lecture
        close(pipefd[1]); // Fermer l'écriture

        printf("  [Enfant] En attente de données...\n");
        ssize_t n = read(pipefd[0], buffer, sizeof(buffer));

        if (n > 0) {
            buffer[n] = '\0';
            printf("  [Enfant] Reçu : '%s'\n", buffer);
        }

        close(pipefd[0]);
        exit(0);
    } else {
        // Processus parent : écriture
        close(pipefd[0]); // Fermer la lecture

        const char *message = "Message depuis le processus parent!";
        printf("  [Parent] Envoi : '%s'\n", message);
        write(pipefd[1], message, strlen(message));

        close(pipefd[1]);
        wait(NULL);
        printf("  [Parent] Communication terminée\n");
    }
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION MÉMOIRE PARTAGÉE
// ═══════════════════════════════════════════════════════════════════════════

#ifndef _WIN32
void demo_shared_memory() {
    printf("\n═══ Démonstration Mémoire Partagée ═══\n\n");

    const char *shm_name = "/my_shared_memory";
    int shm_fd;
    SharedData *shared_data;

    // Créer objet mémoire partagée
    shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return;
    }

    // Configurer la taille
    ftruncate(shm_fd, sizeof(SharedData));

    // Mapper en mémoire
    shared_data = mmap(NULL, sizeof(SharedData),
                       PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shared_data == MAP_FAILED) {
        perror("mmap");
        shm_unlink(shm_name);
        return;
    }

    // Initialiser
    shared_data->counter = 0;
    strcpy(shared_data->buffer, "Données partagées initiales");

    pid_t pid = fork();

    if (pid == 0) {
        // Processus enfant
        sleep(1);
        printf("  [Enfant] Lecture : counter=%d, buffer='%s'\n",
               shared_data->counter, shared_data->buffer);

        shared_data->counter = 42;
        strcpy(shared_data->buffer, "Modifié par l'enfant");

        printf("  [Enfant] Écriture effectuée\n");
        munmap(shared_data, sizeof(SharedData));
        exit(0);
    } else {
        // Processus parent
        printf("  [Parent] Valeurs initiales : counter=%d, buffer='%s'\n",
               shared_data->counter, shared_data->buffer);

        wait(NULL);
        sleep(1);

        printf("  [Parent] Après modification : counter=%d, buffer='%s'\n",
               shared_data->counter, shared_data->buffer);

        // Nettoyer
        munmap(shared_data, sizeof(SharedData));
        shm_unlink(shm_name);
    }
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Module 21 : Processus et Threads\n");
    printf("═══════════════════════════════════════════════════════════════\n");

#ifdef _WIN32
    printf("\nPlateforme : Windows\n");
    demo_create_process();
#else
    printf("\nPlateforme : Linux/Unix\n");
    demo_fork_exec();
    demo_pipes();
    demo_shared_memory();
#endif

    demo_threads();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  Démonstrations terminées\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    return 0;
}
