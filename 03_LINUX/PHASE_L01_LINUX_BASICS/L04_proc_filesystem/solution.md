# Solutions - Proc Filesystem

## Exercice 1 : Découverte (Très facile)

### Objectif
Lire le PID et le nom du processus courant via /proc/self

### Solution

```c
// solution_ex1.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    // Obtenir le PID du processus courant
    pid_t pid = getpid();
    printf("[*] PID du processus: %d\n", pid);

    // Lire le nom du processus depuis /proc/self/status
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // La première ligne contient "Name: <nom_processus>"
    char line[256];
    if (fgets(line, sizeof(line), f)) {
        printf("[*] Contenu de /proc/self/status (première ligne):\n%s", line);
    }

    fclose(f);

    // Lire la ligne de commande
    f = fopen("/proc/self/cmdline", "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    char cmdline[256];
    size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
    cmdline[n] = '\0';

    printf("[*] Ligne de commande: %s\n", cmdline);

    fclose(f);

    return 0;
}
```

**Compilation et exécution:**
```bash
gcc -o solution_ex1 solution_ex1.c
./solution_ex1
```

**Explication:**
- `getpid()` retourne le PID du processus courant
- `/proc/self` est un lien symbolique qui pointe toujours vers le répertoire /proc/PID du processus courant
- Le fichier `status` contient les informations du processus en format texte lisible
- Le fichier `cmdline` contient la ligne de commande complète

---

## Exercice 2 : Modification (Facile)

### Objectif
Créer un programme qui affiche les informations d'un PID donné en argument

### Solution

```c
// solution_ex2.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Fonction pour lire et afficher le status d'un processus
void print_process_info(int pid) {
    char path[256];

    // Construire le chemin vers /proc/PID/status
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        printf("[-] Erreur: impossible d'ouvrir %s\n", path);
        printf("[-] Le processus n'existe peut-être pas ou vous n'avez pas les permissions\n");
        return;
    }

    printf("[+] Informations du processus PID %d:\n", pid);
    printf("=====================================\n");

    // Lire et afficher les lignes importantes
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Afficher seulement les lignes importantes
        if (strncmp(line, "Name:", 5) == 0 ||
            strncmp(line, "State:", 6) == 0 ||
            strncmp(line, "Pid:", 4) == 0 ||
            strncmp(line, "PPid:", 5) == 0 ||
            strncmp(line, "Uid:", 4) == 0 ||
            strncmp(line, "VmSize:", 7) == 0 ||
            strncmp(line, "VmRSS:", 6) == 0) {
            printf("%s", line);
        }
    }

    fclose(f);

    // Lire et afficher la ligne de commande
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = fopen(path, "r");

    if (f) {
        char cmdline[1024];
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);

        if (n > 0) {
            // Remplacer les \0 par des espaces pour l'affichage
            for (size_t i = 0; i < n; i++) {
                if (cmdline[i] == '\0')
                    cmdline[i] = ' ';
            }
            cmdline[n] = '\0';
            printf("Cmdline: %s\n", cmdline);
        } else {
            printf("Cmdline: [kernel thread]\n");
        }

        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        fprintf(stderr, "Exemple: %s 1\n", argv[0]);
        return 1;
    }

    // Convertir l'argument en entier
    int pid = atoi(argv[1]);

    if (pid <= 0) {
        fprintf(stderr, "[-] PID invalide: %s\n", argv[1]);
        return 1;
    }

    print_process_info(pid);

    return 0;
}
```

**Compilation et tests:**
```bash
gcc -o solution_ex2 solution_ex2.c
./solution_ex2 1        # Processus init/systemd
./solution_ex2 $$       # Votre shell courant
./solution_ex2 9999999  # PID inexistant (doit afficher une erreur)
```

**Explication:**
- `snprintf()` construit le chemin vers le fichier /proc de manière sécurisée
- On filtre les lignes du fichier status pour n'afficher que les informations importantes
- La ligne de commande dans `cmdline` utilise des `\0` comme séparateurs d'arguments

---

## Exercice 3 : Création (Moyen)

### Objectif
Créer un mini-scanner de processus qui liste tous les processus et permet de rechercher par nom

### Solution

```c
// solution_ex3.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

// Structure pour stocker les infos d'un processus
typedef struct {
    int pid;
    char name[256];
    char state;
    int uid;
    int ppid;
} ProcessInfo;

// Vérifier si une chaîne est un nombre (PID)
int is_number(const char *str) {
    for (int i = 0; str[i]; i++) {
        if (!isdigit(str[i]))
            return 0;
    }
    return 1;
}

// Lire les informations d'un processus
int get_process_info(int pid, ProcessInfo *info) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    // Initialiser la structure
    info->pid = pid;
    strcpy(info->name, "???");
    info->state = '?';
    info->uid = -1;
    info->ppid = -1;

    // Parser le fichier status
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:\t%s", info->name);
        } else if (strncmp(line, "State:", 6) == 0) {
            sscanf(line, "State:\t%c", &info->state);
        } else if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%d", &info->uid);
        } else if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line, "PPid:\t%d", &info->ppid);
        }
    }

    fclose(f);
    return 1;
}

// Lister tous les processus
void list_all_processes(const char *filter) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    printf("%-8s %-20s %-6s %-8s %-8s\n", "PID", "NAME", "STATE", "UID", "PPID");
    printf("================================================================\n");

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(proc)) != NULL) {
        // Vérifier si c'est un répertoire avec un nom numérique (PID)
        if (entry->d_type == DT_DIR && is_number(entry->d_name)) {
            int pid = atoi(entry->d_name);
            ProcessInfo info;

            if (get_process_info(pid, &info)) {
                // Si un filtre est spécifié, ne montrer que les processus correspondants
                if (filter == NULL || strstr(info.name, filter) != NULL) {
                    printf("%-8d %-20s %-6c %-8d %-8d\n",
                           info.pid, info.name, info.state, info.uid, info.ppid);
                    count++;
                }
            }
        }
    }

    closedir(proc);
    printf("\n[+] Total: %d processus", count);
    if (filter)
        printf(" (filtrés par '%s')", filter);
    printf("\n");
}

// Rechercher des processus par critère
void find_processes_by_uid(int target_uid) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return;
    }

    printf("[*] Recherche des processus avec UID=%d (root=0)\n\n", target_uid);
    printf("%-8s %-20s %-8s\n", "PID", "NAME", "PPID");
    printf("==========================================\n");

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type == DT_DIR && is_number(entry->d_name)) {
            int pid = atoi(entry->d_name);
            ProcessInfo info;

            if (get_process_info(pid, &info) && info.uid == target_uid) {
                printf("%-8d %-20s %-8d\n", info.pid, info.name, info.ppid);
                count++;
            }
        }
    }

    closedir(proc);
    printf("\n[+] %d processus trouvés\n", count);
}

int main(int argc, char *argv[]) {
    printf("[*] Scanner de processus via /proc\n");
    printf("[*] ================================\n\n");

    if (argc == 1) {
        // Sans argument: lister tous les processus
        list_all_processes(NULL);
    } else if (argc == 2) {
        // Avec un argument: filtrer par nom
        printf("[*] Filtrage par nom: %s\n\n", argv[1]);
        list_all_processes(argv[1]);
    } else if (argc == 3 && strcmp(argv[1], "--uid") == 0) {
        // Mode recherche par UID
        int uid = atoi(argv[2]);
        find_processes_by_uid(uid);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s              # Lister tous les processus\n", argv[0]);
        fprintf(stderr, "  %s <nom>        # Filtrer par nom\n", argv[0]);
        fprintf(stderr, "  %s --uid <uid>  # Chercher par UID\n", argv[0]);
        return 1;
    }

    return 0;
}
```

**Compilation et tests:**
```bash
gcc -o solution_ex3 solution_ex3.c

# Lister tous les processus
./solution_ex3

# Filtrer par nom
./solution_ex3 bash
./solution_ex3 systemd

# Chercher les processus root
./solution_ex3 --uid 0

# Chercher vos processus
./solution_ex3 --uid $(id -u)
```

**Explication:**
- On parcourt `/proc` avec `opendir()` et `readdir()`
- Seuls les répertoires avec des noms numériques sont des PIDs
- On parse le fichier `status` pour extraire les informations importantes
- Le filtrage permet de chercher des processus spécifiques sans utiliser `ps`

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Créer un outil Red Team pour énumérer discrètement les informations sensibles (processus, connexions réseau, variables d'environnement)

### Solution

```c
// solution_ex4.c - Outil d'énumération furtive Red Team
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>

// Chercher des processus intéressants (serveurs, outils admin)
void enum_interesting_processes(void) {
    printf("[*] === PROCESSUS INTÉRESSANTS ===\n\n");

    DIR *proc = opendir("/proc");
    if (!proc) return;

    // Mots-clés suspects
    const char *keywords[] = {
        "ssh", "sshd", "sudo", "su", "mysql", "postgres",
        "apache", "nginx", "docker", "kubectl", "aws", "gcloud",
        NULL
    };

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0]))
            continue;

        int pid = atoi(entry->d_name);
        char path[256], cmdline[1024];

        // Lire cmdline
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        cmdline[n] = '\0';

        // Convertir \0 en espaces
        for (size_t i = 0; i < n; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }

        // Chercher les mots-clés
        for (int i = 0; keywords[i]; i++) {
            if (strcasestr(cmdline, keywords[i])) {
                printf("[!] PID %-6d : %s\n", pid, cmdline);
                break;
            }
        }
    }

    closedir(proc);
    printf("\n");
}

// Chercher des credentials dans les variables d'environnement
void enum_credentials(void) {
    printf("[*] === RECHERCHE DE CREDENTIALS ===\n\n");

    DIR *proc = opendir("/proc");
    if (!proc) return;

    // Patterns de credentials
    const char *patterns[] = {
        "PASSWORD", "PASS", "SECRET", "TOKEN", "API_KEY",
        "AWS_", "AZURE_", "GCP_", "DATABASE_URL", "DB_PASS",
        NULL
    };

    struct dirent *entry;
    int found_count = 0;

    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0]))
            continue;

        int pid = atoi(entry->d_name);
        char path[256];

        // Lire environ
        snprintf(path, sizeof(path), "/proc/%d/environ", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;  // Pas les permissions

        char buffer[8192];
        size_t n = fread(buffer, 1, sizeof(buffer) - 1, f);
        fclose(f);

        // Parser les variables (format: VAR=value\0VAR2=value2\0)
        for (size_t i = 0; i < n; ) {
            char *var = &buffer[i];

            // Chercher les patterns
            for (int j = 0; patterns[j]; j++) {
                if (strcasestr(var, patterns[j])) {
                    // Obtenir le nom du processus
                    char name[256] = "???";
                    char status_path[256];
                    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
                    FILE *sf = fopen(status_path, "r");
                    if (sf) {
                        char line[256];
                        if (fgets(line, sizeof(line), sf))
                            sscanf(line, "Name:\t%s", name);
                        fclose(sf);
                    }

                    printf("[!] PID %-6d (%s) : %s\n", pid, name, var);
                    found_count++;
                    break;
                }
            }

            // Avancer au prochain \0
            while (i < n && buffer[i] != '\0') i++;
            i++;
        }
    }

    closedir(proc);
    printf("\n[+] %d credentials potentiels trouvés\n\n", found_count);
}

// Lister les connexions TCP actives (comme netstat)
void enum_network_connections(void) {
    printf("[*] === CONNEXIONS RÉSEAU TCP ===\n\n");

    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) {
        perror("fopen /proc/net/tcp");
        return;
    }

    printf("%-20s %-20s %-10s\n", "LOCAL", "REMOTE", "STATE");
    printf("========================================================\n");

    char line[512];
    fgets(line, sizeof(line), f);  // Skip header

    while (fgets(line, sizeof(line), f)) {
        unsigned int local_addr, remote_addr;
        unsigned int local_port, remote_port;
        int state;

        // Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
        sscanf(line, "%*d: %X:%X %X:%X %X",
               &local_addr, &local_port,
               &remote_addr, &remote_port,
               &state);

        // Convertir en format lisible
        struct in_addr l, r;
        l.s_addr = local_addr;
        r.s_addr = remote_addr;

        // États TCP
        const char *states[] = {
            "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
            "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
            "LISTEN", "CLOSING"
        };
        const char *state_str = (state >= 1 && state <= 11) ? states[state] : "UNKNOWN";

        // Afficher seulement les connexions intéressantes (ESTABLISHED ou LISTEN)
        if (state == 1 || state == 10) {
            printf("%-20s %-20s %-10s\n",
                   inet_ntoa(l), inet_ntoa(r), state_str);
        }
    }

    fclose(f);
    printf("\n");
}

// Lister les fichiers ouverts par les processus intéressants
void enum_open_files(int pid) {
    printf("[*] === FICHIERS OUVERTS PAR PID %d ===\n\n", pid);

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);

    DIR *fd_dir = opendir(path);
    if (!fd_dir) {
        printf("[-] Impossible d'accéder à /proc/%d/fd (permissions?)\n\n", pid);
        return;
    }

    printf("%-5s %-50s\n", "FD", "TARGET");
    printf("==========================================================\n");

    struct dirent *entry;
    while ((entry = readdir(fd_dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        // Lire le lien symbolique
        char fd_path[512], target[256];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", path, entry->d_name);
        ssize_t len = readlink(fd_path, target, sizeof(target) - 1);

        if (len != -1) {
            target[len] = '\0';
            // Afficher seulement les fichiers intéressants (pas stdin/out/err)
            if (strstr(target, "/dev/pts") == NULL &&
                strstr(target, "pipe:") == NULL) {
                printf("%-5s %-50s\n", entry->d_name, target);
            }
        }
    }

    closedir(fd_dir);
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║   Outil d'énumération furtive Linux via /proc       ║\n");
    printf("║   Red Team - Information Gathering                  ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");

    // 1. Processus intéressants
    enum_interesting_processes();

    // 2. Credentials potentiels
    enum_credentials();

    // 3. Connexions réseau
    enum_network_connections();

    // 4. Si un PID est fourni, lister ses fichiers ouverts
    if (argc == 2) {
        int pid = atoi(argv[1]);
        if (pid > 0) {
            enum_open_files(pid);
        }
    }

    printf("[*] Énumération terminée\n");
    printf("[*] TIP: Lancez avec un PID pour voir les fichiers ouverts\n");
    printf("[*] Exemple: %s 1234\n\n", argv[0]);

    return 0;
}
```

**Compilation et utilisation:**
```bash
gcc -o solution_ex4 solution_ex4.c

# Énumération complète
./solution_ex4

# Énumération + fichiers ouverts d'un processus spécifique
./solution_ex4 1234
```

**Caractéristiques Red Team:**
- Pas d'appel à `ps`, `netstat`, `lsof` (furtif)
- Recherche automatique de credentials dans les variables d'environnement
- Détection de processus sensibles (SSH, bases de données, cloud tools)
- Énumération des connexions réseau actives
- Inspection des fichiers ouverts

**OPSEC:**
- Accès en lecture seule à `/proc` (pas de logs)
- Pas de commandes externes exécutées
- Fonctionne avec des permissions utilisateur normales (sauf pour certains processus)

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Lire et parser les fichiers /proc/PID/status, cmdline, environ
- [x] Parcourir /proc pour énumérer tous les processus
- [x] Filtrer et rechercher des processus par critères
- [x] Utiliser /proc/net/tcp pour voir les connexions réseau
- [x] Lire les fichiers ouverts via /proc/PID/fd
- [x] Implémenter un outil d'énumération Red Team furtif
