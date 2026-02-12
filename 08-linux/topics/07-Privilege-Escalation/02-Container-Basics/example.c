/*
 * OBJECTIF  : Comprendre les fondamentaux des containers Linux
 * PREREQUIS : Bases C, syscalls, /proc, notions de namespaces
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les composants fondamentaux des containers :
 * namespaces (isolation), cgroups (limitation de ressources),
 * et comment inspecter l'environnement d'un container.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

/*
 * Etape 1 : Architecture des containers
 */
static void explain_container_architecture(void) {
    printf("[*] Etape 1 : Architecture des containers Linux\n\n");

    printf("    ┌──────────────────────────────────────────────┐\n");
    printf("    │              HOST KERNEL                      │\n");
    printf("    │  (un seul kernel partage entre tous)          │\n");
    printf("    ├──────────────────────────────────────────────┤\n");
    printf("    │  Container A        │  Container B            │\n");
    printf("    │  ┌────────────┐     │  ┌────────────┐        │\n");
    printf("    │  │ Namespaces │     │  │ Namespaces │        │\n");
    printf("    │  │ - PID      │     │  │ - PID      │        │\n");
    printf("    │  │ - NET      │     │  │ - NET      │        │\n");
    printf("    │  │ - MNT      │     │  │ - MNT      │        │\n");
    printf("    │  │ - UTS      │     │  │ - UTS      │        │\n");
    printf("    │  │ - IPC      │     │  │ - IPC      │        │\n");
    printf("    │  │ - USER     │     │  │ - USER     │        │\n");
    printf("    │  └────────────┘     │  └────────────┘        │\n");
    printf("    │  ┌────────────┐     │  ┌────────────┐        │\n");
    printf("    │  │  Cgroups   │     │  │  Cgroups   │        │\n");
    printf("    │  │ CPU/MEM/IO │     │  │ CPU/MEM/IO │        │\n");
    printf("    │  └────────────┘     │  └────────────┘        │\n");
    printf("    └──────────────────────────────────────────────┘\n\n");

    printf("    Un container N'EST PAS une VM :\n");
    printf("    - Pas d'hyperviseur ni de kernel separe\n");
    printf("    - Isolation par namespaces (vue limitee du systeme)\n");
    printf("    - Limitation par cgroups (quotas de ressources)\n");
    printf("    - Meme kernel que l'hote -> surface d'attaque partagee\n\n");
}

/*
 * Etape 2 : Les 8 types de namespaces Linux
 */
static void explain_namespaces(void) {
    printf("[*] Etape 2 : Les namespaces Linux\n\n");

    printf("    Namespace | Flag          | Isole\n");
    printf("    ──────────|───────────────|──────────────────────────\n");
    printf("    PID       | CLONE_NEWPID  | Arbre de processus\n");
    printf("    NET       | CLONE_NEWNET  | Interfaces reseau, routes\n");
    printf("    MNT       | CLONE_NEWNS   | Points de montage\n");
    printf("    UTS       | CLONE_NEWUTS  | Hostname, domainname\n");
    printf("    IPC       | CLONE_NEWIPC  | Semaphores, shared memory\n");
    printf("    USER      | CLONE_NEWUSER | UIDs/GIDs (remapping)\n");
    printf("    CGROUP    | CLONE_NEWCGRP | Hierarchie cgroup\n");
    printf("    TIME      | CLONE_NEWTIME | Horloge systeme (5.6+)\n\n");
}

/*
 * Etape 3 : Inspecter nos namespaces actuels
 */
static void inspect_current_namespaces(void) {
    printf("[*] Etape 3 : Nos namespaces actuels\n\n");

    printf("    PID actuel : %d\n", getpid());
    printf("    UID actuel : %d\n\n", getuid());

    /* Lire les liens symboliques dans /proc/self/ns/ */
    DIR *dir = opendir("/proc/self/ns");
    if (!dir) {
        printf("    (impossible d'ouvrir /proc/self/ns)\n\n");
        return;
    }

    printf("    Namespaces de ce processus (/proc/self/ns/) :\n");
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;

        char path[256];
        char target[256];
        snprintf(path, sizeof(path), "/proc/self/ns/%s", entry->d_name);
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            printf("      %-10s -> %s\n", entry->d_name, target);
        }
    }
    closedir(dir);
    printf("\n");

    printf("    Les numeros entre crochets sont les inode des namespaces.\n");
    printf("    Deux processus avec le meme inode partagent le meme namespace.\n\n");
}

/*
 * Etape 4 : Detecter si on est dans un container
 */
static void detect_container(void) {
    printf("[*] Etape 4 : Detection de container\n\n");

    int in_container = 0;

    /* Methode 1 : /.dockerenv */
    if (access("/.dockerenv", F_OK) == 0) {
        printf("    [+] /.dockerenv EXISTE -> probablement Docker\n");
        in_container = 1;
    } else {
        printf("    [-] /.dockerenv absent\n");
    }

    /* Methode 2 : /run/.containerenv (Podman) */
    if (access("/run/.containerenv", F_OK) == 0) {
        printf("    [+] /run/.containerenv EXISTE -> probablement Podman\n");
        in_container = 1;
    } else {
        printf("    [-] /run/.containerenv absent\n");
    }

    /* Methode 3 : cgroup */
    FILE *fp = fopen("/proc/1/cgroup", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "docker") || strstr(line, "kubepods") ||
                strstr(line, "containerd") || strstr(line, "lxc")) {
                printf("    [+] /proc/1/cgroup contient des references container :\n");
                printf("        %s", line);
                in_container = 1;
                break;
            }
        }
        fclose(fp);
    }

    /* Methode 4 : PID 1 */
    fp = fopen("/proc/1/comm", "r");
    if (fp) {
        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), fp)) {
            /* Retirer le newline */
            comm[strcspn(comm, "\n")] = '\0';
            printf("    PID 1 = \"%s\"", comm);
            if (strcmp(comm, "systemd") != 0 && strcmp(comm, "init") != 0) {
                printf(" (pas systemd/init -> peut-etre un container)");
                in_container = 1;
            }
            printf("\n");
        }
        fclose(fp);
    }

    /* Methode 5 : nombre de processus */
    int proc_count = 0;
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9')
                proc_count++;
        }
        closedir(dir);
        printf("    Nombre de processus visibles : %d", proc_count);
        if (proc_count < 20) {
            printf(" (peu -> indice de container)");
            in_container = 1;
        }
        printf("\n");
    }

    printf("\n    Verdict : %s\n\n",
           in_container ? "PROBABLEMENT dans un container"
                        : "Probablement sur l'hote");
}

/*
 * Etape 5 : Inspecter les cgroups
 */
static void inspect_cgroups(void) {
    printf("[*] Etape 5 : Cgroups - limitation de ressources\n\n");

    printf("    Cgroups v1 : hierarchie dans /sys/fs/cgroup/\n");
    printf("    Cgroups v2 : hierarchie unifiee dans /sys/fs/cgroup/\n\n");

    /* Lire notre cgroup */
    FILE *fp = fopen("/proc/self/cgroup", "r");
    if (fp) {
        printf("    Notre cgroup (/proc/self/cgroup) :\n");
        char line[256];
        while (fgets(line, sizeof(line), fp))
            printf("      %s", line);
        fclose(fp);
        printf("\n");
    }

    /* Limites memoire (cgroups v2) */
    const char *mem_paths[] = {
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory.max",
        NULL
    };

    for (int i = 0; mem_paths[i]; i++) {
        fp = fopen(mem_paths[i], "r");
        if (fp) {
            char val[64] = {0};
            if (fgets(val, sizeof(val), fp)) {
                val[strcspn(val, "\n")] = '\0';
                printf("    Limite memoire (%s) : %s\n", mem_paths[i], val);
            }
            fclose(fp);
            break;
        }
    }

    /* Limites CPU */
    const char *cpu_paths[] = {
        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
        "/sys/fs/cgroup/cpu.max",
        NULL
    };

    for (int i = 0; cpu_paths[i]; i++) {
        fp = fopen(cpu_paths[i], "r");
        if (fp) {
            char val[64] = {0};
            if (fgets(val, sizeof(val), fp)) {
                val[strcspn(val, "\n")] = '\0';
                printf("    Limite CPU (%s) : %s\n", cpu_paths[i], val);
            }
            fclose(fp);
            break;
        }
    }
    printf("\n");
}

/*
 * Etape 6 : Points de montage et filesystem
 */
static void inspect_mounts(void) {
    printf("[*] Etape 6 : Points de montage\n\n");

    FILE *fp = fopen("/proc/self/mounts", "r");
    if (!fp) {
        printf("    (impossible de lire /proc/self/mounts)\n\n");
        return;
    }

    printf("    Points de montage interessants :\n");
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < 15) {
        /* Filtrer les montages interessants */
        if (strstr(line, "overlay") || strstr(line, "cgroup") ||
            strstr(line, "docker") || strstr(line, "tmpfs /run") ||
            strstr(line, "/ ")) {
            line[strcspn(line, "\n")] = '\0';
            /* Tronquer les longues lignes */
            if (strlen(line) > 80)
                line[80] = '\0';
            printf("      %s\n", line);
            count++;
        }
    }
    fclose(fp);

    if (count == 0)
        printf("      (aucun montage specifique aux containers)\n");
    printf("\n");
}

/*
 * Etape 7 : Capabilities
 */
static void inspect_capabilities(void) {
    printf("[*] Etape 7 : Capabilities du processus\n\n");

    printf("    Les containers ont des capabilities reduites par defaut.\n");
    printf("    Un container 'privileged' a TOUTES les capabilities.\n\n");

    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Cap", 3) == 0) {
            printf("    %s", line);
        }
    }
    fclose(fp);

    printf("\n    Decodage : capsh --decode=<hex_value>\n");
    printf("    Toutes les caps : 000001ffffffffff (privileged)\n");
    printf("    Docker default  : 00000000a80425fb\n\n");

    printf("    Capabilities dangereuses pour l'evasion :\n");
    printf("    - CAP_SYS_ADMIN    : mount, pivot_root, cgroups\n");
    printf("    - CAP_SYS_PTRACE   : ptrace sur l'hote\n");
    printf("    - CAP_SYS_RAWIO    : acces direct aux devices\n");
    printf("    - CAP_NET_ADMIN    : manipulation reseau\n");
    printf("    - CAP_DAC_OVERRIDE : ignorer les permissions fichier\n\n");
}

int main(void) {
    printf("[*] Demo : Container Basics\n\n");

    explain_container_architecture();
    explain_namespaces();
    inspect_current_namespaces();
    detect_container();
    inspect_cgroups();
    inspect_mounts();
    inspect_capabilities();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
