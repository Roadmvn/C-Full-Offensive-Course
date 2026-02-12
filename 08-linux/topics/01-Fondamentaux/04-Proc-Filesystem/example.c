/*
 * OBJECTIF  : Comprendre le systeme de fichiers /proc sous Linux
 * PREREQUIS : Bases C, lecture de fichiers, connaissance des processus
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre comment lire les informations du systeme
 * et des processus via le pseudo-filesystem /proc sans utiliser
 * de commandes comme ps, netstat ou lsof.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>

/* Lit et affiche le contenu d'un fichier /proc */
static void read_proc_file(const char *path, const char *label) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("  [-] Impossible de lire %s\n", path);
        return;
    }

    printf("  [+] %s (%s) :\n", label, path);

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < 10) {
        printf("      %s", line);
        count++;
    }
    if (count == 10)
        printf("      ... (tronque)\n");

    fclose(fp);
    printf("\n");
}

/* Lit la ligne de commande d'un processus via /proc/[pid]/cmdline
 * cmdline utilise des \0 comme separateurs au lieu d'espaces */
static void read_cmdline(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *fp = fopen(path, "r");
    if (!fp)
        return;

    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);

    if (n == 0)
        return;

    /* Remplacer les \0 internes par des espaces pour l'affichage */
    for (size_t i = 0; i < n - 1; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }
    buf[n] = '\0';

    printf("    PID %-6d : %s\n", pid, buf);
}

/* Enumere les processus en parcourant /proc
 * Chaque sous-dossier dont le nom est un nombre = un processus */
static void enumerate_processes(void) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        perror("opendir /proc");
        return;
    }

    printf("[*] Etape 3 : Enumeration des processus via /proc\n");
    printf("    (equivalent de 'ps' sans executer de commande)\n\n");

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < 15) {
        /* Verifier si le nom du dossier est un nombre (= un PID) */
        int is_pid = 1;
        for (int i = 0; entry->d_name[i]; i++) {
            if (!isdigit((unsigned char)entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }

        if (is_pid) {
            pid_t pid = (pid_t)atoi(entry->d_name);
            read_cmdline(pid);
            count++;
        }
    }

    if (count == 15)
        printf("    ... (limite a 15 processus)\n");

    closedir(dir);
    printf("\n");
}

/* Lit les variables d'environnement d'un processus
 * /proc/[pid]/environ contient des paires KEY=VALUE separees par \0 */
static void read_environ(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("  [-] Impossible de lire %s (permissions)\n", path);
        return;
    }

    printf("[*] Variables d'environnement de PID %d :\n", pid);

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    /* Chaque variable est terminee par \0 */
    int count = 0;
    char *ptr = buf;
    while (ptr < buf + n && count < 8) {
        if (*ptr) {
            printf("    %s\n", ptr);
            ptr += strlen(ptr) + 1;
            count++;
        } else {
            ptr++;
        }
    }
    if (count == 8)
        printf("    ... (tronque)\n");
    printf("\n");
}

/* Lit les mappings memoire de notre propre processus */
static void read_memory_maps(void) {
    printf("[*] Etape 5 : Memory maps du processus courant\n");
    printf("    (equivalent de 'pmap' ou lecture de /proc/self/maps)\n\n");

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        printf("  [-] Impossible de lire /proc/self/maps\n");
        return;
    }

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < 10) {
        printf("    %s", line);
        count++;
    }
    printf("    ... (tronque)\n\n");
    fclose(fp);
}

/* Lit le lien symbolique /proc/[pid]/exe pour trouver l'executable */
static void read_exe_link(pid_t pid) {
    char path[256], target[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        printf("    Executable : %s\n", target);
    } else {
        printf("    Executable : (non accessible)\n");
    }
}

int main(void) {
    printf("[*] Demo : Proc Filesystem - Espionner le systeme via /proc\n\n");

    /* Etape 1 : Informations systeme globales */
    printf("[*] Etape 1 : Informations systeme globales\n\n");
    read_proc_file("/proc/version", "Version du kernel");
    read_proc_file("/proc/cpuinfo", "Informations CPU");
    read_proc_file("/proc/meminfo", "Informations memoire");

    /* Etape 2 : Informations sur notre propre processus via /proc/self */
    printf("[*] Etape 2 : Notre propre processus (/proc/self)\n\n");

    pid_t mypid = getpid();
    printf("    Notre PID : %d\n", mypid);
    read_exe_link(mypid);

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", mypid);
    read_proc_file(path, "Status du processus");

    /* Etape 3 : Enumeration des processus */
    enumerate_processes();

    /* Etape 4 : Variables d'environnement de notre processus */
    printf("[*] Etape 4 : Variables d'environnement\n\n");
    read_environ(mypid);

    /* Etape 5 : Memory maps */
    read_memory_maps();

    /* Etape 6 : Fichiers ouverts (file descriptors) */
    printf("[*] Etape 6 : File descriptors ouverts\n\n");

    snprintf(path, sizeof(path), "/proc/%d/fd", mypid);
    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;

            char fd_path[512], target[256];
            snprintf(fd_path, sizeof(fd_path), "%s/%s", path, entry->d_name);
            ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                printf("    fd %s -> %s\n", entry->d_name, target);
            }
        }
        closedir(dir);
    }
    printf("\n");

    /* Etape 7 : Informations reseau */
    printf("[*] Etape 7 : Connexions reseau via /proc\n");
    printf("    (equivalent de 'netstat' sans executer de commande)\n\n");
    read_proc_file("/proc/net/tcp", "Connexions TCP");
    read_proc_file("/proc/net/udp", "Connexions UDP");

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
