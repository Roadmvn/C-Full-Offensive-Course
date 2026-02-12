/*
 * OBJECTIF  : Comprendre le masquage de processus au niveau kernel
 * PREREQUIS : Bases C, LKM, syscall hooking, /proc filesystem
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de masquage de processus :
 * manipulation de task_struct, hook de getdents64 sur /proc,
 * et comment les rootkits cachent leurs processus du systeme.
 * Demonstration pedagogique en userspace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>

/*
 * Etape 1 : Comment les processus sont visibles
 */
static void explain_process_visibility(void) {
    printf("[*] Etape 1 : Visibilite des processus Linux\n\n");

    printf("    Les processus sont visibles via :\n\n");

    printf("    ┌─────────────────────────────────────────────────┐\n");
    printf("    │  /proc/                                         │\n");
    printf("    │  ├── 1/        <- init/systemd                  │\n");
    printf("    │  ├── 2/        <- kthreadd                      │\n");
    printf("    │  ├── 1234/     <- un processus utilisateur      │\n");
    printf("    │  │   ├── comm          (nom du processus)       │\n");
    printf("    │  │   ├── cmdline       (ligne de commande)      │\n");
    printf("    │  │   ├── status        (etat, PID, UID...)      │\n");
    printf("    │  │   ├── maps          (memoire mappee)         │\n");
    printf("    │  │   └── fd/           (descripteurs de fichier)│\n");
    printf("    │  └── ...                                        │\n");
    printf("    └─────────────────────────────────────────────────┘\n\n");

    printf("    Outils qui lisent /proc :\n");
    printf("    - ps       : appelle getdents64() sur /proc\n");
    printf("    - top/htop : lit /proc/<pid>/stat\n");
    printf("    - pgrep    : itere sur /proc\n");
    printf("    - ls /proc : appelle getdents64()\n\n");

    printf("    Pour cacher un processus, il suffit de :\n");
    printf("    -> Filtrer les resultats de getdents64() sur /proc\n");
    printf("    -> Supprimer le PID des entrees retournees\n\n");
}

/*
 * Etape 2 : Technique de masquage kernel
 */
static void explain_kernel_hiding(void) {
    printf("[*] Etape 2 : Techniques de masquage kernel\n\n");

    printf("    Technique 1 : Hook de getdents64()\n");
    printf("    ─────────────────────────────────────\n");
    printf("    hooked_getdents64() {\n");
    printf("        ret = orig_getdents64(fd, dirent, count);\n");
    printf("        // Pour chaque entree dans /proc :\n");
    printf("        // Si d_name == \"<PID_A_CACHER>\" :\n");
    printf("        //   Supprimer l'entree du buffer\n");
    printf("        //   Decrementer ret de d_reclen\n");
    printf("        return ret;\n");
    printf("    }\n\n");

    printf("    Technique 2 : Manipulation de task_struct\n");
    printf("    ─────────────────────────────────────\n");
    printf("    // Retirer le processus de la liste des taches\n");
    printf("    struct task_struct *task;\n");
    printf("    for_each_process(task) {\n");
    printf("        if (task->pid == hidden_pid) {\n");
    printf("            list_del(&task->tasks);  // Plus dans la liste\n");
    printf("            break;\n");
    printf("        }\n");
    printf("    }\n");
    printf("    // ATTENTION : peut rendre le processus unkillable\n\n");

    printf("    Technique 3 : Hook de /proc/pid/status\n");
    printf("    ─────────────────────────────────────\n");
    printf("    // Hooker seq_show() pour /proc/<pid>\n");
    printf("    // Retourner 0 (rien) pour les PIDs caches\n\n");
}

/*
 * Etape 3 : Simulation userspace - lister les processus
 */
static void demo_process_listing(void) {
    printf("[*] Etape 3 : Listing des processus (simulation)\n\n");

    DIR *dir = opendir("/proc");
    if (!dir) {
        printf("    (impossible d'ouvrir /proc)\n\n");
        return;
    }

    printf("    %-8s %-20s %s\n", "PID", "Comm", "Cmdline (debut)");
    printf("    %-8s %-20s %s\n", "────────", "────────────────────",
           "────────────────────");

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) && count < 12) {
        /* Seuls les repertoires numeriques sont des processus */
        if (!isdigit(entry->d_name[0]))
            continue;

        char path[128], buf[128] = {0};

        /* Lire le nom */
        snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
        FILE *fp = fopen(path, "r");
        char comm[32] = "?";
        if (fp) {
            if (fgets(comm, sizeof(comm), fp))
                comm[strcspn(comm, "\n")] = '\0';
            fclose(fp);
        }

        /* Lire la cmdline */
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        fp = fopen(path, "r");
        char cmdline[64] = "";
        if (fp) {
            size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
            fclose(fp);
            for (size_t i = 0; i < n; i++)
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            cmdline[50] = '\0';
        }

        printf("    %-8s %-20s %s\n", entry->d_name, comm, cmdline);
        count++;
    }
    closedir(dir);
    printf("    ... (tronque)\n\n");
}

/*
 * Etape 4 : Simulation de masquage (userspace)
 */
static void demo_hiding_simulation(void) {
    printf("[*] Etape 4 : Simulation de masquage de processus\n\n");

    pid_t my_pid = getpid();
    printf("    Notre PID : %d\n\n", my_pid);

    printf("    Simulation : filtrer getdents64 pour cacher PID %d\n\n", my_pid);

    DIR *dir = opendir("/proc");
    if (!dir) return;

    char hidden_pid_str[16];
    snprintf(hidden_pid_str, sizeof(hidden_pid_str), "%d", my_pid);

    printf("    Processus VISIBLES (sans le notre) :\n");
    struct dirent *entry;
    int count = 0;
    int total = 0;
    int hidden = 0;
    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0]))
            continue;
        total++;

        /* Simuler le filtrage : si c'est notre PID, on le cache */
        if (strcmp(entry->d_name, hidden_pid_str) == 0) {
            hidden = 1;
            continue;
        }
        if (count < 8) {
            printf("      /proc/%s/\n", entry->d_name);
            count++;
        }
    }
    closedir(dir);

    printf("      ...\n");
    printf("    Total : %d processus affiches (%d avec le cache)\n",
           total - (hidden ? 1 : 0), total);
    if (hidden)
        printf("    [!] PID %d a ete FILTRE de la liste !\n", my_pid);
    printf("\n");
}

/*
 * Etape 5 : Detection du masquage
 */
static void explain_detection(void) {
    printf("[*] Etape 5 : Detection du masquage de processus\n\n");

    printf("    Techniques de detection :\n\n");

    printf("    1. Comparer /proc avec la syscall table directe\n");
    printf("       -> Appeler directement le syscall getdents64\n");
    printf("       -> Comparer avec readdir() de glibc\n\n");

    printf("    2. Scanner les PIDs sequentiellement\n");
    printf("       for pid in range(1, pid_max):\n");
    printf("           if kill(pid, 0) == 0 and not in /proc:\n");
    printf("               PROCESS CACHE DETECTE !\n\n");

    printf("    3. Examiner /proc/net/tcp pour des connexions\n");
    printf("       de processus invisibles\n\n");

    printf("    4. Outils :\n");
    printf("       - unhide : detecte les processus caches\n");
    printf("       - rkhunter : verifie l'integrite du systeme\n");
    printf("       - LKRG : detection de hooks en temps reel\n\n");

    /* Demonstration : tester kill(0) sur des PIDs */
    printf("    Test rapide (kill -0 sur des PIDs) :\n");
    int visible = 0, hidden_count = 0;
    for (int pid = 1; pid < 100; pid++) {
        if (kill(pid, 0) == 0 || errno == EPERM) {
            /* Le processus existe */
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d", pid);
            if (access(path, F_OK) != 0) {
                printf("      [!] PID %d existe mais PAS dans /proc !\n", pid);
                hidden_count++;
            } else {
                visible++;
            }
        }
    }
    printf("    PIDs 1-99 : %d visibles, %d caches\n\n",
           visible, hidden_count);
}

int main(void) {
    printf("[*] Demo : Process Hiding (Kernel Level)\n\n");

    explain_process_visibility();
    explain_kernel_hiding();
    demo_process_listing();
    demo_hiding_simulation();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
