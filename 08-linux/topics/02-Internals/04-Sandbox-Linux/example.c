/*
 * OBJECTIF  : Comprendre la detection et l'evasion de sandbox Linux
 * PREREQUIS : Bases C, namespaces, /proc filesystem
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre comment detecter si on s'execute dans
 * un container (Docker/LXC), une sandbox seccomp, ou une VM,
 * et les techniques de fingerprinting d'environnement.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>
#include <fcntl.h>

/*
 * Technique 1 : Detecter Docker via /.dockerenv et /proc/1/cgroup
 * Docker cree un fichier /.dockerenv dans le container
 */
static int check_docker(void) {
    printf("[*] Technique 1 : Detection Docker\n\n");

    int detected = 0;

    /* Verifier /.dockerenv */
    if (access("/.dockerenv", F_OK) == 0) {
        printf("    [!] /.dockerenv existe -> probablement Docker\n");
        detected = 1;
    } else {
        printf("    [+] /.dockerenv absent\n");
    }

    /* Verifier /proc/1/cgroup pour les marqueurs docker */
    FILE *fp = fopen("/proc/1/cgroup", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "docker") || strstr(line, "lxc") ||
                strstr(line, "kubepods") || strstr(line, "containerd")) {
                line[strcspn(line, "\n")] = '\0';
                printf("    [!] cgroup container : %s\n", line);
                detected = 1;
                break;
            }
        }
        fclose(fp);
    }

    if (!detected)
        printf("    [+] Aucun marqueur Docker/LXC/Kubernetes detecte dans cgroups\n");

    printf("\n");
    return detected;
}

/*
 * Technique 2 : Verifier le PID namespace
 * Dans un container, PID 1 est souvent le processus d'entree du container
 * et pas systemd/init
 */
static int check_pid_namespace(void) {
    printf("[*] Technique 2 : Verification du PID namespace\n\n");

    /* Lire le nom du PID 1 */
    FILE *fp = fopen("/proc/1/comm", "r");
    if (fp) {
        char comm[256];
        if (fgets(comm, sizeof(comm), fp)) {
            comm[strcspn(comm, "\n")] = '\0';
            printf("    PID 1 = %s\n", comm);

            /* systemd ou init = hote reel, autre = container probable */
            if (strcmp(comm, "systemd") != 0 && strcmp(comm, "init") != 0) {
                printf("    [!] PID 1 n'est pas systemd/init -> container probable\n");
                fclose(fp);
                printf("\n");
                return 1;
            }
        }
        fclose(fp);
    }

    printf("    [+] PID 1 semble normal\n\n");
    return 0;
}

/*
 * Technique 3 : Verifier les ressources systeme
 * Les containers ont souvent des ressources limitees
 */
static void check_resources(void) {
    printf("[*] Technique 3 : Verification des ressources\n\n");

    /* Nombre de CPUs */
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    printf("    CPUs disponibles : %ld\n", nprocs);
    if (nprocs <= 1)
        printf("      [?] Un seul CPU - possible container avec limites\n");

    /* Memoire totale */
    long page_size = sysconf(_SC_PAGESIZE);
    long pages = sysconf(_SC_PHYS_PAGES);
    long total_mb = (pages * page_size) / (1024 * 1024);
    printf("    Memoire totale   : %ld MB\n", total_mb);
    if (total_mb < 512)
        printf("      [?] Peu de memoire - possible container/VM limitee\n");

    /* Espace disque */
    FILE *fp = fopen("/proc/mounts", "r");
    if (fp) {
        char line[512];
        int overlay_found = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "overlay") || strstr(line, "aufs")) {
                printf("    [!] Filesystem overlay detecte (typique Docker)\n");
                overlay_found = 1;
                break;
            }
        }
        if (!overlay_found)
            printf("    [+] Pas de filesystem overlay detecte\n");
        fclose(fp);
    }
    printf("\n");
}

/*
 * Technique 4 : Detecter une VM via DMI/SMBIOS
 * Les hyperviseurs laissent des traces dans le hardware info
 */
static int check_vm(void) {
    printf("[*] Technique 4 : Detection de VM (hyperviseur)\n\n");

    int detected = 0;

    /* Verifier /sys/class/dmi/id/ */
    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        NULL
    };

    const char *vm_markers[] = {
        "VirtualBox", "VMware", "QEMU", "KVM",
        "Xen", "Hyper-V", "Parallels", "innotek",
        "Microsoft Corporation", NULL
    };

    for (int i = 0; dmi_files[i]; i++) {
        FILE *fp = fopen(dmi_files[i], "r");
        if (!fp)
            continue;

        char content[256];
        if (fgets(content, sizeof(content), fp)) {
            content[strcspn(content, "\n")] = '\0';
            printf("    %s : %s\n", dmi_files[i], content);

            for (int j = 0; vm_markers[j]; j++) {
                if (strstr(content, vm_markers[j])) {
                    printf("      [!] Marqueur VM detecte : %s\n", vm_markers[j]);
                    detected = 1;
                }
            }
        }
        fclose(fp);
    }

    /* Verifier aussi le modele CPU pour QEMU/KVM */
    FILE *cpu_fp = fopen("/proc/cpuinfo", "r");
    if (cpu_fp) {
        char line[512];
        while (fgets(line, sizeof(line), cpu_fp)) {
            if (strstr(line, "model name")) {
                if (strstr(line, "QEMU") || strstr(line, "KVM")) {
                    printf("    [!] CPU virtuel detecte : %s", line);
                    detected = 1;
                }
                break;
            }
        }
        fclose(cpu_fp);
    }

    if (!detected)
        printf("    [+] Aucun marqueur de VM detecte\n");

    printf("\n");
    return detected;
}

/*
 * Technique 5 : Verifier seccomp (sandbox au niveau syscalls)
 * /proc/self/status contient le champ Seccomp
 */
static int check_seccomp(void) {
    printf("[*] Technique 5 : Detection seccomp\n\n");

    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        printf("    [-] Impossible de lire /proc/self/status\n\n");
        return -1;
    }

    char line[256];
    int seccomp_mode = -1;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            seccomp_mode = atoi(line + 8);
            break;
        }
    }
    fclose(fp);

    printf("    Seccomp mode : ");
    switch (seccomp_mode) {
    case 0:
        printf("0 (desactive)\n");
        printf("    [+] Aucun filtre seccomp actif\n");
        break;
    case 1:
        printf("1 (strict)\n");
        printf("    [!] Mode strict : seuls read/write/exit/sigreturn autorises\n");
        break;
    case 2:
        printf("2 (filter)\n");
        printf("    [!] Filtre BPF actif : certains syscalls sont bloques\n");
        break;
    default:
        printf("inconnu (%d)\n", seccomp_mode);
    }

    printf("\n");
    return (seccomp_mode > 0) ? 1 : 0;
}

/*
 * Technique 6 : Informations systeme generales
 */
static void show_system_info(void) {
    printf("[*] Technique 6 : Informations systeme\n\n");

    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("    System  : %s\n", uts.sysname);
        printf("    Node    : %s\n", uts.nodename);
        printf("    Release : %s\n", uts.release);
        printf("    Machine : %s\n", uts.machine);
    }

    /* Uptime */
    FILE *fp = fopen("/proc/uptime", "r");
    if (fp) {
        double uptime;
        if (fscanf(fp, "%lf", &uptime) == 1) {
            printf("    Uptime  : %.0f secondes (%.1f heures)\n", uptime, uptime / 3600);
            if (uptime < 300)
                printf("      [?] Uptime tres court (< 5min) - sandbox recente ?\n");
        }
        fclose(fp);
    }

    printf("\n");
}

int main(void) {
    printf("[*] Demo : Detection de Sandbox Linux\n\n");

    int score = 0;

    score += check_docker();
    score += check_pid_namespace();
    check_resources();
    score += check_vm();
    score += check_seccomp();
    show_system_info();

    printf("    =============================================\n");
    printf("    Score de detection : %d/4\n", score);
    if (score >= 2)
        printf("    [!] Environnement sandbox/container probable\n");
    else if (score == 1)
        printf("    [?] Un indicateur suspect detecte\n");
    else
        printf("    [+] Environnement semble etre un hote reel\n");
    printf("    =============================================\n\n");

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
