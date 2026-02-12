/*
 * OBJECTIF  : Comprendre les techniques d'evasion sur Linux
 * PREREQUIS : Bases C, /proc, ELF, processus Linux
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques d'evasion Linux :
 * renommage de processus, suppression de fichier en cours
 * d'execution, anti-debugging, anti-VM, nettoyage de traces.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

/*
 * Etape 1 : Panorama des techniques d'evasion
 */
static void explain_evasion_overview(void) {
    printf("[*] Etape 1 : Techniques d'evasion Linux\n\n");

    printf("    ┌─────────────────────────────────────────────┐\n");
    printf("    │          EVASION TECHNIQUES                  │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── Process ──────────────────────┐       │\n");
    printf("    │  │ argv[0] rename                    │       │\n");
    printf("    │  │ prctl(PR_SET_NAME)                │       │\n");
    printf("    │  │ Masquerade as system process      │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── File ─────────────────────────┐       │\n");
    printf("    │  │ Delete self after exec             │       │\n");
    printf("    │  │ memfd_create (fileless)            │       │\n");
    printf("    │  │ Timestomping                      │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── Anti-analysis ────────────────┐       │\n");
    printf("    │  │ ptrace detection                  │       │\n");
    printf("    │  │ /proc/self/status TracerPid       │       │\n");
    printf("    │  │ Timing checks                     │       │\n");
    printf("    │  │ VM/Sandbox detection              │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── Anti-forensics ───────────────┐       │\n");
    printf("    │  │ Log cleaning                      │       │\n");
    printf("    │  │ History deletion                   │       │\n");
    printf("    │  │ Secure file deletion              │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    └─────────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Renommage de processus
 */
static void demo_process_rename(int argc, char *argv[]) {
    printf("[*] Etape 2 : Renommage de processus\n\n");

    /* Afficher le nom actuel */
    printf("    Nom actuel du processus :\n");
    printf("    PID     : %d\n", getpid());
    printf("    argv[0] : %s\n\n", argv[0]);

    printf("    Technique 1 : Modifier argv[0]\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Ecraser argv[0] avec un nom legitime\n");
    printf("    memset(argv[0], 0, strlen(argv[0]));\n");
    printf("    strcpy(argv[0], \"[kworker/0:1]\");\n");
    printf("    // Visible dans 'ps aux' et /proc/pid/cmdline\n\n");

    printf("    Technique 2 : prctl(PR_SET_NAME)\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <sys/prctl.h>\n");
    printf("    prctl(PR_SET_NAME, \"kworker/0:1\", 0, 0, 0);\n");
    printf("    // Modifie /proc/pid/comm (max 16 chars)\n\n");

    printf("    Technique 3 : Ecrire dans /proc/self/comm\n");
    printf("    ───────────────────────────────────\n");
    printf("    FILE *f = fopen(\"/proc/self/comm\", \"w\");\n");
    printf("    fputs(\"kworker/0:1\", f);\n");
    printf("    fclose(f);\n\n");

    /* Noms courants utilises pour le masquage */
    printf("    Noms de processus courants pour le masquage :\n");
    printf("    - [kworker/0:1]   (thread kernel)\n");
    printf("    - [migration/0]   (thread kernel)\n");
    printf("    - sshd            (service SSH)\n");
    printf("    - crond           (cron daemon)\n");
    printf("    - rsyslogd        (syslog)\n");
    printf("    - dbus-daemon     (D-Bus)\n\n");

    /* Demo : lire notre propre comm */
    printf("    Notre /proc/self/comm actuel :\n");
    FILE *fp = fopen("/proc/self/comm", "r");
    if (fp) {
        char comm[32] = {0};
        if (fgets(comm, sizeof(comm), fp))
            printf("    -> %s", comm);
        fclose(fp);
    } else {
        printf("    -> (impossible de lire /proc/self/comm)\n");
    }
    printf("\n");
}

/*
 * Etape 3 : Execution sans fichier (fileless)
 */
static void explain_fileless(void) {
    printf("[*] Etape 3 : Execution sans fichier (fileless)\n\n");

    printf("    Technique 1 : memfd_create()\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Creer un fichier en memoire (pas sur le disque)\n");
    printf("    int fd = memfd_create(\"\" , MFD_CLOEXEC);\n");
    printf("    // Ecrire l'ELF en memoire\n");
    printf("    write(fd, elf_payload, elf_size);\n");
    printf("    // L'executer via /proc/self/fd/N\n");
    printf("    char path[64];\n");
    printf("    snprintf(path, sizeof(path), \"/proc/self/fd/%%d\", fd);\n");
    printf("    execl(path, \"[kworker]\", NULL);\n\n");

    printf("    Technique 2 : Supprimer apres execution\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Le binaire continue de tourner meme supprime\n");
    printf("    // car le kernel garde le fd ouvert\n");
    printf("    unlink(argv[0]);  // Supprimer notre propre binaire\n");
    printf("    // /proc/pid/exe -> '(deleted)'\n\n");

    printf("    Technique 3 : Ecrire dans /dev/shm\n");
    printf("    ───────────────────────────────────\n");
    printf("    // /dev/shm est un tmpfs (RAM, pas de disque)\n");
    printf("    // Mais visible avec ls /dev/shm\n");
    printf("    cp payload /dev/shm/.cache\n");
    printf("    chmod +x /dev/shm/.cache\n");
    printf("    /dev/shm/.cache\n\n");

    /* Verifier si /dev/shm existe */
    struct stat st;
    if (stat("/dev/shm", &st) == 0)
        printf("    /dev/shm : present (tmpfs %s)\n\n",
               S_ISDIR(st.st_mode) ? "directory" : "?");
    else
        printf("    /dev/shm : non disponible\n\n");
}

/*
 * Etape 4 : Anti-debugging et anti-analysis
 */
static void demo_anti_debug(void) {
    printf("[*] Etape 4 : Detection de debugger et sandbox\n\n");

    printf("    Technique 1 : ptrace(PTRACE_TRACEME)\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Si deja debug, ptrace echoue\n");
    printf("    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {\n");
    printf("        // Debugger detecte !\n");
    printf("        exit(1);\n");
    printf("    }\n\n");

    /* Verifier TracerPid */
    printf("    Technique 2 : /proc/self/status\n");
    printf("    ───────────────────────────────────\n");
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer = atoi(line + 10);
                printf("    TracerPid : %d (%s)\n\n",
                       tracer, tracer ? "DEBUGGE !" : "pas de debugger");
                break;
            }
        }
        fclose(fp);
    } else {
        printf("    (impossible de lire /proc/self/status)\n\n");
    }

    printf("    Technique 3 : Timing check\n");
    printf("    ───────────────────────────────────\n");
    printf("    struct timespec t1, t2;\n");
    printf("    clock_gettime(CLOCK_MONOTONIC, &t1);\n");
    printf("    // ... code sensible ...\n");
    printf("    clock_gettime(CLOCK_MONOTONIC, &t2);\n");
    printf("    long delta = (t2.tv_sec - t1.tv_sec) * 1000000000\n");
    printf("                 + (t2.tv_nsec - t1.tv_nsec);\n");
    printf("    if (delta > 1000000)  // > 1ms = probablement debug\n");
    printf("        exit(1);\n\n");

    /* Demo timing */
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long delta = (t2.tv_sec - t1.tv_sec) * 1000000000L +
                 (t2.tv_nsec - t1.tv_nsec);
    printf("    Timing de 1000 iterations : %ld ns\n\n", delta);
}

/*
 * Etape 5 : Detection de VM et sandbox
 */
static void demo_vm_detection(void) {
    printf("[*] Etape 5 : Detection de VM et sandbox\n\n");

    printf("    Indicateurs de VM :\n");
    printf("    ───────────────────────────────────\n");

    /* Verifier DMI */
    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        NULL
    };

    for (int i = 0; dmi_files[i]; i++) {
        FILE *fp = fopen(dmi_files[i], "r");
        if (fp) {
            char val[128] = {0};
            if (fgets(val, sizeof(val), fp)) {
                val[strcspn(val, "\n")] = '\0';
                printf("    %s : %s", dmi_files[i], val);
                /* Checker les mots-cles VM */
                if (strstr(val, "Virtual") || strstr(val, "VMware") ||
                    strstr(val, "QEMU") || strstr(val, "VirtualBox") ||
                    strstr(val, "Xen") || strstr(val, "Hyper-V"))
                    printf(" [VM DETECTEE]");
                printf("\n");
            }
            fclose(fp);
        }
    }
    printf("\n");

    printf("    Autres indicateurs :\n");
    printf("    - /proc/cpuinfo : hypervisor flag\n");
    printf("    - MAC address   : prefixe VM (00:0C:29=VMware)\n");
    printf("    - Nombre de CPUs < 2\n");
    printf("    - RAM < 2 GB\n");
    printf("    - Disque < 50 GB\n");
    printf("    - /proc/scsi/scsi : VBOX, VMWARE\n\n");

    /* Verifier le nombre de CPUs */
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("    CPUs disponibles : %ld %s\n",
           cpus, cpus < 2 ? "(suspicieux)" : "(ok)");

    /* Verifier la RAM */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0) {
        long ram_mb = (pages * page_size) / (1024 * 1024);
        printf("    RAM totale      : %ld MB %s\n",
               ram_mb, ram_mb < 2048 ? "(suspicieux)" : "(ok)");
    }
    printf("\n");
}

/*
 * Etape 6 : Anti-forensics et nettoyage
 */
static void explain_anti_forensics(void) {
    printf("[*] Etape 6 : Anti-forensics et nettoyage de traces\n\n");

    printf("    Fichiers de logs a nettoyer :\n");
    printf("    ───────────────────────────────────\n");
    printf("    /var/log/auth.log      : authentifications\n");
    printf("    /var/log/syslog        : messages systeme\n");
    printf("    /var/log/wtmp          : connexions (binary)\n");
    printf("    /var/log/btmp          : echecs auth (binary)\n");
    printf("    /var/log/lastlog       : dernieres connexions\n");
    printf("    ~/.bash_history        : historique commandes\n\n");

    printf("    Techniques de nettoyage :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Supprimer les lignes specifiques des logs\n");
    printf("       sed -i '/attacker_ip/d' /var/log/auth.log\n\n");
    printf("    2. Truncate les fichiers binaires\n");
    printf("       > /var/log/wtmp\n\n");
    printf("    3. Desactiver l'historique\n");
    printf("       unset HISTFILE\n");
    printf("       export HISTSIZE=0\n\n");
    printf("    4. Timestomping (modifier les dates)\n");
    printf("       touch -r /bin/ls /tmp/malware  // copier le timestamp\n\n");
    printf("    5. Secure delete\n");
    printf("       shred -u -z -n 3 fichier\n\n");

    /* Demo : verifier si l'historique est active */
    printf("    Etat de l'historique shell :\n");
    char *histfile = getenv("HISTFILE");
    char *histsize = getenv("HISTSIZE");
    printf("    HISTFILE : %s\n", histfile ? histfile : "(non defini)");
    printf("    HISTSIZE : %s\n\n", histsize ? histsize : "(non defini)");
}

/*
 * Etape 7 : Detection des techniques d'evasion
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection des techniques d'evasion\n\n");

    printf("    Detecter le renommage de processus :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Comparer /proc/pid/comm et /proc/pid/exe\n");
    printf("    - Verifier si /proc/pid/exe -> (deleted)\n");
    printf("    - Comparer le hash du binaire avec rpm/dpkg\n\n");

    printf("    Detecter l'execution fileless :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - /proc/pid/exe pointe vers memfd: ou (deleted)\n");
    printf("    - Surveiller les appels memfd_create (auditd)\n");
    printf("    - Scanner /dev/shm pour des executables\n\n");

    printf("    Detecter l'anti-forensics :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Gaps dans les fichiers de log\n");
    printf("    - Timestamps incoherents (mtime < ctime)\n");
    printf("    - Fichiers de log vides alors qu'ils ne devraient pas\n\n");

    printf("    Outils :\n");
    printf("    - auditd          : audit des syscalls\n");
    printf("    - Sysmon for Linux : monitoring des processus\n");
    printf("    - Falco           : detection runtime\n");
    printf("    - osquery         : queries sur l'etat systeme\n");
    printf("    - YARA            : detection de patterns en memoire\n\n");
}

int main(int argc, char *argv[]) {
    printf("[*] Demo : Evasion Linux\n\n");

    explain_evasion_overview();
    demo_process_rename(argc, argv);
    explain_fileless();
    demo_anti_debug();
    demo_vm_detection();
    explain_anti_forensics();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
