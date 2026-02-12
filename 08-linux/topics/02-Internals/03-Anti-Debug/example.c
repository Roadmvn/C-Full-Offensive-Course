/*
 * OBJECTIF  : Comprendre les techniques anti-debugging sous Linux
 * PREREQUIS : Bases C, ptrace, /proc filesystem
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques classiques pour detecter
 * la presence d'un debugger : ptrace self-attach, verification
 * de /proc/self/status, timing checks, et breakpoint detection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

/*
 * Technique 1 : ptrace(PTRACE_TRACEME)
 * Un processus ne peut etre trace que par UN seul debugger.
 * Si on se trace soi-meme, un debugger ne peut plus s'attacher.
 */
static int check_ptrace(void) {
    printf("[*] Technique 1 : ptrace(PTRACE_TRACEME)\n\n");

    /*
     * PTRACE_TRACEME signale au kernel que ce processus doit etre
     * trace par son parent. Si un debugger est deja attache,
     * cet appel echouera avec EPERM.
     */
    long result = ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    if (result < 0) {
        printf("    [!] DETECTE : ptrace echoue (errno=%d: %s)\n", errno, strerror(errno));
        printf("    Un debugger est probablement attache !\n\n");
        return 1;
    }

    printf("    [+] Aucun debugger detecte via ptrace\n");
    printf("    (Note: apres TRACEME, on ne peut plus ptrace ce processus)\n\n");
    return 0;
}

/*
 * Technique 2 : Lire /proc/self/status
 * Le champ TracerPid indique le PID du debugger attache
 */
static int check_tracer_pid(void) {
    printf("[*] Technique 2 : /proc/self/status (TracerPid)\n\n");

    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        printf("    [-] Impossible d'ouvrir /proc/self/status\n");
        printf("    (fonctionne uniquement sur Linux)\n\n");
        return -1;
    }

    char line[256];
    int tracer_pid = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            printf("    TracerPid: %d\n", tracer_pid);
            break;
        }
    }
    fclose(fp);

    if (tracer_pid > 0) {
        printf("    [!] DETECTE : Un debugger (PID=%d) est attache !\n\n", tracer_pid);
        return 1;
    }

    printf("    [+] TracerPid = 0 : aucun debugger attache\n\n");
    return 0;
}

/*
 * Technique 3 : Timing check
 * Un debugger introduit des delais notables entre les instructions
 * Si le temps d'execution d'un bloc simple est trop long -> debug
 */
static int check_timing(void) {
    printf("[*] Technique 3 : Timing check (rdtsc concept)\n\n");

    struct timespec start, end;

    /* Mesurer le temps d'execution d'un bloc simple */
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Operations simples qui devraient etre quasi instantanees */
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);

    printf("    Temps d'execution du bloc : %ld ns\n", elapsed_ns);

    /*
     * Seuil arbitraire : si > 10ms pour une boucle de 1000 additions,
     * c'est suspect (un step-by-step prendrait beaucoup plus)
     */
    long threshold = 10000000;  /* 10ms en nanosecondes */
    if (elapsed_ns > threshold) {
        printf("    [!] SUSPECT : temps anormalement long (> %ld ns)\n", threshold);
        printf("    Un debugger en mode step-by-step ?\n\n");
        return 1;
    }

    printf("    [+] Timing normal (< %ld ns)\n\n", threshold);
    return 0;
}

/*
 * Technique 4 : Verifier le nom du parent (ppid)
 * Sous un debugger, le parent est gdb/lldb/strace au lieu du shell
 */
static int check_parent_process(void) {
    printf("[*] Technique 4 : Verification du processus parent\n\n");

    pid_t ppid = getppid();
    printf("    Notre PID  : %d\n", getpid());
    printf("    Parent PID : %d\n", ppid);

    /* Lire le nom du parent via /proc */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", ppid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("    [-] Impossible de lire le nom du parent\n\n");
        return -1;
    }

    char parent_name[256];
    if (fgets(parent_name, sizeof(parent_name), fp)) {
        /* Supprimer le newline */
        parent_name[strcspn(parent_name, "\n")] = '\0';
        printf("    Nom du parent : %s\n", parent_name);

        /* Verifier si le parent est un debugger connu */
        const char *debuggers[] = {"gdb", "lldb", "strace", "ltrace", "radare2", "r2", NULL};
        for (int i = 0; debuggers[i]; i++) {
            if (strstr(parent_name, debuggers[i])) {
                printf("    [!] DETECTE : parent = %s (debugger connu)\n\n", parent_name);
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);

    printf("    [+] Parent ne semble pas etre un debugger\n\n");
    return 0;
}

/*
 * Technique 5 : Detection de breakpoints (INT3 = 0xCC)
 * Un debugger pose des breakpoints en remplacant des octets par 0xCC
 */
static int check_breakpoints(void) {
    printf("[*] Technique 5 : Detection de breakpoints (0xCC)\n\n");

    /* Verifier les premiers octets de nos propres fonctions */
    unsigned char *func_ptr = (unsigned char *)check_breakpoints;

    printf("    Premiers octets de check_breakpoints() : ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", func_ptr[i]);
    }
    printf("\n");

    /* Chercher 0xCC (INT3 = software breakpoint) */
    int found = 0;
    for (int i = 0; i < 64; i++) {
        if (func_ptr[i] == 0xCC) {
            printf("    [!] DETECTE : 0xCC trouve a l'offset %d !\n", i);
            printf("    Un breakpoint software est pose !\n");
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("    [+] Aucun breakpoint 0xCC detecte dans les 64 premiers octets\n");
    }
    printf("\n");
    return found;
}

/*
 * Technique 6 : Signal handler pour SIGTRAP
 * En execution normale, SIGTRAP n'arrive pas.
 * Sous debugger, le handler peut ne pas etre appele.
 */
static volatile int sigtrap_received = 0;

static void sigtrap_handler(int sig) {
    (void)sig;
    sigtrap_received = 1;
}

static int check_sigtrap(void) {
    printf("[*] Technique 6 : Test SIGTRAP\n\n");

    sigtrap_received = 0;

    /* Installer un handler pour SIGTRAP */
    struct sigaction sa, old_sa;
    sa.sa_handler = sigtrap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTRAP, &sa, &old_sa);

    /* Envoyer SIGTRAP a soi-meme */
    raise(SIGTRAP);

    /* Restaurer l'ancien handler */
    sigaction(SIGTRAP, &old_sa, NULL);

    if (sigtrap_received) {
        printf("    [+] SIGTRAP recu par notre handler (pas de debugger)\n\n");
        return 0;
    }

    printf("    [!] SIGTRAP intercepte par le debugger !\n\n");
    return 1;
}

int main(void) {
    printf("[*] Demo : Techniques Anti-Debug Linux\n\n");

    int detections = 0;

    detections += (check_ptrace() > 0);
    detections += (check_tracer_pid() > 0);
    detections += (check_timing() > 0);
    detections += (check_parent_process() > 0);
    detections += (check_breakpoints() > 0);
    detections += (check_sigtrap() > 0);

    printf("    =============================================\n");
    printf("    Resultat : %d technique(s) ont detecte un debugger\n", detections);
    if (detections > 0)
        printf("    [!] Un debugger est probablement actif\n");
    else
        printf("    [+] Aucun debugger detecte\n");
    printf("    =============================================\n\n");

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
