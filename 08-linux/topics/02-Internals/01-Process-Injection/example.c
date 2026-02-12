/*
 * OBJECTIF  : Comprendre l'injection de processus sous Linux avec ptrace
 * PREREQUIS : Bases C, ptrace, notion de memoire virtuelle
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre comment attacher un processus avec ptrace(),
 * lire/ecrire sa memoire, et inspecter ses registres.
 * Le programme cree un processus fils comme cible de demonstration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>

/*
 * Etape 1 : Processus cible (fils) qui tourne en boucle
 * On va l'attacher et inspecter sa memoire
 */
static void target_process(void) {
    volatile int counter = 0;

    printf("    [CIBLE] PID=%d, demarrage...\n", getpid());

    while (counter < 100) {
        counter++;
        usleep(100000);
    }

    printf("    [CIBLE] counter=%d\n", counter);
    _exit(0);
}

/*
 * Etape 2 : Attacher un processus avec PTRACE_ATTACH
 * Le processus cible est stoppe (SIGSTOP) apres l'attach
 */
static int attach_to_process(pid_t pid) {
    printf("\n[*] Etape 2 : Attacher au processus %d\n\n", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        printf("    [-] PTRACE_ATTACH echoue : %s\n", strerror(errno));
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFSTOPPED(status)) {
        printf("    [+] Processus %d stoppe (signal %d)\n", pid, WSTOPSIG(status));
    }

    return 0;
}

/*
 * Etape 3 : Lire la memoire d'un processus avec PTRACE_PEEKDATA
 * Lit un mot (8 octets sur x86_64) a une adresse donnee
 */
static long read_memory(pid_t pid, unsigned long addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (errno != 0) {
        printf("    [-] PEEKDATA echoue a 0x%lx : %s\n", addr, strerror(errno));
        return -1;
    }
    return data;
}

/*
 * Etape 4 : Ecrire dans la memoire d'un processus avec PTRACE_POKEDATA
 */
static int write_memory(pid_t pid, unsigned long addr, long data) {
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)data) < 0) {
        printf("    [-] POKEDATA echoue a 0x%lx : %s\n", addr, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Etape 5 : Lire les registres du processus cible
 * Les registres contiennent l'etat d'execution (RIP, RSP, RAX...)
 */
static void dump_registers(pid_t pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        printf("    [-] GETREGS echoue : %s\n", strerror(errno));
        return;
    }

    printf("    Registres du processus %d :\n", pid);
    printf("      RIP (instruction pointer) : 0x%llx\n", regs.rip);
    printf("      RSP (stack pointer)       : 0x%llx\n", regs.rsp);
    printf("      RBP (base pointer)        : 0x%llx\n", regs.rbp);
    printf("      RAX (return value)        : 0x%llx\n", regs.rax);
    printf("      RDI (1er argument)        : 0x%llx\n", regs.rdi);
    printf("      RSI (2eme argument)       : 0x%llx\n", regs.rsi);
}

/*
 * Etape 6 : Modifier les registres du processus cible
 */
static void demo_register_modification(pid_t pid) {
    printf("\n[*] Etape 6 : Modification des registres\n\n");

    struct user_regs_struct regs, saved_regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        printf("    [-] GETREGS echoue\n");
        return;
    }

    saved_regs = regs;

    printf("    RAX original : 0x%llx\n", regs.rax);

    regs.rax = 0x41414141;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == 0) {
        printf("    RAX modifie  : 0x%llx\n", regs.rax);
    }

    /* Restaurer les registres originaux */
    ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
    printf("    Registres restaures\n");
}

/*
 * Etape 7 : Lire les mappings memoire via /proc/pid/maps
 */
static void read_proc_maps(pid_t pid) {
    printf("\n[*] Etape 7 : Mappings memoire de PID %d\n\n", pid);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *maps = fopen(path, "r");
    if (!maps) {
        printf("    [-] Impossible d'ouvrir %s\n", path);
        return;
    }

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), maps) && count < 8) {
        printf("    %s", line);
        count++;
    }
    if (count >= 8)
        printf("    ... (tronque)\n");

    fclose(maps);
}

int main(void) {
    printf("[*] Demo : Injection de Processus Linux avec ptrace\n\n");

    /* Etape 1 : Creer un processus cible */
    printf("[*] Etape 1 : Creation du processus cible\n\n");

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        target_process();
    }

    printf("    [PARENT] Processus cible cree : PID=%d\n", child);
    usleep(200000);

    /* Etape 2 : Attacher au processus */
    if (attach_to_process(child) < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }

    /* Etape 3 : Lire la memoire */
    printf("\n[*] Etape 3 : Lecture memoire avec PTRACE_PEEKDATA\n\n");

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0) {
        unsigned long rsp = (unsigned long)regs.rsp;
        printf("    RSP du processus cible : 0x%lx\n", rsp);
        printf("    Lecture de la stack :\n");

        for (int i = 0; i < 4; i++) {
            long val = read_memory(child, rsp + (unsigned long)(i * 8));
            printf("      [RSP+%02d] 0x%016lx\n", i * 8, (unsigned long)val);
        }
    }

    /* Etape 4 : Ecrire dans la memoire */
    printf("\n[*] Etape 4 : Ecriture memoire avec PTRACE_POKEDATA\n\n");
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0) {
        unsigned long rsp = (unsigned long)regs.rsp;
        long original = read_memory(child, rsp);
        printf("    Valeur originale a RSP : 0x%lx\n", (unsigned long)original);

        write_memory(child, rsp, 0x4141414142424242L);
        long modified = read_memory(child, rsp);
        printf("    Valeur modifiee a RSP  : 0x%lx\n", (unsigned long)modified);

        write_memory(child, rsp, original);
        printf("    Valeur restauree\n");
    }

    /* Etape 5 : Dump des registres */
    printf("\n[*] Etape 5 : Dump des registres\n\n");
    dump_registers(child);

    /* Etape 6 : Modification des registres */
    demo_register_modification(child);

    /* Etape 7 : Mappings memoire */
    read_proc_maps(child);

    /* Detacher et terminer proprement */
    printf("\n[*] Detachement du processus\n");
    ptrace(PTRACE_DETACH, child, NULL, NULL);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    printf("    Processus cible termine\n\n");

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
