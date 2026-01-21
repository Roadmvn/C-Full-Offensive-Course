#include "handler.h"
#include <sys/socket.h>
#include <sys/select.h>

// Gérer session client
int handle_client(int client_sock, const char *client_ip) {
    INFO_PRINT("Handling client from %s", client_ip);
    
    // Envoyer message de bienvenue
    const char *welcome = "Shell connected. Type 'exit' to disconnect.\n";
    send(client_sock, welcome, strlen(welcome), 0);
    
    // Boucle interactive
    interactive_shell(client_sock);
    
    close(client_sock);
    INFO_PRINT("Client %s disconnected", client_ip);
    
    return SUCCESS;
}

// Envoyer commande
int send_command(int sock, const char *cmd) {
    ssize_t sent = send(sock, cmd, strlen(cmd), 0);
    if (sent < 0) {
        ERROR_PRINT("Send failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    return SUCCESS;
}

// Recevoir résultat
int receive_result(int sock, char *buffer, size_t max_length) {
    ssize_t received = recv(sock, buffer, max_length - 1, 0);
    if (received < 0) {
        ERROR_PRINT("Receive failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    if (received == 0) {
        INFO_PRINT("Client disconnected");
        return 0;
    }
    
    buffer[received] = '\0';
    return received;
}

// Shell interactif
void interactive_shell(int client_sock) {
    char buffer[BUFFER_SIZE];
    fd_set read_fds;
    
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║           SHELL INTERACTIF ACTIF             ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);  // Clavier
        FD_SET(client_sock, &read_fds);    // Socket
        
        int max_fd = (client_sock > STDIN_FILENO) ? client_sock : STDIN_FILENO;
        
        // Attendre données (clavier OU socket)
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            ERROR_PRINT("Select failed");
            break;
        }
        
        // Données depuis le clavier (commande à envoyer)
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                break;
            }
            
            // Vérifier commande exit
            if (strncmp(buffer, "exit", 4) == 0) {
                INFO_PRINT("Closing session...");
                break;
            }
            
            // Envoyer au client
            send(client_sock, buffer, strlen(buffer), 0);
        }
        
        // Données depuis le client (résultat)
        if (FD_ISSET(client_sock, &read_fds)) {
            int received = receive_result(client_sock, buffer, sizeof(buffer));
            if (received <= 0) {
                break;  // Connexion fermée
            }
            
            // Afficher résultat
            printf("%s", buffer);
            fflush(stdout);
        }
    }
}

