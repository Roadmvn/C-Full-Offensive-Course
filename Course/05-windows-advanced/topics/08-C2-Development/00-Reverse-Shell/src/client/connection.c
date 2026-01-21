#include "connection.h"

int DEBUG_MODE = 0;

// Établir connexion
int connect_to_server(const char *ip, int port) {
    DEBUG_PRINT("Connecting to %s:%d", ip, port);
    
    // Créer socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ERROR_PRINT("Socket creation failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    // Configuration serveur
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server.sin_addr) <= 0) {
        ERROR_PRINT("Invalid IP address: %s", ip);
        close(sock);
        return ERROR_CONNECT;
    }
    
    // Connexion
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        ERROR_PRINT("Connection failed: %s", strerror(errno));
        close(sock);
        return ERROR_CONNECT;
    }
    
    INFO_PRINT("Connected to %s:%d", ip, port);
    return sock;
}

// Envoyer données
int send_data(int sock, const unsigned char *data, size_t length) {
    ssize_t sent = send(sock, data, length, 0);
    if (sent < 0) {
        ERROR_PRINT("Send failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    DEBUG_PRINT("Sent %zd bytes", sent);
    return SUCCESS;
}

// Recevoir données
int receive_data(int sock, unsigned char *buffer, size_t max_length) {
    ssize_t received = recv(sock, buffer, max_length - 1, 0);
    if (received < 0) {
        ERROR_PRINT("Receive failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    if (received == 0) {
        INFO_PRINT("Connection closed by server");
        return 0;
    }
    
    buffer[received] = '\0';
    DEBUG_PRINT("Received %zd bytes", received);
    return received;
}

// Fermer connexion
void close_connection(int sock) {
    if (sock >= 0) {
        close(sock);
        DEBUG_PRINT("Connection closed");
    }
}

// Boucle de reconnexion
int reconnect_loop(const char *ip, int port, int retry_delay) {
    int attempts = 0;
    
    while (1) {
        attempts++;
        INFO_PRINT("Connection attempt #%d", attempts);
        
        int sock = connect_to_server(ip, port);
        if (sock >= 0) {
            return sock;  // Succès
        }
        
        INFO_PRINT("Retrying in %d seconds...", retry_delay);
        sleep(retry_delay);
    }
}

