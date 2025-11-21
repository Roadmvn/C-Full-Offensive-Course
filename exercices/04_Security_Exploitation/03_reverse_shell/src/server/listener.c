#include "listener.h"

// Créer socket d'écoute
int create_listener(int port) {
    INFO_PRINT("Creating listener on port %d", port);
    
    // Créer socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ERROR_PRINT("Socket creation failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    // Option SO_REUSEADDR (réutiliser port immédiatement)
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ERROR_PRINT("setsockopt failed: %s", strerror(errno));
        close(sock);
        return ERROR_SOCKET;
    }
    
    // Configuration adresse
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  // Toutes les interfaces
    addr.sin_port = htons(port);
    
    // Bind
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ERROR_PRINT("Bind failed: %s", strerror(errno));
        close(sock);
        return ERROR_SOCKET;
    }
    
    // Listen
    if (listen(sock, 5) < 0) {
        ERROR_PRINT("Listen failed: %s", strerror(errno));
        close(sock);
        return ERROR_SOCKET;
    }
    
    INFO_PRINT("Listening on 0.0.0.0:%d", port);
    return sock;
}

// Accepter client
int accept_client(int listener_sock, char *client_ip, size_t ip_len) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    INFO_PRINT("Waiting for client connection...");
    
    int client_sock = accept(listener_sock, (struct sockaddr *)&client_addr, &addr_len);
    
    if (client_sock < 0) {
        ERROR_PRINT("Accept failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    // Extraire IP du client
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, ip_len);
    
    INFO_PRINT("Client connected from %s:%d", client_ip, ntohs(client_addr.sin_port));
    
    return client_sock;
}

// Fermer listener
void close_listener(int listener_sock) {
    if (listener_sock >= 0) {
        close(listener_sock);
        INFO_PRINT("Listener closed");
    }
}

