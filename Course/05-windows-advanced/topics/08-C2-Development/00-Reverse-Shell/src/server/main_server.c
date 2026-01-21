#include "listener.h"
#include "handler.h"

#define DEFAULT_PORT 4444

int main(int argc, char **argv) {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   REVERSE SHELL SERVER (Usage Éducatif)      ║\n");
    printf("║                                              ║\n");
    printf("║   ⚠️  TESTS SUR VOS MACHINES UNIQUEMENT     ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    
    // Créer listener
    int listener = create_listener(port);
    if (listener < 0) {
        return 1;
    }
    
    // Boucle d'acceptation
    while (1) {
        char client_ip[INET_ADDRSTRLEN];
        
        int client_sock = accept_client(listener, client_ip, sizeof(client_ip));
        
        if (client_sock < 0) {
            continue;
        }
        
        // Gérer le client
        handle_client(client_sock, client_ip);
        
        INFO_PRINT("Ready for next client...");
    }
    
    close_listener(listener);
    return 0;
}

