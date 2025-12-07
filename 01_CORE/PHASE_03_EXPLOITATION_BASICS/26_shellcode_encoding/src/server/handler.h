#ifndef SERVER_HANDLER_H
#define SERVER_HANDLER_H

#include "../utils/common.h"

// Gérer une session client
int handle_client(int client_sock, const char *client_ip);

// Envoyer une commande au client
int send_command(int sock, const char *cmd);

// Recevoir résultat du client
int receive_result(int sock, char *buffer, size_t max_length);

// Boucle interactive
void interactive_shell(int client_sock);

#endif // SERVER_HANDLER_H

