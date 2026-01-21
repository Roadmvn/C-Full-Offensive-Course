#ifndef SERVER_LISTENER_H
#define SERVER_LISTENER_H

#include "../utils/common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Créer socket d'écoute
int create_listener(int port);

// Accepter une connexion cliente
int accept_client(int listener_sock, char *client_ip, size_t ip_len);

// Fermer le listener
void close_listener(int listener_sock);

#endif // SERVER_LISTENER_H

