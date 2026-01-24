#ifndef CLIENT_CONNECTION_H
#define CLIENT_CONNECTION_H

#include "../utils/common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Établir connexion au serveur
int connect_to_server(const char *ip, int port);

// Envoyer données
int send_data(int sock, const unsigned char *data, size_t length);

// Recevoir données
int receive_data(int sock, unsigned char *buffer, size_t max_length);

// Fermer connexion proprement
void close_connection(int sock);

// Reconnexion avec retry
int reconnect_loop(const char *ip, int port, int retry_delay);

#endif // CLIENT_CONNECTION_H

