#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

// Configuration réseau
#define BUFFER_SIZE 4096
#define MAX_CMD_SIZE 1024
#define MAGIC_BYTES 0xDEADBEEF

// Codes de retour
#define SUCCESS 0
#define ERROR_SOCKET -1
#define ERROR_CONNECT -2
#define ERROR_MEMORY -3
#define ERROR_CRYPTO -4

// Types de messages (protocole)
typedef enum {
    MSG_COMMAND = 0x01,
    MSG_RESULT = 0x02,
    MSG_HEARTBEAT = 0x03,
    MSG_ERROR = 0x04,
    MSG_DISCONNECT = 0x05
} MessageType;

// Structure d'un message
typedef struct {
    unsigned int magic;       // 0xDEADBEEF (vérification)
    MessageType type;         // Type de message
    unsigned int length;      // Longueur des données
    unsigned char checksum;   // Checksum simple
    unsigned char data[BUFFER_SIZE];  // Données
} Message;

// Macros utiles
#define DEBUG_PRINT(fmt, ...) \
    do { if (DEBUG_MODE) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

#define ERROR_PRINT(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

#define INFO_PRINT(fmt, ...) \
    fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)

// Variables globales
extern int DEBUG_MODE;

#endif // COMMON_H

