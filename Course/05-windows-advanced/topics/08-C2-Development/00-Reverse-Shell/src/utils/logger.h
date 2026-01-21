#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

// Niveaux de log
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} LogLevel;

// Initialiser le logger
int logger_init(const char *logfile);

// Logger un message
void logger_log(LogLevel level, const char *format, ...);

// Fermer le logger
void logger_close();

#endif // LOGGER_H

