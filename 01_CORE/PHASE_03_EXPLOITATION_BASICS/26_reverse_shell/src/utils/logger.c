#include "logger.h"
#include <stdarg.h>

static FILE *log_file = NULL;
static LogLevel current_level = LOG_INFO;

// Noms des niveaux
static const char *level_names[] = {
    "DEBUG", "INFO", "WARNING", "ERROR"
};

// Initialiser
int logger_init(const char *logfile) {
    log_file = fopen(logfile, "a");
    if (log_file == NULL) {
        ERROR_PRINT("Cannot open log file: %s", logfile);
        return ERROR_SOCKET;
    }
    return SUCCESS;
}

// Logger
void logger_log(LogLevel level, const char *format, ...) {
    if (level < current_level) return;
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
    
    // Format du message
    fprintf(log_file ? log_file : stderr, "[%s] [%s] ", 
            timestamp, level_names[level]);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file ? log_file : stderr, format, args);
    va_end(args);
    
    fprintf(log_file ? log_file : stderr, "\n");
    fflush(log_file);
}

// Fermer
void logger_close() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

