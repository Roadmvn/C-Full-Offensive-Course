#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sqlite3.h>

// Vérifier statut TCC
void check_tcc_access(const char *service) {
    char *home = getenv("HOME");
    char db_path[512];
    snprintf(db_path, sizeof(db_path),
             "%s/Library/Application Support/com.apple.TCC/TCC.db",
             home);
    
    sqlite3 *db;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        printf("Cannot open TCC database\n");
        return;
    }
    
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT allowed FROM access WHERE service='%s'",
             service);
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int allowed = sqlite3_column_int(stmt, 0);
            printf("TCC %s: %s\n", service, 
                   allowed ? "ALLOWED" : "DENIED");
        } else {
            printf("TCC %s: NOT REQUESTED\n", service);
        }
        sqlite3_finalize(stmt);
    }
    
    sqlite3_close(db);
}

// Vérifier SIP status
void check_sip() {
    printf("\n=== SIP STATUS ===\n");
    system("csrutil status");
}

// Vérifier code signing
void check_codesign() {
    printf("\n=== CODE SIGNING ===\n");
    
    char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        char cmd[1536];
        snprintf(cmd, sizeof(cmd), "codesign -dv %s 2>&1", path);
        system(cmd);
    }
}

int main() {
    printf("=== macOS EVASION CHECKS ===\n\n");
    
    check_tcc_access("kTCCServiceCamera");
    check_tcc_access("kTCCServiceMicrophone");
    check_tcc_access("kTCCServiceScreenCapture");
    
    check_sip();
    check_codesign();
    
    return 0;
}

/*
 * Compilation:
 * clang example.c -o example -lsqlite3
 *
 * TCC Bypass techniques:
 * 1. Injection dans app autorisée
 * 2. Synthetic events (si Accessibility accordé)
 * 3. Exploitation bugs TCC
 *
 * SIP: Vérifié avec csrutil status
 * Désactiver (dev uniquement): csrutil disable (recovery mode)
 */
