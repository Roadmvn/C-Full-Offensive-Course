/*
 * =============================================================================
 * File Operations Linux - Exfiltration Example
 * =============================================================================
 *
 * Description : Scanner recursif de fichiers sensibles
 *
 * Compilation :
 *   gcc example.c -o file_hunter
 *
 * Usage :
 *   ./file_hunter /home
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PATH 4096

// Patterns a rechercher
const char *sensitive_patterns[] = {
    "password", "passwd", "pwd",
    "secret", "token", "api_key",
    "private", "credential", "auth",
    ".ssh", ".aws", ".docker",
    NULL
};

// Extensions interessantes
const char *interesting_ext[] = {
    ".conf", ".config", ".cfg",
    ".key", ".pem", ".ppk",
    ".sql", ".db", ".sqlite",
    ".env", ".ini", ".yaml", ".yml",
    NULL
};

/*
 * Verifie si un fichier est interessant
 */
int is_interesting_file(const char *filename) {
    // Verifier patterns sensibles
    for (int i = 0; sensitive_patterns[i]; i++) {
        if (strstr(filename, sensitive_patterns[i])) {
            return 1;
        }
    }

    // Verifier extensions
    for (int i = 0; interesting_ext[i]; i++) {
        if (strstr(filename, interesting_ext[i])) {
            return 1;
        }
    }

    return 0;
}

/*
 * Scanner recursif de repertoires
 */
void scan_directory(const char *path, int depth) {
    // Limiter la profondeur pour eviter les boucles infinies
    if (depth > 5) return;

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer . et ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(fullpath, &st) != 0) {
            continue;
        }

        // Si repertoire, recursion
        if (S_ISDIR(st.st_mode)) {
            // Eviter /proc, /sys, /dev pour performance
            if (strncmp(fullpath, "/proc", 5) == 0 ||
                strncmp(fullpath, "/sys", 4) == 0 ||
                strncmp(fullpath, "/dev", 4) == 0) {
                continue;
            }

            scan_directory(fullpath, depth + 1);
        }
        // Si fichier regulier
        else if (S_ISREG(st.st_mode)) {
            if (is_interesting_file(entry->d_name)) {
                printf("[+] Found: %s (%ld bytes)\n",
                       fullpath, st.st_size);
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    printf("[*] File Hunter - Recherche de fichiers sensibles\n");
    printf("[*] ==========================================\n\n");

    const char *start_path = (argc > 1) ? argv[1] : "/home";

    printf("[*] Scanning from: %s\n\n", start_path);
    scan_directory(start_path, 0);

    printf("\n[+] Scan termine\n");

    return 0;
}
