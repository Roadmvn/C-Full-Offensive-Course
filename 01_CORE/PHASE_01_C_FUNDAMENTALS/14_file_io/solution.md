# Module 14 : File I/O - Solutions

## Solution 1 : Lecture/Écriture Texte

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Écriture
    FILE *fp = fopen("rapport.txt", "w");
    if (fp == NULL) {
        perror("fopen write");
        return 1;
    }

    fprintf(fp, "Ligne 1 : Rapport de scan\n");
    fprintf(fp, "Ligne 2 : Cibles identifiées\n");
    fprintf(fp, "Ligne 3 : Vulnérabilités trouvées\n");
    fprintf(fp, "Ligne 4 : Actions recommandées\n");
    fprintf(fp, "Ligne 5 : Fin du rapport\n");
    fclose(fp);

    printf("Fichier écrit avec succès.\n\n");

    // Lecture
    fp = fopen("rapport.txt", "r");
    if (fp == NULL) {
        perror("fopen read");
        return 1;
    }

    char buffer[256];
    printf("Contenu du fichier:\n");
    printf("-------------------\n");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    printf("-------------------\n");

    fclose(fp);
    return 0;
}
```

---

## Solution 2 : Mode Append

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void log_message(const char *msg) {
    FILE *fp = fopen("log.txt", "a");
    if (fp == NULL) {
        perror("fopen");
        return;
    }

    // Timestamp
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[24] = '\0';  // Retirer le \n

    fprintf(fp, "[%s] %s\n", timestamp, msg);
    fclose(fp);
}

void display_log(void) {
    FILE *fp = fopen("log.txt", "r");
    if (fp == NULL) {
        printf("Aucun log trouvé.\n");
        return;
    }

    char buffer[512];
    printf("\n=== CONTENU DU LOG ===\n");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    printf("======================\n");
    fclose(fp);
}

int main(void) {
    log_message("Application démarrée");
    log_message("Connexion établie");
    log_message("Scan en cours...");

    display_log();
    return 0;
}
```

---

## Solution 3 : Copie de Fichier

```c
#include <stdio.h>
#include <stdlib.h>

long copy_file(const char *src, const char *dst) {
    FILE *fsrc = fopen(src, "rb");
    if (fsrc == NULL) {
        perror("fopen source");
        return -1;
    }

    FILE *fdst = fopen(dst, "wb");
    if (fdst == NULL) {
        perror("fopen dest");
        fclose(fsrc);
        return -1;
    }

    long bytes_copied = 0;
    int c;

    while ((c = fgetc(fsrc)) != EOF) {
        fputc(c, fdst);
        bytes_copied++;
    }

    fclose(fsrc);
    fclose(fdst);

    return bytes_copied;
}

int main(void) {
    // Créer fichier source
    FILE *fp = fopen("source.txt", "w");
    fprintf(fp, "Contenu à copier\nDeuxième ligne\n");
    fclose(fp);

    // Copier
    long copied = copy_file("source.txt", "copie.txt");

    if (copied >= 0) {
        printf("Copié %ld bytes.\n", copied);
    }

    return 0;
}
```

---

## Solution 4 : Taille de Fichier

```c
#include <stdio.h>
#include <stdlib.h>

long get_file_size(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);  // Aller à la fin
    long size = ftell(fp);    // Position = taille
    fclose(fp);

    return size;
}

int main(void) {
    // Test
    long size = get_file_size("/etc/passwd");
    if (size >= 0) {
        printf("/etc/passwd : %ld bytes\n", size);
    } else {
        printf("Erreur lecture fichier\n");
    }

    size = get_file_size("/bin/ls");
    if (size >= 0) {
        printf("/bin/ls : %ld bytes\n", size);
    }

    return 0;
}
```

---

## Solution 5 : Lecture Fichier Entier

```c
#include <stdio.h>
#include <stdlib.h>

char *read_entire_file(const char *filename, long *size_out) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        return NULL;
    }

    // Calculer taille
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allouer mémoire
    char *buffer = malloc(size + 1);
    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }

    // Lire tout d'un coup
    size_t read = fread(buffer, 1, size, fp);
    buffer[read] = '\0';

    fclose(fp);

    if (size_out != NULL) {
        *size_out = (long)read;
    }

    return buffer;
}

int main(void) {
    long size;
    char *content = read_entire_file("/etc/hostname", &size);

    if (content != NULL) {
        printf("Lu %ld bytes:\n%s\n", size, content);
        free(content);
    } else {
        printf("Erreur lecture\n");
    }

    return 0;
}
```

---

## Solution 6 : Fichier Binaire - Structure

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char username[32];
    char password_hash[64];
    int privilege_level;
} UserRecord;

int save_users(UserRecord *users, int count, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) return -1;

    // Écrire le nombre d'enregistrements d'abord
    fwrite(&count, sizeof(int), 1, fp);
    // Écrire les enregistrements
    fwrite(users, sizeof(UserRecord), count, fp);

    fclose(fp);
    return 0;
}

UserRecord *load_users(const char *filename, int *count_out) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) return NULL;

    // Lire le nombre d'enregistrements
    int count;
    fread(&count, sizeof(int), 1, fp);

    // Allouer et lire
    UserRecord *users = malloc(sizeof(UserRecord) * count);
    if (users == NULL) {
        fclose(fp);
        return NULL;
    }

    fread(users, sizeof(UserRecord), count, fp);
    fclose(fp);

    *count_out = count;
    return users;
}

int main(void) {
    // Créer des utilisateurs
    UserRecord users[] = {
        {"admin", "5f4dcc3b5aa765d61d8327deb882cf99", 3},
        {"user1", "e99a18c428cb38d5f260853678922e03", 1},
        {"guest", "084e0343a0486ff05530df6c705c8bb4", 0}
    };

    // Sauvegarder
    save_users(users, 3, "users.db");
    printf("3 utilisateurs sauvegardés.\n");

    // Recharger
    int count;
    UserRecord *loaded = load_users("users.db", &count);

    if (loaded != NULL) {
        printf("\n%d utilisateurs chargés:\n", count);
        for (int i = 0; i < count; i++) {
            printf("  [%d] %s (level %d)\n",
                   i, loaded[i].username, loaded[i].privilege_level);
        }
        free(loaded);
    }

    return 0;
}
```

---

## Solution 7 : Parser de Logs

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int errors;
    int warnings;
    int failed;
} LogStats;

LogStats parse_log_file(const char *filename) {
    LogStats stats = {0, 0, 0};

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("fopen");
        return stats;
    }

    char line[1024];
    int line_num = 0;

    printf("=== LIGNES SUSPECTES ===\n");
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_num++;

        // Recherche insensible à la casse serait mieux
        if (strstr(line, "ERROR") || strstr(line, "error")) {
            printf("[L%d] ERROR: %s", line_num, line);
            stats.errors++;
        }
        else if (strstr(line, "WARNING") || strstr(line, "warning")) {
            stats.warnings++;
        }
        else if (strstr(line, "FAILED") || strstr(line, "failed") ||
                 strstr(line, "Failed")) {
            printf("[L%d] FAILED: %s", line_num, line);
            stats.failed++;
        }
    }
    printf("========================\n");

    fclose(fp);
    return stats;
}

int main(void) {
    // Créer un fichier de log de test
    FILE *fp = fopen("test.log", "w");
    fprintf(fp, "2025-01-01 INFO: Application started\n");
    fprintf(fp, "2025-01-01 WARNING: High memory usage\n");
    fprintf(fp, "2025-01-01 ERROR: Connection timeout\n");
    fprintf(fp, "2025-01-01 INFO: Retrying connection\n");
    fprintf(fp, "2025-01-01 Failed password for root\n");
    fprintf(fp, "2025-01-01 ERROR: Authentication failed\n");
    fprintf(fp, "2025-01-01 INFO: Connection established\n");
    fclose(fp);

    // Parser
    LogStats stats = parse_log_file("test.log");

    printf("\n=== STATISTIQUES ===\n");
    printf("Erreurs:      %d\n", stats.errors);
    printf("Warnings:     %d\n", stats.warnings);
    printf("Failed:       %d\n", stats.failed);

    return 0;
}
```

---

## Solution 8 : Extraction de Payload

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAGIC_MARKER 0xDEADBEEF

int extract_payload(const char *input, const char *output) {
    FILE *fp_in = fopen(input, "rb");
    if (fp_in == NULL) {
        perror("fopen input");
        return -1;
    }

    // Lire tout le fichier
    fseek(fp_in, 0, SEEK_END);
    long size = ftell(fp_in);
    fseek(fp_in, 0, SEEK_SET);

    unsigned char *data = malloc(size);
    fread(data, 1, size, fp_in);
    fclose(fp_in);

    // Chercher le magic marker
    uint32_t marker = MAGIC_MARKER;
    long payload_start = -1;

    for (long i = 0; i <= size - sizeof(marker); i++) {
        if (memcmp(data + i, &marker, sizeof(marker)) == 0) {
            payload_start = i + sizeof(marker);
            printf("Magic marker trouvé à l'offset 0x%lX\n", i);
            break;
        }
    }

    if (payload_start == -1) {
        printf("Magic marker non trouvé\n");
        free(data);
        return -1;
    }

    // Trouver la fin (double null byte)
    long payload_end = payload_start;
    while (payload_end < size - 1) {
        if (data[payload_end] == 0x00 && data[payload_end + 1] == 0x00) {
            break;
        }
        payload_end++;
    }

    long payload_size = payload_end - payload_start;
    printf("Payload trouvé: %ld bytes\n", payload_size);

    // Extraire
    FILE *fp_out = fopen(output, "wb");
    if (fp_out == NULL) {
        perror("fopen output");
        free(data);
        return -1;
    }

    fwrite(data + payload_start, 1, payload_size, fp_out);
    fclose(fp_out);

    free(data);
    printf("Payload extrait vers %s\n", output);
    return 0;
}

int main(void) {
    // Créer un fichier de test avec payload
    FILE *fp = fopen("payload.bin", "wb");

    // Garbage initial
    char garbage[] = "GARBAGE DATA HERE";
    fwrite(garbage, 1, strlen(garbage), fp);

    // Magic marker
    uint32_t marker = MAGIC_MARKER;
    fwrite(&marker, sizeof(marker), 1, fp);

    // Payload (shellcode simulé)
    unsigned char payload[] = {0x48, 0x31, 0xc0, 0x48, 0x89, 0xc2,
                                0x48, 0x89, 0xc6, 0x48, 0x8d};
    fwrite(payload, 1, sizeof(payload), fp);

    // Terminateur
    unsigned char term[] = {0x00, 0x00};
    fwrite(term, 1, 2, fp);

    fclose(fp);
    printf("Fichier de test créé.\n\n");

    // Extraire
    extract_payload("payload.bin", "extracted.bin");

    return 0;
}
```

---

## Solution 9 : Patching d'Exécutable

```c
#include <stdio.h>
#include <stdlib.h>

int patch_file(const char *filename, long offset, unsigned char new_byte) {
    FILE *fp = fopen(filename, "r+b");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    // Vérifier que l'offset est valide
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);

    if (offset >= size) {
        fprintf(stderr, "Offset 0x%lX hors limites (taille: %ld)\n",
                offset, size);
        fclose(fp);
        return -1;
    }

    // Aller à l'offset
    fseek(fp, offset, SEEK_SET);

    // Lire l'ancien byte
    unsigned char old_byte;
    fread(&old_byte, 1, 1, fp);
    printf("Offset 0x%lX: 0x%02X -> 0x%02X\n", offset, old_byte, new_byte);

    // Retourner à l'offset pour écrire
    fseek(fp, offset, SEEK_SET);

    // Écrire le nouveau byte
    size_t written = fwrite(&new_byte, 1, 1, fp);
    fclose(fp);

    if (written != 1) {
        fprintf(stderr, "Erreur écriture\n");
        return -1;
    }

    printf("Patch appliqué avec succès.\n");
    return 0;
}

int patch_bytes(const char *filename, long offset,
                unsigned char *bytes, int count) {
    FILE *fp = fopen(filename, "r+b");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    fseek(fp, offset, SEEK_SET);
    size_t written = fwrite(bytes, 1, count, fp);
    fclose(fp);

    return (written == count) ? 0 : -1;
}

int main(void) {
    // Créer un fichier de test
    FILE *fp = fopen("test.bin", "wb");
    unsigned char data[] = {0x90, 0x90, 0x75, 0x10, 0x90, 0x90};
    //                             ↑ JNZ +16 (saut conditionnel)
    fwrite(data, 1, sizeof(data), fp);
    fclose(fp);

    printf("=== AVANT PATCH ===\n");
    fp = fopen("test.bin", "rb");
    unsigned char buf[6];
    fread(buf, 1, 6, fp);
    fclose(fp);
    for (int i = 0; i < 6; i++) printf("%02X ", buf[i]);
    printf("\n\n");

    // Patch: Remplacer JNZ (0x75) par JMP (0xEB)
    // Ceci bypasse la vérification conditionnelle
    patch_file("test.bin", 2, 0xEB);

    printf("\n=== APRÈS PATCH ===\n");
    fp = fopen("test.bin", "rb");
    fread(buf, 1, 6, fp);
    fclose(fp);
    for (int i = 0; i < 6; i++) printf("%02X ", buf[i]);
    printf("\n");

    return 0;
}
```

---

## Solution 10 : Exfiltration Config

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XOR_KEY 0x42

void xor_encrypt(char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

int collect_system_info(const char *output_file) {
    FILE *fp_out = fopen(output_file, "wb");
    if (fp_out == NULL) {
        perror("fopen output");
        return -1;
    }

    char buffer[4096];
    char line[256];

    // Header
    snprintf(buffer, sizeof(buffer), "=== SYSTEM INFORMATION ===\n\n");

    // Hostname
    FILE *fp = fopen("/etc/hostname", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            strcat(buffer, "Hostname: ");
            strcat(buffer, line);
        }
        fclose(fp);
    }

    // User
    char *user = getenv("USER");
    if (user != NULL) {
        strcat(buffer, "User: ");
        strcat(buffer, user);
        strcat(buffer, "\n");
    }

    // Home
    char *home = getenv("HOME");
    if (home != NULL) {
        strcat(buffer, "Home: ");
        strcat(buffer, home);
        strcat(buffer, "\n");
    }

    // Shell
    char *shell = getenv("SHELL");
    if (shell != NULL) {
        strcat(buffer, "Shell: ");
        strcat(buffer, shell);
        strcat(buffer, "\n");
    }

    // Premier utilisateurs de /etc/passwd
    strcat(buffer, "\n=== USERS ===\n");
    fp = fopen("/etc/passwd", "r");
    if (fp != NULL) {
        int count = 0;
        while (fgets(line, sizeof(line), fp) != NULL && count < 5) {
            strcat(buffer, line);
            count++;
        }
        fclose(fp);
    }

    // Chiffrer
    size_t len = strlen(buffer);
    xor_encrypt(buffer, len);

    // Écrire
    fwrite(buffer, 1, len, fp_out);
    fclose(fp_out);

    printf("Info collectées et chiffrées (%zu bytes)\n", len);
    return 0;
}

int decrypt_and_display(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) return -1;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(size + 1);
    fread(buffer, 1, size, fp);
    fclose(fp);

    // Déchiffrer
    xor_encrypt(buffer, size);
    buffer[size] = '\0';

    printf("%s\n", buffer);
    free(buffer);
    return 0;
}

int main(void) {
    printf("Collecte des informations...\n");
    collect_system_info("exfil.dat");

    printf("\n=== CONTENU DÉCHIFFRÉ ===\n");
    decrypt_and_display("exfil.dat");

    return 0;
}
```

---

## Solution 11 : Stéganographie Basique

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// PNG IEND chunk : 00 00 00 00 49 45 4E 44 AE 42 60 82
const unsigned char PNG_IEND[] = {0x00, 0x00, 0x00, 0x00,
                                   0x49, 0x45, 0x4E, 0x44,
                                   0xAE, 0x42, 0x60, 0x82};

int hide_data_in_png(const char *png_file, const char *output,
                      const unsigned char *data, size_t data_len) {
    FILE *fp_in = fopen(png_file, "rb");
    if (fp_in == NULL) {
        perror("fopen png");
        return -1;
    }

    // Lire le PNG
    fseek(fp_in, 0, SEEK_END);
    long png_size = ftell(fp_in);
    fseek(fp_in, 0, SEEK_SET);

    unsigned char *png_data = malloc(png_size);
    fread(png_data, 1, png_size, fp_in);
    fclose(fp_in);

    // Écrire PNG + données cachées
    FILE *fp_out = fopen(output, "wb");
    if (fp_out == NULL) {
        free(png_data);
        return -1;
    }

    // PNG original
    fwrite(png_data, 1, png_size, fp_out);

    // Marker de début
    unsigned char marker[] = {0xDE, 0xAD, 0xC0, 0xDE};
    fwrite(marker, 1, 4, fp_out);

    // Taille des données
    fwrite(&data_len, sizeof(size_t), 1, fp_out);

    // Données cachées
    fwrite(data, 1, data_len, fp_out);

    fclose(fp_out);
    free(png_data);

    printf("Données cachées: %zu bytes ajoutés\n", data_len);
    return 0;
}

unsigned char *extract_hidden_data(const char *png_file, size_t *data_len) {
    FILE *fp = fopen(png_file, "rb");
    if (fp == NULL) return NULL;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *file_data = malloc(size);
    fread(file_data, 1, size, fp);
    fclose(fp);

    // Chercher le marker
    unsigned char marker[] = {0xDE, 0xAD, 0xC0, 0xDE};
    long marker_pos = -1;

    for (long i = 0; i <= size - 4; i++) {
        if (memcmp(file_data + i, marker, 4) == 0) {
            marker_pos = i;
            break;
        }
    }

    if (marker_pos == -1) {
        printf("Aucune donnée cachée trouvée\n");
        free(file_data);
        return NULL;
    }

    // Lire taille
    size_t hidden_size;
    memcpy(&hidden_size, file_data + marker_pos + 4, sizeof(size_t));

    // Extraire données
    unsigned char *hidden = malloc(hidden_size);
    memcpy(hidden, file_data + marker_pos + 4 + sizeof(size_t), hidden_size);

    *data_len = hidden_size;
    free(file_data);
    return hidden;
}

int main(void) {
    // Créer un faux PNG (juste les octets magiques + IEND)
    FILE *fp = fopen("test.png", "wb");
    unsigned char png_magic[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    fwrite(png_magic, 1, sizeof(png_magic), fp);
    // Fake IHDR chunk
    unsigned char fake_chunk[50] = {0};
    fwrite(fake_chunk, 1, sizeof(fake_chunk), fp);
    // IEND
    fwrite(PNG_IEND, 1, sizeof(PNG_IEND), fp);
    fclose(fp);

    // Cacher des données
    const char *secret = "Shellcode: \\x48\\x31\\xc0...";
    hide_data_in_png("test.png", "stego.png",
                     (unsigned char*)secret, strlen(secret) + 1);

    // Extraire
    printf("\nExtraction...\n");
    size_t hidden_len;
    unsigned char *hidden = extract_hidden_data("stego.png", &hidden_len);

    if (hidden != NULL) {
        printf("Données extraites (%zu bytes): %s\n", hidden_len, hidden);
        free(hidden);
    }

    return 0;
}
```

---

## Solution 12 : Implant Persistence

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define INSTALL_PATH "/tmp/.system_helper"
#define AUTOSTART_SCRIPT "/tmp/.autostart.sh"

int file_exists(const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        fclose(fp);
        return 1;
    }
    return 0;
}

int copy_self(const char *dest) {
    // Obtenir le chemin de l'exécutable actuel
    char self_path[1024];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);

    if (len == -1) {
        perror("readlink");
        return -1;
    }
    self_path[len] = '\0';

    printf("Copie de %s vers %s\n", self_path, dest);

    // Lire et copier
    FILE *src = fopen(self_path, "rb");
    if (src == NULL) {
        perror("fopen src");
        return -1;
    }

    FILE *dst = fopen(dest, "wb");
    if (dst == NULL) {
        perror("fopen dst");
        fclose(src);
        return -1;
    }

    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }

    fclose(src);
    fclose(dst);

    // Rendre exécutable
    chmod(dest, 0755);

    return 0;
}

int create_autostart(void) {
    FILE *fp = fopen(AUTOSTART_SCRIPT, "w");
    if (fp == NULL) {
        perror("fopen autostart");
        return -1;
    }

    fprintf(fp, "#!/bin/bash\n");
    fprintf(fp, "# System helper service\n");
    fprintf(fp, "nohup %s &>/dev/null &\n", INSTALL_PATH);

    fclose(fp);
    chmod(AUTOSTART_SCRIPT, 0755);

    printf("Script autostart créé: %s\n", AUTOSTART_SCRIPT);
    return 0;
}

int install_persistence(void) {
    // Vérifier si déjà installé
    if (file_exists(INSTALL_PATH)) {
        printf("Déjà installé à %s\n", INSTALL_PATH);
        return 0;
    }

    printf("Installation de la persistence...\n");

    // Copier l'exécutable
    if (copy_self(INSTALL_PATH) != 0) {
        return -1;
    }

    // Créer script d'autostart
    if (create_autostart() != 0) {
        return -1;
    }

    printf("Persistence installée avec succès.\n");
    printf("  Binaire: %s\n", INSTALL_PATH);
    printf("  Autostart: %s\n", AUTOSTART_SCRIPT);

    return 0;
}

int main(void) {
    printf("=== DEMO PERSISTENCE ===\n");
    printf("(Utilise /tmp pour la démonstration)\n\n");

    int result = install_persistence();

    if (result == 0) {
        printf("\nVérification:\n");
        printf("  ls -la %s\n", INSTALL_PATH);
        printf("  cat %s\n", AUTOSTART_SCRIPT);
    }

    return result;
}
```

---

## Résumé

| Exercice | Concept | Application |
|----------|---------|-------------|
| 1-2 | fopen, fprintf, fgets | Basics |
| 3-4 | fgetc, fseek, ftell | Navigation fichier |
| 5-6 | fread, fwrite, malloc | Fichiers binaires |
| 7 | Parsing logs | Surveillance |
| 8 | Extraction payload | Malware analysis |
| 9 | Patching | Modification binaire |
| 10 | Exfiltration | Collecte info |
| 11 | Stéganographie | Dissimulation |
| 12 | Persistence | Installation implant |
