# Exercices - Module 14 : File I/O

**Objectif** : Maîtriser les opérations fichiers pour des applications offensives.

---

## Exo 1 : Read file helper (5 min)

**But** : Fonction utilitaire réutilisable partout.

```c
#include <stdio.h>
#include <stdlib.h>

unsigned char* read_file(const char* path, long* out_size) {
    // TODO:
    // 1. Ouvrir en mode "rb"
    // 2. fseek(SEEK_END) + ftell() pour la taille
    // 3. fseek(SEEK_SET) pour revenir au début
    // 4. malloc() + fread()
    // 5. fclose() et retourner le buffer
    // Gère les erreurs (retourne NULL si échec)
    return NULL;
}

int main(void) {
    long size;
    unsigned char* data = read_file("/etc/passwd", &size);

    if (data) {
        printf("[+] Lu %ld bytes\n", size);
        printf("%.100s...\n", data);  // Premiers 100 chars
        free(data);
    } else {
        printf("[-] Échec lecture\n");
    }

    return 0;
}
```

---

## Exo 2 : Binary patcher (10 min)

**But** : Modifier un binaire pour bypasser une vérification.

```c
#include <stdio.h>

int patch_at_offset(const char* file, long offset,
                    unsigned char* patch, int patch_len) {
    // TODO:
    // 1. Ouvrir en mode "r+b" (lecture + écriture binaire)
    // 2. fseek() à l'offset
    // 3. fwrite() le patch
    // 4. fclose()
    // Retourne 0 si succès, -1 si erreur
    return -1;
}

int main(void) {
    // Créer un fichier test
    FILE* fp = fopen("test.bin", "wb");
    unsigned char code[] = {
        0x55,                    // push rbp
        0x48, 0x89, 0xE5,        // mov rbp, rsp
        0x83, 0xFF, 0x01,        // cmp edi, 1
        0x75, 0x07,              // JNE +7 ← On veut changer ça
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xC9, 0xC3               // leave, ret
    };
    fwrite(code, 1, sizeof(code), fp);
    fclose(fp);

    printf("[*] Fichier créé avec JNE (0x75) à l'offset 7\n");

    // Patcher JNE → JMP
    unsigned char jmp = 0xEB;
    if (patch_at_offset("test.bin", 7, &jmp, 1) == 0) {
        printf("[+] Patché: 0x75 → 0xEB\n");
    }

    // Vérifier
    fp = fopen("test.bin", "rb");
    fseek(fp, 7, SEEK_SET);
    unsigned char byte;
    fread(&byte, 1, 1, fp);
    fclose(fp);
    printf("[*] Byte à offset 7: 0x%02X\n", byte);

    return 0;
}
```

---

## Exo 3 : Log scanner (10 min)

**But** : Parser des logs pour extraire des informations.

```c
#include <stdio.h>
#include <string.h>

void scan_logs(const char* logfile, const char** keywords, int num_keywords) {
    // TODO:
    // 1. Ouvrir le fichier en lecture
    // 2. Lire ligne par ligne avec fgets()
    // 3. Pour chaque ligne, vérifier si elle contient un keyword
    // 4. Afficher les lignes correspondantes avec le keyword trouvé
}

int main(void) {
    // Créer un fichier de test
    FILE* fp = fopen("test.log", "w");
    fprintf(fp, "2024-01-01 10:00:00 User login successful\n");
    fprintf(fp, "2024-01-01 10:01:00 Failed password for admin\n");
    fprintf(fp, "2024-01-01 10:02:00 sudo: user executed command\n");
    fprintf(fp, "2024-01-01 10:03:00 Connection closed\n");
    fprintf(fp, "2024-01-01 10:04:00 Failed password for root\n");
    fclose(fp);

    const char* keywords[] = {"Failed", "sudo", "root"};
    printf("=== Scanning logs ===\n\n");
    scan_logs("test.log", keywords, 3);

    return 0;
}
```

**Output attendu** :
```
=== Scanning logs ===

[Failed] 2024-01-01 10:01:00 Failed password for admin
[sudo] 2024-01-01 10:02:00 sudo: user executed command
[Failed] 2024-01-01 10:04:00 Failed password for root
[root] 2024-01-01 10:04:00 Failed password for root
```

---

## Exo 4 : Payload extractor (15 min)

**But** : Extraire un payload caché après un marker.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MARKER "\xDE\xAD\xBE\xEF"
#define MARKER_LEN 4

unsigned char* extract_after_marker(const char* file, long* payload_size) {
    // TODO:
    // 1. Lire le fichier entier
    // 2. Chercher le marker byte par byte
    // 3. Si trouvé, extraire tout ce qui suit
    // 4. Retourner le payload (ou NULL si pas trouvé)
    return NULL;
}

int main(void) {
    // Créer un dropper avec payload caché
    FILE* fp = fopen("dropper.bin", "wb");

    // Garbage au début (simule un EXE)
    unsigned char header[] = {0x4D, 0x5A, 0x90, 0x00, 0x00, 0x00};
    fwrite(header, 1, sizeof(header), fp);

    // Plus de garbage
    for (int i = 0; i < 100; i++) fputc(i & 0xFF, fp);

    // Marker
    fwrite(MARKER, 1, 4, fp);

    // Payload (shellcode factice)
    unsigned char payload[] = {0x48, 0x31, 0xC0, 0x48, 0x89, 0xC7, 0xC3};
    fwrite(payload, 1, sizeof(payload), fp);
    fclose(fp);

    printf("[*] Dropper créé (header + garbage + marker + payload)\n");

    // Extraire
    long size;
    unsigned char* extracted = extract_after_marker("dropper.bin", &size);

    if (extracted) {
        printf("[+] Payload extrait (%ld bytes): ", size);
        for (long i = 0; i < size; i++) printf("%02X ", extracted[i]);
        printf("\n");
        free(extracted);
    } else {
        printf("[-] Marker non trouvé\n");
    }

    return 0;
}
```

**Output attendu** :
```
[*] Dropper créé (header + garbage + marker + payload)
[+] Payload extrait (7 bytes): 48 31 C0 48 89 C7 C3
```

---

## Exo 5 : Steganographie PNG (15 min)

**But** : Cacher/extraire des données dans un fichier image.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEG_MARKER "HIDE"

int hide_data(const char* image, unsigned char* data, int len) {
    // TODO:
    // 1. Ouvrir l'image en mode append binaire ("ab")
    // 2. Écrire le marker
    // 3. Écrire la taille (4 bytes)
    // 4. Écrire les données
    // 5. Fermer
    return -1;
}

unsigned char* extract_hidden(const char* image, int* out_len) {
    // TODO:
    // 1. Lire tout le fichier
    // 2. Chercher le marker "HIDE"
    // 3. Lire la taille (4 bytes après marker)
    // 4. Extraire les données
    return NULL;
}

int main(void) {
    // Créer un faux PNG (juste le header)
    FILE* fp = fopen("image.png", "wb");
    unsigned char png_header[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    unsigned char fake_data[100];
    memset(fake_data, 0xAA, sizeof(fake_data));
    fwrite(png_header, 1, sizeof(png_header), fp);
    fwrite(fake_data, 1, sizeof(fake_data), fp);
    fclose(fp);

    // Cacher un message secret
    unsigned char secret[] = "http://c2.evil.com/beacon";
    printf("[*] Cachant: %s\n", secret);

    if (hide_data("image.png", secret, strlen((char*)secret)) == 0) {
        printf("[+] Données cachées dans image.png\n");
    }

    // Extraire
    int len;
    unsigned char* extracted = extract_hidden("image.png", &len);
    if (extracted) {
        printf("[+] Extrait (%d bytes): %s\n", len, extracted);
        free(extracted);
    }

    return 0;
}
```

---

## Exo 6 : Config exfiltrator (20 min)

**But** : Collecter et encoder des fichiers de configuration.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void xor_encode(unsigned char* data, long size, unsigned char key) {
    for (long i = 0; i < size; i++) data[i] ^= key;
}

int exfiltrate(const char** targets, int num_targets,
               const char* output, unsigned char key) {
    // TODO:
    // 1. Ouvrir le fichier output en écriture binaire
    // 2. Pour chaque target:
    //    - Lire le fichier (ignorer si erreur)
    //    - Écrire un header: [filename_len][filename][data_len][xor_data]
    //    - Encoder les données avec XOR
    // 3. Fermer le fichier
    // Retourne le nombre de fichiers exfiltrés
    return 0;
}

int main(void) {
    // Créer des fichiers de test
    FILE* fp = fopen("config1.txt", "w");
    fprintf(fp, "username=admin\npassword=secret123\n");
    fclose(fp);

    fp = fopen("config2.txt", "w");
    fprintf(fp, "API_KEY=sk-12345abcdef\n");
    fclose(fp);

    const char* targets[] = {"config1.txt", "config2.txt", "nonexistent.txt"};

    printf("[*] Exfiltrating configs...\n");
    int count = exfiltrate(targets, 3, "exfil.bin", 0x42);
    printf("[+] Exfiltrated %d files to exfil.bin\n", count);

    // Afficher le contenu encodé
    long size;
    // ... (utiliser read_file pour vérifier)

    return 0;
}
```

---

## Exo 7 : Self-reader (Challenge - 10 min)

**But** : Un programme qui lit son propre exécutable.

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    // TODO:
    // 1. argv[0] contient le chemin de l'exécutable
    // 2. Lire les premiers 64 bytes
    // 3. Afficher en hexdump
    // 4. Identifier le format (ELF: 0x7F "ELF", PE: "MZ")

    printf("=== Self-reading executable ===\n");
    printf("Path: %s\n\n", argv[0]);

    // Ton code ici...

    return 0;
}
```

**Output attendu (Linux)** :
```
=== Self-reading executable ===
Path: ./self_reader

00000000: 7F 45 4C 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010: 03 00 3E 00 01 00 00 00  60 10 00 00 00 00 00 00  |..>.....`.......|
...

[+] Format: ELF 64-bit
```

---

## Checklist finale

```
□ Je sais implémenter read_file() réutilisable
□ Je sais patcher un binaire à un offset donné
□ Je sais parser des logs avec filtres
□ Je sais extraire des données après un marker
□ Je comprends la steganographie basique
□ Je sais encoder/exfiltrer des configs
□ Je sais lire mon propre exécutable
```

---

## Solutions

Voir [solution.md](solution.md)
