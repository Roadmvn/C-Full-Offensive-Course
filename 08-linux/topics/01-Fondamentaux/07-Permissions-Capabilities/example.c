/*
 * OBJECTIF  : Comprendre les permissions Linux, SUID/SGID et capabilities
 * PREREQUIS : Bases C, notions de permissions Unix (rwx)
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre comment lire et manipuler les permissions
 * de fichiers, detecter les binaires SUID/SGID, et comprendre
 * les capabilities Linux pour l'audit de securite.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

/*
 * Convertit un mode_t en chaine de permissions lisible (rwxrwxrwx)
 * Inclut les bits speciaux : SUID (s), SGID (s), Sticky (t)
 */
static void mode_to_string(mode_t mode, char *str) {
    /* Type de fichier */
    if (S_ISDIR(mode))       str[0] = 'd';
    else if (S_ISLNK(mode))  str[0] = 'l';
    else if (S_ISCHR(mode))  str[0] = 'c';
    else if (S_ISBLK(mode))  str[0] = 'b';
    else if (S_ISFIFO(mode)) str[0] = 'p';
    else if (S_ISSOCK(mode)) str[0] = 's';
    else                     str[0] = '-';

    /* Permissions owner */
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    if (mode & S_ISUID)
        str[3] = (mode & S_IXUSR) ? 's' : 'S';  /* SUID */
    else
        str[3] = (mode & S_IXUSR) ? 'x' : '-';

    /* Permissions group */
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    if (mode & S_ISGID)
        str[6] = (mode & S_IXGRP) ? 's' : 'S';  /* SGID */
    else
        str[6] = (mode & S_IXGRP) ? 'x' : '-';

    /* Permissions other */
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    if (mode & S_ISVTX)
        str[9] = (mode & S_IXOTH) ? 't' : 'T';  /* Sticky */
    else
        str[9] = (mode & S_IXOTH) ? 'x' : '-';

    str[10] = '\0';
}

/*
 * Etape 1 : Afficher les permissions detaillees d'un fichier
 */
static void show_file_permissions(const char *path) {
    struct stat st;
    if (lstat(path, &st) < 0) {
        printf("    [-] Impossible de lire %s : %s\n", path, strerror(errno));
        return;
    }

    char perms[12];
    mode_to_string(st.st_mode, perms);

    /* Resoudre UID/GID en noms */
    struct passwd *pw = getpwuid(st.st_uid);
    struct group *gr = getgrgid(st.st_gid);

    printf("    %s  %-8s %-8s  %8ld  %s\n",
           perms,
           pw ? pw->pw_name : "???",
           gr ? gr->gr_name : "???",
           (long)st.st_size,
           path);

    /* Signaler les bits speciaux */
    if (st.st_mode & S_ISUID)
        printf("      [!] SUID actif - s'execute avec les droits du proprietaire (uid=%d)\n", st.st_uid);
    if (st.st_mode & S_ISGID)
        printf("      [!] SGID actif - s'execute avec le groupe du proprietaire (gid=%d)\n", st.st_gid);
    if (st.st_mode & S_ISVTX)
        printf("      [!] Sticky bit actif\n");
}

/*
 * Etape 2 : Afficher nos propres identites (UID/GID reels et effectifs)
 */
static void show_process_identity(void) {
    printf("[*] Etape 2 : Identite du processus courant\n\n");

    uid_t ruid = getuid();
    uid_t euid = geteuid();
    gid_t rgid = getgid();
    gid_t egid = getegid();

    struct passwd *pw_r = getpwuid(ruid);
    struct passwd *pw_e = getpwuid(euid);

    printf("    UID reel     : %d (%s)\n", ruid, pw_r ? pw_r->pw_name : "???");
    printf("    UID effectif : %d (%s)\n", euid, pw_e ? pw_e->pw_name : "???");
    printf("    GID reel     : %d\n", rgid);
    printf("    GID effectif : %d\n", egid);

    if (ruid != euid) {
        printf("    [!] UID reel != effectif : ce programme est probablement SUID !\n");
    } else {
        printf("    [+] UID reel == effectif (pas de privilege SUID)\n");
    }
    printf("\n");
}

/*
 * Etape 3 : Scanner un repertoire a la recherche de binaires SUID
 * Technique Red Team classique pour trouver des vecteurs de privesc
 */
static void scan_suid_binaries(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        printf("    [-] Impossible d'ouvrir %s : %s\n", dirpath, strerror(errno));
        return;
    }

    struct dirent *entry;
    int found = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

        struct stat st;
        if (stat(fullpath, &st) < 0)
            continue;

        /* Chercher les fichiers reguliers avec le bit SUID */
        if (S_ISREG(st.st_mode) && (st.st_mode & S_ISUID)) {
            struct passwd *pw = getpwuid(st.st_uid);
            char perms[12];
            mode_to_string(st.st_mode, perms);
            printf("    %s  owner=%-8s  %s\n",
                   perms, pw ? pw->pw_name : "???", fullpath);
            found++;

            if (found >= 20) {
                printf("    ... (limite a 20 resultats)\n");
                break;
            }
        }
    }

    closedir(dir);

    if (found == 0)
        printf("    (aucun binaire SUID trouve dans %s)\n", dirpath);
}

/*
 * Etape 4 : Creer un fichier temporaire et manipuler ses permissions
 */
static void demo_permission_manipulation(void) {
    printf("[*] Etape 4 : Manipulation des permissions\n\n");

    const char *tmpfile = "/tmp/perm_demo_test";

    /* Creer un fichier avec des permissions restrictives */
    int fd = open(tmpfile, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        printf("    [-] Impossible de creer %s\n", tmpfile);
        return;
    }
    write(fd, "test data\n", 10);
    close(fd);

    printf("    Fichier cree : %s\n", tmpfile);
    printf("    Permissions initiales (0600 = rw-------) :\n");
    show_file_permissions(tmpfile);

    /* Changer en 0755 (rwxr-xr-x) */
    chmod(tmpfile, 0755);
    printf("    Apres chmod 0755 (rwxr-xr-x) :\n");
    show_file_permissions(tmpfile);

    /* Ajouter SUID */
    chmod(tmpfile, 04755);
    printf("    Apres chmod 04755 (SUID + rwxr-xr-x) :\n");
    show_file_permissions(tmpfile);

    /* Changer le umask et montrer l'effet */
    mode_t old_umask = umask(0077);
    printf("\n    umask courant : 0%03o\n", old_umask);
    printf("    Nouveau umask : 0077\n");
    printf("    Un fichier cree avec mode 0666 aura effectivement : 0%03o\n",
           0666 & ~0077);

    umask(old_umask);

    /* Nettoyer */
    unlink(tmpfile);
    printf("    Fichier temporaire supprime\n\n");
}

/*
 * Etape 5 : Verifier les acces sans les effectuer (access())
 */
static void demo_access_check(void) {
    printf("[*] Etape 5 : Verification des acces avec access()\n\n");

    const char *files[] = {
        "/etc/passwd",
        "/etc/shadow",
        "/usr/bin/sudo",
        "/root",
        NULL
    };

    for (int i = 0; files[i]; i++) {
        printf("    %s :\n", files[i]);
        printf("      Lecture   : %s\n", access(files[i], R_OK) == 0 ? "OUI" : "NON");
        printf("      Ecriture  : %s\n", access(files[i], W_OK) == 0 ? "OUI" : "NON");
        printf("      Execution : %s\n", access(files[i], X_OK) == 0 ? "OUI" : "NON");
    }
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Permissions Linux, SUID/SGID, Capabilities\n\n");

    /* Etape 1 : Examiner les permissions de fichiers systeme */
    printf("[*] Etape 1 : Permissions de fichiers systeme\n\n");
    show_file_permissions("/etc/passwd");
    show_file_permissions("/etc/shadow");
    show_file_permissions("/usr/bin/sudo");
    show_file_permissions("/usr/bin/passwd");
    show_file_permissions("/tmp");
    printf("\n");

    /* Etape 2 : Identite du processus */
    show_process_identity();

    /* Etape 3 : Scanner les binaires SUID */
    printf("[*] Etape 3 : Scan des binaires SUID (technique Red Team)\n\n");
    printf("    Scan de /usr/bin/ :\n");
    scan_suid_binaries("/usr/bin");
    printf("\n    Scan de /usr/sbin/ :\n");
    scan_suid_binaries("/usr/sbin");
    printf("\n");

    /* Etape 4 : Manipulation des permissions */
    demo_permission_manipulation();

    /* Etape 5 : Verification des acces */
    demo_access_check();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
