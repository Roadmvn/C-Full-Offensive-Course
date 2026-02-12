/*
 * OBJECTIF  : Comprendre le masquage de fichiers au niveau kernel
 * PREREQUIS : Bases C, LKM, syscall hooking, VFS
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de masquage de fichiers :
 * hook de getdents64 pour filtrer les entrees, manipulation du
 * VFS (Virtual File System), et detection de fichiers caches.
 * Demonstration pedagogique en userspace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * Etape 1 : Comment les fichiers sont listes
 */
static void explain_file_listing(void) {
    printf("[*] Etape 1 : Comment les fichiers sont listes\n\n");

    printf("    ┌────────────────────────────────────────────────┐\n");
    printf("    │  ls, find, etc.                                │\n");
    printf("    │       │                                        │\n");
    printf("    │       v                                        │\n");
    printf("    │  glibc readdir() / opendir()                   │\n");
    printf("    │       │                                        │\n");
    printf("    │       v                                        │\n");
    printf("    │  syscall getdents64(fd, buf, count)            │\n");
    printf("    │       │                                        │\n");
    printf("    │       v                                        │\n");
    printf("    │  VFS : iterate_dir() -> iterate_shared()       │\n");
    printf("    │       │                                        │\n");
    printf("    │       v                                        │\n");
    printf("    │  Filesystem (ext4, xfs...) : readdir callback  │\n");
    printf("    └────────────────────────────────────────────────┘\n\n");

    printf("    getdents64 retourne un buffer de struct linux_dirent64 :\n");
    printf("    struct linux_dirent64 {\n");
    printf("        ino64_t  d_ino;    // numero d'inode\n");
    printf("        off64_t  d_off;    // offset vers l'entree suivante\n");
    printf("        uint16_t d_reclen; // taille de cette entree\n");
    printf("        uint8_t  d_type;   // type de fichier\n");
    printf("        char     d_name[]; // nom du fichier\n");
    printf("    };\n\n");

    printf("    Pour cacher un fichier : supprimer son entree du buffer\n\n");
}

/*
 * Etape 2 : Technique de masquage kernel
 */
static void explain_hiding_techniques(void) {
    printf("[*] Etape 2 : Techniques de masquage de fichiers\n\n");

    printf("    Technique 1 : Hook de getdents64()\n");
    printf("    ─────────────────────────────────────\n");
    printf("    asmlinkage long hooked_getdents64(\n");
    printf("        unsigned int fd, struct linux_dirent64 *dirent,\n");
    printf("        unsigned int count) {\n\n");
    printf("        long ret = orig_getdents64(fd, dirent, count);\n");
    printf("        // Parcourir le buffer de dirents\n");
    printf("        struct linux_dirent64 *d;\n");
    printf("        long offset = 0;\n");
    printf("        while (offset < ret) {\n");
    printf("            d = (void *)dirent + offset;\n");
    printf("            if (should_hide(d->d_name)) {\n");
    printf("                // Decaler les entrees suivantes\n");
    printf("                int reclen = d->d_reclen;\n");
    printf("                memmove(d, (void*)d + reclen,\n");
    printf("                        ret - offset - reclen);\n");
    printf("                ret -= reclen;\n");
    printf("            } else {\n");
    printf("                offset += d->d_reclen;\n");
    printf("            }\n");
    printf("        }\n");
    printf("        return ret;\n");
    printf("    }\n\n");

    printf("    Technique 2 : Hook du VFS (iterate_shared)\n");
    printf("    ─────────────────────────────────────\n");
    printf("    // Remplacer la fonction iterate_dir du filesystem\n");
    printf("    // Plus specifique, ne touche pas la syscall table\n");
    printf("    struct file_operations *fops;\n");
    printf("    fops = (void *)dir_file->f_path.dentry->d_inode->i_fop;\n");
    printf("    orig_iterate = fops->iterate_shared;\n");
    printf("    fops->iterate_shared = hooked_iterate;\n\n");

    printf("    Technique 3 : Prefixe magique\n");
    printf("    ─────────────────────────────────────\n");
    printf("    Convention : cacher tout fichier commencant par un\n");
    printf("    prefixe specifique (ex: 'rootkit_', '.hidden_')\n\n");
}

/*
 * Etape 3 : Simulation userspace - listing de fichiers
 */
static void demo_file_listing(void) {
    printf("[*] Etape 3 : Listing de fichiers (simulation)\n\n");

    const char *target = "/tmp";
    DIR *dir = opendir(target);
    if (!dir) {
        printf("    (impossible d'ouvrir %s)\n\n", target);
        return;
    }

    printf("    Contenu de %s (premiers 15) :\n", target);
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) && count < 15) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        printf("      %s\n", entry->d_name);
        count++;
    }
    closedir(dir);
    if (count == 0)
        printf("      (vide)\n");
    printf("\n");
}

/*
 * Etape 4 : Simulation de filtrage
 */
static void demo_hiding_simulation(void) {
    printf("[*] Etape 4 : Simulation de masquage de fichiers\n\n");

    printf("    Prefixe a cacher : fichiers commencant par '.'\n\n");

    const char *target = "/etc";
    DIR *dir = opendir(target);
    if (!dir) {
        printf("    (impossible d'ouvrir %s)\n\n", target);
        return;
    }

    int visible = 0, hidden = 0;
    struct dirent *entry;

    printf("    Fichiers VISIBLES dans %s (sans les .hidden) :\n", target);
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if (entry->d_name[0] == '.') {
            hidden++;
            continue;
        }

        if (visible < 10)
            printf("      %s\n", entry->d_name);
        visible++;
    }
    closedir(dir);

    printf("      ...\n");
    printf("    Visible : %d, Cache : %d\n", visible, hidden);
    printf("    [!] %d fichiers ont ete FILTRES du listing !\n\n", hidden);
}

/*
 * Etape 5 : Ce que les rootkits cachent
 */
static void explain_hidden_items(void) {
    printf("[*] Etape 5 : Fichiers typiquement caches par un rootkit\n\n");

    printf("    Type                | Exemples\n");
    printf("    ────────────────────|──────────────────────────────\n");
    printf("    Backdoor binaires   | /usr/bin/.backdoor\n");
    printf("    Config rootkit      | /etc/.rootkit.conf\n");
    printf("    Logs voles          | /tmp/.keylog, /tmp/.sniff\n");
    printf("    Scripts persistence | /etc/cron.d/.cron_evil\n");
    printf("    SSH keys            | /root/.ssh/.evil_key\n");
    printf("    Modules LKM         | /lib/modules/.rootkit.ko\n");
    printf("    Repertoires         | /opt/.hidden_c2/\n\n");

    printf("    Techniques avancees :\n");
    printf("    - Hook de stat/lstat pour cacher les metadonnees\n");
    printf("    - Hook de open pour rediriger vers de faux fichiers\n");
    printf("    - Hook de read pour modifier le contenu a la volee\n");
    printf("    - Modifier les timestamps (timestomping)\n\n");
}

/*
 * Etape 6 : Detection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection de fichiers caches\n\n");

    printf("    1. Appel direct du syscall getdents64\n");
    printf("       -> Bypass un hook glibc mais pas kernel\n\n");

    printf("    2. Comparaison par inode\n");
    printf("       -> Compter les inodes utilises vs les inodes visibles\n");
    printf("       -> S'ils ne correspondent pas -> fichiers caches\n\n");

    printf("    3. Acces direct au filesystem\n");
    printf("       -> debugfs, e2fsck (pour ext4)\n");
    printf("       -> Lit les blocs directement, bypass le VFS\n\n");

    printf("    4. Montage en lecture seule depuis un live boot\n");
    printf("       -> Le rootkit n'est pas charge\n");
    printf("       -> Tous les fichiers sont visibles\n\n");

    printf("    5. Outils :\n");
    printf("       - rkhunter : verifie les fichiers caches\n");
    printf("       - unhide-tcp : detecte les ports caches\n");
    printf("       - AIDE/Tripwire : integrite des fichiers\n\n");

    /* Demonstration : verifier les fichiers caches dans /tmp */
    printf("    Verification dans /tmp :\n");
    DIR *dir = opendir("/tmp");
    if (dir) {
        struct dirent *entry;
        int dot_files = 0;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] == '.' &&
                strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0) {
                if (dot_files < 5)
                    printf("      [?] Fichier cache : /tmp/%s\n", entry->d_name);
                dot_files++;
            }
        }
        closedir(dir);
        printf("    Total fichiers commencant par '.' : %d\n\n", dot_files);
    }
}

int main(void) {
    printf("[*] Demo : File Hiding (Kernel Level)\n\n");

    explain_file_listing();
    explain_hiding_techniques();
    demo_file_listing();
    demo_hiding_simulation();
    explain_hidden_items();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
