# Module 60 : Blue Team & Detection

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Détecter les intrusions avec SIEM et IDS
- Analyser les logs système et réseau
- Threat hunting proactif
- Incident response et forensics
- SOC operations et playbooks
- Créer des règles de détection
- Honeypots et deception

## 📚 Théorie

### C'est quoi le Blue Team ?

Le **Blue Team** est l'équipe défensive qui protège l'organisation contre les cyberattaques. Leurs responsabilités :

- **Monitoring** : Surveiller les systèmes 24/7
- **Detection** : Identifier les activités suspectes
- **Response** : Réagir aux incidents
- **Prevention** : Implémenter des contrôles de sécurité
- **Threat Hunting** : Rechercher proactivement les menaces

### Pyramide de la douleur

La **Pyramid of Pain** montre l'impact des IOCs sur l'attaquant :

1. **Hash Values** (facile à changer) - Douleur faible
2. **IP Addresses** - Douleur faible
3. **Domain Names** - Douleur moyenne
4. **Network Artifacts** - Douleur moyenne-élevée
5. **Host Artifacts** - Douleur élevée
6. **Tools** - Douleur élevée
7. **TTPs** (Tactics, Techniques, Procedures) - Douleur très élevée

### Kill Chain Defense

Défendre à chaque étape de l'attaque :

1. **Reconnaissance** : Threat intelligence, honeypots
2. **Weaponization** : Endpoint protection
3. **Delivery** : Email filtering, web proxy
4. **Exploitation** : Patch management, EDR
5. **Installation** : Application whitelisting
6. **C2** : Network monitoring, DNS filtering
7. **Actions** : DLP, anomaly detection

## 🔍 Visualisation

### SOC Architecture

```
┌─────────────────────────────────────────────────────┐
│       SECURITY OPERATIONS CENTER (SOC)              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Data Sources                                       │
│  ┌────────────────────────────────────┐            │
│  │ Firewall logs                      │            │
│  │ IDS/IPS alerts                     │            │
│  │ Endpoint logs (EDR)                │            │
│  │ Windows Event Logs                 │            │
│  │ Linux syslog                       │            │
│  │ Application logs                   │            │
│  │ Network flow (NetFlow)             │            │
│  │ DNS queries                        │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Log Aggregation                    │            │
│  │ - Syslog server                    │            │
│  │ - SIEM (Splunk, ELK)               │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Correlation & Detection            │            │
│  │ - Signature-based                  │            │
│  │ - Anomaly detection                │            │
│  │ - Behavioral analysis              │            │
│  │ - Threat intelligence feeds        │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Alerting                           │            │
│  │ - High/Medium/Low priority         │            │
│  │ - Automated tickets                │            │
│  │ - Escalation rules                 │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ SOC Analysts                       │            │
│  │ - L1: Triage                       │            │
│  │ - L2: Investigation                │            │
│  │ - L3: Advanced hunting             │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Response Actions                   │            │
│  │ - Block IP/domain                  │            │
│  │ - Isolate endpoint                 │            │
│  │ - Kill process                     │            │
│  │ - Collect forensics                │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Detection Pipeline

```
┌─────────────────────────────────────────────────────┐
│         THREAT DETECTION PIPELINE                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Event Log                                          │
│  ┌────────────────────────────────────┐            │
│  │ User john.doe logged in            │            │
│  │ from 10.0.0.50                     │            │
│  │ at 02:34 AM                        │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  Enrichment                                         │
│  ┌────────────────────────────────────┐            │
│  │ - GeoIP: Location = Russia         │            │
│  │ - Time: Outside business hours     │            │
│  │ - User: Normal location = US       │            │
│  │ - Context: VPN not used            │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  Detection Rules                                    │
│  ┌────────────────────────────────────┐            │
│  │ IF location != normal_location     │            │
│  │ AND time = after_hours             │            │
│  │ AND VPN = false                    │            │
│  │ THEN alert = HIGH                  │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  Alert Generated                                    │
│  ┌────────────────────────────────────┐            │
│  │ Title: Anomalous Login              │            │
│  │ Severity: HIGH                     │            │
│  │ User: john.doe                     │            │
│  │ Source IP: 10.0.0.50 (Russia)      │            │
│  │ Recommendations:                   │            │
│  │ - Verify with user                 │            │
│  │ - Check MFA logs                   │            │
│  │ - Review account activity          │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Analyseur de logs système

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE 1024

typedef struct {
    char timestamp[64];
    char source_ip[64];
    char event_type[128];
    int severity;
} LogEvent;

void parse_auth_log(const char *logfile) {
    printf("[*] Analyzing auth.log: %s\n", logfile);

    FILE *fp = fopen(logfile, "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    char line[MAX_LINE];
    int failed_logins = 0;
    int successful_logins = 0;
    int sudo_commands = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Failed login
        if (strstr(line, "Failed password")) {
            failed_logins++;

            // Extraire l'IP
            char *ip_start = strstr(line, "from ");
            if (ip_start) {
                ip_start += 5;
                char *ip_end = strchr(ip_start, ' ');
                if (ip_end) {
                    int ip_len = ip_end - ip_start;
                    char ip[64];
                    strncpy(ip, ip_start, ip_len);
                    ip[ip_len] = '\0';

                    printf("[!] Failed login from: %s\n", ip);
                }
            }
        }

        // Successful login
        if (strstr(line, "Accepted password") || strstr(line, "Accepted publickey")) {
            successful_logins++;
        }

        // Sudo commands
        if (strstr(line, "sudo:")) {
            sudo_commands++;

            printf("[*] Sudo command: %s", line);
        }
    }

    fclose(fp);

    printf("\n=== Summary ===\n");
    printf("Failed logins: %d\n", failed_logins);
    printf("Successful logins: %d\n", successful_logins);
    printf("Sudo commands: %d\n", sudo_commands);

    if (failed_logins > 10) {
        printf("\n[!] HIGH ALERT: Possible brute force attack!\n");
    }
}

void detect_anomalies(const char *logfile) {
    printf("[*] Detecting anomalies in: %s\n", logfile);

    FILE *fp = fopen(logfile, "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    char line[MAX_LINE];

    // Patterns suspects
    const char *suspicious_patterns[] = {
        "/etc/shadow",
        "/etc/passwd",
        "rm -rf",
        "wget http://",
        "curl http://",
        "nc -e",
        "/dev/tcp/",
        "bash -i",
        "python -c",
        NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; suspicious_patterns[i] != NULL; i++) {
            if (strstr(line, suspicious_patterns[i])) {
                printf("[!] SUSPICIOUS: %s", line);
                break;
            }
        }
    }

    fclose(fp);
}

void analyze_connections() {
    printf("[*] Analyzing network connections...\n");

    // Analyser /proc/net/tcp
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    char line[MAX_LINE];
    int line_num = 0;

    printf("\n[+] Established connections:\n");

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        if (line_num == 1) continue; // Skip header

        // Parse la ligne (format complexe)
        // Simplification: afficher les connexions ESTABLISHED

        if (strstr(line, " 01 ")) { // ESTABLISHED state
            printf("%s", line);
        }
    }

    fclose(fp);
}

void check_persistence_mechanisms() {
    printf("[*] Checking persistence mechanisms...\n");

    printf("\n[+] Cron jobs:\n");
    system("crontab -l");

    printf("\n[+] Systemd services (user):\n");
    system("systemctl --user list-unit-files | grep enabled");

    printf("\n[+] .bashrc modifications:\n");
    system("find /home -name '.bashrc' -exec grep -H 'http\\|wget\\|curl' {} \\;");

    printf("\n[+] Startup scripts:\n");
    system("ls -la /etc/init.d/");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s authlog <logfile>\n", argv[0]);
        printf("  %s anomaly <logfile>\n", argv[0]);
        printf("  %s connections\n", argv[0]);
        printf("  %s persistence\n", argv[0]);
        return 1;
    }

    printf("=== Blue Team Log Analyzer ===\n\n");

    if (strcmp(argv[1], "authlog") == 0 && argc == 3) {
        parse_auth_log(argv[2]);
    }
    else if (strcmp(argv[1], "anomaly") == 0 && argc == 3) {
        detect_anomalies(argv[2]);
    }
    else if (strcmp(argv[1], "connections") == 0) {
        analyze_connections();
    }
    else if (strcmp(argv[1], "persistence") == 0) {
        check_persistence_mechanisms();
    }
    else {
        printf("[-] Invalid arguments\n");
    }

    return 0;
}

/*
Utilisation:

1. Analyser auth.log:
   ./blue_team authlog /var/log/auth.log

2. Détecter anomalies:
   ./blue_team anomaly /var/log/syslog

3. Analyser connexions:
   ./blue_team connections

4. Vérifier persistence:
   ./blue_team persistence
*/
```

### Exemple 2 : Générateur de règles SIEM (Sigma)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void generate_sigma_rule_bruteforce() {
    printf("=== Sigma Rule: SSH Bruteforce Detection ===\n\n");

    FILE *fp = fopen("ssh_bruteforce.yml", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "title: SSH Bruteforce Attack\n");
    fprintf(fp, "id: b1234567-89ab-cdef-0123-456789abcdef\n");
    fprintf(fp, "description: Detects multiple failed SSH login attempts\n");
    fprintf(fp, "status: stable\n");
    fprintf(fp, "author: Blue Team\n");
    fprintf(fp, "date: 2024/01/01\n");
    fprintf(fp, "logsource:\n");
    fprintf(fp, "  product: linux\n");
    fprintf(fp, "  service: sshd\n");
    fprintf(fp, "detection:\n");
    fprintf(fp, "  selection:\n");
    fprintf(fp, "    EventID: 'Failed password'\n");
    fprintf(fp, "  timeframe: 5m\n");
    fprintf(fp, "  condition: selection | count() > 5\n");
    fprintf(fp, "falsepositives:\n");
    fprintf(fp, "  - User forgot password\n");
    fprintf(fp, "level: high\n");
    fprintf(fp, "tags:\n");
    fprintf(fp, "  - attack.credential_access\n");
    fprintf(fp, "  - attack.t1110\n");

    fclose(fp);

    printf("[+] Sigma rule created: ssh_bruteforce.yml\n");
}

void generate_sigma_rule_privilege_esc() {
    printf("=== Sigma Rule: Privilege Escalation ===\n\n");

    FILE *fp = fopen("privilege_escalation.yml", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "title: Suspicious SUID Binary Execution\n");
    fprintf(fp, "id: c2345678-90ab-cdef-0123-456789abcdef\n");
    fprintf(fp, "description: Detects execution of SUID binaries\n");
    fprintf(fp, "status: stable\n");
    fprintf(fp, "logsource:\n");
    fprintf(fp, "  product: linux\n");
    fprintf(fp, "  category: process_creation\n");
    fprintf(fp, "detection:\n");
    fprintf(fp, "  selection:\n");
    fprintf(fp, "    CommandLine|contains:\n");
    fprintf(fp, "      - 'find / -perm -4000'\n");
    fprintf(fp, "      - 'chmod +s'\n");
    fprintf(fp, "      - 'pkexec'\n");
    fprintf(fp, "      - 'sudo su'\n");
    fprintf(fp, "  condition: selection\n");
    fprintf(fp, "level: high\n");
    fprintf(fp, "tags:\n");
    fprintf(fp, "  - attack.privilege_escalation\n");
    fprintf(fp, "  - attack.t1548\n");

    fclose(fp);

    printf("[+] Sigma rule created: privilege_escalation.yml\n");
}

void generate_sigma_rule_c2() {
    printf("=== Sigma Rule: C2 Communication ===\n\n");

    FILE *fp = fopen("c2_communication.yml", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "title: Suspicious Outbound Connection\n");
    fprintf(fp, "id: d3456789-01ab-cdef-0123-456789abcdef\n");
    fprintf(fp, "description: Detects potential C2 beacons\n");
    fprintf(fp, "status: experimental\n");
    fprintf(fp, "logsource:\n");
    fprintf(fp, "  category: firewall\n");
    fprintf(fp, "detection:\n");
    fprintf(fp, "  selection:\n");
    fprintf(fp, "    DestinationPort:\n");
    fprintf(fp, "      - 4444\n");
    fprintf(fp, "      - 8080\n");
    fprintf(fp, "      - 443\n");
    fprintf(fp, "    Protocol: TCP\n");
    fprintf(fp, "    Direction: Outbound\n");
    fprintf(fp, "  filter:\n");
    fprintf(fp, "    DestinationIP:\n");
    fprintf(fp, "      - '10.*'\n");
    fprintf(fp, "      - '192.168.*'\n");
    fprintf(fp, "  condition: selection and not filter\n");
    fprintf(fp, "level: medium\n");
    fprintf(fp, "tags:\n");
    fprintf(fp, "  - attack.command_and_control\n");
    fprintf(fp, "  - attack.t1071\n");

    fclose(fp);

    printf("[+] Sigma rule created: c2_communication.yml\n");
}

void generate_yara_rule() {
    printf("=== YARA Rule: Malware Detection ===\n\n");

    FILE *fp = fopen("malware_detection.yar", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "rule SuspiciousScript {\n");
    fprintf(fp, "    meta:\n");
    fprintf(fp, "        description = \"Detects suspicious script patterns\"\n");
    fprintf(fp, "        author = \"Blue Team\"\n");
    fprintf(fp, "        date = \"2024-01-01\"\n");
    fprintf(fp, "    \n");
    fprintf(fp, "    strings:\n");
    fprintf(fp, "        $bash_reverse_shell = \"bash -i >& /dev/tcp/\"\n");
    fprintf(fp, "        $python_reverse_shell = \"import socket,subprocess,os\"\n");
    fprintf(fp, "        $nc_reverse_shell = \"nc -e /bin/sh\"\n");
    fprintf(fp, "        $wget_download = \"wget http://\" nocase\n");
    fprintf(fp, "        $curl_download = \"curl http://\" nocase\n");
    fprintf(fp, "    \n");
    fprintf(fp, "    condition:\n");
    fprintf(fp, "        any of them\n");
    fprintf(fp, "}\n");

    fclose(fp);

    printf("[+] YARA rule created: malware_detection.yar\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s bruteforce\n", argv[0]);
        printf("  %s privesc\n", argv[0]);
        printf("  %s c2\n", argv[0]);
        printf("  %s yara\n", argv[0]);
        printf("  %s all\n", argv[0]);
        return 1;
    }

    printf("=== Detection Rule Generator ===\n\n");

    if (strcmp(argv[1], "bruteforce") == 0) {
        generate_sigma_rule_bruteforce();
    }
    else if (strcmp(argv[1], "privesc") == 0) {
        generate_sigma_rule_privilege_esc();
    }
    else if (strcmp(argv[1], "c2") == 0) {
        generate_sigma_rule_c2();
    }
    else if (strcmp(argv[1], "yara") == 0) {
        generate_yara_rule();
    }
    else if (strcmp(argv[1], "all") == 0) {
        generate_sigma_rule_bruteforce();
        printf("\n");
        generate_sigma_rule_privilege_esc();
        printf("\n");
        generate_sigma_rule_c2();
        printf("\n");
        generate_yara_rule();
    }
    else {
        printf("[-] Invalid command\n");
    }

    return 0;
}
```

### Exemple 3 : Honeypot simple

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define HONEYPOT_PORT 2222
#define LOG_FILE "/var/log/honeypot.log"

void log_event(const char *message, const char *ip, int port) {
    FILE *fp = fopen(LOG_FILE, "a");

    if (!fp) {
        perror("fopen");
        return;
    }

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
             localtime(&now));

    fprintf(fp, "[%s] %s from %s:%d\n", timestamp, message, ip, port);

    fclose(fp);

    // Also print to console
    printf("[%s] %s from %s:%d\n", timestamp, message, ip, port);
}

void handle_ssh_honeypot(int client_fd, struct sockaddr_in client_addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
    int port = ntohs(client_addr.sin_port);

    log_event("Connection attempt", ip, port);

    // Simuler un banner SSH
    const char *banner = "SSH-2.0-OpenSSH_7.4\r\n";
    send(client_fd, banner, strlen(banner), 0);

    // Recevoir et logger les tentatives d'authentification
    char buffer[1024];
    int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

    if (bytes > 0) {
        buffer[bytes] = '\0';

        // Logger les credentials
        log_event("Auth attempt", ip, port);

        // Refuser la connexion
        const char *error = "Authentication failed.\r\n";
        send(client_fd, error, strlen(error), 0);
    }

    close(client_fd);
}

void run_honeypot() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Créer socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Reuse address
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configurer
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(HONEYPOT_PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[+] Honeypot listening on port %d\n", HONEYPOT_PORT);
    printf("[+] Logging to: %s\n", LOG_FILE);

    // Boucle d'acceptation
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr,
                          &client_len);

        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        // Handle dans un fork (pour multi-clients)
        pid_t pid = fork();

        if (pid == 0) {
            // Processus enfant
            close(server_fd);
            handle_ssh_honeypot(client_fd, client_addr);
            exit(0);
        } else {
            // Processus parent
            close(client_fd);
        }
    }

    close(server_fd);
}

int main() {
    printf("=== SSH Honeypot ===\n\n");

    run_honeypot();

    return 0;
}

/*
Utilisation:

1. Compiler:
   gcc honeypot.c -o honeypot

2. Lancer (root requis pour port < 1024):
   sudo ./honeypot

3. Tester:
   ssh -p 2222 localhost

4. Voir les logs:
   tail -f /var/log/honeypot.log
*/
```

## 📝 Points clés à retenir

1. **SIEM** : Centraliser et corréler les logs
2. **Detection** : Règles Sigma/Yara pour détecter les menaces
3. **Monitoring** : Surveiller 24/7 les activités suspectes
4. **Threat Hunting** : Recherche proactive de menaces
5. **Incident Response** : Procédures pour réagir rapidement

### Indicateurs de Compromission (IOCs)

```
Type              Exemples                           Outils
──────────────────────────────────────────────────────────────────
File Hash         MD5, SHA-256                       YARA
IP Address        C2 servers                         Firewall
Domain            Malicious domains                  DNS logs
URL               Phishing links                     Proxy logs
Email             Sender addresses                   Email gateway
Process           Malware process names              EDR
Registry          Persistence keys                   Sysmon
```

### Cycle de réponse aux incidents

```
1. Preparation   → Playbooks, outils, formation
2. Identification→ Détecter et confirmer l'incident
3. Containment   → Isoler les systèmes affectés
4. Eradication   → Supprimer la menace
5. Recovery      → Restaurer les opérations
6. Lessons Learned → Post-mortem, amélioration
```

## ➡️ Prochaine étape

Félicitations ! Tu as atteint le **Module 61 : Projet Final**, le dernier module où tu vas mettre en pratique TOUT ce que tu as appris dans un projet complet de Red Team vs Blue Team.

### Ce que tu as appris
- Détection d'intrusions avec SIEM
- Analyse de logs système
- Création de règles de détection
- Honeypots et deception
- Incident response

### Ce qui t'attend
- Projet final complet
- Simulation Red Team vs Blue Team
- Mise en pratique de tous les modules
- Certification de complétion du cours
