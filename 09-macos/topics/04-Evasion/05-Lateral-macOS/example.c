/*
 * OBJECTIF  : Comprendre le mouvement lateral sur macOS
 * PREREQUIS : Bases C, reseau, SSH, securite macOS
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre les techniques de mouvement lateral
 * sur macOS : SSH, Apple Remote Desktop, Bonjour discovery,
 * services macOS, et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
 * Etape 1 : Techniques de mouvement lateral macOS
 */
static void explain_lateral_techniques(void) {
    printf("[*] Etape 1 : Techniques de mouvement lateral macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Machine compromise                       │\n");
    printf("    │       │                                   │\n");
    printf("    │       ├──> SSH (port 22)                 │\n");
    printf("    │       ├──> ARD (port 5900)               │\n");
    printf("    │       ├──> Apple Remote Events (port 3031)│\n");
    printf("    │       ├──> Bonjour/mDNS discovery        │\n");
    printf("    │       ├──> SMB/AFP partages              │\n");
    printf("    │       └──> AirDrop exploitation           │\n");
    printf("    │                                          │\n");
    printf("    │       v                                   │\n");
    printf("    │  Cible macOS                              │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Technique        | Port  | Prerequis\n");
    printf("    ─────────────────|───────|──────────────────\n");
    printf("    SSH              | 22    | Credentials/cles\n");
    printf("    ARD/VNC          | 5900  | Mot de passe\n");
    printf("    Apple Remote     | 3031  | Active + auth\n");
    printf("    SMB              | 445   | Partage + auth\n");
    printf("    AFP              | 548   | Partage + auth\n");
    printf("    Bonjour          | 5353  | Decouverte only\n\n");
}

/*
 * Etape 2 : Decouverte reseau
 */
static void demo_network_discovery(void) {
    printf("[*] Etape 2 : Decouverte reseau macOS\n\n");

    /* Interfaces reseau */
    printf("    Interfaces reseau :\n");
    FILE *fp = popen("ifconfig 2>/dev/null | grep -E '(^[a-z]|inet )' | head -12", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    /* Decouverte Bonjour */
    printf("    Decouverte Bonjour (mDNS) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Decouvrir les machines sur le reseau\n");
    printf("    dns-sd -B _ssh._tcp local.\n");
    printf("    dns-sd -B _rfb._tcp local.   # VNC/ARD\n");
    printf("    dns-sd -B _smb._tcp local.   # SMB\n");
    printf("    dns-sd -B _afpovertcp._tcp local. # AFP\n\n");

    /* ARP table */
    printf("    Table ARP (machines connues) :\n");
    fp = popen("arp -a 2>/dev/null | head -10", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 3 : Mouvement lateral via SSH
 */
static void demo_ssh_lateral(void) {
    printf("[*] Etape 3 : Mouvement lateral via SSH\n\n");

    printf("    SSH est le vecteur principal sur macOS :\n");
    printf("    ───────────────────────────────────\n\n");

    /* Verifier le statut SSH */
    printf("    Statut SSH :\n");
    FILE *fp = popen("sudo systemsetup -getremotelogin 2>/dev/null || "
                     "echo '    Verifier: systemsetup -getremotelogin'", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    /* Cles SSH */
    printf("    Cles SSH disponibles :\n");
    const char *home = getenv("HOME");
    if (home) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ls -la '%s/.ssh/' 2>/dev/null | head -10", home);
        fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            int count = 0;
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                printf("      %s\n", line);
                count++;
            }
            pclose(fp);
            if (count == 0) printf("      (pas de cles SSH)\n");
        }
    }
    printf("\n");

    /* Known hosts */
    printf("    Known hosts (cibles potentielles) :\n");
    if (home) {
        char path[512];
        snprintf(path, sizeof(path), "%s/.ssh/known_hosts", home);
        struct stat st;
        if (stat(path, &st) == 0) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "wc -l < '%s' 2>/dev/null", path);
            fp = popen(cmd, "r");
            if (fp) {
                char line[64];
                if (fgets(line, sizeof(line), fp)) {
                    line[strcspn(line, "\n")] = '\0';
                    printf("      %s hosts connus\n", line);
                }
                pclose(fp);
            }
        } else {
            printf("      (pas de known_hosts)\n");
        }
    }
    printf("\n");

    printf("    Techniques SSH :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Avec cle volee\n");
    printf("    ssh -i stolen_key user@target\n\n");
    printf("    # Agent forwarding hijack\n");
    printf("    SSH_AUTH_SOCK=/tmp/com.apple.launchd.xxx/agent\n");
    printf("    ssh user@target  # utilise l'agent\n\n");
    printf("    # Tunnel SSH (pivoting)\n");
    printf("    ssh -D 1080 user@target  # SOCKS proxy\n");
    printf("    ssh -L 8080:internal:80 user@target\n\n");
}

/*
 * Etape 4 : Apple Remote Desktop (ARD)
 */
static void explain_ard(void) {
    printf("[*] Etape 4 : Apple Remote Desktop\n\n");

    printf("    ARD utilise le protocole VNC + extensions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Port 5900 : VNC/ARD\n");
    printf("    Port 3283 : ARD agent\n\n");

    printf("    Commandes ARD (kickstart) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Activer ARD\n");
    printf("    sudo /System/Library/CoreServices/\n");
    printf("      RemoteManagement/ARDAgent.app/\n");
    printf("      Contents/Resources/kickstart \\\n");
    printf("      -activate -configure -access -on \\\n");
    printf("      -users admin -privs -all -restart -agent\n\n");

    printf("    # Executer une commande a distance via ARD\n");
    printf("    # (Apple Remote Desktop.app necessaire)\n\n");

    printf("    Alternatives :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - osascript via SSH :\n");
    printf("      ssh user@target 'osascript -e \"...\"'\n\n");
    printf("    - Apple Remote Events :\n");
    printf("      osascript -e 'tell application \"Finder\" \\\n");
    printf("        of machine \"eppc://target\" to ...'\n\n");
}

/*
 * Etape 5 : Partages et services macOS
 */
static void explain_shares_services(void) {
    printf("[*] Etape 5 : Partages et services\n\n");

    printf("    Partages de fichiers :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Monter un partage SMB\n");
    printf("    mount_smbfs //user:pass@target/share /mnt\n\n");
    printf("    # Monter un partage AFP\n");
    printf("    mount_afp afp://user:pass@target/share /mnt\n\n");

    /* Verifier les services actifs */
    printf("    Services de partage locaux :\n");
    FILE *fp = popen("sharing -l 2>/dev/null | head -10 || "
                     "echo '      (pas de partages configures)'", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    printf("    iCloud et Airdrop :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - AirDrop : transfert de fichiers Bluetooth/WiFi\n");
    printf("    - Peut etre abuse pour envoyer des payloads\n");
    printf("    - iCloud Drive : synchronisation de fichiers\n");
    printf("    - Si compromis, fichiers sync sur toutes les machines\n\n");

    printf("    Credential reuse :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Les utilisateurs reutilisent souvent\n");
    printf("      le meme mot de passe sur plusieurs Macs\n");
    printf("    - Keychain peut contenir des mots de passe SSH\n");
    printf("    - Wi-Fi passwords dans le Keychain systeme\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Monitorer les connexions SSH entrantes\n");
    printf("    - Surveiller ARD/VNC (port 5900)\n");
    printf("    - Detecter les scans Bonjour anormaux\n");
    printf("    - Alerter sur les montages de partages\n\n");

    printf("    Commandes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Connexions actives\n");
    printf("    lsof -i -n -P | grep ESTABLISHED\n\n");
    printf("    # Sessions SSH\n");
    printf("    who\n\n");
    printf("    # Logs SSH\n");
    printf("    log show --predicate 'process == \"sshd\"'\n\n");

    /* Afficher les sessions actuelles */
    printf("    Sessions actuelles :\n");
    FILE *fp = popen("who 2>/dev/null", "r");
    if (fp) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
            count++;
        }
        pclose(fp);
        if (count == 0) printf("      (aucune session distante)\n");
    }
    printf("\n");

    printf("    Protection :\n");
    printf("    - Desactiver SSH si non necessaire\n");
    printf("    - Desactiver ARD si non necessaire\n");
    printf("    - Utiliser des cles SSH (pas de mots de passe)\n");
    printf("    - MDM pour gerer les acces distants\n");
    printf("    - Firewall applicatif (LuLu/Little Snitch)\n");
    printf("    - Monitorer les connexions avec ES Framework\n\n");
}

int main(void) {
    printf("[*] Demo : Mouvement lateral macOS\n\n");

    explain_lateral_techniques();
    demo_network_discovery();
    demo_ssh_lateral();
    explain_ard();
    explain_shares_services();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
