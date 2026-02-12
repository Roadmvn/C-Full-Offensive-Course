/*
 * OBJECTIF  : Comprendre la programmation reseau bas niveau sous Linux
 * PREREQUIS : Bases C, notions TCP/IP, sockets
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les sockets TCP/UDP, la creation d'un
 * mini-serveur, un client TCP, et l'utilisation de raw sockets
 * pour analyser les headers reseau.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>

#define LISTEN_PORT 9999
#define BUFFER_SIZE 1024

/*
 * Etape 1 : Creer un socket TCP et se connecter a un serveur
 * C'est la base de toute communication reseau
 */
static void demo_tcp_client(void) {
    printf("[*] Etape 1 : Client TCP simple\n\n");

    /* Creer un socket : AF_INET = IPv4, SOCK_STREAM = TCP */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("    socket");
        return;
    }
    printf("    Socket cree (fd=%d)\n", sockfd);

    /* Preparer l'adresse de destination */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);  /* Port HTTP */

    /* Resoudre le nom de domaine en adresse IP */
    struct hostent *host = gethostbyname("example.com");
    if (!host) {
        printf("    [-] Resolution DNS echouee\n");
        close(sockfd);
        return;
    }
    memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
    printf("    Connexion a %s:%d...\n",
           inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    /* Connexion TCP (3-way handshake) */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("    [-] Connexion echouee : %s\n", strerror(errno));
        printf("    (verifie ta connexion internet)\n");
        close(sockfd);
        return;
    }
    printf("    [+] Connecte !\n");

    /* Envoyer une requete HTTP GET */
    const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    send(sockfd, request, strlen(request), 0);
    printf("    Requete HTTP envoyee\n");

    /* Lire la reponse (premieres lignes) */
    char buffer[BUFFER_SIZE];
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        /* Afficher seulement les headers (jusqu'a la premiere ligne vide) */
        char *end = strstr(buffer, "\r\n\r\n");
        if (end)
            *end = '\0';
        printf("    Reponse :\n");
        printf("    ---\n    %s\n    ---\n", buffer);
    }

    close(sockfd);
    printf("\n");
}

/*
 * Etape 2 : Mini serveur TCP
 * Accepte une connexion, lit le message, et repond
 */
static void demo_tcp_server(void) {
    printf("[*] Etape 2 : Mini serveur TCP (port %d)\n\n", LISTEN_PORT);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("    socket");
        return;
    }

    /* Permettre la reutilisation du port */
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  /* 127.0.0.1 uniquement */
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("    [-] Bind echoue : %s\n", strerror(errno));
        close(server_fd);
        return;
    }

    if (listen(server_fd, 1) < 0) {
        perror("    listen");
        close(server_fd);
        return;
    }
    printf("    Serveur en ecoute sur 127.0.0.1:%d\n", LISTEN_PORT);

    /* Fork : le fils est le serveur, le pere est le client */
    pid_t pid = fork();
    if (pid < 0) {
        perror("    fork");
        close(server_fd);
        return;
    }

    if (pid == 0) {
        /* Processus fils : serveur - attend une connexion */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("    accept");
            close(server_fd);
            _exit(1);
        }

        char buf[256];
        ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            /* Repondre au client */
            const char *response = "Message recu par le serveur !";
            send(client_fd, response, strlen(response), 0);
        }

        close(client_fd);
        close(server_fd);
        _exit(0);
    }

    /* Processus pere : client */
    close(server_fd);
    usleep(100000);  /* Attendre que le serveur soit pret */

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv.sin_port = htons(LISTEN_PORT);

    if (connect(client_fd, (struct sockaddr *)&srv, sizeof(srv)) == 0) {
        const char *msg = "Hello depuis le client !";
        send(client_fd, msg, strlen(msg), 0);
        printf("    Client -> Serveur : \"%s\"\n", msg);

        char buf[256];
        ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            printf("    Serveur -> Client : \"%s\"\n", buf);
        }
    } else {
        printf("    [-] Connexion client echouee\n");
    }

    close(client_fd);
    waitpid(pid, NULL, 0);
    printf("    [+] Communication TCP terminee\n\n");
}

/*
 * Etape 3 : Socket UDP (mode datagramme)
 * UDP est sans connexion : pas de handshake, pas de garantie de livraison
 */
static void demo_udp(void) {
    printf("[*] Etape 3 : Communication UDP\n\n");

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("    socket UDP");
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LISTEN_PORT + 1);

    /* Bind pour recevoir */
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("    [-] Bind UDP echoue : %s\n", strerror(errno));
        close(sockfd);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Fils : recepteur */
        char buf[256];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&from, &from_len);
        if (n > 0) {
            buf[n] = '\0';
        }
        close(sockfd);
        _exit(0);
    }

    /* Pere : emetteur */
    close(sockfd);
    usleep(50000);

    int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    const char *msg = "Datagramme UDP de test";
    sendto(send_fd, msg, strlen(msg), 0,
           (struct sockaddr *)&addr, sizeof(addr));
    printf("    Envoye via UDP : \"%s\"\n", msg);
    printf("    (UDP : pas de confirmation de reception)\n");

    close(send_fd);
    waitpid(pid, NULL, 0);
    printf("\n");
}

/*
 * Etape 4 : Informations sur les interfaces reseau
 * Utilise getaddrinfo pour resoudre des noms
 */
static void demo_dns_resolution(void) {
    printf("[*] Etape 4 : Resolution DNS avec getaddrinfo\n\n");

    const char *hosts[] = {"localhost", "example.com", "google.com", NULL};

    for (int i = 0; hosts[i]; i++) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(hosts[i], "80", &hints, &res);
        if (ret == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
            printf("    %-15s -> %s\n", hosts[i], inet_ntoa(addr->sin_addr));
            freeaddrinfo(res);
        } else {
            printf("    %-15s -> (erreur: %s)\n", hosts[i], gai_strerror(ret));
        }
    }
    printf("\n");
}

/*
 * Etape 5 : Afficher la structure d'un header IP
 * Montre comment les paquets sont structures en memoire
 */
static void demo_packet_structure(void) {
    printf("[*] Etape 5 : Structure d'un paquet IP (pedagogique)\n\n");

    printf("    Header IP (20 octets minimum) :\n");
    printf("    +------+------+------+------+------+------+------+------+\n");
    printf("    |Version| IHL  |   TOS      |       Total Length        |\n");
    printf("    +------+------+------+------+------+------+------+------+\n");
    printf("    |     Identification         | Flags|  Fragment Offset  |\n");
    printf("    +------+------+------+------+------+------+------+------+\n");
    printf("    |   TTL  |   Protocol  |       Header Checksum         |\n");
    printf("    +------+------+------+------+------+------+------+------+\n");
    printf("    |                 Source IP Address                     |\n");
    printf("    +------+------+------+------+------+------+------+------+\n");
    printf("    |              Destination IP Address                   |\n");
    printf("    +------+------+------+------+------+------+------+------+\n\n");

    printf("    sizeof(struct iphdr)  = %zu octets\n", sizeof(struct iphdr));
    printf("    sizeof(struct tcphdr) = %zu octets\n", sizeof(struct tcphdr));

    /* Construire un faux header IP en memoire pour montrer les champs */
    struct iphdr ip;
    memset(&ip, 0, sizeof(ip));
    ip.version = 4;
    ip.ihl = 5;                     /* 5 x 4 = 20 octets */
    ip.ttl = 64;
    ip.protocol = IPPROTO_TCP;      /* 6 */
    ip.saddr = inet_addr("192.168.1.100");
    ip.daddr = inet_addr("10.0.0.1");
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    printf("\n    Exemple de header IP forge en memoire :\n");
    printf("      Version  : %d\n", ip.version);
    printf("      IHL      : %d (%d octets)\n", ip.ihl, ip.ihl * 4);
    printf("      TTL      : %d\n", ip.ttl);
    printf("      Protocol : %d (TCP)\n", ip.protocol);
    printf("      Source   : %s\n", inet_ntoa(*(struct in_addr *)&ip.saddr));
    printf("      Dest     : %s\n", inet_ntoa(*(struct in_addr *)&ip.daddr));
    printf("      Taille   : %d octets\n", ntohs(ip.tot_len));
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Networking Linux - Sockets et Reseau\n\n");

    /* Ignorer SIGPIPE pour eviter les crashs sur les connexions fermees */
    signal(SIGPIPE, SIG_IGN);

    demo_tcp_client();
    demo_tcp_server();
    demo_udp();
    demo_dns_resolution();
    demo_packet_structure();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
