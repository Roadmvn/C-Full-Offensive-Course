/*
 * OBJECTIF  : Comprendre le modele de securite Windows (tokens, privileges, ACL)
 * PREREQUIS : Bases du C, notions de processus Windows
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib
 *
 * Ce programme explore les mecanismes de securite Windows :
 * - Tokens d'acces (identite du processus)
 * - Privileges (SeDebugPrivilege, SeBackupPrivilege, etc.)
 * - Niveaux d'integrite (Low, Medium, High, SYSTEM)
 * - SID (Security Identifiers)
 */

#include <windows.h>
#include <stdio.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

/* Afficher les informations du token courant */
void display_token_user(HANDLE hToken) {
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    TOKEN_USER* user = (TOKEN_USER*)malloc(size);

    if (GetTokenInformation(hToken, TokenUser, user, size, &size)) {
        char name[256], domain[256];
        DWORD nsize = sizeof(name), dsize = sizeof(domain);
        SID_NAME_USE type;

        if (LookupAccountSidA(NULL, user->User.Sid, name, &nsize, domain, &dsize, &type)) {
            printf("    Utilisateur : %s\\%s\n", domain, name);
        }

        /* Convertir le SID en chaine lisible */
        LPSTR sid_str = NULL;
        if (ConvertSidToStringSidA(user->User.Sid, &sid_str)) {
            printf("    SID         : %s\n", sid_str);
            LocalFree(sid_str);
        }
    }
    free(user);
}

/* Afficher le niveau d'integrite */
void display_integrity_level(HANDLE hToken) {
    DWORD size = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &size);
    TOKEN_MANDATORY_LABEL* label = (TOKEN_MANDATORY_LABEL*)malloc(size);

    if (GetTokenInformation(hToken, TokenIntegrityLevel, label, size, &size)) {
        DWORD integrity = *GetSidSubAuthority(
            label->Label.Sid,
            *GetSidSubAuthorityCount(label->Label.Sid) - 1);

        const char* level_name;
        if (integrity < SECURITY_MANDATORY_LOW_RID)
            level_name = "Untrusted";
        else if (integrity < SECURITY_MANDATORY_MEDIUM_RID)
            level_name = "Low";
        else if (integrity < SECURITY_MANDATORY_HIGH_RID)
            level_name = "Medium";
        else if (integrity < SECURITY_MANDATORY_SYSTEM_RID)
            level_name = "High";
        else
            level_name = "SYSTEM";

        printf("    Integrite   : %s (0x%lX)\n", level_name, integrity);
    }
    free(label);
}

/* Afficher le type de token (Primary vs Impersonation) */
void display_token_type(HANDLE hToken) {
    TOKEN_TYPE type;
    DWORD size;
    if (GetTokenInformation(hToken, TokenType, &type, sizeof(type), &size)) {
        printf("    Type token  : %s\n", type == TokenPrimary ? "Primary" : "Impersonation");
    }

    /* Verifier si elevated */
    TOKEN_ELEVATION elevation;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        printf("    Eleve (UAC) : %s\n", elevation.TokenIsElevated ? "OUI (admin)" : "NON");
    }
}

/* Lister les privileges du token */
void display_privileges(HANDLE hToken) {
    DWORD size = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &size);
    TOKEN_PRIVILEGES* privs = (TOKEN_PRIVILEGES*)malloc(size);

    if (GetTokenInformation(hToken, TokenPrivileges, privs, size, &size)) {
        printf("\n[*] Privileges du token (%lu) :\n", privs->PrivilegeCount);
        printf("    %-35s  %s\n", "Privilege", "Status");
        printf("    %-35s  %s\n", "-----------------------------------", "--------");

        for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
            char name[256];
            DWORD nsize = sizeof(name);
            LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, name, &nsize);

            DWORD attr = privs->Privileges[i].Attributes;
            const char* status;
            if (attr & SE_PRIVILEGE_ENABLED)
                status = "[ACTIVE]";
            else if (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                status = "[DEFAULT]";
            else
                status = "[DESACTIVE]";

            printf("    %-35s  %s\n", name, status);
        }
    }
    free(privs);
}

/* Lister les groupes du token */
void display_groups(HANDLE hToken) {
    DWORD size = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &size);
    TOKEN_GROUPS* groups = (TOKEN_GROUPS*)malloc(size);

    if (GetTokenInformation(hToken, TokenGroups, groups, size, &size)) {
        printf("\n[*] Groupes du token (%lu) :\n", groups->GroupCount);

        int displayed = 0;
        for (DWORD i = 0; i < groups->GroupCount && displayed < 15; i++) {
            char name[256], domain[256];
            DWORD nsize = sizeof(name), dsize = sizeof(domain);
            SID_NAME_USE type;

            if (LookupAccountSidA(NULL, groups->Groups[i].Sid,
                                   name, &nsize, domain, &dsize, &type)) {
                DWORD attr = groups->Groups[i].Attributes;
                printf("    %s\\%-20s", domain, name);
                if (attr & SE_GROUP_ENABLED) printf(" [ACTIF]");
                if (attr & SE_GROUP_OWNER)   printf(" [OWNER]");
                printf("\n");
                displayed++;
            }
        }
        if (groups->GroupCount > 15)
            printf("    ... (%lu de plus)\n", groups->GroupCount - 15);
    }
    free(groups);
}

/* Demo : Activer SeDebugPrivilege */
BOOL enable_privilege(HANDLE hToken, const char* privilege_name) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, privilege_name, &luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
        return FALSE;

    return (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}

int main(void) {
    printf("[*] Demo : Modele de securite Windows\n");
    printf("[*] ==========================================\n\n");

    /* Ouvrir le token du processus courant */
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                           TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("[-] OpenProcessToken echoue (err %lu)\n", GetLastError());
        return 1;
    }

    /* Informations de base */
    printf("[1] Token du processus courant (PID %lu)\n", GetCurrentProcessId());
    display_token_user(hToken);
    display_integrity_level(hToken);
    display_token_type(hToken);

    /* Privileges */
    display_privileges(hToken);

    /* Groupes */
    display_groups(hToken);

    /* Demo activation de privilege */
    printf("\n[*] Tentative d'activation de SeDebugPrivilege\n");
    if (enable_privilege(hToken, "SeDebugPrivilege")) {
        printf("    [+] SeDebugPrivilege active avec succes\n");
        printf("    [*] Permet d'ouvrir n'importe quel processus (meme SYSTEM)\n");
    } else {
        printf("    [-] Echec : necessite un token administrateur\n");
    }

    CloseHandle(hToken);
    printf("\n[+] Exemple termine avec succes\n");
    return 0;
}
