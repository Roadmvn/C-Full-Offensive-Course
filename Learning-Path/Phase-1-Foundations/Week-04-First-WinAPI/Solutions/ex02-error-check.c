/*
 * Solution Exercise 02 - Gestion d'erreurs
 * =========================================
 *
 * Solution complète avec gestion d'erreurs robuste.
 */

#include <windows.h>
#include <stdio.h>

/*
 * Fonction réutilisable pour afficher les erreurs Windows
 */
void PrintLastError(const char* functionName) {
    DWORD dwError = GetLastError();

    if (dwError == 0) {
        printf("[%s] Aucune erreur détectée\n", functionName);
        return;
    }

    // Allouer un buffer pour le message d'erreur
    LPVOID lpMsgBuf = NULL;

    DWORD result = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |  // Windows alloue le buffer
        FORMAT_MESSAGE_FROM_SYSTEM |      // Message d'erreur système
        FORMAT_MESSAGE_IGNORE_INSERTS,    // Ignore les paramètres %1, %2
        NULL,                              // Source (NULL = système)
        dwError,                           // Code d'erreur
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Langue par défaut
        (LPSTR)&lpMsgBuf,                 // Pointeur vers le buffer
        0,                                 // Taille minimale (0 = auto)
        NULL                               // Arguments
    );

    if (result == 0) {
        // FormatMessage a échoué
        printf("[!] %s failed with error %lu (unable to format message)\n",
               functionName, dwError);
        return;
    }

    // Afficher le message d'erreur
    printf("[!] %s failed with error %lu: %s",
           functionName, dwError, (char*)lpMsgBuf);

    // IMPORTANT : Libérer le buffer alloué par FormatMessage
    LocalFree(lpMsgBuf);
}

int main(void) {
    printf("=== SOLUTION EXERCICE 02 : Gestion d'erreurs ===\n\n");

    // ÉTAPE 1 : Tenter d'ouvrir un fichier inexistant
    HANDLE hFile;
    const char* fileName = "C:\\fichier_qui_nexiste_pas.txt";

    printf("Tentative d'ouverture de %s...\n", fileName);

    hFile = CreateFileA(
        fileName,              // Nom du fichier
        GENERIC_READ,          // Accès en lecture
        0,                     // Pas de partage
        NULL,                  // Sécurité par défaut
        OPEN_EXISTING,         // Ouvrir seulement si existe
        FILE_ATTRIBUTE_NORMAL, // Attributs normaux
        NULL                   // Pas de template
    );

    // ÉTAPE 2 : Vérifier l'échec
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA a échoué (attendu)\n\n");

        // ÉTAPE 3 : Récupérer le code d'erreur
        DWORD dwError = GetLastError();

        // ÉTAPE 4 : Afficher le code brut
        printf("Code d'erreur brut : %lu\n", dwError);

        // ÉTAPE 5 : Utiliser FormatMessage via notre fonction
        PrintLastError("CreateFileA");

        // ÉTAPE 6 : Vérifier si c'est ERROR_FILE_NOT_FOUND
        if (dwError == ERROR_FILE_NOT_FOUND) {
            printf("\n[+] Erreur confirmée : Fichier introuvable (ERROR_FILE_NOT_FOUND)\n");
        }
    } else {
        printf("[!] Le fichier existe réellement (inattendu) !\n");
        CloseHandle(hFile);
    }

    printf("\n");

    // BONUS 1 : Test avec fichier protégé (accès refusé)
    printf("=== BONUS 1 : Test avec fichier protégé ===\n");
    const char* protectedFile = "C:\\Windows\\System32\\config\\SAM";

    printf("Tentative d'ouverture de %s en écriture...\n", protectedFile);

    hFile = CreateFileA(
        protectedFile,
        GENERIC_WRITE,         // Tentative d'écriture (normalement refusée)
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();
        printf("CreateFileA a échoué (attendu)\n\n");
        printf("Code d'erreur : %lu\n", dwError);
        PrintLastError("CreateFileA");

        if (dwError == ERROR_ACCESS_DENIED) {
            printf("\n[+] Erreur confirmée : Accès refusé (ERROR_ACCESS_DENIED)\n");
            printf("    Raison : Privilèges insuffisants ou fichier protégé\n");
        } else if (dwError == ERROR_SHARING_VIOLATION) {
            printf("\n[+] Erreur : Fichier déjà ouvert par un autre processus\n");
        }
    } else {
        printf("[!] Accès accordé (élévation de privilèges ?)\n");
        CloseHandle(hFile);
    }

    printf("\n");

    // BONUS 2 : Afficher les codes d'erreur courants
    printf("=== BONUS 2 : Codes d'erreur courants ===\n\n");

    struct ErrorCode {
        DWORD code;
        const char* name;
    };

    struct ErrorCode errors[] = {
        {ERROR_SUCCESS, "ERROR_SUCCESS"},
        {ERROR_FILE_NOT_FOUND, "ERROR_FILE_NOT_FOUND"},
        {ERROR_PATH_NOT_FOUND, "ERROR_PATH_NOT_FOUND"},
        {ERROR_ACCESS_DENIED, "ERROR_ACCESS_DENIED"},
        {ERROR_INVALID_HANDLE, "ERROR_INVALID_HANDLE"},
        {ERROR_NOT_ENOUGH_MEMORY, "ERROR_NOT_ENOUGH_MEMORY"},
        {ERROR_INVALID_PARAMETER, "ERROR_INVALID_PARAMETER"},
        {ERROR_SHARING_VIOLATION, "ERROR_SHARING_VIOLATION"}
    };

    printf("%-30s | Code\n", "Constante");
    printf("-----------------------------------------------\n");

    for (int i = 0; i < sizeof(errors) / sizeof(struct ErrorCode); i++) {
        printf("%-30s | %lu\n", errors[i].name, errors[i].code);
    }

    printf("\n");

    // BONUS 3 : Test de formatage de différents codes
    printf("=== BONUS 3 : Messages formatés ===\n\n");

    DWORD testCodes[] = {
        ERROR_FILE_NOT_FOUND,
        ERROR_ACCESS_DENIED,
        ERROR_INVALID_HANDLE,
        ERROR_NOT_ENOUGH_MEMORY
    };

    for (int i = 0; i < sizeof(testCodes) / sizeof(DWORD); i++) {
        LPVOID lpMsgBuf = NULL;

        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            testCodes[i],
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&lpMsgBuf,
            0,
            NULL
        );

        printf("Code %lu: %s", testCodes[i], (char*)lpMsgBuf);
        LocalFree(lpMsgBuf);
    }

    // BONUS 4 : Afficher l'erreur dans une MessageBox
    printf("\n=== BONUS 4 : MessageBox avec erreur ===\n");

    // Forcer une erreur
    CreateFileA("inexistant.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD dwLastError = GetLastError();
    LPVOID lpMsgBuf = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0,
        NULL
    );

    char errorTitle[64];
    sprintf(errorTitle, "Erreur %lu", dwLastError);

    MessageBoxA(NULL, (char*)lpMsgBuf, errorTitle, MB_OK | MB_ICONERROR);
    LocalFree(lpMsgBuf);

    printf("Programme terminé!\n");
    return 0;
}
