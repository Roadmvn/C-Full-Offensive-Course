/*
 * Lesson 03 - Gestion d'erreurs WinAPI
 * =====================================
 *
 * OBJECTIF :
 * Maîtriser la gestion d'erreurs dans les appels WinAPI.
 *
 * CONCEPTS CLÉS :
 * - GetLastError() : Récupérer le code d'erreur
 * - FormatMessage() : Convertir code en message lisible
 * - SetLastError() : Définir un code d'erreur
 * - Patterns de vérification d'erreur
 *
 * PRINCIPE WINDOWS :
 * 1. L'API retourne une valeur indiquant succès/échec
 * 2. En cas d'échec, appeler GetLastError() pour le code d'erreur
 * 3. Le code d'erreur est thread-local (TLS)
 * 4. GetLastError() ne réinitialise PAS l'erreur
 *
 * ATTENTION :
 * - Appeler GetLastError() immédiatement après l'échec
 * - D'autres appels peuvent modifier le code d'erreur
 * - En succès, GetLastError() n'est PAS garanti à 0
 */

#include <windows.h>
#include <stdio.h>

/*
 * Fonction utilitaire : Afficher le message d'erreur Windows
 * Pattern essentiel en maldev
 */
void PrintLastError(const char* functionName) {
    DWORD dwError = GetLastError();

    if (dwError == 0) {
        printf("[%s] Aucune erreur (code 0)\n", functionName);
        return;
    }

    // Buffer pour le message d'erreur
    LPVOID lpMsgBuf = NULL;

    // FormatMessage : Convertit un code d'erreur en message lisible
    DWORD dwResult = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |  // Windows alloue le buffer
        FORMAT_MESSAGE_FROM_SYSTEM |      // Message d'erreur système
        FORMAT_MESSAGE_IGNORE_INSERTS,    // Ignore les paramètres %1, %2...
        NULL,                              // Source (NULL = système)
        dwError,                           // Code d'erreur
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Langue par défaut
        (LPSTR)&lpMsgBuf,                 // Buffer (cast requis pour ALLOCATE)
        0,                                 // Taille min (0 = auto)
        NULL                               // Arguments
    );

    if (dwResult == 0) {
        // FormatMessage a échoué
        printf("[%s] Erreur %lu (impossible de formater le message)\n",
               functionName, dwError);
        return;
    }

    // Afficher l'erreur
    printf("[%s] Erreur %lu: %s", functionName, dwError, (char*)lpMsgBuf);

    // IMPORTANT : Libérer le buffer alloué par FormatMessage
    LocalFree(lpMsgBuf);
}

/*
 * Exemple 1 : Erreur basique - Fichier inexistant
 */
void Example1_FileNotFound(void) {
    printf("\n=== EXEMPLE 1 : Fichier inexistant ===\n");

    // Tentative d'ouverture d'un fichier qui n'existe pas
    HANDLE hFile = CreateFileA(
        "C:\\fichier_inexistant.txt",  // Nom du fichier
        GENERIC_READ,                   // Accès lecture
        0,                              // Pas de partage
        NULL,                           // Sécurité par défaut
        OPEN_EXISTING,                  // Ouvrir seulement si existe
        FILE_ATTRIBUTE_NORMAL,          // Attributs normaux
        NULL                            // Pas de template
    );

    // Vérification : CreateFile retourne INVALID_HANDLE_VALUE en cas d'erreur
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA a échoué !\n");
        PrintLastError("CreateFileA");

        // Code d'erreur attendu : ERROR_FILE_NOT_FOUND (2)
        DWORD dwError = GetLastError();
        if (dwError == ERROR_FILE_NOT_FOUND) {
            printf("Erreur confirmée : Le fichier n'existe pas (ERROR_FILE_NOT_FOUND)\n");
        }
    } else {
        printf("Succès inattendu !\n");
        CloseHandle(hFile);
    }
}

/*
 * Exemple 2 : Erreur d'accès refusé
 */
void Example2_AccessDenied(void) {
    printf("\n=== EXEMPLE 2 : Accès refusé ===\n");

    // Tentative d'ouverture de System32 en écriture (normalement refusé)
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\config\\SAM",  // Fichier SAM (protégé)
        GENERIC_WRITE,                         // Accès écriture
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA a échoué (attendu) !\n");
        PrintLastError("CreateFileA");

        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED) {
            printf("Erreur confirmée : Accès refusé (ERROR_ACCESS_DENIED)\n");
        } else if (dwError == ERROR_SHARING_VIOLATION) {
            printf("Erreur : Fichier utilisé par un autre processus\n");
        }
    } else {
        printf("Succès inattendu ! (élévation ?)\n");
        CloseHandle(hFile);
    }
}

/*
 * Exemple 3 : FormatMessage détaillé
 */
void Example3_FormatMessageDetailed(void) {
    printf("\n=== EXEMPLE 3 : FormatMessage détaillé ===\n");

    // Simuler plusieurs codes d'erreur courants
    DWORD errorCodes[] = {
        ERROR_SUCCESS,           // 0
        ERROR_FILE_NOT_FOUND,    // 2
        ERROR_ACCESS_DENIED,     // 5
        ERROR_INVALID_HANDLE,    // 6
        ERROR_NOT_ENOUGH_MEMORY, // 8
        ERROR_INVALID_PARAMETER  // 87
    };

    printf("Traduction de codes d'erreur courants :\n\n");

    for (int i = 0; i < sizeof(errorCodes) / sizeof(DWORD); i++) {
        DWORD dwError = errorCodes[i];
        LPVOID lpMsgBuf = NULL;

        DWORD dwResult = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            dwError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&lpMsgBuf,
            0,
            NULL
        );

        if (dwResult > 0) {
            printf("  Code %lu: %s", dwError, (char*)lpMsgBuf);
            LocalFree(lpMsgBuf);
        } else {
            printf("  Code %lu: <Impossible de formater>\n", dwError);
        }
    }
}

/*
 * Exemple 4 : Pattern de gestion d'erreur robuste
 */
BOOL SecureFileOperation(const char* fileName) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOL bSuccess = FALSE;
    DWORD dwError = 0;

    printf("\n=== EXEMPLE 4 : Pattern robuste ===\n");
    printf("Tentative d'ouverture de %s...\n", fileName);

    // Étape 1 : Appel API
    hFile = CreateFileA(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // Étape 2 : Vérification immédiate
    if (hFile == INVALID_HANDLE_VALUE) {
        dwError = GetLastError();  // Capturer IMMÉDIATEMENT
        printf("Échec de CreateFileA\n");
        PrintLastError("CreateFileA");
        goto cleanup;  // Nettoyage propre
    }

    printf("Fichier ouvert avec succès !\n");
    printf("Handle : 0x%p\n", (void*)hFile);

    // Opérations sur le fichier...
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        dwError = GetLastError();
        printf("Échec de GetFileSizeEx\n");
        PrintLastError("GetFileSizeEx");
        goto cleanup;
    }

    printf("Taille du fichier : %lld bytes\n", fileSize.QuadPart);
    bSuccess = TRUE;

cleanup:
    // Étape 3 : Nettoyage (TOUJOURS exécuté)
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        printf("Handle fermé proprement\n");
    }

    // Étape 4 : Restaurer le code d'erreur si nécessaire
    if (!bSuccess && dwError != 0) {
        SetLastError(dwError);
    }

    return bSuccess;
}

/*
 * Exemple 5 : Codes d'erreur courants en maldev
 */
void Example5_CommonMaldevErrors(void) {
    printf("\n=== EXEMPLE 5 : Codes d'erreur courants en maldev ===\n\n");

    printf("Codes d'erreur à connaître :\n\n");

    printf("FICHIERS :\n");
    printf("  ERROR_FILE_NOT_FOUND (%lu)    : Fichier introuvable\n",
           (DWORD)ERROR_FILE_NOT_FOUND);
    printf("  ERROR_PATH_NOT_FOUND (%lu)    : Chemin introuvable\n",
           (DWORD)ERROR_PATH_NOT_FOUND);
    printf("  ERROR_ACCESS_DENIED (%lu)     : Accès refusé\n",
           (DWORD)ERROR_ACCESS_DENIED);
    printf("  ERROR_SHARING_VIOLATION (%lu) : Fichier en cours d'utilisation\n\n",
           (DWORD)ERROR_SHARING_VIOLATION);

    printf("MÉMOIRE :\n");
    printf("  ERROR_NOT_ENOUGH_MEMORY (%lu) : Mémoire insuffisante\n",
           (DWORD)ERROR_NOT_ENOUGH_MEMORY);
    printf("  ERROR_OUTOFMEMORY (%lu)       : Mémoire épuisée\n\n",
           (DWORD)ERROR_OUTOFMEMORY);

    printf("PROCESSUS :\n");
    printf("  ERROR_INVALID_HANDLE (%lu)    : Handle invalide\n",
           (DWORD)ERROR_INVALID_HANDLE);
    printf("  ERROR_ACCESS_DENIED (%lu)     : Privilèges insuffisants\n",
           (DWORD)ERROR_ACCESS_DENIED);
    printf("  ERROR_INVALID_PARAMETER (%lu) : Paramètre invalide\n\n",
           (DWORD)ERROR_INVALID_PARAMETER);

    printf("INJECTIONS :\n");
    printf("  ERROR_PARTIAL_COPY (%lu)      : WriteProcessMemory partiel\n",
           (DWORD)ERROR_PARTIAL_COPY);
    printf("  ERROR_ACCESS_DENIED (%lu)     : DEP/ASLR/CFG actif\n",
           (DWORD)ERROR_ACCESS_DENIED);
}

/*
 * Exemple 6 : Fonction wrapper pour affichage d'erreur
 */
void PrintFormattedError(const char* functionName, DWORD dwError) {
    char errorMsg[512] = {0};

    DWORD result = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        errorMsg,
        sizeof(errorMsg),
        NULL
    );

    if (result > 0) {
        printf("[!] %s failed with error %lu: %s", functionName, dwError, errorMsg);
    } else {
        printf("[!] %s failed with error %lu (unable to format message)\n",
               functionName, dwError);
    }
}

/*
 * Exemple 7 : Macro pour simplifier la gestion d'erreur
 */
#define CHECK_API_CALL(call, errorValue) \
    do { \
        if ((call) == (errorValue)) { \
            DWORD dwErr = GetLastError(); \
            printf("[!] %s failed at line %d\n", #call, __LINE__); \
            PrintFormattedError(#call, dwErr); \
            goto cleanup; \
        } \
    } while(0)

void Example7_MacroUsage(void) {
    printf("\n=== EXEMPLE 7 : Utilisation de macros ===\n");

    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Utilisation de la macro pour simplifier le code
    CHECK_API_CALL(
        hFile = CreateFileA(
            "test_inexistant.txt",
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        ),
        INVALID_HANDLE_VALUE
    );

    printf("Fichier ouvert avec succès\n");

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }

    printf("Macro pattern : utile pour code répétitif\n");
}

int main(void) {
    printf("===================================================\n");
    printf("  LESSON 03 - GESTION D'ERREURS WINAPI\n");
    printf("===================================================\n");

    Example1_FileNotFound();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example2_AccessDenied();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example3_FormatMessageDetailed();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    // Test avec fichier existant (ce fichier lui-même)
    SecureFileOperation(__FILE__);

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example5_CommonMaldevErrors();

    Example7_MacroUsage();

    printf("\n===================================================\n");
    printf("  Points clés à retenir :\n");
    printf("  1. GetLastError() IMMÉDIATEMENT après échec\n");
    printf("  2. FormatMessage() pour traduire les codes\n");
    printf("  3. Pattern : appel -> vérif -> GetLastError -> cleanup\n");
    printf("  4. HANDLE invalide = INVALID_HANDLE_VALUE ou NULL\n");
    printf("  5. Toujours libérer les ressources (CloseHandle)\n");
    printf("===================================================\n");

    return 0;
}
