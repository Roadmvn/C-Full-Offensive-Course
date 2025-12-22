/*
 * Exercise 02 - Gestion d'erreurs
 * ================================
 *
 * OBJECTIF :
 * Maîtriser GetLastError et FormatMessage en tentant d'ouvrir un fichier inexistant.
 *
 * INSTRUCTIONS :
 * 1. Tenter d'ouvrir un fichier qui n'existe pas avec CreateFileA
 * 2. Vérifier si l'appel a échoué (INVALID_HANDLE_VALUE)
 * 3. Utiliser GetLastError() pour récupérer le code d'erreur
 * 4. Utiliser FormatMessage() pour convertir le code en message lisible
 * 5. Afficher le code d'erreur et le message
 * 6. Vérifier si le code est ERROR_FILE_NOT_FOUND (2)
 *
 * BONUS :
 * - Créer une fonction réutilisable PrintLastError(const char* funcName)
 * - Tester avec différents types d'erreur (accès refusé, chemin invalide...)
 * - Afficher un MessageBox avec le message d'erreur
 *
 * COMPILATION :
 * cl /W4 ex02-error-check.c /link kernel32.lib
 */

#include <windows.h>
#include <stdio.h>

/*
 * TODO : Implémenter cette fonction
 * Elle doit :
 * 1. Appeler GetLastError()
 * 2. Utiliser FormatMessage pour obtenir le message
 * 3. Afficher le nom de la fonction, le code et le message
 * 4. Libérer le buffer avec LocalFree
 */
void PrintLastError(const char* functionName) {
    // TODO : Implémenter
}

int main(void) {
    printf("=== EXERCICE 02 : Gestion d'erreurs ===\n\n");

    // TODO : Étape 1 - Tenter d'ouvrir un fichier inexistant
    HANDLE hFile;
    const char* fileName = "C:\\fichier_qui_nexiste_pas.txt";

    printf("Tentative d'ouverture de %s...\n", fileName);

    // TODO : Appeler CreateFileA avec OPEN_EXISTING
    // Paramètres attendus :
    // - Nom du fichier
    // - GENERIC_READ
    // - 0 (pas de partage)
    // - NULL (sécurité par défaut)
    // - OPEN_EXISTING
    // - FILE_ATTRIBUTE_NORMAL
    // - NULL (pas de template)

    // TODO : Étape 2 - Vérifier l'échec
    // if (hFile == INVALID_HANDLE_VALUE) { ... }

    // TODO : Étape 3 - Récupérer le code d'erreur
    DWORD dwError;  // TODO : = GetLastError();

    // TODO : Étape 4 - Afficher le code
    // printf("Code d'erreur : %lu\n", dwError);

    // TODO : Étape 5 - Utiliser FormatMessage
    // Utiliser la fonction PrintLastError() que vous avez implémentée

    // TODO : Étape 6 - Vérifier si c'est ERROR_FILE_NOT_FOUND
    // if (dwError == ERROR_FILE_NOT_FOUND) { ... }

    printf("\n");

    // BONUS 1 : Tester avec un fichier protégé (accès refusé)
    printf("=== BONUS : Test avec fichier protégé ===\n");
    // TODO : Essayer d'ouvrir C:\\Windows\\System32\\config\\SAM
    // Vous devriez obtenir ERROR_ACCESS_DENIED (5)

    // BONUS 2 : Afficher les codes d'erreur courants
    printf("\n=== Codes d'erreur courants ===\n");
    printf("ERROR_SUCCESS          : %lu\n", (DWORD)ERROR_SUCCESS);
    printf("ERROR_FILE_NOT_FOUND   : %lu\n", (DWORD)ERROR_FILE_NOT_FOUND);
    printf("ERROR_PATH_NOT_FOUND   : %lu\n", (DWORD)ERROR_PATH_NOT_FOUND);
    printf("ERROR_ACCESS_DENIED    : %lu\n", (DWORD)ERROR_ACCESS_DENIED);
    printf("ERROR_INVALID_HANDLE   : %lu\n", (DWORD)ERROR_INVALID_HANDLE);
    printf("ERROR_NOT_ENOUGH_MEMORY: %lu\n", (DWORD)ERROR_NOT_ENOUGH_MEMORY);

    return 0;
}

/*
 * AIDE : Prototype de FormatMessage
 *
 * DWORD FormatMessageA(
 *     DWORD   dwFlags,       // FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
 *     LPCVOID lpSource,      // NULL pour les messages système
 *     DWORD   dwMessageId,   // Code d'erreur de GetLastError()
 *     DWORD   dwLanguageId,  // MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
 *     LPSTR   lpBuffer,      // &buffer si ALLOCATE_BUFFER
 *     DWORD   nSize,         // 0 si ALLOCATE_BUFFER
 *     va_list *Arguments     // NULL
 * );
 *
 * IMPORTANT :
 * - Si FORMAT_MESSAGE_ALLOCATE_BUFFER, Windows alloue le buffer
 * - Il faut ensuite libérer avec LocalFree(buffer)
 * - Le buffer doit être casté en (LPSTR*)&buffer
 */
