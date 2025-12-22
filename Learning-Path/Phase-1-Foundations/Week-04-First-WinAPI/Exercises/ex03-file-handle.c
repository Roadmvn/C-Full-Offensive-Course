/*
 * Exercise 03 - Manipulation de handles fichier
 * ==============================================
 *
 * OBJECTIF :
 * Manipuler un handle de fichier : créer, écrire, lire, obtenir la taille, fermer.
 *
 * INSTRUCTIONS :
 * 1. Créer un fichier "test.txt" avec CreateFileA
 * 2. Écrire du texte dedans avec WriteFile
 * 3. Récupérer la taille du fichier avec GetFileSizeEx
 * 4. Repositionner le pointeur au début avec SetFilePointerEx
 * 5. Lire le contenu avec ReadFile
 * 6. Fermer le handle avec CloseHandle
 * 7. Vérifier chaque étape et gérer les erreurs
 *
 * BONUS :
 * - Ajouter du texte à la fin du fichier (FILE_APPEND_DATA)
 * - Créer un fichier binaire et écrire une structure
 * - Mapper le fichier en mémoire avec CreateFileMapping
 *
 * COMPILATION :
 * cl /W4 ex03-file-handle.c /link kernel32.lib
 */

#include <windows.h>
#include <stdio.h>

/*
 * Fonction utilitaire pour afficher les erreurs
 */
void PrintError(const char* functionName) {
    DWORD dwError = GetLastError();
    LPVOID lpMsgBuf = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0,
        NULL
    );

    printf("[!] %s failed with error %lu: %s",
           functionName, dwError, (char*)lpMsgBuf);

    LocalFree(lpMsgBuf);
}

int main(void) {
    printf("=== EXERCICE 03 : Manipulation de handles fichier ===\n\n");

    HANDLE hFile = INVALID_HANDLE_VALUE;
    const char* fileName = "test.txt";
    BOOL bSuccess = FALSE;

    // TODO : ÉTAPE 1 - Créer le fichier
    printf("ÉTAPE 1 : Création du fichier %s\n", fileName);

    // TODO : Utiliser CreateFileA
    // Paramètres :
    // - fileName
    // - GENERIC_WRITE | GENERIC_READ (lecture et écriture)
    // - 0 (pas de partage)
    // - NULL
    // - CREATE_ALWAYS (créer ou écraser)
    // - FILE_ATTRIBUTE_NORMAL
    // - NULL

    // TODO : Vérifier si le handle est valide
    // if (hFile == INVALID_HANDLE_VALUE) { ... }

    printf("[+] Fichier créé, handle : 0x%p\n\n", (void*)hFile);

    // TODO : ÉTAPE 2 - Écrire dans le fichier
    printf("ÉTAPE 2 : Écriture de données\n");

    const char* data = "Bonjour WinAPI!\nCeci est un test de WriteFile.\n";
    DWORD bytesWritten = 0;

    // TODO : Utiliser WriteFile
    // BOOL WriteFile(
    //     HANDLE hFile,
    //     LPCVOID lpBuffer,
    //     DWORD nNumberOfBytesToWrite,
    //     LPDWORD lpNumberOfBytesWritten,
    //     LPOVERLAPPED lpOverlapped
    // );

    // TODO : Vérifier le succès et afficher bytesWritten

    // TODO : ÉTAPE 3 - Obtenir la taille du fichier
    printf("ÉTAPE 3 : Récupération de la taille\n");

    LARGE_INTEGER fileSize;

    // TODO : Utiliser GetFileSizeEx
    // BOOL GetFileSizeEx(
    //     HANDLE hFile,
    //     PLARGE_INTEGER lpFileSize
    // );

    // TODO : Afficher fileSize.QuadPart

    // TODO : ÉTAPE 4 - Repositionner au début
    printf("ÉTAPE 4 : Retour au début du fichier\n");

    LARGE_INTEGER moveDistance = {0};
    LARGE_INTEGER newPosition;

    // TODO : Utiliser SetFilePointerEx
    // BOOL SetFilePointerEx(
    //     HANDLE hFile,
    //     LARGE_INTEGER liDistanceToMove,
    //     PLARGE_INTEGER lpNewFilePointer,
    //     DWORD dwMoveMethod
    // );
    // dwMoveMethod : FILE_BEGIN, FILE_CURRENT, FILE_END

    // TODO : ÉTAPE 5 - Lire le contenu
    printf("ÉTAPE 5 : Lecture du contenu\n");

    char buffer[512] = {0};
    DWORD bytesRead = 0;

    // TODO : Utiliser ReadFile
    // BOOL ReadFile(
    //     HANDLE hFile,
    //     LPVOID lpBuffer,
    //     DWORD nNumberOfBytesToRead,
    //     LPDWORD lpNumberOfBytesRead,
    //     LPOVERLAPPED lpOverlapped
    // );

    // TODO : Afficher le contenu lu et bytesRead

    // TODO : ÉTAPE 6 - Fermer le handle
    printf("ÉTAPE 6 : Fermeture du handle\n");

    // TODO : Utiliser CloseHandle
    // if (CloseHandle(hFile)) { ... }

    printf("[+] Handle fermé avec succès\n\n");

    // Mettre le handle à NULL après fermeture (bonne pratique)
    hFile = INVALID_HANDLE_VALUE;

    // TODO : BONUS 1 - Vérifier que le fichier existe avec GetFileAttributes
    printf("=== BONUS 1 : Vérification de l'existence ===\n");
    DWORD attributes = GetFileAttributesA(fileName);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        printf("[+] Fichier existe\n");
        printf("    Attributs : 0x%lX\n", attributes);

        // Afficher les attributs
        if (attributes & FILE_ATTRIBUTE_ARCHIVE)
            printf("    - Archive\n");
        if (attributes & FILE_ATTRIBUTE_READONLY)
            printf("    - Read-only\n");
        if (attributes & FILE_ATTRIBUTE_HIDDEN)
            printf("    - Hidden\n");
    }

    // TODO : BONUS 2 - Supprimer le fichier avec DeleteFileA
    printf("\n=== BONUS 2 : Suppression du fichier ===\n");
    // if (DeleteFileA(fileName)) { ... }

    printf("\nProgramme terminé!\n");
    return 0;
}

/*
 * RAPPELS :
 *
 * 1. TOUJOURS vérifier le retour de CreateFile :
 *    if (hFile == INVALID_HANDLE_VALUE) { ... }
 *
 * 2. TOUJOURS fermer les handles :
 *    CloseHandle(hFile);
 *
 * 3. LARGE_INTEGER pour les tailles > 4GB :
 *    LARGE_INTEGER size;
 *    GetFileSizeEx(hFile, &size);
 *    printf("%lld bytes\n", size.QuadPart);
 *
 * 4. Pattern typique :
 *    Create -> Check -> Use -> Close -> Check
 *
 * 5. Gestion d'erreur :
 *    if (!WriteFile(...)) {
 *        PrintError("WriteFile");
 *        goto cleanup;
 *    }
 *
 * cleanup:
 *    if (hFile != INVALID_HANDLE_VALUE) {
 *        CloseHandle(hFile);
 *    }
 */
