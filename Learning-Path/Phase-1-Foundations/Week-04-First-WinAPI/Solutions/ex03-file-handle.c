/*
 * Solution Exercise 03 - Manipulation de handles fichier
 * =======================================================
 *
 * Solution complète avec gestion d'erreurs et bonuses.
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
    printf("=== SOLUTION EXERCICE 03 : Manipulation de handles fichier ===\n\n");

    HANDLE hFile = INVALID_HANDLE_VALUE;
    const char* fileName = "test.txt";
    BOOL bSuccess = FALSE;

    // ÉTAPE 1 : Créer le fichier
    printf("ÉTAPE 1 : Création du fichier %s\n", fileName);

    hFile = CreateFileA(
        fileName,                       // Nom du fichier
        GENERIC_WRITE | GENERIC_READ,   // Lecture et écriture
        0,                              // Pas de partage
        NULL,                           // Sécurité par défaut
        CREATE_ALWAYS,                  // Créer ou écraser
        FILE_ATTRIBUTE_NORMAL,          // Attributs normaux
        NULL                            // Pas de template
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFileA");
        return 1;
    }

    printf("[+] Fichier créé, handle : 0x%p\n\n", (void*)hFile);

    // ÉTAPE 2 : Écrire dans le fichier
    printf("ÉTAPE 2 : Écriture de données\n");

    const char* data = "Bonjour WinAPI!\nCeci est un test de WriteFile.\nLigne 3 de test.\n";
    DWORD bytesWritten = 0;

    bSuccess = WriteFile(
        hFile,                    // Handle du fichier
        data,                     // Données à écrire
        (DWORD)strlen(data),      // Nombre de bytes
        &bytesWritten,            // Bytes réellement écrits
        NULL                      // Pas d'I/O asynchrone
    );

    if (!bSuccess) {
        PrintError("WriteFile");
        goto cleanup;
    }

    printf("[+] %lu bytes écrits\n\n", bytesWritten);

    // ÉTAPE 3 : Obtenir la taille du fichier
    printf("ÉTAPE 3 : Récupération de la taille\n");

    LARGE_INTEGER fileSize;

    bSuccess = GetFileSizeEx(hFile, &fileSize);
    if (!bSuccess) {
        PrintError("GetFileSizeEx");
        goto cleanup;
    }

    printf("[+] Taille du fichier : %lld bytes\n\n", fileSize.QuadPart);

    // ÉTAPE 4 : Repositionner au début
    printf("ÉTAPE 4 : Retour au début du fichier\n");

    LARGE_INTEGER moveDistance = {0};
    LARGE_INTEGER newPosition;

    bSuccess = SetFilePointerEx(
        hFile,          // Handle du fichier
        moveDistance,   // Distance à parcourir (0)
        &newPosition,   // Nouvelle position
        FILE_BEGIN      // Depuis le début du fichier
    );

    if (!bSuccess) {
        PrintError("SetFilePointerEx");
        goto cleanup;
    }

    printf("[+] Pointeur repositionné au début (position : %lld)\n\n",
           newPosition.QuadPart);

    // ÉTAPE 5 : Lire le contenu
    printf("ÉTAPE 5 : Lecture du contenu\n");

    char buffer[512] = {0};
    DWORD bytesRead = 0;

    bSuccess = ReadFile(
        hFile,              // Handle du fichier
        buffer,             // Buffer pour stocker les données
        sizeof(buffer) - 1, // Taille max à lire (garder 1 pour \0)
        &bytesRead,         // Bytes réellement lus
        NULL                // Pas d'I/O asynchrone
    );

    if (!bSuccess) {
        PrintError("ReadFile");
        goto cleanup;
    }

    printf("[+] %lu bytes lus\n", bytesRead);
    printf("Contenu :\n");
    printf("------------------\n");
    printf("%s", buffer);
    printf("------------------\n\n");

    // ÉTAPE 6 : Fermer le handle
    printf("ÉTAPE 6 : Fermeture du handle\n");

    if (CloseHandle(hFile)) {
        printf("[+] Handle fermé avec succès\n\n");
        hFile = INVALID_HANDLE_VALUE; // Bonne pratique
    } else {
        PrintError("CloseHandle");
    }

    // BONUS 1 : Vérifier que le fichier existe
    printf("=== BONUS 1 : Vérification de l'existence ===\n");

    DWORD attributes = GetFileAttributesA(fileName);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        printf("[!] Le fichier n'existe pas\n");
        PrintError("GetFileAttributesA");
    } else {
        printf("[+] Fichier existe\n");
        printf("    Attributs : 0x%08lX\n", attributes);

        // Décoder les attributs
        if (attributes & FILE_ATTRIBUTE_ARCHIVE)
            printf("    - Archive (prêt pour sauvegarde)\n");
        if (attributes & FILE_ATTRIBUTE_READONLY)
            printf("    - Read-only\n");
        if (attributes & FILE_ATTRIBUTE_HIDDEN)
            printf("    - Hidden\n");
        if (attributes & FILE_ATTRIBUTE_SYSTEM)
            printf("    - System\n");
        if (attributes & FILE_ATTRIBUTE_NORMAL)
            printf("    - Normal\n");
    }

    printf("\n");

    // BONUS 2 : Ajouter du texte à la fin du fichier
    printf("=== BONUS 2 : Ajout de texte à la fin ===\n");

    hFile = CreateFileA(
        fileName,
        FILE_APPEND_DATA,           // Mode append
        0,
        NULL,
        OPEN_EXISTING,              // Fichier doit exister
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFileA (append)");
    } else {
        const char* appendData = "Ligne ajoutée en mode append.\n";
        DWORD bytesAppended = 0;

        if (WriteFile(hFile, appendData, (DWORD)strlen(appendData),
                      &bytesAppended, NULL)) {
            printf("[+] %lu bytes ajoutés à la fin\n", bytesAppended);
        } else {
            PrintError("WriteFile (append)");
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }

    printf("\n");

    // BONUS 3 : Écrire une structure binaire
    printf("=== BONUS 3 : Fichier binaire avec structure ===\n");

    // Définir une structure
    struct PersonData {
        DWORD id;
        char name[32];
        DWORD age;
    };

    struct PersonData person = {
        .id = 12345,
        .name = "Alice Maldev",
        .age = 25
    };

    const char* binaryFile = "person.bin";

    hFile = CreateFileA(
        binaryFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFileA (binary)");
    } else {
        DWORD bytesWrittenBin = 0;

        if (WriteFile(hFile, &person, sizeof(struct PersonData),
                      &bytesWrittenBin, NULL)) {
            printf("[+] Structure écrite : %lu bytes\n", bytesWrittenBin);
        } else {
            PrintError("WriteFile (binary)");
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        // Relire la structure
        hFile = CreateFileA(
            binaryFile,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            struct PersonData readPerson = {0};
            DWORD bytesReadBin = 0;

            if (ReadFile(hFile, &readPerson, sizeof(struct PersonData),
                         &bytesReadBin, NULL)) {
                printf("[+] Structure lue : %lu bytes\n", bytesReadBin);
                printf("    ID   : %lu\n", readPerson.id);
                printf("    Nom  : %s\n", readPerson.name);
                printf("    Age  : %lu\n", readPerson.age);
            }

            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }

        DeleteFileA(binaryFile);
    }

    printf("\n");

    // BONUS 4 : Obtenir les temps du fichier
    printf("=== BONUS 4 : Timestamps du fichier ===\n");

    hFile = CreateFileA(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME creationTime, lastAccessTime, lastWriteTime;

        if (GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime)) {
            SYSTEMTIME stCreation, stWrite;

            FileTimeToSystemTime(&creationTime, &stCreation);
            FileTimeToSystemTime(&lastWriteTime, &stWrite);

            printf("[+] Création : %02d/%02d/%04d %02d:%02d:%02d\n",
                   stCreation.wDay, stCreation.wMonth, stCreation.wYear,
                   stCreation.wHour, stCreation.wMinute, stCreation.wSecond);

            printf("[+] Modification : %02d/%02d/%04d %02d:%02d:%02d\n",
                   stWrite.wDay, stWrite.wMonth, stWrite.wYear,
                   stWrite.wHour, stWrite.wMinute, stWrite.wSecond);
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }

    printf("\n");

    // BONUS 5 : Suppression du fichier
    printf("=== BONUS 5 : Suppression du fichier ===\n");

    if (DeleteFileA(fileName)) {
        printf("[+] Fichier %s supprimé\n", fileName);
    } else {
        PrintError("DeleteFileA");
    }

    printf("\nProgramme terminé!\n");
    return 0;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    return 1;
}
