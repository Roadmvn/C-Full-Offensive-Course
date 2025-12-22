/*
 * Lesson 04 - Handles Windows
 * ============================
 *
 * OBJECTIF :
 * Comprendre le concept fondamental de HANDLE sous Windows.
 *
 * CONCEPTS CLÉS :
 * - Qu'est-ce qu'un HANDLE ?
 * - Types de handles (Process, Thread, File, Registry...)
 * - Cycle de vie d'un handle
 * - Pseudo-handles vs Real handles
 * - Handle inheritance
 *
 * DÉFINITION :
 * Un HANDLE est un identifiant opaque vers un objet du noyau Windows.
 * C'est une abstraction : on ne manipule jamais directement l'objet,
 * seulement son handle.
 *
 * PHILOSOPHIE WINDOWS :
 * "Everything is an object" - Chaque ressource système est un objet
 * identifié par un handle : processus, thread, fichier, mutex, event...
 *
 * EN MALDEV :
 * Les handles sont au cœur de tout : injection de processus, manipulation
 * de threads, évasion, persistence...
 */

#include <windows.h>
#include <stdio.h>

/*
 * Exemple 1 : Qu'est-ce qu'un HANDLE ?
 */
void Example1_WhatIsHandle(void) {
    printf("\n=== EXEMPLE 1 : Nature d'un HANDLE ===\n\n");

    printf("HANDLE = Identifiant opaque vers un objet kernel\n\n");

    printf("Propriétés :\n");
    printf("  - Type : void* (opaque)\n");
    printf("  - Taille : %zu bytes (8 en x64, 4 en x86)\n", sizeof(HANDLE));
    printf("  - Scope : Process-local (valide uniquement dans le processus)\n");
    printf("  - Valeur : Index dans la table de handles du processus\n\n");

    // Obtenir différents types de handles
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    printf("Exemples de handles :\n");
    printf("  Process handle : 0x%p\n", (void*)hProcess);
    printf("  Thread handle  : 0x%p\n\n", (void*)hThread);

    printf("IMPORTANT :\n");
    printf("  - Un handle n'est PAS un pointeur vers l'objet\n");
    printf("  - C'est un index dans une table interne au kernel\n");
    printf("  - On ne peut pas déréférencer un handle\n");
    printf("  - La valeur 0xFFFFFFFF (-1) est INVALID_HANDLE_VALUE\n");
    printf("  - La valeur 0x00000000 (0) est NULL\n");
}

/*
 * Exemple 2 : Cycle de vie d'un handle
 */
void Example2_HandleLifecycle(void) {
    printf("\n=== EXEMPLE 2 : Cycle de vie d'un handle ===\n\n");

    printf("Étapes du cycle de vie :\n");
    printf("1. Création    : CreateFile, OpenProcess, CreateThread...\n");
    printf("2. Utilisation : ReadFile, GetFileSize, TerminateProcess...\n");
    printf("3. Fermeture   : CloseHandle (OBLIGATOIRE)\n\n");

    // ÉTAPE 1 : Création d'un fichier
    printf("ÉTAPE 1 : Création du handle\n");
    HANDLE hFile = CreateFileA(
        "test_handle.txt",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,  // Créer ou écraser
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA a échoué\n");
        return;
    }

    printf("[+] Handle créé : 0x%p\n\n", (void*)hFile);

    // ÉTAPE 2 : Utilisation du handle
    printf("ÉTAPE 2 : Utilisation du handle\n");
    const char* data = "Hello from handle!";
    DWORD bytesWritten = 0;

    BOOL bSuccess = WriteFile(
        hFile,              // Handle du fichier
        data,               // Données à écrire
        (DWORD)strlen(data),// Nombre de bytes
        &bytesWritten,      // Bytes réellement écrits
        NULL                // Pas d'overlapped I/O
    );

    if (bSuccess) {
        printf("[+] %lu bytes écrits\n\n", bytesWritten);
    } else {
        printf("[!] WriteFile a échoué\n\n");
    }

    // ÉTAPE 3 : Fermeture du handle
    printf("ÉTAPE 3 : Fermeture du handle\n");
    if (CloseHandle(hFile)) {
        printf("[+] Handle fermé avec succès\n");
        printf("    Le handle 0x%p n'est plus valide\n\n", (void*)hFile);
    }

    printf("ATTENTION : Après CloseHandle, le handle est INVALIDE\n");
    printf("L'utiliser causerait ERROR_INVALID_HANDLE (6)\n");
}

/*
 * Exemple 3 : Pseudo-handles vs Real handles
 */
void Example3_PseudoHandles(void) {
    printf("\n=== EXEMPLE 3 : Pseudo-handles vs Real handles ===\n\n");

    // Pseudo-handles : Valeurs spéciales, pas de vrais handles
    HANDLE hPseudoProcess = GetCurrentProcess();
    HANDLE hPseudoThread = GetCurrentThread();

    printf("PSEUDO-HANDLES :\n");
    printf("  GetCurrentProcess() : 0x%p\n", (void*)hPseudoProcess);
    printf("  GetCurrentThread()  : 0x%p\n\n", (void*)hPseudoThread);

    printf("Valeurs magiques :\n");
    printf("  -1 (0x%p) : Processus actuel\n", (void*)(HANDLE)-1);
    printf("  -2 (0x%p) : Thread actuel\n\n", (void*)(HANDLE)-2);

    printf("Caractéristiques des pseudo-handles :\n");
    printf("  - Valeurs constantes magiques\n");
    printf("  - Valides dans n'importe quel contexte du processus\n");
    printf("  - NE PAS appeler CloseHandle dessus !\n");
    printf("  - Pas de référence dans la table de handles\n\n");

    // Real handle : Obtenu via duplication
    HANDLE hRealProcess = NULL;
    BOOL bSuccess = DuplicateHandle(
        GetCurrentProcess(),  // Process source
        GetCurrentProcess(),  // Handle à dupliquer (pseudo)
        GetCurrentProcess(),  // Process destination
        &hRealProcess,        // Nouveau handle (real)
        0,                    // Droits d'accès (identiques)
        FALSE,                // Pas héritable
        DUPLICATE_SAME_ACCESS // Conserver les droits
    );

    if (bSuccess) {
        printf("REAL HANDLE (après duplication) :\n");
        printf("  DuplicateHandle() : 0x%p\n\n", (void*)hRealProcess);

        printf("Caractéristiques du real handle :\n");
        printf("  - Valeur unique dans la table de handles\n");
        printf("  - DOIT être fermé avec CloseHandle\n");
        printf("  - Augmente le reference count de l'objet\n\n");

        // IMPORTANT : Fermer le real handle
        CloseHandle(hRealProcess);
        printf("[+] Real handle fermé\n");
    }
}

/*
 * Exemple 4 : Manipulation de fichiers avec handles
 */
void Example4_FileHandleOperations(void) {
    printf("\n=== EXEMPLE 4 : Opérations sur fichier ===\n\n");

    const char* fileName = "handle_demo.txt";
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Création du fichier
    printf("1. Création du fichier\n");
    hFile = CreateFileA(
        fileName,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Impossible de créer le fichier\n");
        return;
    }
    printf("[+] Fichier créé : 0x%p\n\n", (void*)hFile);

    // Écriture
    printf("2. Écriture de données\n");
    const char* content = "Ligne 1\nLigne 2\nLigne 3\n";
    DWORD bytesWritten = 0;

    WriteFile(hFile, content, (DWORD)strlen(content), &bytesWritten, NULL);
    printf("[+] %lu bytes écrits\n\n", bytesWritten);

    // Obtenir la taille
    printf("3. Récupération de la taille\n");
    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(hFile, &fileSize)) {
        printf("[+] Taille du fichier : %lld bytes\n\n", fileSize.QuadPart);
    }

    // Obtenir la position actuelle
    printf("4. Position dans le fichier\n");
    LARGE_INTEGER currentPos;
    LARGE_INTEGER moveZero = {0};
    if (SetFilePointerEx(hFile, moveZero, &currentPos, FILE_CURRENT)) {
        printf("[+] Position actuelle : %lld\n\n", currentPos.QuadPart);
    }

    // Retour au début
    printf("5. Retour au début du fichier\n");
    LARGE_INTEGER moveToStart = {0};
    if (SetFilePointerEx(hFile, moveToStart, NULL, FILE_BEGIN)) {
        printf("[+] Pointeur repositionné au début\n\n");
    }

    // Lecture
    printf("6. Lecture des données\n");
    char buffer[256] = {0};
    DWORD bytesRead = 0;

    if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        printf("[+] %lu bytes lus\n", bytesRead);
        printf("Contenu :\n%s\n", buffer);
    }

    // Fermeture
    printf("7. Fermeture du handle\n");
    CloseHandle(hFile);
    printf("[+] Handle fermé\n\n");

    // Nettoyage
    DeleteFileA(fileName);
    printf("[+] Fichier supprimé\n");
}

/*
 * Exemple 5 : Vérification de validité d'un handle
 */
void Example5_HandleValidation(void) {
    printf("\n=== EXEMPLE 5 : Validation de handles ===\n\n");

    HANDLE hFile = INVALID_HANDLE_VALUE;

    printf("Valeurs spéciales :\n");
    printf("  INVALID_HANDLE_VALUE = 0x%p (%d)\n",
           (void*)INVALID_HANDLE_VALUE, (int)(LONG_PTR)INVALID_HANDLE_VALUE);
    printf("  NULL                 = 0x%p (%d)\n\n",
           (void*)NULL, (int)(LONG_PTR)NULL);

    // Test 1 : Fichier inexistant
    printf("Test 1 : Ouverture fichier inexistant\n");
    hFile = CreateFileA(
        "inexistant.txt",
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Handle invalide (attendu)\n");
        printf("    Valeur : 0x%p\n\n", (void*)hFile);
    }

    // Test 2 : CreateFile avec succès
    printf("Test 2 : Création réussie\n");
    hFile = CreateFileA(
        "valid_handle.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE && hFile != NULL) {
        printf("[+] Handle valide : 0x%p\n", (void*)hFile);

        // Vérifier le type de handle
        DWORD dwType = GetFileType(hFile);
        printf("    Type : ");
        switch (dwType) {
            case FILE_TYPE_DISK:
                printf("FILE_TYPE_DISK\n");
                break;
            case FILE_TYPE_CHAR:
                printf("FILE_TYPE_CHAR\n");
                break;
            case FILE_TYPE_PIPE:
                printf("FILE_TYPE_PIPE\n");
                break;
            default:
                printf("Unknown\n");
        }

        CloseHandle(hFile);
        DeleteFileA("valid_handle.txt");
    }

    printf("\nPattern de validation recommandé :\n");
    printf("  if (hFile == INVALID_HANDLE_VALUE) {\n");
    printf("      // Échec\n");
    printf("  }\n");
}

/*
 * Exemple 6 : Types de handles courants en maldev
 */
void Example6_CommonHandleTypes(void) {
    printf("\n=== EXEMPLE 6 : Types de handles en maldev ===\n\n");

    printf("HANDLES PROCESSUS :\n");
    printf("  - Process handle (HANDLE) : OpenProcess, CreateProcess\n");
    printf("  - Thread handle (HANDLE)  : OpenThread, CreateThread\n");
    printf("  - Token handle (HANDLE)   : OpenProcessToken, DuplicateToken\n\n");

    printf("HANDLES FICHIERS :\n");
    printf("  - File handle (HANDLE)    : CreateFile, OpenFile\n");
    printf("  - Mapping handle (HANDLE) : CreateFileMapping\n\n");

    printf("HANDLES MÉMOIRE :\n");
    printf("  - Heap handle (HANDLE)    : GetProcessHeap, HeapCreate\n");
    printf("  - Section handle (HANDLE) : CreateFileMapping (Named Sections)\n\n");

    printf("HANDLES SYNCHRONISATION :\n");
    printf("  - Mutex handle (HANDLE)   : CreateMutex, OpenMutex\n");
    printf("  - Event handle (HANDLE)   : CreateEvent, OpenEvent\n");
    printf("  - Semaphore (HANDLE)      : CreateSemaphore\n\n");

    printf("HANDLES REGISTRY :\n");
    printf("  - Key handle (HKEY)       : RegOpenKeyEx, RegCreateKeyEx\n\n");

    printf("HANDLES MODULES :\n");
    printf("  - Module handle (HMODULE) : LoadLibrary, GetModuleHandle\n");
}

/*
 * Exemple 7 : Erreurs courantes avec les handles
 */
void Example7_CommonMistakes(void) {
    printf("\n=== EXEMPLE 7 : Erreurs courantes ===\n\n");

    printf("1. Handle leak (fuite de handle)\n");
    printf("   Oublier de fermer un handle -> épuisement ressources\n");
    printf("   TOUJOURS appeler CloseHandle !\n\n");

    printf("2. Double close\n");
    printf("   Fermer deux fois le même handle -> ERROR_INVALID_HANDLE\n");
    printf("   Mettre à NULL après CloseHandle\n\n");

    printf("3. Use-after-close\n");
    printf("   Utiliser un handle après CloseHandle -> comportement indéfini\n\n");

    printf("4. Confusion NULL vs INVALID_HANDLE_VALUE\n");
    printf("   CreateFile retourne INVALID_HANDLE_VALUE (-1)\n");
    printf("   OpenProcess retourne NULL (0)\n");
    printf("   Toujours vérifier la documentation !\n\n");

    printf("5. Fermer un pseudo-handle\n");
    printf("   NE PAS CloseHandle sur GetCurrentProcess() !\n\n");

    printf("6. Oublier les droits d'accès\n");
    printf("   OpenProcess sans PROCESS_VM_WRITE -> injection échoue\n");
    printf("   Toujours spécifier les droits nécessaires\n");
}

int main(void) {
    printf("===================================================\n");
    printf("  LESSON 04 - HANDLES WINDOWS\n");
    printf("===================================================\n");

    Example1_WhatIsHandle();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example2_HandleLifecycle();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example3_PseudoHandles();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example4_FileHandleOperations();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    Example5_HandleValidation();
    Example6_CommonHandleTypes();
    Example7_CommonMistakes();

    printf("\n===================================================\n");
    printf("  Points clés à retenir :\n");
    printf("  1. HANDLE = identifiant opaque vers objet kernel\n");
    printf("  2. Cycle : Create -> Use -> Close (TOUJOURS)\n");
    printf("  3. Pseudo-handles : NE PAS CloseHandle\n");
    printf("  4. Vérifier NULL vs INVALID_HANDLE_VALUE\n");
    printf("  5. Handle = scope processus (pas partageable)\n");
    printf("  6. En maldev : handles = base de tout\n");
    printf("===================================================\n");

    return 0;
}
