/*
 * Lesson 02: GetProcAddress - Dynamic Function Resolution
 *
 * OBJECTIF:
 * Apprendre à résoudre dynamiquement les adresses de fonctions dans une DLL
 * chargée en mémoire, permettant d'appeler n'importe quelle fonction sans
 * qu'elle apparaisse dans l'import table.
 *
 * CONCEPTS CLÉS:
 * - Export Table: table contenant les fonctions exportées par une DLL
 * - GetProcAddress: résout l'adresse d'une fonction par son nom (ou ordinal)
 * - Function Pointer: pointeur vers du code exécutable
 * - Typedef: créer des types pour les pointeurs de fonction
 *
 * INTÉRÊT OFFENSIF:
 * - Import table vide = analyse statique aveugle
 * - Résolution à la volée = évasion des hooks EDR sur l'import table
 * - Chargement conditionnel de fonctions sensibles
 */

#include <windows.h>
#include <stdio.h>

/*
 * GetProcAddress: la fonction magique du maldev
 *
 * PROTOTYPE:
 * FARPROC GetProcAddress(
 *     HMODULE hModule,      // Handle de la DLL (depuis LoadLibrary)
 *     LPCSTR  lpProcName    // Nom de la fonction OU ordinal
 * );
 *
 * RETOUR:
 * - Adresse de la fonction si succès
 * - NULL si échec
 *
 * FONCTIONNEMENT:
 * 1. Parse l'Export Table de la DLL
 * 2. Cherche le nom de la fonction
 * 3. Retourne son adresse (RVA + base address)
 */

void demo_basic_getprocaddress(void)
{
    printf("\n=== DEMO 1: GetProcAddress basique ===\n");

    // Charger kernel32.dll
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Échec LoadLibrary\n");
        return;
    }

    printf("[+] kernel32.dll chargé à: 0x%p\n", hKernel32);

    /*
     * Résoudre l'adresse de GetCurrentProcessId
     *
     * IMPORTANT: GetProcAddress retourne FARPROC (void*)
     * Il faut caster vers le bon type de fonction.
     */

    FARPROC pGetCurrentProcessId = GetProcAddress(hKernel32, "GetCurrentProcessId");

    if (!pGetCurrentProcessId) {
        printf("[-] Échec GetProcAddress\n");
        FreeLibrary(hKernel32);
        return;
    }

    printf("[+] GetCurrentProcessId trouvé à: 0x%p\n", pGetCurrentProcessId);

    /*
     * CASTING ET APPEL:
     *
     * Pour appeler la fonction, il faut caster FARPROC vers le bon prototype.
     *
     * GetCurrentProcessId n'a pas de paramètres et retourne DWORD:
     * DWORD WINAPI GetCurrentProcessId(void);
     */

    typedef DWORD (WINAPI *pfnGetCurrentProcessId)(void);

    pfnGetCurrentProcessId fnGetPid = (pfnGetCurrentProcessId)pGetCurrentProcessId;

    DWORD pid = fnGetPid();
    printf("[+] PID du processus courant: %lu\n", pid);

    FreeLibrary(hKernel32);
}

void demo_messageboxA(void)
{
    printf("\n=== DEMO 2: Appel de MessageBoxA dynamiquement ===\n");

    /*
     * MessageBoxA est dans user32.dll
     * Prototype: int MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);
     */

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        printf("[-] Échec LoadLibrary user32.dll\n");
        return;
    }

    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("[-] MessageBoxA non trouvé\n");
        FreeLibrary(hUser32);
        return;
    }

    printf("[+] MessageBoxA résolu à: 0x%p\n", pMessageBoxA);

    /*
     * Typedef pour le prototype de MessageBoxA
     */
    typedef int (WINAPI *pfnMessageBoxA)(
        HWND hWnd,
        LPCSTR lpText,
        LPCSTR lpCaption,
        UINT uType
    );

    pfnMessageBoxA fnMsgBox = (pfnMessageBoxA)pMessageBoxA;

    /*
     * Appel de la fonction résolue dynamiquement
     * La messagebox s'affiche mais MessageBoxA n'est PAS dans l'import table!
     */
    fnMsgBox(NULL, "Résolu dynamiquement!", "GetProcAddress Demo", MB_OK | MB_ICONINFORMATION);

    FreeLibrary(hUser32);
}

void demo_typedef_patterns(void)
{
    printf("\n=== DEMO 3: Patterns de typedef ===\n");

    /*
     * En maldev, on crée souvent des typedefs pour chaque API.
     * Convention de nommage:
     * - typedef nom: pfn<FunctionName> (pointer to function)
     * - variable: fn<FunctionName>
     */

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    // Typedef pour CreateFileA
    typedef HANDLE (WINAPI *pfnCreateFileA)(
        LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );

    pfnCreateFileA fnCreateFileA = (pfnCreateFileA)GetProcAddress(hKernel32, "CreateFileA");

    if (fnCreateFileA) {
        printf("[+] CreateFileA résolu: 0x%p\n", fnCreateFileA);

        // Test: ouvrir un fichier
        HANDLE hFile = fnCreateFileA(
            "test.txt",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            printf("[+] Fichier créé avec CreateFileA résolu dynamiquement\n");
            CloseHandle(hFile);
        }
    }
}

void demo_ordinal_resolution(void)
{
    printf("\n=== DEMO 4: Résolution par ordinal ===\n");

    /*
     * Les fonctions peuvent être exportées par ordinal (numéro) plutôt que par nom.
     *
     * INTÉRÊT OFFENSIF:
     * - Plus difficile à détecter (pas de string du nom de fonction)
     * - Certaines fonctions non documentées n'ont pas de nom
     *
     * SYNTAXE:
     * GetProcAddress(hModule, MAKEINTRESOURCEA(ordinal))
     *
     * PROBLÈME:
     * - Les ordinaux peuvent changer entre versions de Windows
     * - Moins portable
     */

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;

    /*
     * Note: pour trouver les ordinaux, utiliser:
     * - dumpbin /exports ntdll.dll
     * - PE-bear
     * - CFF Explorer
     *
     * Ici, on utilise quand même le nom pour la démo.
     */

    printf("[+] ntdll.dll chargé: 0x%p\n", hNtdll);
    printf("[*] La résolution par ordinal est possible mais dépend de la version\n");

    FreeLibrary(hNtdll);
}

void demo_error_handling(void)
{
    printf("\n=== DEMO 5: Gestion d'erreurs ===\n");

    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    // Tentative de résolution d'une fonction inexistante
    FARPROC pFake = GetProcAddress(hKernel32, "NonExistentFunction12345");

    if (pFake == NULL) {
        DWORD error = GetLastError();
        printf("[-] GetProcAddress a échoué\n");
        printf("[-] Code d'erreur: %lu\n", error);
        printf("[-] ERROR_PROC_NOT_FOUND = 127\n");
    }

    /*
     * PATTERN DÉFENSIF:
     * Toujours vérifier le retour avant d'appeler la fonction!
     */

    FreeLibrary(hKernel32);
}

void demo_multiple_apis(void)
{
    printf("\n=== DEMO 6: Résolution de multiples APIs ===\n");

    /*
     * Pattern courant en maldev: résoudre plusieurs APIs d'un coup
     * et les stocker dans une structure.
     */

    typedef struct {
        FARPROC pVirtualAlloc;
        FARPROC pVirtualProtect;
        FARPROC pCreateThread;
        FARPROC pWaitForSingleObject;
    } API_TABLE;

    API_TABLE apis = {0};

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    apis.pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    apis.pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");
    apis.pCreateThread = GetProcAddress(hKernel32, "CreateThread");
    apis.pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");

    if (apis.pVirtualAlloc && apis.pVirtualProtect &&
        apis.pCreateThread && apis.pWaitForSingleObject) {
        printf("[+] Toutes les APIs résolues avec succès:\n");
        printf("    VirtualAlloc:        0x%p\n", apis.pVirtualAlloc);
        printf("    VirtualProtect:      0x%p\n", apis.pVirtualProtect);
        printf("    CreateThread:        0x%p\n", apis.pCreateThread);
        printf("    WaitForSingleObject: 0x%p\n", apis.pWaitForSingleObject);
    }
}

void demo_case_sensitivity(void)
{
    printf("\n=== DEMO 7: Sensibilité à la casse ===\n");

    /*
     * IMPORTANT: GetProcAddress est sensible à la casse!
     * "MessageBoxA" != "messageboxA"
     */

    HMODULE hUser32 = LoadLibraryA("user32.dll");

    FARPROC p1 = GetProcAddress(hUser32, "MessageBoxA");  // ✓ Correct
    FARPROC p2 = GetProcAddress(hUser32, "messageboxA");  // ✗ Échec
    FARPROC p3 = GetProcAddress(hUser32, "MESSAGEBOXA");  // ✗ Échec

    printf("[+] MessageBoxA (correct): 0x%p\n", p1);
    printf("[-] messageboxA (mauvaise casse): 0x%p\n", p2);
    printf("[-] MESSAGEBOXA (mauvaise casse): 0x%p\n", p3);

    FreeLibrary(hUser32);
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         WEEK 7 - LESSON 02: GetProcAddress               ║\n");
    printf("║         Résolution dynamique de fonctions                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    demo_basic_getprocaddress();
    demo_messageboxA();
    demo_typedef_patterns();
    demo_ordinal_resolution();
    demo_error_handling();
    demo_multiple_apis();
    demo_case_sensitivity();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ RÉSUMÉ                                                    ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • GetProcAddress résout l'adresse d'une fonction         ║\n");
    printf("║ • Nécessite typedef pour caster correctement             ║\n");
    printf("║ • Sensible à la casse (\"MessageBoxA\" exact)              ║\n");
    printf("║ • Peut utiliser ordinaux (moins portable)                ║\n");
    printf("║ • Pattern: LoadLibrary + GetProcAddress = API invisible  ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    printf("\n[*] Prochaine étape: Résolution complète d'APIs (pattern maldev)\n");

    return 0;
}

/*
 * TECHNIQUES OFFENSIVES AVANCÉES:
 *
 * 1. API HASHING:
 *    - Au lieu de strings, utiliser des hashs des noms de fonctions
 *    - Parse l'export table manuellement
 *    - Hash chaque nom et compare au hash cible
 *    - Aucune string d'API dans le binaire!
 *
 * 2. MANUAL MAPPING:
 *    - Ne pas utiliser LoadLibrary (détectable)
 *    - Charger la DLL manuellement depuis disque/mémoire
 *    - Résoudre l'export table à la main
 *    - Bypass complet des hooks LoadLibrary
 *
 * 3. INDIRECT CALLS:
 *    - Ne pas appeler directement la fonction résolue
 *    - Passer par un trampoline ou du code dynamique
 *    - Évite les hooks sur les adresses de fonctions
 *
 * 4. DELAYED RESOLUTION:
 *    - Ne résoudre les APIs que juste avant utilisation
 *    - Évite d'avoir toutes les adresses en mémoire
 *    - Plus difficile à dumper pour l'analyse
 *
 * 5. OBFUSCATED STRINGS:
 *    - XOR ou chiffrer les noms de fonctions
 *    - Déchiffrer à la volée avant GetProcAddress
 *    - Aucune string claire dans le binaire
 */
