/*
 * Lesson 03: Dynamic API Resolution Pattern
 *
 * OBJECTIF:
 * Implémenter le pattern complet de résolution dynamique d'APIs utilisé
 * en malware development pour éviter la détection statique.
 *
 * CONCEPTS CLÉS:
 * - API Table: structure contenant tous les pointeurs de fonction
 * - Lazy Loading: résolution à la demande
 * - String Obfuscation: masquer les noms d'APIs
 * - Clean Import Table: PE sans imports suspects
 *
 * INTÉRÊT OFFENSIF:
 * - Analyse statique: import table quasi vide
 * - Signatures AV: pas de noms d'APIs sensibles
 * - Sandboxes: résolution conditionnelle selon l'environnement
 * - EDR Evasion: bypass des hooks sur import table
 */

#include <windows.h>
#include <stdio.h>

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 1: API Table Structure
 * ════════════════════════════════════════════════════════════════════════
 *
 * Plutôt que de résoudre chaque API à chaque fois, on crée une structure
 * globale contenant tous les pointeurs de fonction.
 */

// Typedefs pour les fonctions courantes
typedef LPVOID (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *pfnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *pfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI *pfnWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL (WINAPI *pfnCloseHandle)(HANDLE);
typedef int (WINAPI *pfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef DWORD (WINAPI *pfnGetLastError)(void);

// Structure globale contenant toutes les APIs
typedef struct _API_TABLE {
    // Memory APIs
    pfnVirtualAlloc         VirtualAlloc;
    pfnVirtualProtect       VirtualProtect;
    pfnVirtualFree          VirtualFree;

    // Thread APIs
    pfnCreateThread         CreateThread;
    pfnWaitForSingleObject  WaitForSingleObject;
    pfnCloseHandle          CloseHandle;

    // UI APIs
    pfnMessageBoxA          MessageBoxA;

    // Error APIs
    pfnGetLastError         GetLastError;
} API_TABLE, *PAPI_TABLE;

// Instance globale (sera initialisée au runtime)
API_TABLE g_Api = {0};

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 2: Initialization Function
 * ════════════════════════════════════════════════════════════════════════
 */

BOOL InitializeApiTable(void)
{
    printf("\n[*] Initialisation de la table d'APIs...\n");

    /*
     * GetModuleHandleA vs LoadLibraryA:
     * - GetModuleHandle: retourne le handle si déjà chargée (pas de new load)
     * - LoadLibrary: charge si pas chargée, incrémente ref count
     *
     * Pour kernel32 et ntdll, toujours chargées, on peut utiliser GetModuleHandle.
     * Pour user32, peut ne pas être chargée dans un service, on fait LoadLibrary.
     */

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] kernel32.dll non trouvé\n");
        return FALSE;
    }

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        printf("[-] Échec LoadLibrary user32.dll\n");
        // user32 n'est pas critique, on continue
    }

    /*
     * Résolution de chaque API avec vérification
     */

    // Memory APIs
    g_Api.VirtualAlloc = (pfnVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    g_Api.VirtualProtect = (pfnVirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
    g_Api.VirtualFree = (pfnVirtualFree)GetProcAddress(hKernel32, "VirtualFree");

    // Thread APIs
    g_Api.CreateThread = (pfnCreateThread)GetProcAddress(hKernel32, "CreateThread");
    g_Api.WaitForSingleObject = (pfnWaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");
    g_Api.CloseHandle = (pfnCloseHandle)GetProcAddress(hKernel32, "CloseHandle");

    // Error APIs
    g_Api.GetLastError = (pfnGetLastError)GetProcAddress(hKernel32, "GetLastError");

    // UI APIs (peut échouer si user32 pas chargé)
    if (hUser32) {
        g_Api.MessageBoxA = (pfnMessageBoxA)GetProcAddress(hUser32, "MessageBoxA");
    }

    /*
     * Vérification: toutes les APIs critiques sont résolues?
     */
    if (!g_Api.VirtualAlloc || !g_Api.VirtualProtect || !g_Api.CreateThread) {
        printf("[-] Échec de résolution d'APIs critiques\n");
        return FALSE;
    }

    printf("[+] Table d'APIs initialisée avec succès\n");
    printf("    VirtualAlloc:        0x%p\n", g_Api.VirtualAlloc);
    printf("    VirtualProtect:      0x%p\n", g_Api.VirtualProtect);
    printf("    CreateThread:        0x%p\n", g_Api.CreateThread);
    printf("    MessageBoxA:         0x%p\n", g_Api.MessageBoxA);

    return TRUE;
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 3: Using the API Table
 * ════════════════════════════════════════════════════════════════════════
 */

void demo_using_api_table(void)
{
    printf("\n=== DEMO 1: Utilisation de la table d'APIs ===\n");

    /*
     * Maintenant qu'on a notre table d'APIs, on les utilise comme
     * des fonctions normales, mais elles ne sont PAS dans l'import table!
     */

    // Allouer de la mémoire
    LPVOID pMemory = g_Api.VirtualAlloc(
        NULL,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pMemory) {
        printf("[+] Mémoire allouée via API résolue: 0x%p\n", pMemory);

        // Écrire dedans
        memcpy(pMemory, "Dynamic API Call!", 17);
        printf("[+] Données écrites: %s\n", (char*)pMemory);

        // Libérer
        g_Api.VirtualFree(pMemory, 0, MEM_RELEASE);
        printf("[+] Mémoire libérée\n");
    }

    // Afficher une MessageBox (si user32 chargé)
    if (g_Api.MessageBoxA) {
        g_Api.MessageBoxA(
            NULL,
            "Appelé via API table dynamique!",
            "Dynamic API Demo",
            MB_OK | MB_ICONINFORMATION
        );
    }
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 4: String Obfuscation (Simple XOR)
 * ════════════════════════════════════════════════════════════════════════
 *
 * Pour éviter d'avoir les noms d'APIs en clair, on peut les chiffrer.
 */

void xor_decrypt_string(char* str, size_t len, BYTE key)
{
    for (size_t i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

void demo_obfuscated_api_resolution(void)
{
    printf("\n=== DEMO 2: Résolution avec strings obfusquées ===\n");

    /*
     * Au lieu de "MessageBoxA" en clair dans le code,
     * on stocke une version XOR.
     *
     * Script Python pour générer:
     * key = 0xAA
     * name = "MessageBoxA"
     * encrypted = ''.join([f'\\x{ord(c) ^ key:02x}' for c in name])
     */

    // "MessageBoxA" XOR 0xAA
    char encryptedName[] = "\xe7\xcb\xc3\xc3\xcb\xcf\xcb\xea\xc5\xd8\xeb\xaa";
    BYTE key = 0xAA;

    printf("[*] String chiffrée: ");
    for (int i = 0; i < 11; i++) {
        printf("\\x%02x", (unsigned char)encryptedName[i]);
    }
    printf("\n");

    // Déchiffrement à la volée
    xor_decrypt_string(encryptedName, 11, key);
    printf("[+] String déchiffrée: %s\n", encryptedName);

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        FARPROC pFunc = GetProcAddress(hUser32, encryptedName);
        printf("[+] Fonction résolue: 0x%p\n", pFunc);
        FreeLibrary(hUser32);
    }

    /*
     * IMPORTANT: dans un vrai malware, on rechiffre la string après usage
     * pour ne pas laisser de traces en mémoire.
     */
    xor_decrypt_string(encryptedName, 11, key);  // Re-chiffre
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 5: Lazy Loading
 * ════════════════════════════════════════════════════════════════════════
 *
 * Ne charger les DLLs/APIs que quand on en a besoin.
 */

typedef struct _LAZY_API {
    HMODULE hModule;
    FARPROC pFunction;
    BOOL    bResolved;
} LAZY_API;

LAZY_API g_LazyWinInet = {0};

FARPROC GetLazyAPI(LAZY_API* api, const char* dllName, const char* funcName)
{
    if (api->bResolved) {
        return api->pFunction;  // Déjà résolu
    }

    printf("[*] Lazy loading: %s!%s\n", dllName, funcName);

    api->hModule = LoadLibraryA(dllName);
    if (!api->hModule) {
        return NULL;
    }

    api->pFunction = GetProcAddress(api->hModule, funcName);
    if (!api->pFunction) {
        FreeLibrary(api->hModule);
        return NULL;
    }

    api->bResolved = TRUE;
    return api->pFunction;
}

void demo_lazy_loading(void)
{
    printf("\n=== DEMO 3: Lazy Loading ===\n");

    /*
     * wininet.dll est suspecte (réseau).
     * On ne la charge que si on en a vraiment besoin.
     */

    printf("[*] wininet.dll pas encore chargé\n");

    // Simulation: on décide d'utiliser le réseau
    printf("[*] Décision d'utiliser le réseau...\n");

    typedef HINTERNET (WINAPI *pfnInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    pfnInternetOpenA fnInternetOpenA = (pfnInternetOpenA)GetLazyAPI(
        &g_LazyWinInet,
        "wininet.dll",
        "InternetOpenA"
    );

    if (fnInternetOpenA) {
        printf("[+] InternetOpenA résolu: 0x%p\n", fnInternetOpenA);

        // Appel test
        HINTERNET hInternet = fnInternetOpenA(
            "MaldevAgent/1.0",
            INTERNET_OPEN_TYPE_DIRECT,
            NULL,
            NULL,
            0
        );

        if (hInternet) {
            printf("[+] Session Internet ouverte\n");
            // InternetCloseHandle(hInternet);  // On devrait la résoudre aussi
        }
    }
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 6: Conditional Loading (Anti-Sandbox)
 * ════════════════════════════════════════════════════════════════════════
 */

BOOL is_sandbox_check(void)
{
    /*
     * Check simple: nombre de processeurs
     * Les sandboxes ont souvent 1-2 CPUs pour économiser les ressources.
     */
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    if (si.dwNumberOfProcessors < 2) {
        return TRUE;  // Possiblement sandbox
    }

    /*
     * Check: RAM
     * Moins de 4GB = suspect
     */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    DWORD ramGB = (DWORD)(ms.ullTotalPhys / (1024 * 1024 * 1024));
    if (ramGB < 4) {
        return TRUE;
    }

    return FALSE;
}

void demo_conditional_loading(void)
{
    printf("\n=== DEMO 4: Chargement conditionnel (Anti-Sandbox) ===\n");

    if (is_sandbox_check()) {
        printf("[!] Environnement suspect détecté\n");
        printf("[*] Skip du chargement d'APIs sensibles\n");
        return;
    }

    printf("[+] Environnement normal détecté\n");
    printf("[*] Chargement des APIs sensibles...\n");

    // Charger des APIs réseau, injection, etc.
    HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
    if (hWs2) {
        printf("[+] ws2_32.dll chargé (sockets)\n");
        FreeLibrary(hWs2);
    }
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PATTERN 7: Macro Helpers
 * ════════════════════════════════════════════════════════════════════════
 */

#define RESOLVE_API(module, name) \
    (pfn##name)GetProcAddress(GetModuleHandleA(module), #name)

void demo_macro_helpers(void)
{
    printf("\n=== DEMO 5: Macros pour simplifier ===\n");

    /*
     * Macro qui combine GetModuleHandle + GetProcAddress + cast
     * Attention: moins flexible, mais plus concis
     */

    pfnVirtualAlloc pVA = RESOLVE_API("kernel32.dll", VirtualAlloc);

    if (pVA) {
        printf("[+] VirtualAlloc résolu via macro: 0x%p\n", pVA);
    }
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         WEEK 7 - LESSON 03: Dynamic API Pattern          ║\n");
    printf("║         Résolution complète d'APIs (maldev pattern)       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    // Initialiser la table d'APIs
    if (!InitializeApiTable()) {
        printf("[-] Échec initialisation\n");
        return 1;
    }

    demo_using_api_table();
    demo_obfuscated_api_resolution();
    demo_lazy_loading();
    demo_conditional_loading();
    demo_macro_helpers();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ RÉSUMÉ                                                    ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • API Table: structure globale avec tous les pointeurs   ║\n");
    printf("║ • InitializeApiTable: résolution au startup              ║\n");
    printf("║ • String Obfuscation: XOR des noms d'APIs                ║\n");
    printf("║ • Lazy Loading: charger uniquement si nécessaire         ║\n");
    printf("║ • Conditional: charger selon l'environnement             ║\n");
    printf("║ • Résultat: import table quasi vide, évasion AV/EDR      ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    printf("\n[*] Prochaine étape: Introduction au PEB (Process Environment Block)\n");

    return 0;
}

/*
 * IMPLÉMENTATION COMPLÈTE EN MALWARE:
 *
 * 1. STRUCTURE:
 *    typedef struct {
 *        // Kernel32
 *        pfnVirtualAlloc VirtualAlloc;
 *        pfnVirtualProtect VirtualProtect;
 *        // ... toutes les APIs nécessaires
 *
 *        // Ntdll (syscalls)
 *        pfnNtAllocateVirtualMemory NtAllocateVirtualMemory;
 *        // ...
 *
 *        // Network
 *        pfnInternetOpenA InternetOpenA;
 *        // ...
 *    } MALDEV_API_TABLE;
 *
 * 2. OBFUSCATION:
 *    - XOR/RC4 tous les noms de DLLs et fonctions
 *    - Stack strings (construire les strings char par char)
 *    - Hash-based resolution (API hashing)
 *
 * 3. ANTI-ANALYSIS:
 *    - Résolution en plusieurs étapes
 *    - Sleep entre chaque résolution
 *    - Vérifications anti-debug avant résolution
 *
 * 4. CLEANUP:
 *    - Après usage, mettre les pointeurs à NULL
 *    - FreeLibrary des DLLs suspectes
 *    - Effacer les strings déchiffrées
 */
