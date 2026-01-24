/*
 * Lesson 01: LoadLibrary - Dynamic DLL Loading
 *
 * OBJECTIF:
 * Comprendre ce qu'est une DLL et comment la charger dynamiquement en mémoire
 * au runtime plutôt qu'au moment du link.
 *
 * CONCEPTS CLÉS:
 * - DLL (Dynamic Link Library): bibliothèque de code partagé sous Windows
 * - LoadLibraryA/W: charge une DLL en mémoire et retourne son handle
 * - FreeLibrary: décharge la DLL de la mémoire
 * - HMODULE: handle vers un module (DLL) chargé en mémoire
 *
 * INTÉRÊT OFFENSIF:
 * - Éviter d'avoir des DLLs suspectes dans la liste des imports statiques
 * - Charger des DLLs uniquement quand nécessaire (anti-sandbox)
 * - Charger des DLLs depuis des chemins non standards
 */

#include <windows.h>
#include <stdio.h>

/*
 * Qu'est-ce qu'une DLL?
 *
 * Une DLL est un fichier contenant du code et des données qui peuvent être
 * utilisés par plusieurs programmes simultanément. Windows lui-même utilise
 * massivement les DLLs:
 *
 * - kernel32.dll: fonctions système de base (process, threads, mémoire)
 * - ntdll.dll: interface avec le kernel (syscalls)
 * - user32.dll: interface graphique (fenêtres, messages)
 * - advapi32.dll: sécurité, registre, services
 *
 * DEUX MÉTHODES DE CHARGEMENT:
 *
 * 1. STATIQUE (Import Table):
 *    - Le linker ajoute la DLL dans la PE Import Table
 *    - Windows charge automatiquement au démarrage
 *    - Visible dans les outils d'analyse (PEview, PE-bear, etc.)
 *    - Exemple: #pragma comment(lib, "user32.lib")
 *
 * 2. DYNAMIQUE (LoadLibrary):
 *    - Pas dans l'import table
 *    - Chargement à la demande dans le code
 *    - Invisible pour l'analyse statique
 *    - Utilisé en maldev pour l'évasion
 */

void demo_basic_loadlibrary(void)
{
    printf("\n=== DEMO 1: LoadLibrary basique ===\n");

    /*
     * LoadLibraryA charge une DLL en mémoire.
     *
     * PROTOTYPE:
     * HMODULE LoadLibraryA(LPCSTR lpLibFileName);
     *
     * PARAMÈTRES:
     * - lpLibFileName: nom ou chemin complet de la DLL
     *
     * RETOUR:
     * - Handle vers le module (HMODULE) si succès
     * - NULL si échec
     *
     * COMPORTEMENT:
     * 1. Windows cherche la DLL dans cet ordre:
     *    - Répertoire de l'application
     *    - Répertoire système (C:\Windows\System32)
     *    - Répertoire Windows (C:\Windows)
     *    - Répertoire courant
     *    - Répertoires dans PATH
     *
     * 2. Si déjà chargée: incrémente le compteur de référence
     * 3. Si pas chargée: mappe la DLL, résout ses imports, exécute DllMain
     */

    HMODULE hUser32 = LoadLibraryA("user32.dll");

    if (hUser32 == NULL) {
        printf("[-] Échec du chargement de user32.dll\n");
        printf("[-] Erreur: %lu\n", GetLastError());
        return;
    }

    printf("[+] user32.dll chargé avec succès\n");
    printf("[+] Adresse de base: 0x%p\n", hUser32);

    /*
     * HMODULE est en fait l'adresse de base de la DLL en mémoire.
     * C'est l'adresse où commence le header PE de la DLL.
     */

    /*
     * FreeLibrary décrémente le compteur de référence.
     * Quand il atteint 0, Windows décharge la DLL.
     */
    FreeLibrary(hUser32);
    printf("[+] user32.dll déchargé\n");
}

void demo_multiple_loads(void)
{
    printf("\n=== DEMO 2: Chargements multiples ===\n");

    /*
     * Windows utilise un compteur de référence pour chaque DLL.
     * Plusieurs LoadLibrary sur la même DLL retournent le même handle
     * mais incrémentent le compteur.
     */

    HMODULE h1 = LoadLibraryA("kernel32.dll");
    HMODULE h2 = LoadLibraryA("kernel32.dll");
    HMODULE h3 = LoadLibraryA("kernel32.dll");

    printf("[+] Premier chargement:  0x%p\n", h1);
    printf("[+] Deuxième chargement: 0x%p\n", h2);
    printf("[+] Troisième chargement: 0x%p\n", h3);

    if (h1 == h2 && h2 == h3) {
        printf("[+] Tous les handles sont identiques (même adresse de base)\n");
    }

    /*
     * Il faut appeler FreeLibrary autant de fois que LoadLibrary
     * pour vraiment décharger la DLL.
     */
    FreeLibrary(h1);
    FreeLibrary(h2);
    FreeLibrary(h3);

    printf("[+] Compteur de référence décrémenté 3 fois\n");
}

void demo_full_path(void)
{
    printf("\n=== DEMO 3: Chargement avec chemin complet ===\n");

    /*
     * Pour des raisons de sécurité ou pour charger une DLL non standard,
     * on peut spécifier le chemin complet.
     *
     * INTÉRÊT OFFENSIF:
     * - DLL Sideloading: placer une DLL malveillante dans un répertoire
     *   où elle sera chargée à la place de la légitime
     * - Éviter les DLLs système hookées par les EDR
     */

    HMODULE hNtdll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");

    if (hNtdll) {
        printf("[+] ntdll.dll chargé depuis chemin complet\n");
        printf("[+] Adresse de base: 0x%p\n", hNtdll);
        FreeLibrary(hNtdll);
    }
}

void demo_loadlibrary_variants(void)
{
    printf("\n=== DEMO 4: Variantes de LoadLibrary ===\n");

    /*
     * LoadLibraryExA offre plus de contrôle avec des flags.
     *
     * FLAGS UTILES:
     * - LOAD_LIBRARY_AS_DATAFILE: charge comme fichier de données (pas d'exécution)
     * - LOAD_LIBRARY_AS_IMAGE_RESOURCE: charge comme ressource image
     * - DONT_RESOLVE_DLL_REFERENCES: ne résout pas les dépendances
     *
     * INTÉRÊT OFFENSIF:
     * DONT_RESOLVE_DLL_REFERENCES évite l'exécution de DllMain,
     * utile pour analyser une DLL sans déclencher son code.
     */

    HMODULE hModule = LoadLibraryExA(
        "kernel32.dll",
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );

    if (hModule) {
        printf("[+] kernel32.dll chargé sans résolution des dépendances\n");
        printf("[+] DllMain non exécuté\n");
        FreeLibrary(hModule);
    }
}

void demo_error_handling(void)
{
    printf("\n=== DEMO 5: Gestion d'erreurs ===\n");

    /*
     * Toujours vérifier le retour de LoadLibrary.
     * GetLastError() donne le code d'erreur.
     */

    HMODULE hInvalid = LoadLibraryA("nonexistent_dll_12345.dll");

    if (hInvalid == NULL) {
        DWORD error = GetLastError();
        printf("[-] Échec du chargement\n");
        printf("[-] Code d'erreur: %lu\n", error);

        /*
         * Codes d'erreur courants:
         * - ERROR_MOD_NOT_FOUND (126): DLL non trouvée
         * - ERROR_BAD_EXE_FORMAT (193): format PE invalide ou architecture incorrecte
         * - ERROR_DLL_INIT_FAILED (1114): DllMain a retourné FALSE
         */

        if (error == ERROR_MOD_NOT_FOUND) {
            printf("[-] La DLL n'existe pas ou n'est pas dans le PATH\n");
        }
    }
}

/*
 * TECHNIQUE OFFENSIVE: Delayed Loading
 *
 * Charger les DLLs suspectes seulement après avoir passé les checks
 * anti-sandbox initiaux.
 */
void demo_delayed_loading(void)
{
    printf("\n=== DEMO 6: Chargement retardé (Anti-Sandbox) ===\n");

    printf("[*] Simulation: attente de 2 secondes...\n");
    Sleep(2000);  // Les sandboxes ont souvent un timeout court

    printf("[*] Sandbox timeout potentiellement dépassé\n");
    printf("[*] Chargement de DLLs sensibles maintenant...\n");

    HMODULE hWininet = LoadLibraryA("wininet.dll");
    if (hWininet) {
        printf("[+] wininet.dll chargé (réseau)\n");
        FreeLibrary(hWininet);
    }
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         WEEK 7 - LESSON 01: LoadLibrary                  ║\n");
    printf("║         Chargement dynamique de DLLs                      ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    demo_basic_loadlibrary();
    demo_multiple_loads();
    demo_full_path();
    demo_loadlibrary_variants();
    demo_error_handling();
    demo_delayed_loading();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ RÉSUMÉ                                                    ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • LoadLibraryA charge une DLL en mémoire                 ║\n");
    printf("║ • Retourne HMODULE (adresse de base de la DLL)           ║\n");
    printf("║ • FreeLibrary pour décharger (compteur de référence)     ║\n");
    printf("║ • LoadLibraryExA pour contrôle avancé                    ║\n");
    printf("║ • Intérêt maldev: chargement invisible, delayed load     ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    printf("\n[*] Prochaine étape: GetProcAddress pour résoudre les fonctions\n");

    return 0;
}

/*
 * NOTES DE SÉCURITÉ OFFENSIVE:
 *
 * 1. DLL HIJACKING:
 *    - Placer une DLL malveillante dans le répertoire de l'application
 *    - Si l'app utilise LoadLibrary sans chemin complet, notre DLL est chargée
 *
 * 2. DLL SIDELOADING:
 *    - Exploiter l'ordre de recherche de Windows
 *    - Placer une DLL dans un répertoire prioritaire
 *
 * 3. PHANTOM DLL HIJACKING:
 *    - Certaines apps tentent de charger des DLLs inexistantes
 *    - On peut créer ces DLLs pour injecter du code
 *
 * 4. SEARCH ORDER HIJACKING:
 *    - Manipuler PATH ou le répertoire courant
 *    - Forcer le chargement de notre DLL
 *
 * 5. EVASION:
 *    - LoadLibrary ne laisse pas de trace dans l'import table
 *    - Utile pour charger des DLLs réseau (wininet) sans éveiller les soupçons
 *    - Combiné avec des sleep(), bypass des sandboxes à timeout court
 */
