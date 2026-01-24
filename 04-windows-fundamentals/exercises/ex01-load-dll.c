/*
 * ╔═══════════════════════════════════════════════════════════════════════╗
 * ║                        EXERCISE 01: Load DLL                          ║
 * ║                   Charger user32.dll et appeler MessageBoxA           ║
 * ╚═══════════════════════════════════════════════════════════════════════╝
 *
 * OBJECTIF:
 * Charger dynamiquement user32.dll avec LoadLibraryA, résoudre l'adresse
 * de MessageBoxA avec GetProcAddress, et l'appeler pour afficher une boîte
 * de dialogue.
 *
 * CONTRAINTES:
 * - NE PAS utiliser #pragma comment(lib, "user32.lib")
 * - NE PAS appeler MessageBoxA directement
 * - Tout doit être fait dynamiquement au runtime
 *
 * RÉSULTAT ATTENDU:
 * - user32.dll chargée avec succès
 * - MessageBoxA résolue
 * - MessageBox affichée avec un message personnalisé
 * - Import table ne contient PAS user32.dll
 *
 * COMPÉTENCES ÉVALUÉES:
 * - LoadLibraryA / FreeLibrary
 * - GetProcAddress
 * - Typedef de pointeurs de fonction
 * - Gestion d'erreurs
 */

#include <windows.h>
#include <stdio.h>

/*
 * TODO 1: Créer un typedef pour MessageBoxA
 *
 * Prototype de MessageBoxA:
 * int WINAPI MessageBoxA(
 *     HWND hWnd,
 *     LPCSTR lpText,
 *     LPCSTR lpCaption,
 *     UINT uType
 * );
 *
 * Créez un typedef nommé pfnMessageBoxA
 */

// typedef ... pfnMessageBoxA;

/*
 * TODO 2: Implémenter la fonction LoadAndCallMessageBox
 *
 * Cette fonction doit:
 * 1. Charger user32.dll avec LoadLibraryA
 * 2. Vérifier que le chargement a réussi
 * 3. Résoudre l'adresse de MessageBoxA avec GetProcAddress
 * 4. Vérifier que la résolution a réussi
 * 5. Caster le pointeur vers le bon type
 * 6. Appeler MessageBoxA avec les paramètres fournis
 * 7. Nettoyer (FreeLibrary)
 *
 * PARAMÈTRES:
 * - text: texte à afficher
 * - caption: titre de la fenêtre
 *
 * RETOUR:
 * - TRUE si succès
 * - FALSE si échec
 */

BOOL LoadAndCallMessageBox(const char* text, const char* caption)
{
    // TODO: Implémenter la logique complète

    printf("[*] Tentative de chargement de user32.dll...\n");

    // TODO: LoadLibraryA

    // TODO: Vérification d'erreur

    // TODO: GetProcAddress

    // TODO: Vérification d'erreur

    // TODO: Cast et appel

    // TODO: FreeLibrary

    return FALSE;  // Remplacer par la vraie logique
}

/*
 * TODO 3: Implémenter une version avec gestion d'erreur détaillée
 *
 * Cette fonction fait la même chose que LoadAndCallMessageBox, mais
 * affiche des messages détaillés pour chaque étape et en cas d'erreur.
 */

BOOL LoadAndCallMessageBoxVerbose(const char* text, const char* caption)
{
    // TODO: Implémenter avec printf pour chaque étape

    return FALSE;
}

/*
 * BONUS TODO 4: Implémenter LoadAndCallMessageBoxW (version Unicode)
 *
 * Même logique mais avec:
 * - MessageBoxW au lieu de MessageBoxA
 * - Paramètres en wchar_t* au lieu de char*
 */

BOOL LoadAndCallMessageBoxW(const wchar_t* text, const wchar_t* caption)
{
    // TODO: Implémenter version Unicode

    return FALSE;
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║              EXERCISE 01: Load DLL                        ║\n");
    printf("║              Chargement dynamique de user32.dll           ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    /*
     * TEST 1: Appel basique
     */
    printf("=== TEST 1: Appel basique ===\n");
    if (LoadAndCallMessageBox("Hello from dynamic loading!", "Exercise 01")) {
        printf("[+] Test 1 réussi\n\n");
    } else {
        printf("[-] Test 1 échoué\n\n");
    }

    /*
     * TEST 2: Appel avec mode verbose
     */
    printf("=== TEST 2: Mode verbose ===\n");
    if (LoadAndCallMessageBoxVerbose("Message avec logs détaillés", "Verbose Mode")) {
        printf("[+] Test 2 réussi\n\n");
    } else {
        printf("[-] Test 2 échoué\n\n");
    }

    /*
     * TEST 3: Version Unicode (bonus)
     */
    printf("=== TEST 3: Unicode (BONUS) ===\n");
    if (LoadAndCallMessageBoxW(L"Unicode message!", L"Unicode Title")) {
        printf("[+] Test 3 réussi\n\n");
    } else {
        printf("[-] Test 3 échoué (normal si pas implémenté)\n\n");
    }

    /*
     * VÉRIFICATION:
     * Utilisez PE-bear, CFF Explorer ou dumpbin pour vérifier que
     * user32.dll N'APPARAÎT PAS dans l'import table du binaire compilé!
     *
     * Commande: dumpbin /imports ex01-load-dll.exe
     * Résultat attendu: seulement kernel32.dll dans les imports
     */

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ VÉRIFICATION                                              ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ Compilez ce programme et vérifiez l'import table:        ║\n");
    printf("║                                                           ║\n");
    printf("║   dumpbin /imports ex01-load-dll.exe                     ║\n");
    printf("║                                                           ║\n");
    printf("║ user32.dll ne doit PAS apparaître dans les imports!      ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}

/*
 * QUESTIONS DE COMPRÉHENSION:
 *
 * 1. Pourquoi LoadLibraryA peut retourner NULL?
 *    - DLL non trouvée
 *    - Format PE invalide
 *    - Architecture incompatible (x86 vs x64)
 *    - DllMain a retourné FALSE
 *
 * 2. Pourquoi GetProcAddress peut retourner NULL?
 *    - Nom de fonction incorrect (case-sensitive!)
 *    - Fonction non exportée par la DLL
 *    - Handle de module invalide
 *
 * 3. Que se passe-t-il si on oublie FreeLibrary?
 *    - Fuite de mémoire (la DLL reste chargée)
 *    - Pas grave pour un .exe qui se termine
 *    - Critique pour un service long-running
 *
 * 4. Pourquoi cette technique est utilisée en maldev?
 *    - Import table vide = pas de red flags dans l'analyse statique
 *    - Chargement conditionnel (après checks anti-sandbox)
 *    - Évite les hooks EDR sur l'import table
 *
 * 5. Quelle est la différence entre MessageBoxA et MessageBoxW?
 *    - MessageBoxA: version ANSI (char*)
 *    - MessageBoxW: version Unicode (wchar_t*)
 *    - Windows utilise Unicode en interne
 *    - MessageBoxA fait une conversion ANSI→Unicode puis appelle MessageBoxW
 */

/*
 * INDICES SI BLOQUÉ:
 *
 * INDICE 1 - Typedef:
 * typedef int (WINAPI *pfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
 *
 * INDICE 2 - LoadLibrary:
 * HMODULE hUser32 = LoadLibraryA("user32.dll");
 * if (!hUser32) {
 *     printf("Erreur: %lu\n", GetLastError());
 *     return FALSE;
 * }
 *
 * INDICE 3 - GetProcAddress:
 * FARPROC pFunc = GetProcAddress(hUser32, "MessageBoxA");
 * if (!pFunc) {
 *     FreeLibrary(hUser32);
 *     return FALSE;
 * }
 *
 * INDICE 4 - Cast et appel:
 * pfnMessageBoxA fnMsgBox = (pfnMessageBoxA)pFunc;
 * fnMsgBox(NULL, text, caption, MB_OK | MB_ICONINFORMATION);
 *
 * INDICE 5 - Nettoyage:
 * FreeLibrary(hUser32);
 * return TRUE;
 */
