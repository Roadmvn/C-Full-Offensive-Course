/*
 * ╔═══════════════════════════════════════════════════════════════════════╗
 * ║                    EXERCISE 02: API Resolver                          ║
 * ║          Créer une fonction générique de résolution d'APIs            ║
 * ╚═══════════════════════════════════════════════════════════════════════╝
 *
 * OBJECTIF:
 * Implémenter une fonction réutilisable qui peut résoudre n'importe quelle
 * API depuis n'importe quelle DLL. Créer ensuite une table d'APIs complète
 * pour un implant basique.
 *
 * CONTRAINTES:
 * - Une seule fonction pour résoudre toutes les APIs
 * - Gestion d'erreur robuste
 * - Support du chargement de nouvelles DLLs si nécessaire
 * - Cache des handles de DLL pour éviter LoadLibrary répétés
 *
 * RÉSULTAT ATTENDU:
 * - Fonction ResolveAPI générique et réutilisable
 * - Table d'APIs initialisée correctement
 * - Toutes les fonctions appelables via la table
 * - Code propre et maintenable
 *
 * COMPÉTENCES ÉVALUÉES:
 * - Conception de fonctions génériques
 * - Structures de données
 * - Gestion de cache
 * - Pattern maldev professionnel
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 1: Cache de DLLs
 * ════════════════════════════════════════════════════════════════════════
 */

#define MAX_DLL_CACHE 16

typedef struct _DLL_CACHE_ENTRY {
    char name[64];
    HMODULE handle;
    BOOL loaded;
} DLL_CACHE_ENTRY;

// Cache global de DLLs
DLL_CACHE_ENTRY g_DllCache[MAX_DLL_CACHE] = {0};

/*
 * TODO 1: Implémenter GetOrLoadDll
 *
 * Cette fonction doit:
 * 1. Chercher la DLL dans le cache
 * 2. Si trouvée et chargée, retourner le handle
 * 3. Si pas trouvée, charger avec LoadLibraryA
 * 4. Ajouter au cache
 * 5. Retourner le handle
 *
 * PARAMÈTRES:
 * - dllName: nom de la DLL (ex: "kernel32.dll")
 *
 * RETOUR:
 * - Handle de la DLL si succès
 * - NULL si échec
 */

HMODULE GetOrLoadDll(const char* dllName)
{
    // TODO: Implémenter la logique de cache

    // Étape 1: Chercher dans le cache
    // ...

    // Étape 2: Si pas trouvé, charger
    // ...

    // Étape 3: Ajouter au cache
    // ...

    return NULL;
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 2: Résolution générique d'API
 * ════════════════════════════════════════════════════════════════════════
 */

/*
 * TODO 2: Implémenter ResolveAPI
 *
 * Cette fonction est la fonction CLÉE de tout implant malware.
 * Elle doit être capable de résoudre n'importe quelle API.
 *
 * PARAMÈTRES:
 * - dllName: nom de la DLL (ex: "kernel32.dll")
 * - apiName: nom de la fonction (ex: "VirtualAlloc")
 *
 * RETOUR:
 * - Adresse de la fonction si succès
 * - NULL si échec
 *
 * BONUS: Ajouter un système de log pour debugging
 */

FARPROC ResolveAPI(const char* dllName, const char* apiName)
{
    // TODO: Implémenter

    // Étape 1: Obtenir le handle de la DLL (via cache)
    // ...

    // Étape 2: Résoudre l'API avec GetProcAddress
    // ...

    // Étape 3: Vérifier et retourner
    // ...

    return NULL;
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 3: Table d'APIs pour implant
 * ════════════════════════════════════════════════════════════════════════
 */

/*
 * TODO 3: Définir les typedefs pour chaque API
 *
 * Créez les typedefs pour les APIs suivantes:
 * - VirtualAlloc
 * - VirtualProtect
 * - VirtualFree
 * - CreateThread
 * - WaitForSingleObject
 * - GetCurrentProcessId
 * - Sleep
 */

// typedef ... pfnVirtualAlloc;
// typedef ... pfnVirtualProtect;
// ... etc

/*
 * TODO 4: Définir la structure API_TABLE
 *
 * Cette structure doit contenir des pointeurs vers toutes les fonctions
 * nécessaires pour un implant basique.
 */

typedef struct _API_TABLE {
    // Memory APIs
    // pfnVirtualAlloc VirtualAlloc;
    // ...

    // Thread APIs
    // ...

    // Process APIs
    // ...

    // Utility APIs
    // ...
} API_TABLE, *PAPI_TABLE;

// Instance globale
API_TABLE g_Api = {0};

/*
 * TODO 5: Implémenter InitializeApiTable
 *
 * Cette fonction doit initialiser toute la table d'APIs en utilisant
 * ResolveAPI pour chaque fonction.
 *
 * RETOUR:
 * - TRUE si toutes les APIs critiques sont résolues
 * - FALSE si une API critique a échoué
 */

BOOL InitializeApiTable(void)
{
    printf("[*] Initialisation de la table d'APIs...\n");

    // TODO: Résoudre chaque API avec ResolveAPI

    // Exemple:
    // g_Api.VirtualAlloc = (pfnVirtualAlloc)ResolveAPI("kernel32.dll", "VirtualAlloc");

    // TODO: Vérifier que les APIs critiques sont bien résolues

    // TODO: Afficher un résumé

    return FALSE;
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 4: Fonctions de test
 * ════════════════════════════════════════════════════════════════════════
 */

/*
 * TODO 6: Implémenter TestMemoryAPIs
 *
 * Cette fonction doit tester les APIs de gestion mémoire:
 * 1. Allouer 4096 bytes avec VirtualAlloc
 * 2. Écrire des données dedans
 * 3. Changer la protection en PAGE_EXECUTE_READ avec VirtualProtect
 * 4. Libérer avec VirtualFree
 */

BOOL TestMemoryAPIs(void)
{
    printf("\n=== TEST: Memory APIs ===\n");

    // TODO: Implémenter les tests

    return FALSE;
}

/*
 * TODO 7: Implémenter TestThreadAPIs
 *
 * Cette fonction doit tester les APIs de threads:
 * 1. Créer un thread simple avec CreateThread
 * 2. Attendre qu'il se termine avec WaitForSingleObject
 * 3. Fermer le handle
 */

DWORD WINAPI SimpleThreadFunc(LPVOID lpParam)
{
    printf("[Thread] Démarré!\n");
    // TODO: Utiliser Sleep résolu dynamiquement
    printf("[Thread] Terminé!\n");
    return 0;
}

BOOL TestThreadAPIs(void)
{
    printf("\n=== TEST: Thread APIs ===\n");

    // TODO: Implémenter les tests

    return FALSE;
}

/*
 * TODO 8: Implémenter CleanupApiTable
 *
 * Cette fonction doit nettoyer toutes les ressources:
 * - FreeLibrary pour chaque DLL dans le cache
 * - Réinitialiser la table d'APIs
 */

void CleanupApiTable(void)
{
    printf("\n[*] Nettoyage...\n");

    // TODO: Parcourir le cache et FreeLibrary chaque DLL

    // TODO: Réinitialiser g_Api à 0

    printf("[+] Nettoyage terminé\n");
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * MAIN
 * ════════════════════════════════════════════════════════════════════════
 */

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║              EXERCISE 02: API Resolver                    ║\n");
    printf("║              Système générique de résolution d'APIs       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    /*
     * TEST 1: Initialisation
     */
    if (!InitializeApiTable()) {
        printf("[-] Échec de l'initialisation\n");
        return 1;
    }
    printf("[+] Table d'APIs initialisée\n");

    /*
     * TEST 2: Memory APIs
     */
    if (TestMemoryAPIs()) {
        printf("[+] Memory APIs fonctionnent\n");
    } else {
        printf("[-] Memory APIs échouent\n");
    }

    /*
     * TEST 3: Thread APIs
     */
    if (TestThreadAPIs()) {
        printf("[+] Thread APIs fonctionnent\n");
    } else {
        printf("[-] Thread APIs échouent\n");
    }

    /*
     * TEST 4: Nettoyage
     */
    CleanupApiTable();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ VALIDATION                                                ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ Vérifiez que:                                             ║\n");
    printf("║ 1. Toutes les APIs sont résolues correctement            ║\n");
    printf("║ 2. Le cache de DLLs évite les LoadLibrary répétés        ║\n");
    printf("║ 3. Les tests de mémoire et threads passent               ║\n");
    printf("║ 4. Le nettoyage libère toutes les ressources             ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}

/*
 * QUESTIONS DE COMPRÉHENSION:
 *
 * 1. Pourquoi utiliser un cache de DLLs?
 *    → Éviter d'appeler LoadLibrary plusieurs fois sur la même DLL
 *    → LoadLibrary incrémente un compteur de référence
 *    → Performance: LoadLibrary est coûteux
 *
 * 2. Que se passe-t-il si on appelle LoadLibrary 3 fois sur kernel32?
 *    → Windows retourne toujours le même HMODULE
 *    → Le compteur de référence passe à 3
 *    → Il faut FreeLibrary 3 fois pour vraiment décharger
 *    → En pratique, kernel32 ne se décharge jamais (OS l'utilise)
 *
 * 3. Pourquoi créer une fonction ResolveAPI générique?
 *    → Code réutilisable et maintenable
 *    → Une seule fonction à tester/débugger
 *    → Facilite l'ajout de logging, obfuscation, etc.
 *    → Pattern professionnel utilisé dans vrais implants
 *
 * 4. Comment améliorer cette implémentation pour un vrai malware?
 *    → Obfuscation des strings (noms de DLLs et APIs)
 *    → API hashing au lieu de noms en clair
 *    → Résolution lazy (à la demande)
 *    → PEB walking au lieu de GetModuleHandle
 *    → Manual mapping au lieu de LoadLibrary
 *
 * 5. Quelle est la différence entre cette approche et l'import table?
 *    → Import table: résolution au chargement par Windows
 *    → Notre approche: résolution au runtime par notre code
 *    → Import table: visible dans PE
 *    → Notre approche: invisible à l'analyse statique
 */

/*
 * INDICES SI BLOQUÉ:
 *
 * INDICE 1 - Cache de DLL:
 * for (int i = 0; i < MAX_DLL_CACHE; i++) {
 *     if (g_DllCache[i].loaded && strcmp(g_DllCache[i].name, dllName) == 0) {
 *         return g_DllCache[i].handle;
 *     }
 * }
 *
 * INDICE 2 - ResolveAPI:
 * HMODULE hDll = GetOrLoadDll(dllName);
 * if (!hDll) return NULL;
 * return GetProcAddress(hDll, apiName);
 *
 * INDICE 3 - InitializeApiTable:
 * g_Api.VirtualAlloc = (pfnVirtualAlloc)ResolveAPI("kernel32.dll", "VirtualAlloc");
 * if (!g_Api.VirtualAlloc) {
 *     printf("[-] Échec VirtualAlloc\n");
 *     return FALSE;
 * }
 *
 * INDICE 4 - TestMemoryAPIs:
 * LPVOID pMem = g_Api.VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 * if (!pMem) return FALSE;
 * memcpy(pMem, "Test", 4);
 * DWORD old;
 * g_Api.VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &old);
 * g_Api.VirtualFree(pMem, 0, MEM_RELEASE);
 */
