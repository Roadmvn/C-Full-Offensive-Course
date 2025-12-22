/*
 * ╔═══════════════════════════════════════════════════════════════════════╗
 * ║                   EXERCISE 03: No Imports                             ║
 * ║        Appeler MessageBox SANS qu'elle apparaisse dans l'import table ║
 * ╚═══════════════════════════════════════════════════════════════════════╝
 *
 * OBJECTIF:
 * Créer un programme qui affiche une MessageBox, mais où:
 * - user32.dll n'apparaît PAS dans l'import table
 * - MessageBoxA n'apparaît PAS dans l'import table
 * - Le programme compile sans warnings
 * - L'analyse statique ne peut pas voir qu'on utilise MessageBox
 *
 * CONTRAINTES STRICTES:
 * - AUCUN #include de headers Windows sauf windows.h basique
 * - AUCUN #pragma comment(lib, "user32.lib")
 * - AUCUNE référence directe à MessageBoxA dans le code
 * - Utiliser uniquement kernel32.dll (déjà présent par défaut)
 *
 * NIVEAU: Avancé
 *
 * RÉSULTAT ATTENDU:
 * - MessageBox affichée à l'écran
 * - dumpbin /imports ne montre QUE kernel32.dll
 * - strings.exe ne trouve PAS "MessageBoxA" en clair
 * - Analyse PE montre un import table minimal
 *
 * COMPÉTENCES ÉVALUÉES:
 * - Chargement dynamique complet
 * - Obfuscation de strings
 * - Évasion d'analyse statique
 * - Compréhension du PE format
 */

#include <windows.h>
#include <stdio.h>

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 1: String Obfuscation
 * ════════════════════════════════════════════════════════════════════════
 *
 * Pour que "user32.dll" et "MessageBoxA" n'apparaissent pas en clair
 * dans le binaire, on doit les obfusquer.
 */

/*
 * TODO 1: Implémenter xor_decrypt_string
 *
 * Cette fonction déchiffre une string XORée avec une clé.
 *
 * PARAMÈTRES:
 * - encrypted: buffer contenant la string chiffrée
 * - length: longueur de la string
 * - key: clé XOR
 * - output: buffer de sortie (doit être alloué par l'appelant)
 */

void xor_decrypt_string(const unsigned char* encrypted, size_t length, unsigned char key, char* output)
{
    // TODO: Implémenter le déchiffrement XOR

    // Pour chaque byte:
    //   output[i] = encrypted[i] ^ key

    // N'oubliez pas le null terminator!
}

/*
 * TODO 2: Créer les strings obfusquées
 *
 * Utilisez ce script Python pour générer les strings chiffrées:
 *
 * #!/usr/bin/env python3
 * def xor_string(s, key):
 *     return ''.join(f'\\x{ord(c) ^ key:02x}' for c in s)
 *
 * key = 0x42
 * print("user32.dll:", xor_string("user32.dll\0", key))
 * print("MessageBoxA:", xor_string("MessageBoxA\0", key))
 *
 * Collez les résultats ici:
 */

#define XOR_KEY 0x42

// "user32.dll" XOR 0x42 (TODO: remplir avec le résultat du script Python)
const unsigned char ENC_USER32_DLL[] = {
    // TODO: remplir
    0x00  // placeholder
};

// "MessageBoxA" XOR 0x42 (TODO: remplir avec le résultat du script Python)
const unsigned char ENC_MESSAGEBOXA[] = {
    // TODO: remplir
    0x00  // placeholder
};

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 2: Dynamic Resolution
 * ════════════════════════════════════════════════════════════════════════
 */

/*
 * TODO 3: Définir le typedef pour MessageBoxA
 *
 * SANS utiliser le header user32 qui rajouterait des imports.
 *
 * Prototype:
 * int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
 */

// typedef ... pfnMessageBoxA;

// Définir les constantes MessageBox (normalement dans windows.h)
#define MB_OK_CUSTOM                0x00000000
#define MB_ICONINFORMATION_CUSTOM   0x00000040

/*
 * TODO 4: Implémenter ResolveMessageBoxA
 *
 * Cette fonction doit:
 * 1. Déchiffrer "user32.dll"
 * 2. Charger user32.dll avec LoadLibraryA
 * 3. Déchiffrer "MessageBoxA"
 * 4. Résoudre MessageBoxA avec GetProcAddress
 * 5. Retourner le pointeur de fonction
 *
 * IMPORTANT: Après déchiffrement, rechiffrer les strings pour ne pas
 * les laisser en clair en mémoire!
 *
 * RETOUR:
 * - Pointeur vers MessageBoxA si succès
 * - NULL si échec
 */

void* ResolveMessageBoxA(void)
{
    // TODO: Implémenter

    // Buffer pour les strings déchiffrées
    char dllName[32] = {0};
    char funcName[32] = {0};

    // TODO: Déchiffrer user32.dll
    // xor_decrypt_string(ENC_USER32_DLL, ..., XOR_KEY, dllName);

    // TODO: LoadLibraryA

    // TODO: Déchiffrer MessageBoxA
    // xor_decrypt_string(ENC_MESSAGEBOXA, ..., XOR_KEY, funcName);

    // TODO: GetProcAddress

    // IMPORTANT: Rechiffrer les buffers (zeroise)
    // memset(dllName, 0, sizeof(dllName));
    // memset(funcName, 0, sizeof(funcName));

    return NULL;
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 3: Utilisation
 * ════════════════════════════════════════════════════════════════════════
 */

/*
 * TODO 5: Implémenter ShowMessageBox
 *
 * Cette fonction doit:
 * 1. Résoudre MessageBoxA dynamiquement
 * 2. L'appeler pour afficher un message
 * 3. Retourner TRUE/FALSE selon le succès
 */

BOOL ShowMessageBox(const char* text, const char* caption)
{
    printf("[*] Résolution dynamique de MessageBoxA...\n");

    // TODO: Résoudre l'API
    // void* pFunc = ResolveMessageBoxA();

    // TODO: Vérifier

    // TODO: Caster et appeler
    // pfnMessageBoxA fnMsgBox = (pfnMessageBoxA)pFunc;
    // fnMsgBox(NULL, text, caption, MB_OK_CUSTOM | MB_ICONINFORMATION_CUSTOM);

    return FALSE;
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PARTIE 4: Tests et validation
 * ════════════════════════════════════════════════════════════════════════
 */

void PrintBanner(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║              EXERCISE 03: No Imports                      ║\n");
    printf("║              MessageBox sans import visible               ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");
}

void ValidateNoImports(void)
{
    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ VALIDATION REQUISE                                        ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ Après compilation, exécutez:                              ║\n");
    printf("║                                                           ║\n");
    printf("║ 1. dumpbin /imports ex03-no-imports.exe                  ║\n");
    printf("║    → Devrait montrer UNIQUEMENT kernel32.dll             ║\n");
    printf("║                                                           ║\n");
    printf("║ 2. strings ex03-no-imports.exe | grep -i messagebox      ║\n");
    printf("║    → Ne devrait RIEN trouver                             ║\n");
    printf("║                                                           ║\n");
    printf("║ 3. strings ex03-no-imports.exe | grep -i user32          ║\n");
    printf("║    → Ne devrait RIEN trouver                             ║\n");
    printf("║                                                           ║\n");
    printf("║ 4. Ouvrir dans PE-bear:                                  ║\n");
    printf("║    → Section Imports: seulement kernel32.dll             ║\n");
    printf("║    → Section .rdata: pas de 'MessageBoxA' visible        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
}

/*
 * TODO BONUS 6: Ajouter un check anti-sandbox
 *
 * Avant d'afficher la MessageBox, vérifier qu'on n'est pas dans une sandbox.
 * Ne résoudre MessageBoxA que si l'environnement est légitime.
 */

BOOL IsLegitEnvironment(void)
{
    // TODO: Implémenter des checks basiques

    // Check 1: Nombre de processeurs
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        printf("[!] Suspect: moins de 2 CPUs\n");
        return FALSE;
    }

    // Check 2: Uptime (sandbox redémarre souvent)
    DWORD uptime = GetTickCount();
    if (uptime < 600000) {  // Moins de 10 minutes
        printf("[!] Suspect: uptime < 10 minutes\n");
        return FALSE;
    }

    // TODO: Ajouter d'autres checks (RAM, etc.)

    return TRUE;
}

int main(void)
{
    PrintBanner();

    /*
     * TEST 1: Vérification de l'environnement (bonus)
     */
    printf("=== CHECK: Environnement ===\n");
    if (!IsLegitEnvironment()) {
        printf("[-] Environnement suspect détecté\n");
        printf("[*] Skip de l'exécution malicieuse\n");
        return 0;
    }
    printf("[+] Environnement légitime\n\n");

    /*
     * TEST 2: Affichage de la MessageBox
     */
    printf("=== TEST: MessageBox dynamique ===\n");
    if (ShowMessageBox("Import table invisible!", "Dynamic Resolution Success")) {
        printf("[+] MessageBox affichée avec succès\n");
    } else {
        printf("[-] Échec de l'affichage\n");
    }

    /*
     * Instructions de validation
     */
    ValidateNoImports();

    return 0;
}

/*
 * QUESTIONS DE COMPRÉHENSION:
 *
 * 1. Pourquoi XOR est utilisé pour l'obfuscation de strings?
 *    → Algorithme simple et rapide
 *    → Réversible (XOR deux fois = texte original)
 *    → Suffisant pour éviter l'analyse statique basique
 *    → En production, utiliser AES ou RC4
 *
 * 2. Pourquoi rechiffrer les strings après utilisation?
 *    → Éviter qu'elles restent en mémoire en clair
 *    → Un dump mémoire ne révélera pas les APIs utilisées
 *    → Bonne pratique de sécurité opérationnelle (OPSEC)
 *
 * 3. Que voit un analyste qui ouvre ce binaire dans IDA/Ghidra?
 *    → Import table presque vide (juste kernel32 basique)
 *    → Pas de strings suspectes
 *    → Code qui fait des XOR et des appels indirects
 *    → Doit analyser le code pour comprendre
 *
 * 4. Comment un AV pourrait détecter cette technique?
 *    → Analyse dynamique (runtime hooking)
 *    → Détection de pattern de déchiffrement XOR
 *    → Heuristiques sur les appels LoadLibrary + GetProcAddress
 *    → Mais analyse statique ne verra RIEN
 *
 * 5. Comment améliorer cette technique?
 *    → PEB walking au lieu de LoadLibrary
 *    → API hashing au lieu de noms
 *    → Manual mapping au lieu de LoadLibrary
 *    → Chiffrement plus fort (AES, ChaCha20)
 *    → Stack strings (construire char par char)
 */

/*
 * INDICES SI BLOQUÉ:
 *
 * INDICE 1 - XOR decrypt:
 * for (size_t i = 0; i < length; i++) {
 *     output[i] = encrypted[i] ^ key;
 * }
 * output[length] = '\0';
 *
 * INDICE 2 - Script Python pour générer les strings:
 * #!/usr/bin/env python3
 * key = 0x42
 * dll = "user32.dll\0"
 * func = "MessageBoxA\0"
 * print("DLL:", ', '.join(f'0x{ord(c) ^ key:02x}' for c in dll))
 * print("Func:", ', '.join(f'0x{ord(c) ^ key:02x}' for c in func))
 *
 * INDICE 3 - ResolveMessageBoxA:
 * char dllName[32] = {0};
 * xor_decrypt_string(ENC_USER32_DLL, 11, XOR_KEY, dllName);
 * HMODULE h = LoadLibraryA(dllName);
 * char funcName[32] = {0};
 * xor_decrypt_string(ENC_MESSAGEBOXA, 12, XOR_KEY, funcName);
 * FARPROC p = GetProcAddress(h, funcName);
 * SecureZeroMemory(dllName, sizeof(dllName));
 * SecureZeroMemory(funcName, sizeof(funcName));
 * return p;
 *
 * INDICE 4 - Validation:
 * Compilez et testez:
 * cl.exe ex03-no-imports.c /link /out:ex03.exe
 * dumpbin /imports ex03.exe | findstr "DLL Name"
 * → Doit afficher seulement KERNEL32.dll
 */
