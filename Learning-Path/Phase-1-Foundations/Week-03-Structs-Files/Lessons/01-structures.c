/*
 * =============================================================================
 * SEMAINE 3 - LESSON 01 : STRUCTURES (STRUCTS)
 * =============================================================================
 *
 * OBJECTIF :
 *   Apprendre à regrouper des données liées dans des structures.
 *   En maldev, on utilise des structs pour représenter des objets complexes
 *   comme des headers PE, des structures Windows (PROCESS_INFORMATION, etc.)
 *
 * PRE-REQUIS :
 *   - Variables et types de base
 *   - Pointeurs (Week 2)
 *
 * COMPILATION :
 *   cl 01-structures.c
 *   .\01-structures.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <string.h>

/*
 * =============================================================================
 * ANALOGIE : C'est quoi une structure ?
 * =============================================================================
 *
 * Imagine que tu veux décrire une VOITURE :
 *   - Elle a une COULEUR (string)
 *   - Elle a un NOMBRE DE ROUES (int)
 *   - Elle a une VITESSE MAXIMALE (int)
 *
 * Au lieu de créer 3 variables séparées pour chaque voiture, on peut créer
 * une "boîte" qui contient toutes ces infos : c'est une STRUCTURE !
 *
 * En maldev :
 *   - On utilise des structs pour représenter des processus, des threads, etc.
 *   - Exemple : La structure PROCESS_INFORMATION contient hProcess, hThread, dwProcessId...
 *
 * =============================================================================
 */

/*
 * =============================================================================
 * PARTIE 1 : DÉCLARER UNE STRUCTURE
 * =============================================================================
 */

// Déclaration d'une structure "Voiture"
// On définit un nouveau TYPE de données qui contient plusieurs membres
struct Voiture {
    char couleur[20];        // Membre 1 : couleur de la voiture
    int nbRoues;             // Membre 2 : nombre de roues
    int vitesseMax;          // Membre 3 : vitesse maximale (km/h)
};

/*
 * Maintenant "struct Voiture" est un TYPE, comme "int" ou "char"
 * On peut créer des variables de ce type !
 */

/*
 * =============================================================================
 * PARTIE 2 : UTILISER TYPEDEF POUR SIMPLIFIER
 * =============================================================================
 */

// Avec typedef, on peut éviter de réécrire "struct" à chaque fois
typedef struct {
    char nom[50];
    int age;
    float taille;            // en mètres
} Personne;

// Maintenant on peut écrire "Personne p;" au lieu de "struct Personne p;"

/*
 * =============================================================================
 * PARTIE 3 : STRUCTURES MALDEV - EXEMPLE SIMPLE
 * =============================================================================
 */

// Exemple inspiré de structures Windows
// (simplifié pour l'apprentissage)
typedef struct {
    unsigned long dwProcessId;       // ID du processus
    unsigned long dwThreadId;        // ID du thread principal
    void* hProcess;                  // Handle vers le processus
    void* hThread;                   // Handle vers le thread
} SIMPLE_PROCESS_INFO;

/*
 * En vrai, Windows définit PROCESS_INFORMATION de manière similaire !
 * On verra ça en détail dans les prochaines semaines.
 */

/*
 * =============================================================================
 * PARTIE 4 : STRUCTURES IMBRIQUÉES (NESTED STRUCTS)
 * =============================================================================
 */

typedef struct {
    int x;
    int y;
} Point;

typedef struct {
    Point topLeft;      // Structure Point à l'intérieur !
    Point bottomRight;
    int couleur;
} Rectangle;

/*
 * =============================================================================
 * FONCTION MAIN : EXEMPLES PRATIQUES
 * =============================================================================
 */

int main() {
    printf("=== SEMAINE 3 - LESSON 01 : STRUCTURES ===\n\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 1 : Créer et initialiser une structure Voiture
    // -------------------------------------------------------------------------
    printf("[1] Creation d'une voiture\n");

    struct Voiture maVoiture;                    // Déclaration d'une variable
    strcpy(maVoiture.couleur, "Rouge");          // On accède aux membres avec "."
    maVoiture.nbRoues = 4;
    maVoiture.vitesseMax = 200;

    printf("   Couleur : %s\n", maVoiture.couleur);
    printf("   Roues   : %d\n", maVoiture.nbRoues);
    printf("   Vitesse : %d km/h\n\n", maVoiture.vitesseMax);

    // -------------------------------------------------------------------------
    // EXEMPLE 2 : Initialisation directe (plus propre !)
    // -------------------------------------------------------------------------
    printf("[2] Initialisation directe\n");

    struct Voiture voiture2 = {"Bleu", 4, 180};  // Initialisation dans l'ordre des membres

    printf("   Couleur : %s\n", voiture2.couleur);
    printf("   Roues   : %d\n", voiture2.nbRoues);
    printf("   Vitesse : %d km/h\n\n", voiture2.vitesseMax);

    // -------------------------------------------------------------------------
    // EXEMPLE 3 : Utiliser typedef (Personne)
    // -------------------------------------------------------------------------
    printf("[3] Utilisation de typedef\n");

    Personne alice = {"Alice", 25, 1.65};        // Plus simple, pas besoin de "struct"

    printf("   Nom    : %s\n", alice.nom);
    printf("   Age    : %d ans\n", alice.age);
    printf("   Taille : %.2f m\n\n", alice.taille);

    // -------------------------------------------------------------------------
    // EXEMPLE 4 : Pointeur vers une structure
    // -------------------------------------------------------------------------
    printf("[4] Pointeur vers structure\n");

    Personne* ptrAlice = &alice;                 // Pointeur vers alice

    // Deux façons d'accéder aux membres via pointeur :
    printf("   Methode 1 - (*ptr).membre : %s\n", (*ptrAlice).nom);
    printf("   Methode 2 - ptr->membre   : %s\n", ptrAlice->nom);  // Plus courant !

    // En maldev, on utilise TOUJOURS la flèche "->" avec les pointeurs
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 5 : Structure maldev simplifiée
    // -------------------------------------------------------------------------
    printf("[5] Structure maldev (SIMPLE_PROCESS_INFO)\n");

    SIMPLE_PROCESS_INFO procInfo = {0};          // Initialiser tout à 0
    procInfo.dwProcessId = 1234;
    procInfo.dwThreadId = 5678;
    procInfo.hProcess = (void*)0xDEADBEEF;       // Valeur fictive pour l'exemple
    procInfo.hThread = (void*)0xCAFEBABE;

    printf("   Process ID : %lu\n", procInfo.dwProcessId);
    printf("   Thread ID  : %lu\n", procInfo.dwThreadId);
    printf("   hProcess   : %p\n", procInfo.hProcess);
    printf("   hThread    : %p\n\n", procInfo.hThread);

    // -------------------------------------------------------------------------
    // EXEMPLE 6 : Structures imbriquées
    // -------------------------------------------------------------------------
    printf("[6] Structures imbriquees (Rectangle)\n");

    Rectangle rect;
    rect.topLeft.x = 10;
    rect.topLeft.y = 20;
    rect.bottomRight.x = 100;
    rect.bottomRight.y = 80;
    rect.couleur = 0xFF0000;                     // Rouge en hexadécimal

    printf("   Top-Left     : (%d, %d)\n", rect.topLeft.x, rect.topLeft.y);
    printf("   Bottom-Right : (%d, %d)\n", rect.bottomRight.x, rect.bottomRight.y);
    printf("   Couleur      : 0x%X\n\n", rect.couleur);

    // -------------------------------------------------------------------------
    // EXEMPLE 7 : Tableau de structures
    // -------------------------------------------------------------------------
    printf("[7] Tableau de structures\n");

    Personne equipe[3] = {
        {"Bob", 30, 1.75},
        {"Charlie", 28, 1.80},
        {"Diana", 32, 1.68}
    };

    for (int i = 0; i < 3; i++) {
        printf("   [%d] %s - %d ans - %.2fm\n",
               i, equipe[i].nom, equipe[i].age, equipe[i].taille);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 8 : Modifier via pointeur (pattern maldev courant)
    // -------------------------------------------------------------------------
    printf("[8] Modification via pointeur\n");

    Personne* ptrBob = &equipe[0];               // Pointeur vers Bob
    ptrBob->age = 31;                            // Modifier l'âge via pointeur
    strcpy(ptrBob->nom, "Robert");               // Modifier le nom

    printf("   Apres modification : %s - %d ans\n\n", equipe[0].nom, equipe[0].age);

    /*
     * =========================================================================
     * RÉSUMÉ :
     * =========================================================================
     *
     * 1. STRUCT = Regrouper plusieurs données dans une seule "boîte"
     * 2. ACCÈS AUX MEMBRES :
     *    - Avec variable directe : variable.membre
     *    - Avec pointeur : pointeur->membre (équivalent à (*pointeur).membre)
     * 3. TYPEDEF = Simplifier la syntaxe (éviter "struct" à chaque fois)
     * 4. INITIALISATION :
     *    - Par membres : s.x = 10; s.y = 20;
     *    - Directe : struct Point p = {10, 20};
     *    - Tout à zéro : struct Point p = {0};
     * 5. POINTEURS : En maldev, on utilise BEAUCOUP les pointeurs vers structs
     *
     * =========================================================================
     */

    /*
     * =========================================================================
     * MALDEV PREVIEW :
     * =========================================================================
     *
     * Dans le développement malware, les structures sont PARTOUT :
     *
     * - PROCESS_INFORMATION : Info sur un processus créé
     * - STARTUPINFO : Configuration de démarrage d'un processus
     * - IMAGE_DOS_HEADER : Header d'un fichier PE (EXE/DLL)
     * - IMAGE_NT_HEADERS : En-têtes NT d'un PE
     * - PEB (Process Environment Block) : Infos sur le processus courant
     * - TEB (Thread Environment Block) : Infos sur le thread courant
     *
     * Exemple de code maldev réel :
     *
     *   PROCESS_INFORMATION pi = {0};
     *   STARTUPINFO si = {0};
     *   si.cb = sizeof(si);
     *
     *   CreateProcess(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
     *
     * On passe des POINTEURS vers les structures (&si, &pi) car Windows
     * va REMPLIR ces structures avec les infos du processus créé !
     *
     * Prochaine leçon : Unions et Enums (encore plus de maldev !)
     *
     * =========================================================================
     */

    printf("=== FIN DE LA LESSON 01 ===\n");
    return 0;
}

/*
 * =============================================================================
 * EXERCICE POUR TOI :
 * =============================================================================
 *
 * 1. Crée une structure "Fichier" avec :
 *    - char nom[100]
 *    - unsigned long taille (en octets)
 *    - int estExecutable (0 ou 1)
 *
 * 2. Crée un tableau de 3 fichiers
 *
 * 3. Affiche les fichiers qui sont exécutables
 *
 * 4. Calcule la taille totale de tous les fichiers
 *
 * Bonne chance ! On se retrouve dans ex01-person-struct.c pour pratiquer !
 *
 * =============================================================================
 */
