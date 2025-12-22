/*
 * =============================================================================
 * SEMAINE 3 - LESSON 02 : UNIONS, ENUMS & BITFIELDS
 * =============================================================================
 *
 * OBJECTIF :
 *   Comprendre les unions (partage de mémoire), les enums (constantes nommées)
 *   et les bitfields (optimisation mémoire).
 *   Ces concepts sont ESSENTIELS en maldev pour manipuler des structures
 *   Windows complexes et économiser de la mémoire.
 *
 * PRE-REQUIS :
 *   - Lesson 01 (Structures)
 *   - Compréhension de base de la mémoire
 *
 * COMPILATION :
 *   cl 02-unions-enums.c
 *   .\02-unions-enums.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <string.h>

/*
 * =============================================================================
 * ANALOGIE : UNION vs STRUCT
 * =============================================================================
 *
 * STRUCT = Une ARMOIRE avec plusieurs TIROIRS :
 *   - Chaque tiroir a son propre espace
 *   - Tiroir 1 : chaussettes, Tiroir 2 : t-shirts, etc.
 *   - Tous existent EN MÊME TEMPS
 *
 * UNION = Une BOÎTE avec UN SEUL ESPACE :
 *   - Tu peux y mettre des chaussettes OU des t-shirts
 *   - Mais PAS les deux en même temps !
 *   - Si tu mets des t-shirts, les chaussettes disparaissent
 *
 * En maldev :
 *   - Les unions permettent de voir la MÊME MÉMOIRE sous différents angles
 *   - Exemple : Voir 4 bytes comme un DWORD OU comme 4 bytes séparés
 *
 * =============================================================================
 */

/*
 * =============================================================================
 * PARTIE 1 : LES UNIONS
 * =============================================================================
 */

// Union simple : tous les membres partagent la MÊME mémoire
union Donnee {
    int entier;              // 4 bytes
    float flottant;          // 4 bytes
    char octets[4];          // 4 bytes
};

// La taille de l'union = taille du PLUS GRAND membre (4 bytes ici)

// Union typique en maldev : voir un DWORD de différentes manières
typedef union {
    unsigned long valeur;    // Voir comme un nombre de 32 bits
    unsigned char bytes[4];  // Voir comme 4 bytes séparés
    struct {
        unsigned short low;  // 16 bits de poids faible
        unsigned short high; // 16 bits de poids fort
    } parts;
} DWORD_UNION;

/*
 * =============================================================================
 * PARTIE 2 : LES ENUMERATIONS (ENUMS)
 * =============================================================================
 */

// Enum = Liste de constantes nommées (plus lisible que des #define)
enum Couleur {
    ROUGE,                   // = 0 par défaut
    VERT,                    // = 1
    BLEU,                    // = 2
    JAUNE                    // = 3
};

// Enum avec valeurs personnalisées
enum StatusCode {
    SUCCESS = 0,
    ERROR_FILE_NOT_FOUND = 1,
    ERROR_ACCESS_DENIED = 2,
    ERROR_INVALID_PARAM = 3
};

// Enum maldev : inspiré des constantes Windows
typedef enum {
    MEM_COMMIT = 0x1000,
    MEM_RESERVE = 0x2000,
    MEM_RELEASE = 0x8000
} MEMORY_ALLOCATION_TYPE;

// Enum pour les droits d'accès mémoire
typedef enum {
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40
} MEMORY_PROTECTION;

/*
 * =============================================================================
 * PARTIE 3 : LES BITFIELDS (CHAMPS DE BITS)
 * =============================================================================
 */

// Bitfields = Spécifier le nombre de bits pour chaque membre
// Utile pour économiser de la mémoire !

// Structure normale (4 bytes minimum à cause de l'alignement)
struct FlagsNormal {
    int isActive;            // 4 bytes pour stocker 0 ou 1 (gaspillage!)
    int isHidden;            // 4 bytes pour stocker 0 ou 1
    int priority;            // 4 bytes pour stocker 0-7
};

// Bitfields (1 byte suffit !)
struct FlagsBitfield {
    unsigned int isActive : 1;   // 1 bit seulement (0 ou 1)
    unsigned int isHidden : 1;   // 1 bit
    unsigned int priority : 3;   // 3 bits (0-7)
    unsigned int reserved : 3;   // 3 bits réservés (total = 8 bits = 1 byte)
};

// Exemple maldev : Flags dans un header PE
typedef struct {
    unsigned short isRelocationsStripped : 1;    // Bit 0
    unsigned short isExecutable : 1;             // Bit 1
    unsigned short lineNumsStripped : 1;         // Bit 2
    unsigned short isSystem : 1;                 // Bit 3
    unsigned short isDLL : 1;                    // Bit 4
    unsigned short reserved : 11;                // Bits 5-15
} PE_CHARACTERISTICS;

/*
 * =============================================================================
 * PARTIE 4 : COMBINAISON STRUCT + UNION (TECHNIQUE AVANCÉE)
 * =============================================================================
 */

// Pattern courant en maldev : struct contenant une union
typedef struct {
    unsigned int type;       // Type de donnée stockée
    union {
        int intValue;
        float floatValue;
        char* stringValue;
        void* pointerValue;
    } data;                  // Union anonyme
} Variant;

/*
 * =============================================================================
 * FONCTION MAIN : EXEMPLES PRATIQUES
 * =============================================================================
 */

int main() {
    printf("=== SEMAINE 3 - LESSON 02 : UNIONS, ENUMS & BITFIELDS ===\n\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 1 : Union basique
    // -------------------------------------------------------------------------
    printf("[1] Union basique - partage de memoire\n");

    union Donnee d;

    d.entier = 1234;
    printf("   Comme entier : %d\n", d.entier);

    d.flottant = 3.14f;                          // ECRASE la valeur entière !
    printf("   Comme flottant : %.2f\n", d.flottant);
    printf("   Entier maintenant : %d (corrompu!)\n\n", d.entier);  // Plus valide

    // -------------------------------------------------------------------------
    // EXEMPLE 2 : Union pour voir un DWORD différemment
    // -------------------------------------------------------------------------
    printf("[2] Union DWORD - vue multiple\n");

    DWORD_UNION dw;
    dw.valeur = 0x12345678;                      // Valeur 32 bits

    printf("   Valeur complete : 0x%08X\n", dw.valeur);
    printf("   Bytes individuels :\n");
    printf("     [0] = 0x%02X\n", dw.bytes[0]);  // Little-endian : 78
    printf("     [1] = 0x%02X\n", dw.bytes[1]);  // 56
    printf("     [2] = 0x%02X\n", dw.bytes[2]);  // 34
    printf("     [3] = 0x%02X\n", dw.bytes[3]);  // 12
    printf("   Low word  : 0x%04X\n", dw.parts.low);   // 5678
    printf("   High word : 0x%04X\n\n", dw.parts.high); // 1234

    // -------------------------------------------------------------------------
    // EXEMPLE 3 : Enumérations
    // -------------------------------------------------------------------------
    printf("[3] Enumerations\n");

    enum Couleur maCouleur = ROUGE;
    printf("   Couleur ROUGE = %d\n", maCouleur);

    enum StatusCode status = SUCCESS;
    printf("   Status SUCCESS = %d\n", status);

    status = ERROR_ACCESS_DENIED;
    printf("   Status ERROR_ACCESS_DENIED = %d\n\n", status);

    // -------------------------------------------------------------------------
    // EXEMPLE 4 : Switch avec enum (très lisible !)
    // -------------------------------------------------------------------------
    printf("[4] Switch avec enum\n");

    enum StatusCode result = ERROR_FILE_NOT_FOUND;

    switch (result) {
        case SUCCESS:
            printf("   Operation reussie !\n");
            break;
        case ERROR_FILE_NOT_FOUND:
            printf("   Erreur : Fichier introuvable\n");
            break;
        case ERROR_ACCESS_DENIED:
            printf("   Erreur : Acces refuse\n");
            break;
        default:
            printf("   Erreur inconnue\n");
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 5 : Enum maldev (types mémoire)
    // -------------------------------------------------------------------------
    printf("[5] Enum maldev - types allocation memoire\n");

    MEMORY_ALLOCATION_TYPE allocType = MEM_COMMIT;
    MEMORY_PROTECTION protection = PAGE_EXECUTE_READWRITE;

    printf("   Type allocation : 0x%X (MEM_COMMIT)\n", allocType);
    printf("   Protection      : 0x%X (PAGE_EXECUTE_READWRITE)\n\n", protection);

    // En vrai maldev, on ferait :
    // VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // -------------------------------------------------------------------------
    // EXEMPLE 6 : Bitfields - économie de mémoire
    // -------------------------------------------------------------------------
    printf("[6] Bitfields - economie memoire\n");

    printf("   Taille FlagsNormal   : %zu bytes\n", sizeof(struct FlagsNormal));
    printf("   Taille FlagsBitfield : %zu bytes\n", sizeof(struct FlagsBitfield));

    struct FlagsBitfield flags = {0};            // Tout à 0
    flags.isActive = 1;
    flags.isHidden = 0;
    flags.priority = 5;

    printf("   isActive = %u\n", flags.isActive);
    printf("   isHidden = %u\n", flags.isHidden);
    printf("   priority = %u\n\n", flags.priority);

    // -------------------------------------------------------------------------
    // EXEMPLE 7 : PE Characteristics (bitfields maldev)
    // -------------------------------------------------------------------------
    printf("[7] PE Characteristics (bitfields maldev)\n");

    PE_CHARACTERISTICS peFlags = {0};
    peFlags.isExecutable = 1;
    peFlags.isDLL = 1;
    peFlags.lineNumsStripped = 1;

    printf("   isExecutable = %u\n", peFlags.isExecutable);
    printf("   isDLL = %u\n", peFlags.isDLL);
    printf("   isSystem = %u\n\n", peFlags.isSystem);

    // -------------------------------------------------------------------------
    // EXEMPLE 8 : Variant (struct + union)
    // -------------------------------------------------------------------------
    printf("[8] Variant - struct + union\n");

    Variant var1;
    var1.type = 1;                               // Type = int
    var1.data.intValue = 42;
    printf("   Type 1 (int) : %d\n", var1.data.intValue);

    Variant var2;
    var2.type = 2;                               // Type = float
    var2.data.floatValue = 3.14f;
    printf("   Type 2 (float) : %.2f\n", var2.data.floatValue);

    Variant var3;
    var3.type = 3;                               // Type = string
    var3.data.stringValue = "Hello Maldev";
    printf("   Type 3 (string) : %s\n\n", var3.data.stringValue);

    // -------------------------------------------------------------------------
    // EXEMPLE 9 : Manipulation de bits avec union
    // -------------------------------------------------------------------------
    printf("[9] Manipulation bits avec union\n");

    DWORD_UNION flags_dword;
    flags_dword.valeur = 0;                      // Tout à 0

    // Activer certains bits individuellement
    flags_dword.bytes[0] = 0x01;                 // Bit 0 activé
    flags_dword.bytes[1] = 0x80;                 // Bit 15 activé

    printf("   Valeur resultante : 0x%08X\n\n", flags_dword.valeur);

    /*
     * =========================================================================
     * RÉSUMÉ :
     * =========================================================================
     *
     * 1. UNION :
     *    - Tous les membres partagent la MÊME mémoire
     *    - Taille = taille du plus grand membre
     *    - Utile pour voir la même donnée de différentes façons
     *
     * 2. ENUM :
     *    - Liste de constantes nommées
     *    - Plus lisible que #define pour les constantes liées
     *    - Très utilisé en maldev (flags, status codes, etc.)
     *
     * 3. BITFIELDS :
     *    - Spécifier le nombre de bits pour chaque membre
     *    - Économise de la mémoire
     *    - Attention : moins performant (bit manipulation nécessaire)
     *
     * 4. COMBINAISONS :
     *    - Struct + Union = variant types
     *    - Union + bytes = manipulation bas niveau
     *
     * =========================================================================
     */

    /*
     * =========================================================================
     * MALDEV PREVIEW :
     * =========================================================================
     *
     * En maldev, ces concepts sont PARTOUT :
     *
     * 1. UNIONS :
     *    - IMAGE_OPTIONAL_HEADER : union pour PE32 vs PE64
     *    - Voir un shellcode comme bytes[] OU comme fonction
     *    - Conversion entre types (DWORD <-> bytes)
     *
     * 2. ENUMS :
     *    - MEMORY_PROTECTION (PAGE_EXECUTE_READWRITE, etc.)
     *    - PROCESS_ACCESS_RIGHTS (PROCESS_ALL_ACCESS, etc.)
     *    - Tous les flags Windows sont des enums !
     *
     * 3. BITFIELDS :
     *    - PE headers (Characteristics, DllCharacteristics)
     *    - Flags de fichiers, processus, threads
     *
     * Exemple de code maldev réel :
     *
     *   typedef union {
     *       IMAGE_NT_HEADERS32 headers32;
     *       IMAGE_NT_HEADERS64 headers64;
     *   } PE_HEADERS;
     *
     *   PE_HEADERS* pHeaders = (PE_HEADERS*)(baseAddress + dosHeader->e_lfanew);
     *   if (pHeaders->headers32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
     *       // PE 32 bits
     *   } else {
     *       // PE 64 bits
     *   }
     *
     * Prochaine leçon : File I/O (lire/écrire des fichiers) !
     *
     * =========================================================================
     */

    printf("=== FIN DE LA LESSON 02 ===\n");
    return 0;
}

/*
 * =============================================================================
 * EXERCICE POUR TOI :
 * =============================================================================
 *
 * 1. Crée une union qui peut représenter :
 *    - Un int (4 bytes)
 *    - Deux shorts (2x2 bytes)
 *    - Quatre chars (4x1 byte)
 *
 * 2. Assigne la valeur 0xAABBCCDD à l'int
 *
 * 3. Affiche les 4 bytes individuels en hexadécimal
 *
 * 4. Crée un enum pour les niveaux de log :
 *    DEBUG = 0, INFO = 1, WARNING = 2, ERROR = 3
 *
 * 5. Écris une fonction qui prend un niveau et affiche le nom
 *
 * On se retrouve dans ex02-config-parser.c pour pratiquer !
 *
 * =============================================================================
 */
