/*
 * =============================================================================
 * Module 02 : Variables et Types - Exemple complet
 * =============================================================================
 *
 * PRÉREQUIS :
 * -----------
 * - Module 01 : comprendre l'hexadécimal et le binaire
 * - Savoir ce qu'est un byte (8 bits, valeurs 0-255)
 *
 * CE QUE TU VAS APPRENDRE :
 * -------------------------
 * - Comment les différents types sont stockés en mémoire
 * - La différence signed vs unsigned (crucial pour les shellcodes)
 * - L'endianness (crucial pour le reverse engineering)
 * - Comment calculer les tailles avec sizeof
 * - Les vulnérabilités liées aux types (integer overflow)
 *
 * COMPILATION :
 *   gcc example.c -o example
 *
 * =============================================================================
 */

#include <stdio.h>      // printf, etc.
#include <stdint.h>     // uint8_t, uint32_t, etc. (types de taille fixe)
#include <string.h>     // memcpy
#include <limits.h>     // INT_MAX, CHAR_MAX, etc.


/*
 * =============================================================================
 * PARTIE 1 : Tailles des types de base
 * =============================================================================
 *
 * POURQUOI C'EST IMPORTANT EN OFFENSIVE ?
 * - En reverse engineering, tu dois savoir combien de bytes occupe une variable
 * - Dans un exploit, tu calcules des offsets en bytes
 * - Les structures Windows (PE headers) ont des tailles précises
 */
void demo_sizeof(void) {
    printf("\n");
    printf("=============================================================\n");
    printf("  PARTIE 1 : Tailles des types (sizeof)\n");
    printf("=============================================================\n\n");

    /*
     * sizeof() retourne la taille en bytes d'un type ou d'une variable.
     * Le résultat est de type size_t, qu'on affiche avec %zu.
     *
     * ASTUCE REVERSE : Quand tu vois dans IDA/Ghidra :
     *   mov DWORD PTR [rbp-0x4], eax
     * Le "DWORD" (4 bytes) te dit que c'est probablement un int.
     */

    printf("    Types entiers :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // char : 1 byte = 8 bits = 256 valeurs possibles
    // Utilisé pour : caractères ASCII, bytes bruts (shellcode)
    printf("    char      : %zu byte   (valeurs: -128 à 127 ou 0 à 255)\n",
           sizeof(char));

    // short : 2 bytes = 16 bits = 65536 valeurs possibles
    // Utilisé pour : ports réseau (0-65535), petits compteurs
    printf("    short     : %zu bytes  (valeurs: -32768 à 32767)\n",
           sizeof(short));

    // int : 4 bytes = 32 bits = ~4 milliards de valeurs
    // Utilisé pour : la plupart des entiers, PIDs, handles (Windows)
    printf("    int       : %zu bytes  (valeurs: ~-2 à +2 milliards)\n",
           sizeof(int));

    // long : 8 bytes sur Linux 64-bit, 4 bytes sur Windows 64-bit !
    // ATTENTION : la taille varie selon l'OS, utilise stdint.h pour être sûr
    printf("    long      : %zu bytes  (ATTENTION: varie selon l'OS!)\n",
           sizeof(long));

    // long long : toujours 8 bytes (garanti par le standard C)
    printf("    long long : %zu bytes  (toujours 8 bytes)\n",
           sizeof(long long));

    printf("\n    Types flottants :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // float/double : rarement utilisés en offensive, mais bon à savoir
    printf("    float     : %zu bytes  (précision ~7 chiffres)\n",
           sizeof(float));
    printf("    double    : %zu bytes  (précision ~15 chiffres)\n",
           sizeof(double));

    printf("\n    Pointeurs :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // void* : taille d'une adresse mémoire
    // 4 bytes sur 32-bit, 8 bytes sur 64-bit
    // CRUCIAL : détermine si tu es sur une architecture 32 ou 64 bits
    printf("    void*     : %zu bytes  → Architecture %zu-bit\n",
           sizeof(void*), sizeof(void*) * 8);

    printf("\n");
}


/*
 * =============================================================================
 * PARTIE 2 : Signed vs Unsigned - Le piège classique
 * =============================================================================
 *
 * POURQUOI C'EST CRUCIAL ?
 * - Les shellcodes utilisent TOUJOURS unsigned char
 * - Les comparaisons signed/unsigned peuvent causer des bugs de sécurité
 * - L'integer overflow se comporte différemment selon le signe
 */
void demo_signed_unsigned(void) {
    printf("=============================================================\n");
    printf("  PARTIE 2 : Signed vs Unsigned\n");
    printf("=============================================================\n\n");

    /*
     * SIGNED : peut être négatif, utilise le complément à deux
     * UNSIGNED : toujours >= 0, toute la plage pour les valeurs positives
     */

    // Même pattern de bits, interprétation différente !
    unsigned char u_byte = 0xFF;  // 11111111 en binaire
    signed char s_byte = 0xFF;    // Même bits !

    printf("    Même valeur binaire (0xFF = 11111111), interprétation différente :\n");
    printf("    ─────────────────────────────────────────────────────────────────\n");
    printf("    unsigned char 0xFF = %u   (tous les bits = valeur)\n", u_byte);
    printf("    signed char   0xFF = %d   (bit de signe = négatif)\n", s_byte);

    /*
     * POURQUOI 0xFF = -1 en signed ?
     *
     * Le complément à deux fonctionne ainsi :
     * - Pour obtenir -N, on inverse les bits de N et on ajoute 1
     * - 1 en binaire = 00000001
     * - Inverser      = 11111110
     * - Ajouter 1     = 11111111 = 0xFF
     *
     * Donc 0xFF représente -1 en signed char.
     */

    printf("\n    Pourquoi c'est important pour les shellcodes :\n");
    printf("    ─────────────────────────────────────────────────────────────────\n");

    // Shellcode = suite de bytes. Certains bytes sont > 127 (comme 0xFF)
    // Si tu utilises signed char, les comparaisons sont faussées !

    char bad_byte = 0xFF;           // signed par défaut
    unsigned char good_byte = 0xFF; // explicitement unsigned

    printf("    Comparaison avec 0 :\n");
    printf("    - signed char 0xFF > 0 ?   %s (car -1 n'est pas > 0)\n",
           (bad_byte > 0) ? "OUI" : "NON");
    printf("    - unsigned char 0xFF > 0 ? %s (car 255 > 0)\n",
           (good_byte > 0) ? "OUI" : "NON");

    /*
     * APPLICATION OFFENSIVE :
     * Si tu fais une boucle sur un shellcode avec signed char,
     * et que tu compares avec > 0, tu vas rater des bytes !
     */

    printf("\n    Démonstration du problème avec un 'shellcode' :\n");
    printf("    ─────────────────────────────────────────────────────────────────\n");

    // Faux shellcode pour la démo (NOP + bytes divers)
    unsigned char shellcode[] = { 0x90, 0x90, 0xFF, 0xC0, 0x90 };
    size_t shellcode_len = sizeof(shellcode);

    printf("    Shellcode : ");
    for (size_t i = 0; i < shellcode_len; i++) {
        printf("0x%02X ", shellcode[i]);
    }
    printf("\n");

    // Mauvaise façon (signed)
    printf("\n    MAUVAIS (signed char, comparaison > 0) :\n    ");
    for (int i = 0; i < (int)shellcode_len; i++) {
        char byte = shellcode[i];  // Cast en signed !
        if (byte > 0) {            // 0xFF = -1, donc pas > 0
            printf("0x%02X ", (unsigned char)byte);
        } else {
            printf("[SKIP] ");     // On rate des bytes !
        }
    }

    // Bonne façon (unsigned)
    printf("\n    BON (unsigned char) :\n    ");
    for (size_t i = 0; i < shellcode_len; i++) {
        unsigned char byte = shellcode[i];
        printf("0x%02X ", byte);   // Tous les bytes sont traités
    }

    printf("\n\n");
}


/*
 * =============================================================================
 * PARTIE 3 : L'Endianness - L'ordre des bytes en mémoire
 * =============================================================================
 *
 * POURQUOI C'EST CRUCIAL ?
 * - Quand tu lis un dump mémoire, tu dois savoir dans quel ordre lire
 * - Les adresses dans les exploits doivent être écrites dans le bon ordre
 * - Les protocoles réseau utilisent big endian, ton CPU utilise little endian
 */
void demo_endianness(void) {
    printf("=============================================================\n");
    printf("  PARTIE 3 : Endianness (ordre des bytes)\n");
    printf("=============================================================\n\n");

    /*
     * LITTLE ENDIAN (x86, x64, ARM) :
     * Le byte de poids FAIBLE (Least Significant Byte) est stocké EN PREMIER
     * Mnémotechnique : "Little end first" = le petit bout d'abord
     *
     * BIG ENDIAN (réseau, PowerPC) :
     * Le byte de poids FORT (Most Significant Byte) est stocké EN PREMIER
     * Mnémotechnique : "Big end first" = le gros bout d'abord
     */

    // Valeur de test : 0x12345678
    // En décimal : 305419896
    uint32_t value = 0x12345678;

    printf("    Valeur : 0x%08X (décimal: %u)\n\n", value, value);

    // Accéder aux bytes individuels via un pointeur
    unsigned char *bytes = (unsigned char*)&value;

    printf("    Comment c'est stocké en mémoire (sur cette machine) :\n");
    printf("    ─────────────────────────────────────────────────────\n");
    printf("    Adresse   Contenu\n");

    for (int i = 0; i < 4; i++) {
        printf("    +%d        0x%02X", i, bytes[i]);
        if (i == 0) printf("    ← Premier byte en mémoire");
        if (i == 3) printf("    ← Dernier byte en mémoire");
        printf("\n");
    }

    // Détection de l'endianness
    printf("\n    Détection de l'endianness :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    if (bytes[0] == 0x78) {
        printf("    Cette machine est LITTLE ENDIAN (x86/x64/ARM)\n");
        printf("    → Le byte de poids faible (0x78) est en premier\n");
        printf("    → Ordre en mémoire : 78 56 34 12\n");
    } else if (bytes[0] == 0x12) {
        printf("    Cette machine est BIG ENDIAN\n");
        printf("    → Le byte de poids fort (0x12) est en premier\n");
        printf("    → Ordre en mémoire : 12 34 56 78\n");
    }

    /*
     * APPLICATION OFFENSIVE : Écrire une adresse dans un exploit
     *
     * Imaginons que tu veux écrire l'adresse 0x7fff1234 pour
     * écraser une adresse de retour. Sur x86/x64 (little endian),
     * tu dois écrire les bytes dans l'ordre INVERSE !
     */

    printf("\n    Application : écrire une adresse dans un exploit\n");
    printf("    ─────────────────────────────────────────────────────\n");

    uint32_t target_addr = 0x7fff1234;
    unsigned char exploit_bytes[4];

    // Conversion manuelle en little endian
    exploit_bytes[0] = (target_addr >> 0) & 0xFF;   // 0x34 (LSB)
    exploit_bytes[1] = (target_addr >> 8) & 0xFF;   // 0x12
    exploit_bytes[2] = (target_addr >> 16) & 0xFF;  // 0xFF
    exploit_bytes[3] = (target_addr >> 24) & 0xFF;  // 0x7F (MSB)

    printf("    Adresse cible : 0x%08X\n", target_addr);
    printf("    Bytes à écrire (little endian) : ");
    for (int i = 0; i < 4; i++) {
        printf("0x%02X ", exploit_bytes[i]);
    }
    printf("\n");
    printf("    → Dans ton payload : \"\\x34\\x12\\xff\\x7f\"\n");

    printf("\n");
}


/*
 * =============================================================================
 * PARTIE 4 : Integer Overflow - Vulnérabilité classique
 * =============================================================================
 *
 * POURQUOI C'EST IMPORTANT ?
 * - L'integer overflow est une classe de vulnérabilités très courante
 * - Peut mener à des buffer overflows, des bypasses de checks, etc.
 * - Tu dois comprendre le "wrap around" pour l'exploiter ou l'éviter
 */
void demo_overflow(void) {
    printf("=============================================================\n");
    printf("  PARTIE 4 : Integer Overflow\n");
    printf("=============================================================\n\n");

    /*
     * OVERFLOW = quand une valeur dépasse la limite du type
     * Le comportement est un "wrap around" : on repart de l'autre côté
     *
     * Pour unsigned char (0-255) :
     * 255 + 1 = 0 (wrap around)
     *
     * Pour signed char (-128 à 127) :
     * 127 + 1 = -128 (wrap around)
     */

    printf("    Overflow UNSIGNED (unsigned char, 0-255) :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    unsigned char u = 255;
    printf("    Valeur initiale : %u\n", u);
    u = u + 1;  // Overflow !
    printf("    Après +1        : %u (wrap around vers 0)\n", u);
    u = u - 1;  // Underflow !
    printf("    Après -1        : %u (wrap around vers 255)\n", u);

    printf("\n    Overflow SIGNED (signed char, -128 à 127) :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    signed char s = 127;
    printf("    Valeur initiale : %d\n", s);
    s = s + 1;  // Overflow !
    printf("    Après +1        : %d (wrap around vers -128)\n", s);

    /*
     * VULNÉRABILITÉ : Integer overflow dans une vérification de taille
     *
     * Code vulnérable typique :
     *
     * void process_data(unsigned short len) {
     *     if (len > MAX_SIZE) return;  // Check de sécurité
     *     char* buf = malloc(len + 1); // +1 pour le null terminator
     *     // Si len = 65535, len + 1 = 0 (overflow!)
     *     // malloc(0) alloue un petit buffer
     *     // → Buffer overflow lors de l'écriture
     * }
     */

    printf("\n    Démonstration de vulnérabilité (simulation) :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    unsigned short len = 65535;  // Max value pour unsigned short
    printf("    len           = %u (0xFFFF)\n", len);

    unsigned short len_plus_1 = len + 1;  // Overflow !
    printf("    len + 1       = %u (OVERFLOW!)\n", len_plus_1);

    printf("\n    Si ce code était utilisé pour malloc() :\n");
    printf("    → malloc(%u) allouerait un buffer quasi-nul\n", len_plus_1);
    printf("    → Mais on écrirait %u bytes → BUFFER OVERFLOW\n", len);

    printf("\n");
}


/*
 * =============================================================================
 * PARTIE 5 : Types Windows API
 * =============================================================================
 *
 * POURQUOI C'EST IMPORTANT ?
 * - Le malware Windows utilise ces types partout
 * - Les headers PE/ELF utilisent des types de taille fixe
 * - Comprendre ces types = comprendre le code Windows
 */
void demo_windows_types(void) {
    printf("=============================================================\n");
    printf("  PARTIE 5 : Types Windows API (simulation)\n");
    printf("=============================================================\n\n");

    /*
     * Windows définit ses propres types dans windows.h
     * On les simule ici pour comprendre leur taille
     */

    // Types Windows simulés
    typedef unsigned char  BYTE;    // 1 byte
    typedef unsigned short WORD;    // 2 bytes
    typedef unsigned int   DWORD;   // 4 bytes (Double WORD)
    typedef unsigned long long QWORD; // 8 bytes (Quad WORD)

    printf("    Types Windows et leurs tailles :\n");
    printf("    ─────────────────────────────────────────────────────\n");
    printf("    BYTE   : %zu byte  (données brutes, shellcode)\n", sizeof(BYTE));
    printf("    WORD   : %zu bytes (ports, offsets 16-bit)\n", sizeof(WORD));
    printf("    DWORD  : %zu bytes (handles, PIDs, adresses 32-bit)\n", sizeof(DWORD));
    printf("    QWORD  : %zu bytes (adresses 64-bit)\n", sizeof(QWORD));

    /*
     * Exemple : Structure simplifiée d'un header PE
     * (le format des exécutables Windows)
     */

    printf("\n    Exemple : Header PE simplifié\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // Structure simplifiée d'IMAGE_FILE_HEADER
    struct {
        WORD  Machine;              // Type de CPU (0x8664 = x64)
        WORD  NumberOfSections;     // Nombre de sections
        DWORD TimeDateStamp;        // Date de compilation
        DWORD SizeOfOptionalHeader; // Taille du header optionnel
        WORD  Characteristics;      // Flags (DLL, executable, etc.)
    } pe_header = {
        .Machine = 0x8664,          // x64
        .NumberOfSections = 5,
        .TimeDateStamp = 0x656789AB,
        .SizeOfOptionalHeader = 240,
        .Characteristics = 0x0022   // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    };

    printf("    Machine           : 0x%04X (x64)\n", pe_header.Machine);
    printf("    NumberOfSections  : %u\n", pe_header.NumberOfSections);
    printf("    TimeDateStamp     : 0x%08X\n", pe_header.TimeDateStamp);
    printf("    Characteristics   : 0x%04X\n", pe_header.Characteristics);

    printf("\n");
}


/*
 * =============================================================================
 * PARTIE 6 : Types à taille fixe (stdint.h)
 * =============================================================================
 *
 * POURQUOI C'EST IMPORTANT ?
 * - Les types standard (int, long) ont des tailles qui VARIENT
 * - Pour du code portable et fiable, utilise stdint.h
 * - Essentiel pour parser des formats binaires (PE, ELF, protocoles)
 */
void demo_stdint(void) {
    printf("=============================================================\n");
    printf("  PARTIE 6 : Types à taille fixe (stdint.h)\n");
    printf("=============================================================\n\n");

    printf("    Types de taille GARANTIE :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // Types signés
    printf("    int8_t   : %zu byte  (signé)\n", sizeof(int8_t));
    printf("    int16_t  : %zu bytes (signé)\n", sizeof(int16_t));
    printf("    int32_t  : %zu bytes (signé)\n", sizeof(int32_t));
    printf("    int64_t  : %zu bytes (signé)\n", sizeof(int64_t));

    printf("\n");

    // Types non signés
    printf("    uint8_t  : %zu byte  (non signé) ← UTILISE POUR LES SHELLCODES\n",
           sizeof(uint8_t));
    printf("    uint16_t : %zu bytes (non signé)\n", sizeof(uint16_t));
    printf("    uint32_t : %zu bytes (non signé)\n", sizeof(uint32_t));
    printf("    uint64_t : %zu bytes (non signé)\n", sizeof(uint64_t));

    /*
     * BONNE PRATIQUE :
     * - Pour des bytes bruts (shellcode, buffers) : uint8_t
     * - Pour des structures binaires : uint16_t, uint32_t, uint64_t
     * - Pour des adresses : uintptr_t (taille d'un pointeur)
     */

    printf("\n    Exemple pratique : définir un shellcode\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // Shellcode NOP sled (pour la démo)
    uint8_t nop_sled[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP NOP NOP NOP
        0x90, 0x90, 0x90, 0x90   // NOP NOP NOP NOP
    };

    printf("    uint8_t nop_sled[] = { 0x90, 0x90, ... };\n");
    printf("    Taille : %zu bytes\n", sizeof(nop_sled));
    printf("    Contenu : ");
    for (size_t i = 0; i < sizeof(nop_sled); i++) {
        printf("%02X ", nop_sled[i]);
    }
    printf("\n");

    printf("\n");
}


/*
 * =============================================================================
 * PARTIE 7 : Visualisation mémoire complète
 * =============================================================================
 */
void demo_memory_layout(void) {
    printf("=============================================================\n");
    printf("  PARTIE 7 : Visualisation mémoire\n");
    printf("=============================================================\n\n");

    // Déclaration de plusieurs variables
    char c = 'A';
    short s = 0x1234;
    int i = 0x12345678;
    long long ll = 0x123456789ABCDEF0LL;

    printf("    Variables déclarées :\n");
    printf("    ─────────────────────────────────────────────────────\n");
    printf("    char c      = 'A'              (0x%02X)\n", c);
    printf("    short s     = 0x1234\n");
    printf("    int i       = 0x12345678\n");
    printf("    long long ll = 0x123456789ABCDEF0\n");

    printf("\n    Représentation en mémoire (little endian) :\n");
    printf("    ─────────────────────────────────────────────────────\n");

    // Afficher chaque variable byte par byte
    unsigned char *ptr;

    printf("\n    char c (%zu byte) @ %p :\n    ", sizeof(c), (void*)&c);
    ptr = (unsigned char*)&c;
    for (size_t j = 0; j < sizeof(c); j++) {
        printf("%02X ", ptr[j]);
    }
    printf("  → '%c'\n", c);

    printf("\n    short s (%zu bytes) @ %p :\n    ", sizeof(s), (void*)&s);
    ptr = (unsigned char*)&s;
    for (size_t j = 0; j < sizeof(s); j++) {
        printf("%02X ", ptr[j]);
    }
    printf("  → 0x%04X (note: little endian, bytes inversés)\n", s);

    printf("\n    int i (%zu bytes) @ %p :\n    ", sizeof(i), (void*)&i);
    ptr = (unsigned char*)&i;
    for (size_t j = 0; j < sizeof(i); j++) {
        printf("%02X ", ptr[j]);
    }
    printf("  → 0x%08X\n", i);

    printf("\n    long long ll (%zu bytes) @ %p :\n    ", sizeof(ll), (void*)&ll);
    ptr = (unsigned char*)&ll;
    for (size_t j = 0; j < sizeof(ll); j++) {
        printf("%02X ", ptr[j]);
    }
    printf("\n    → 0x%016llX\n", ll);

    printf("\n");
}


/*
 * =============================================================================
 * FONCTION PRINCIPALE
 * =============================================================================
 */
int main(void) {

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║  Module 02 : Variables et Types - Démonstration complète      ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    // Exécuter toutes les démonstrations
    demo_sizeof();
    demo_signed_unsigned();
    demo_endianness();
    demo_overflow();
    demo_windows_types();
    demo_stdint();
    demo_memory_layout();

    printf("=============================================================\n");
    printf("  Fin de la démonstration\n");
    printf("=============================================================\n\n");

    printf("Points clés à retenir :\n");
    printf("─────────────────────────────────────────────────────────────\n");
    printf("1. Toujours utiliser unsigned char pour les shellcodes\n");
    printf("2. Les tailles varient selon l'OS → utiliser stdint.h\n");
    printf("3. x86/x64 = little endian → bytes inversés en mémoire\n");
    printf("4. L'integer overflow peut être exploité ou causer des bugs\n");
    printf("5. sizeof() est ton ami pour calculer des offsets\n\n");

    return 0;
}
