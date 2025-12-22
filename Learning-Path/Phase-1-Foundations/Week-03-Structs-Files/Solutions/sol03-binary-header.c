/*
 * =============================================================================
 * EXERCICE 03 : PARSER UN HEADER BINAIRE (MALDEV STYLE)
 * =============================================================================
 *
 * OBJECTIF :
 *   Créer et parser un format de fichier binaire avec header.
 *   C'est exactement ce qu'on fait en maldev pour analyser des PE !
 *
 * FORMAT DU FICHIER :
 *   [HEADER - 32 bytes]
 *   - Magic (4 bytes) : 0x4D414C44 ("MALD" en ASCII)
 *   - Version (4 bytes) : Numéro de version
 *   - Payload Size (4 bytes) : Taille du payload en bytes
 *   - Checksum (4 bytes) : Somme de contrôle du payload
 *   - Flags (4 bytes) : Flags de configuration
 *   - Reserved (12 bytes) : Réservé pour usage futur
 *
 *   [PAYLOAD - Variable]
 *   - Données arbitraires
 *
 * INSTRUCTIONS :
 *   1. Définis la structure MaldevHeader
 *   2. Crée un fichier binaire avec header + payload
 *   3. Lis et valide le header
 *   4. Vérifie le checksum
 *   5. Extrais le payload
 *
 * COMPILATION :
 *   cl ex03-binary-header.c
 *   .\ex03-binary-header.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Constantes
#define MAGIC_NUMBER 0x4D414C44          // "MALD" en little-endian
#define CURRENT_VERSION 1

/*
 * =============================================================================
 * TODO 1 : Définir la structure MaldevHeader
 * =============================================================================
 *
 * Structure alignée sur 32 bytes :
 * - unsigned int magic           : Signature magique
 * - unsigned int version         : Version du format
 * - unsigned int payloadSize     : Taille du payload
 * - unsigned int checksum        : Checksum du payload
 * - unsigned int flags           : Flags de configuration
 * - unsigned char reserved[12]   : Espace réservé
 */

typedef struct {
    unsigned int magic;
    unsigned int version;
    unsigned int payloadSize;
    unsigned int checksum;
    unsigned int flags;
    unsigned char reserved[12];
} MaldevHeader;

// Vérifier que la structure fait bien 32 bytes
// sizeof(MaldevHeader) devrait être 32

/*
 * =============================================================================
 * TODO 2 : Fonction pour calculer un checksum simple
 * =============================================================================
 *
 * Calcule la somme de tous les bytes du payload.
 * C'est un checksum simple, pas cryptographiquement sûr !
 *
 * ASTUCE : Parcours chaque byte et additionne-les
 */

unsigned int calculateChecksum(unsigned char* data, unsigned int size) {
    unsigned int sum = 0;

    for (unsigned int i = 0; i < size; i++) {
        sum += data[i];
    }

    return sum;
}

/*
 * =============================================================================
 * TODO 3 : Fonction pour créer un fichier avec header
 * =============================================================================
 *
 * Cette fonction doit :
 * 1. Créer un header avec les bonnes valeurs
 * 2. Calculer le checksum du payload
 * 3. Écrire le header dans le fichier
 * 4. Écrire le payload
 */

int createBinaryFile(const char* filename,
                     unsigned char* payload,
                     unsigned int payloadSize,
                     unsigned int flags)
{
    printf("   [CREATE] Creation du fichier %s...\n", filename);

    // 1. Créer le header
    MaldevHeader header = {0};
    header.magic = MAGIC_NUMBER;
    header.version = CURRENT_VERSION;
    header.payloadSize = payloadSize;
    header.checksum = calculateChecksum(payload, payloadSize);
    header.flags = flags;
    // reserved reste à 0

    printf("   [CREATE] Header prepare :\n");
    printf("            Magic       : 0x%08X\n", header.magic);
    printf("            Version     : %u\n", header.version);
    printf("            Payload Size: %u bytes\n", header.payloadSize);
    printf("            Checksum    : 0x%08X\n", header.checksum);
    printf("            Flags       : 0x%08X\n", header.flags);

    // 2. Ouvrir le fichier en écriture binaire
    FILE* f = fopen(filename, "wb");
    if (f == NULL) {
        printf("   [ERROR] Impossible de creer le fichier\n");
        return 0;
    }

    // 3. Écrire le header
    fwrite(&header, sizeof(MaldevHeader), 1, f);

    // 4. Écrire le payload
    fwrite(payload, 1, payloadSize, f);

    fclose(f);
    printf("   [CREATE] Fichier cree avec succes !\n");
    return 1;
}

/*
 * =============================================================================
 * TODO 4 : Fonction pour lire et valider le header
 * =============================================================================
 *
 * Cette fonction doit :
 * 1. Ouvrir le fichier
 * 2. Lire le header
 * 3. Valider la signature magique
 * 4. Valider la version
 * 5. Retourner 1 si valide, 0 sinon
 */

int readAndValidateHeader(const char* filename, MaldevHeader* header) {
    printf("   [READ] Lecture du fichier %s...\n", filename);

    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        printf("   [ERROR] Impossible d'ouvrir le fichier\n");
        return 0;
    }

    // Lire le header
    fread(header, sizeof(MaldevHeader), 1, f);
    fclose(f);

    printf("   [READ] Header lu :\n");
    printf("          Magic       : 0x%08X\n", header->magic);
    printf("          Version     : %u\n", header->version);
    printf("          Payload Size: %u bytes\n", header->payloadSize);
    printf("          Checksum    : 0x%08X\n", header->checksum);
    printf("          Flags       : 0x%08X\n", header->flags);

    // Valider la signature
    if (header->magic != MAGIC_NUMBER) {
        printf("   [ERROR] Signature invalide !\n");
        printf("          Attendu : 0x%08X\n", MAGIC_NUMBER);
        printf("          Recu    : 0x%08X\n", header->magic);
        return 0;
    }

    // Valider la version
    if (header->version > CURRENT_VERSION) {
        printf("   [WARN] Version plus recente que celle supportee\n");
        printf("          Version fichier : %u\n", header->version);
        printf("          Version supportee : %u\n", CURRENT_VERSION);
        // On continue quand même pour cet exemple
    }

    printf("   [READ] Header valide !\n");
    return 1;
}

/*
 * =============================================================================
 * TODO 5 : Fonction pour extraire le payload
 * =============================================================================
 *
 * Cette fonction doit :
 * 1. Ouvrir le fichier
 * 2. Sauter le header (fseek)
 * 3. Allouer de la mémoire pour le payload
 * 4. Lire le payload
 * 5. Vérifier le checksum
 */

unsigned char* extractPayload(const char* filename, MaldevHeader* header) {
    printf("   [EXTRACT] Extraction du payload...\n");

    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        printf("   [ERROR] Impossible d'ouvrir le fichier\n");
        return NULL;
    }

    // Sauter le header
    fseek(f, sizeof(MaldevHeader), SEEK_SET);

    // Allouer la mémoire pour le payload
    unsigned char* payload = (unsigned char*)malloc(header->payloadSize);
    if (payload == NULL) {
        printf("   [ERROR] Allocation memoire echouee\n");
        fclose(f);
        return NULL;
    }

    // Lire le payload
    size_t bytesRead = fread(payload, 1, header->payloadSize, f);
    fclose(f);

    printf("   [EXTRACT] %zu bytes lus\n", bytesRead);

    // Vérifier le checksum
    unsigned int calculatedChecksum = calculateChecksum(payload, header->payloadSize);

    printf("   [EXTRACT] Verification du checksum...\n");
    printf("            Checksum header : 0x%08X\n", header->checksum);
    printf("            Checksum calcule: 0x%08X\n", calculatedChecksum);

    if (calculatedChecksum != header->checksum) {
        printf("   [ERROR] Checksum invalide ! Fichier corrompu !\n");
        free(payload);
        return NULL;
    }

    printf("   [EXTRACT] Checksum OK ! Payload extrait avec succes\n");
    return payload;
}

/*
 * =============================================================================
 * TODO 6 : Fonction pour afficher un hex dump
 * =============================================================================
 */

void hexDump(unsigned char* data, unsigned int size, unsigned int bytesPerLine) {
    for (unsigned int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % bytesPerLine == 0) {
            printf("\n            ");
        }
    }
    if (size % bytesPerLine != 0) {
        printf("\n");
    }
}

/*
 * =============================================================================
 * FONCTION MAIN : TESTS
 * =============================================================================
 */

int main() {
    printf("=== EXERCICE 03 : BINARY HEADER PARSING (MALDEV) ===\n\n");

    // -------------------------------------------------------------------------
    // TEST 1 : Vérifier la taille de la structure
    // -------------------------------------------------------------------------
    printf("[1] Verification de la structure MaldevHeader\n");
    printf("   Taille de MaldevHeader : %zu bytes\n", sizeof(MaldevHeader));

    if (sizeof(MaldevHeader) != 32) {
        printf("   [WARN] La taille devrait etre 32 bytes !\n");
        printf("   Verifie l'alignement et le padding\n");
    } else {
        printf("   [OK] Taille correcte : 32 bytes\n");
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 2 : Créer un payload de test (simuler un shellcode)
    // -------------------------------------------------------------------------
    printf("[2] Creation d'un payload de test\n");

    // Simuler un mini-shellcode (NOP sled + INT3 + RET)
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,          // NOP NOP NOP NOP
        0x90, 0x90, 0x90, 0x90,          // NOP NOP NOP NOP
        0xCC,                            // INT3 (breakpoint)
        0xC3,                            // RET
        0x48, 0x65, 0x6C, 0x6C, 0x6F,    // "Hello" en ASCII
        0x00                             // Null terminator
    };

    unsigned int shellcodeSize = sizeof(shellcode);
    printf("   Payload cree : %u bytes\n", shellcodeSize);
    printf("   Contenu (hex):\n            ");
    hexDump(shellcode, shellcodeSize, 16);
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 3 : Créer le fichier binaire
    // -------------------------------------------------------------------------
    printf("[3] Creation du fichier binaire avec header\n");

    unsigned int flags = 0x00000001;     // Flag fictif (ex: ENCRYPTED)

    if (!createBinaryFile("maldev_payload.bin", shellcode, shellcodeSize, flags)) {
        printf("Erreur lors de la creation du fichier\n");
        return 1;
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 4 : Lire et valider le header
    // -------------------------------------------------------------------------
    printf("[4] Lecture et validation du header\n");

    MaldevHeader header = {0};
    if (!readAndValidateHeader("maldev_payload.bin", &header)) {
        printf("Erreur lors de la validation du header\n");
        return 1;
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 5 : Extraire le payload
    // -------------------------------------------------------------------------
    printf("[5] Extraction du payload\n");

    unsigned char* extractedPayload = extractPayload("maldev_payload.bin", &header);
    if (extractedPayload == NULL) {
        printf("Erreur lors de l'extraction du payload\n");
        return 1;
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 6 : Afficher le payload extrait
    // -------------------------------------------------------------------------
    printf("[6] Affichage du payload extrait\n");
    printf("   Taille : %u bytes\n", header.payloadSize);
    printf("   Contenu (hex):\n            ");
    hexDump(extractedPayload, header.payloadSize, 16);
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 7 : Comparer avec l'original
    // -------------------------------------------------------------------------
    printf("[7] Comparaison avec le payload original\n");

    if (memcmp(shellcode, extractedPayload, shellcodeSize) == 0) {
        printf("   [SUCCESS] Le payload extrait est identique a l'original !\n");
    } else {
        printf("   [ERROR] Le payload extrait est different !\n");
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 8 : Tester avec un fichier corrompu
    // -------------------------------------------------------------------------
    printf("[8] Test avec un fichier corrompu\n");

    // Créer un fichier avec un mauvais checksum
    MaldevHeader corruptedHeader = header;
    corruptedHeader.checksum = 0xFFFFFFFF;   // Checksum invalide

    FILE* f = fopen("corrupted_payload.bin", "wb");
    if (f) {
        fwrite(&corruptedHeader, sizeof(MaldevHeader), 1, f);
        fwrite(shellcode, 1, shellcodeSize, f);
        fclose(f);
        printf("   Fichier corrompu cree\n");
    }

    printf("   Tentative d'extraction du fichier corrompu...\n");
    unsigned char* corruptedPayload = extractPayload("corrupted_payload.bin", &corruptedHeader);

    if (corruptedPayload == NULL) {
        printf("   [EXPECTED] Extraction echouee (checksum invalide)\n");
    } else {
        printf("   [UNEXPECTED] Extraction reussie (ne devrait pas arriver)\n");
        free(corruptedPayload);
    }
    printf("\n");

    // Libérer la mémoire
    free(extractedPayload);

    /*
     * =========================================================================
     * DÉFI BONUS (OPTIONNEL) :
     * =========================================================================
     *
     * 1. Ajoute un chiffrement XOR du payload :
     *    - Chiffre le payload avec une clé avant de l'écrire
     *    - Déchiffre après extraction
     *    - Ajoute un flag ENCRYPTED dans le header
     *
     * 2. Ajoute la compression du payload :
     *    - Compresse le payload avant écriture (simple RLE)
     *    - Décompresse après extraction
     *    - Ajoute un champ compressedSize dans le header
     *
     * 3. Parse un VRAI fichier PE :
     *    - Lis un .exe Windows
     *    - Parse le DOS Header (signature "MZ")
     *    - Trouve l'offset du PE Header (e_lfanew)
     *    - Lis le PE Header (signature "PE\0\0")
     *    - Affiche l'Entry Point
     *
     * 4. Crée un format multi-section :
     *    - Header principal
     *    - Section 1 : Code
     *    - Section 2 : Data
     *    - Section 3 : Config
     *
     * =========================================================================
     */

    printf("=== EXERCICE 03 TERMINE ===\n");
    printf("Bravo ! Tu maitrises le parsing de fichiers binaires !\n");
    printf("C'est exactement ce qu'on fait pour analyser des PE en maldev !\n");
    printf("\n");
    printf("Passe maintenant aux solutions pour voir d'autres approches.\n");

    return 0;
}

/*
 * =============================================================================
 * NOTES POUR L'APPRENTISSAGE :
 * =============================================================================
 *
 * 1. FORMAT BINAIRE :
 *    - Header fixe (taille connue)
 *    - Payload variable
 *    - Toujours valider la signature !
 *
 * 2. CHECKSUM :
 *    - Détecte les corruptions
 *    - Simple somme pour l'apprentissage
 *    - En prod : CRC32, MD5, SHA256
 *
 * 3. PARSING :
 *    - Lire le header
 *    - Valider la signature
 *    - Utiliser fseek() pour naviguer
 *    - Toujours vérifier les tailles !
 *
 * 4. MALDEV :
 *    - Les PE Windows ont exactement cette structure !
 *    - DOS Header -> e_lfanew -> PE Header -> Sections
 *    - Même principe pour analyser des DLL, drivers, etc.
 *
 * 5. SÉCURITÉ :
 *    - Toujours valider les entrées
 *    - Vérifier les tailles avant malloc()
 *    - Vérifier les checksums
 *    - Ne jamais faire confiance aux données externes
 *
 * =============================================================================
 */
