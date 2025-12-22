/*
 * =============================================================================
 * SEMAINE 3 - LESSON 04 : FICHIERS BINAIRES & PARSING
 * =============================================================================
 *
 * OBJECTIF :
 *   Apprendre à lire et parser des fichiers binaires.
 *   En maldev, c'est ESSENTIEL pour analyser des PE, injecter du code,
 *   parser des headers, etc.
 *
 * PRE-REQUIS :
 *   - Lesson 03 (File I/O)
 *   - Structures et pointeurs
 *
 * COMPILATION :
 *   cl 04-binary-files.c
 *   .\04-binary-files.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * =============================================================================
 * ANALOGIE : Fichier binaire vs fichier texte
 * =============================================================================
 *
 * FICHIER TEXTE = Un livre que tu peux lire avec tes yeux
 *   - "Hello" s'écrit 'H' 'e' 'l' 'l' 'o'
 *   - Chaque caractère est lisible
 *
 * FICHIER BINAIRE = Un livre écrit en code secret
 *   - Les données sont des bytes bruts (0x48, 0x65, 0x6C...)
 *   - Pas forcément du texte, peut être des nombres, des structures, etc.
 *   - Un .exe est un fichier binaire !
 *
 * En maldev :
 *   - Les .exe, .dll, .bin sont des fichiers binaires
 *   - On doit les parser byte par byte pour comprendre leur structure
 *   - Exemple : Trouver le Entry Point d'un PE
 *
 * =============================================================================
 */

/*
 * =============================================================================
 * PARTIE 1 : DÉFINIR DES STRUCTURES POUR LE PARSING
 * =============================================================================
 */

// Structure simple d'un header de fichier custom
typedef struct {
    unsigned int magic;              // Nombre magique (signature)
    unsigned int version;            // Version du format
    unsigned int dataSize;           // Taille des données
    unsigned int checksum;           // Somme de contrôle
} CustomFileHeader;

// Structure simplifiée d'un DOS Header (début d'un PE)
typedef struct {
    unsigned short e_magic;          // Magic number "MZ" (0x5A4D)
    unsigned short e_cblp;           // Bytes on last page
    unsigned short e_cp;             // Pages in file
    unsigned short e_crlc;           // Relocations
    unsigned short e_cparhdr;        // Size of header in paragraphs
    unsigned short e_minalloc;       // Minimum extra paragraphs
    unsigned short e_maxalloc;       // Maximum extra paragraphs
    unsigned short e_ss;             // Initial SS value
    unsigned short e_sp;             // Initial SP value
    unsigned short e_csum;           // Checksum
    unsigned short e_ip;             // Initial IP value
    unsigned short e_cs;             // Initial CS value
    unsigned short e_lfarlc;         // File address of relocation table
    unsigned short e_ovno;           // Overlay number
    unsigned short e_res[4];         // Reserved
    unsigned short e_oemid;          // OEM identifier
    unsigned short e_oeminfo;        // OEM information
    unsigned short e_res2[10];       // Reserved
    unsigned int   e_lfanew;         // Offset to PE header
} IMAGE_DOS_HEADER_SIMPLE;

// Structure pour stocker des données dans notre format custom
typedef struct {
    char nom[32];
    int age;
    float score;
} DataRecord;

/*
 * =============================================================================
 * FONCTIONS UTILITAIRES
 * =============================================================================
 */

// Calculer un checksum simple (somme de tous les bytes)
unsigned int calculateChecksum(unsigned char* data, size_t size) {
    unsigned int sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum += data[i];
    }
    return sum;
}

// Afficher des bytes en hexadécimal (hex dump)
void hexDump(unsigned char* data, size_t size, size_t bytesPerLine) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % bytesPerLine == 0) {
            printf("\n");
        }
    }
    if (size % bytesPerLine != 0) {
        printf("\n");
    }
}

/*
 * =============================================================================
 * FONCTION MAIN : EXEMPLES PRATIQUES
 * =============================================================================
 */

int main() {
    printf("=== SEMAINE 3 - LESSON 04 : FICHIERS BINAIRES & PARSING ===\n\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 1 : Créer un fichier binaire avec header custom
    // -------------------------------------------------------------------------
    printf("[1] Creation d'un fichier binaire avec header\n");

    // Créer un header
    CustomFileHeader header;
    header.magic = 0xDEADBEEF;                   // Signature unique
    header.version = 1;
    header.dataSize = sizeof(DataRecord);
    header.checksum = 0;                         // On calculera après

    // Créer des données
    DataRecord record = {"Alice", 25, 95.5f};

    // Calculer le checksum des données
    header.checksum = calculateChecksum((unsigned char*)&record, sizeof(DataRecord));

    // Écrire dans un fichier
    FILE* f = fopen("custom_data.bin", "wb");
    if (f == NULL) {
        printf("   Erreur creation fichier\n");
        return 1;
    }

    // Écrire le header puis les données
    fwrite(&header, sizeof(CustomFileHeader), 1, f);
    fwrite(&record, sizeof(DataRecord), 1, f);
    fclose(f);

    printf("   Fichier 'custom_data.bin' cree\n");
    printf("   Header magic: 0x%08X\n", header.magic);
    printf("   Data size: %u bytes\n", header.dataSize);
    printf("   Checksum: 0x%08X\n\n", header.checksum);

    // -------------------------------------------------------------------------
    // EXEMPLE 2 : Lire et parser le fichier binaire
    // -------------------------------------------------------------------------
    printf("[2] Lecture et parsing du fichier binaire\n");

    f = fopen("custom_data.bin", "rb");
    if (f == NULL) {
        printf("   Erreur ouverture fichier\n");
        return 1;
    }

    // Lire le header
    CustomFileHeader readHeader;
    fread(&readHeader, sizeof(CustomFileHeader), 1, f);

    // Vérifier la signature (magic number)
    if (readHeader.magic != 0xDEADBEEF) {
        printf("   Erreur : signature invalide !\n");
        printf("   Attendu : 0xDEADBEEF, recu : 0x%08X\n", readHeader.magic);
        fclose(f);
        return 1;
    }

    printf("   Signature valide : 0x%08X\n", readHeader.magic);
    printf("   Version : %u\n", readHeader.version);

    // Lire les données
    DataRecord readRecord;
    fread(&readRecord, sizeof(DataRecord), 1, f);

    // Vérifier le checksum
    unsigned int calculatedChecksum = calculateChecksum(
        (unsigned char*)&readRecord,
        sizeof(DataRecord)
    );

    if (calculatedChecksum != readHeader.checksum) {
        printf("   ATTENTION : Checksum invalide !\n");
        printf("   Attendu : 0x%08X, calcule : 0x%08X\n",
               readHeader.checksum, calculatedChecksum);
    } else {
        printf("   Checksum OK : 0x%08X\n", calculatedChecksum);
    }

    printf("   Donnees lues :\n");
    printf("     Nom   : %s\n", readRecord.nom);
    printf("     Age   : %d\n", readRecord.age);
    printf("     Score : %.2f\n\n", readRecord.score);

    fclose(f);

    // -------------------------------------------------------------------------
    // EXEMPLE 3 : Hex dump d'un fichier binaire
    // -------------------------------------------------------------------------
    printf("[3] Hex dump du fichier\n");

    f = fopen("custom_data.bin", "rb");
    if (f == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // Lire tout le fichier
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    rewind(f);

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    fread(buffer, 1, fileSize, f);
    fclose(f);

    printf("   Contenu brut (%ld bytes) :\n", fileSize);
    hexDump(buffer, fileSize, 16);

    free(buffer);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 4 : Parser un PE (DOS Header) - VRAI MALDEV !
    // -------------------------------------------------------------------------
    printf("[4] Parser un DOS Header (PE maldev)\n");

    // Note : Sur Windows, tu peux analyser "C:\\Windows\\System32\\notepad.exe"
    // Pour cet exemple, on va créer un faux DOS header

    IMAGE_DOS_HEADER_SIMPLE dosHeader;
    memset(&dosHeader, 0, sizeof(dosHeader));
    dosHeader.e_magic = 0x5A4D;                  // "MZ" en little-endian
    dosHeader.e_lfanew = 0x000000E0;             // Offset vers PE header (exemple)

    // Sauvegarder dans un fichier
    f = fopen("fake_pe_header.bin", "wb");
    if (f) {
        fwrite(&dosHeader, sizeof(dosHeader), 1, f);
        fclose(f);
    }

    // Lire et parser
    f = fopen("fake_pe_header.bin", "rb");
    if (f == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    IMAGE_DOS_HEADER_SIMPLE readDosHeader;
    fread(&readDosHeader, sizeof(readDosHeader), 1, f);
    fclose(f);

    // Vérifier la signature "MZ"
    if (readDosHeader.e_magic == 0x5A4D) {
        printf("   Signature DOS valide : 'MZ' (0x%04X)\n", readDosHeader.e_magic);
        printf("   Offset PE Header : 0x%08X\n", readDosHeader.e_lfanew);
    } else {
        printf("   Signature DOS invalide : 0x%04X\n", readDosHeader.e_magic);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 5 : Lire des bytes spécifiques (pattern matching)
    // -------------------------------------------------------------------------
    printf("[5] Recherche de pattern dans un fichier binaire\n");

    // Créer un fichier avec un pattern
    unsigned char data[] = {
        0x00, 0x01, 0x02, 0x03,
        0xDE, 0xAD, 0xBE, 0xEF,  // Pattern à chercher
        0x04, 0x05, 0x06, 0x07
    };

    f = fopen("pattern_test.bin", "wb");
    if (f) {
        fwrite(data, 1, sizeof(data), f);
        fclose(f);
    }

    // Chercher le pattern 0xDEADBEEF
    f = fopen("pattern_test.bin", "rb");
    if (f == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    unsigned int pattern = 0xDEADBEEF;
    unsigned int readValue;
    int found = 0;
    long offset = 0;

    while (fread(&readValue, sizeof(unsigned int), 1, f) == 1) {
        if (readValue == pattern) {
            printf("   Pattern 0x%08X trouve a l'offset 0x%lX\n", pattern, offset);
            found = 1;
            break;
        }
        offset += sizeof(unsigned int);
    }

    if (!found) {
        printf("   Pattern non trouve\n");
    }

    fclose(f);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 6 : Modifier un fichier binaire (patching)
    // -------------------------------------------------------------------------
    printf("[6] Patcher un fichier binaire\n");

    // Ouvrir en mode lecture/écriture
    f = fopen("pattern_test.bin", "r+b");
    if (f == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // Aller à l'offset 4 (où se trouve DEADBEEF)
    fseek(f, 4, SEEK_SET);

    // Remplacer par CAFEBABE
    unsigned int newPattern = 0xCAFEBABE;
    fwrite(&newPattern, sizeof(unsigned int), 1, f);

    printf("   Pattern 0xDEADBEEF remplace par 0xCAFEBABE a l'offset 0x04\n");

    fclose(f);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 7 : Vérifier le patch
    // -------------------------------------------------------------------------
    printf("[7] Verification du patch\n");

    f = fopen("pattern_test.bin", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        rewind(f);

        unsigned char* buf = (unsigned char*)malloc(size);
        fread(buf, 1, size, f);

        printf("   Contenu apres patch :\n");
        hexDump(buf, size, 16);

        free(buf);
        fclose(f);
    }
    printf("\n");

    /*
     * =========================================================================
     * RÉSUMÉ :
     * =========================================================================
     *
     * 1. FICHIER BINAIRE :
     *    - Contient des bytes bruts, pas forcément du texte
     *    - Ouvrir avec "rb" (lecture) ou "wb" (écriture)
     *
     * 2. PARSING :
     *    - Lire les headers avec fread(&header, sizeof(header), 1, f)
     *    - Vérifier les signatures (magic numbers)
     *    - Valider avec checksum
     *
     * 3. NAVIGATION :
     *    - fseek() pour aller à un offset précis
     *    - ftell() pour connaître la position
     *
     * 4. PATTERN MATCHING :
     *    - Chercher des séquences de bytes spécifiques
     *    - Comparer avec memcmp() ou lecture directe
     *
     * 5. PATCHING :
     *    - Ouvrir en "r+b" (lecture/écriture)
     *    - fseek() vers l'offset
     *    - fwrite() pour écraser
     *
     * 6. HEX DUMP :
     *    - Afficher les bytes en hexadécimal
     *    - Essentiel pour déboguer
     *
     * =========================================================================
     */

    /*
     * =========================================================================
     * MALDEV PREVIEW :
     * =========================================================================
     *
     * En maldev, le parsing binaire est CRUCIAL :
     *
     * 1. ANALYSER UN PE :
     *    - Lire le DOS Header (signature "MZ")
     *    - Aller à e_lfanew pour trouver le PE Header
     *    - Parser les sections (.text, .data, .rdata, etc.)
     *    - Trouver le Entry Point
     *
     * 2. INJECTER DU CODE :
     *    - Trouver une cave dans le PE (espace vide)
     *    - Écrire le shellcode dans cette cave
     *    - Modifier l'Entry Point pour pointer vers le shellcode
     *    - Recalculer les checksums
     *
     * 3. PARSER UN SHELLCODE :
     *    - Identifier les opcodes
     *    - Trouver les appels à GetProcAddress
     *    - Détecter les API utilisées
     *
     * 4. HOOKING :
     *    - Lire les premiers bytes d'une fonction
     *    - Remplacer par un JMP vers notre hook
     *    - Sauvegarder les bytes originaux pour le unhook
     *
     * Exemple de code maldev réel :
     *
     *   FILE* f = fopen("target.exe", "rb");
     *   IMAGE_DOS_HEADER dosHeader;
     *   fread(&dosHeader, sizeof(dosHeader), 1, f);
     *
     *   if (dosHeader.e_magic != 0x5A4D) {
     *       printf("Pas un PE valide !\n");
     *       return 1;
     *   }
     *
     *   fseek(f, dosHeader.e_lfanew, SEEK_SET);
     *   IMAGE_NT_HEADERS ntHeaders;
     *   fread(&ntHeaders, sizeof(ntHeaders), 1, f);
     *
     *   printf("Entry Point: 0x%08X\n",
     *          ntHeaders.OptionalHeader.AddressOfEntryPoint);
     *
     * La semaine prochaine, on commence la WinAPI et le VRAI maldev !
     *
     * =========================================================================
     */

    printf("=== FIN DE LA LESSON 04 ===\n");
    return 0;
}

/*
 * =============================================================================
 * EXERCICE POUR TOI :
 * =============================================================================
 *
 * 1. Crée un fichier binaire "shellcode.bin" contenant :
 *    0x90, 0x90, 0x90 (NOP NOP NOP)
 *    0xCC (INT3 - breakpoint)
 *    0xC3 (RET)
 *
 * 2. Lis ce fichier et affiche un hex dump
 *
 * 3. Cherche l'offset du byte 0xCC
 *
 * 4. Remplace 0xCC par 0x90 (NOP)
 *
 * 5. Vérifie que le patch a réussi
 *
 * On se retrouve dans ex03-binary-header.c pour parser un vrai header maldev !
 *
 * =============================================================================
 */
