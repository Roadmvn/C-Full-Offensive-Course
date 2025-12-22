/*
 * =============================================================================
 * SEMAINE 3 - LESSON 03 : FILE I/O (ENTRÉES/SORTIES FICHIERS)
 * =============================================================================
 *
 * OBJECTIF :
 *   Apprendre à lire et écrire des fichiers en C.
 *   En maldev, on lit/écrit des fichiers pour :
 *   - Charger des shellcodes depuis un fichier
 *   - Modifier des executables (PE patching)
 *   - Écrire des logs, exfiltrer des données
 *
 * PRE-REQUIS :
 *   - Structures (Lesson 01)
 *   - Pointeurs (Week 2)
 *
 * COMPILATION :
 *   cl 03-file-io.c
 *   .\03-file-io.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * =============================================================================
 * ANALOGIE : C'est quoi le File I/O ?
 * =============================================================================
 *
 * Imagine que tu veux lire un LIVRE :
 *   1. Tu OUVRES le livre (fopen)
 *   2. Tu LIS les pages (fread / fgets)
 *   3. Tu FERMES le livre quand tu as fini (fclose)
 *
 * Pour ÉCRIRE dans un cahier :
 *   1. Tu OUVRES le cahier (fopen avec mode "w")
 *   2. Tu ÉCRIS dedans (fwrite / fprintf)
 *   3. Tu FERMES le cahier (fclose)
 *
 * En maldev :
 *   - On ouvre un .exe pour analyser son header PE
 *   - On écrit un shellcode dans un fichier pour le tester
 *   - On lit un fichier de configuration pour le C2
 *
 * =============================================================================
 */

/*
 * =============================================================================
 * PARTIE 1 : LES MODES D'OUVERTURE
 * =============================================================================
 */

/*
 * MODE        DESCRIPTION
 * ----        -----------
 * "r"         Lecture seule (fichier doit exister)
 * "w"         Écriture (crée ou ÉCRASE le fichier)
 * "a"         Ajout à la fin (append)
 * "r+"        Lecture + écriture (fichier doit exister)
 * "w+"        Lecture + écriture (crée ou écrase)
 * "rb"        Lecture binaire
 * "wb"        Écriture binaire
 * "ab"        Ajout binaire
 */

/*
 * =============================================================================
 * PARTIE 2 : FONCTIONS PRINCIPALES
 * =============================================================================
 */

/*
 * fopen()    : Ouvre un fichier, retourne FILE* (ou NULL si erreur)
 * fclose()   : Ferme un fichier
 * fread()    : Lit des données binaires
 * fwrite()   : Écrit des données binaires
 * fgets()    : Lit une ligne de texte
 * fprintf()  : Écrit du texte formaté
 * fseek()    : Déplace le curseur dans le fichier
 * ftell()    : Retourne la position actuelle
 * rewind()   : Retourne au début
 */

/*
 * =============================================================================
 * FONCTION MAIN : EXEMPLES PRATIQUES
 * =============================================================================
 */

int main() {
    printf("=== SEMAINE 3 - LESSON 03 : FILE I/O ===\n\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 1 : Écrire du texte dans un fichier
    // -------------------------------------------------------------------------
    printf("[1] Ecriture texte dans un fichier\n");

    FILE* fichier = fopen("test_output.txt", "w");  // Mode "w" = write

    if (fichier == NULL) {                          // TOUJOURS vérifier !
        printf("   Erreur : impossible d'ouvrir le fichier !\n");
        return 1;
    }

    // Écrire avec fprintf (comme printf, mais dans un fichier)
    fprintf(fichier, "Bonjour depuis le code C !\n");
    fprintf(fichier, "Ligne 2 : nombre = %d\n", 42);
    fprintf(fichier, "Ligne 3 : maldev = %s\n", "awesome");

    fclose(fichier);                                // Toujours fermer !
    printf("   Fichier 'test_output.txt' cree avec succes\n\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 2 : Lire du texte ligne par ligne
    // -------------------------------------------------------------------------
    printf("[2] Lecture texte ligne par ligne\n");

    fichier = fopen("test_output.txt", "r");        // Mode "r" = read

    if (fichier == NULL) {
        printf("   Erreur : fichier introuvable !\n");
        return 1;
    }

    char ligne[256];
    int numeroLigne = 1;

    // fgets() lit UNE ligne (jusqu'au \n ou EOF)
    while (fgets(ligne, sizeof(ligne), fichier) != NULL) {
        printf("   [%d] %s", numeroLigne, ligne);   // ligne contient déjà \n
        numeroLigne++;
    }

    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 3 : Écrire des données binaires (tableau d'entiers)
    // -------------------------------------------------------------------------
    printf("[3] Ecriture binaire (tableau d'entiers)\n");

    int nombres[5] = {10, 20, 30, 40, 50};

    fichier = fopen("numbers.bin", "wb");           // Mode "wb" = write binary

    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // fwrite(données, taille_élément, nombre_éléments, fichier)
    size_t written = fwrite(nombres, sizeof(int), 5, fichier);
    printf("   %zu elements ecrits dans 'numbers.bin'\n", written);

    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 4 : Lire des données binaires
    // -------------------------------------------------------------------------
    printf("[4] Lecture binaire (tableau d'entiers)\n");

    int nombresLus[5] = {0};

    fichier = fopen("numbers.bin", "rb");           // Mode "rb" = read binary

    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // fread(buffer, taille_élément, nombre_éléments, fichier)
    size_t read_count = fread(nombresLus, sizeof(int), 5, fichier);
    printf("   %zu elements lus\n", read_count);

    for (int i = 0; i < 5; i++) {
        printf("   [%d] = %d\n", i, nombresLus[i]);
    }

    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 5 : Obtenir la taille d'un fichier
    // -------------------------------------------------------------------------
    printf("[5] Obtenir la taille d'un fichier\n");

    fichier = fopen("numbers.bin", "rb");

    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // Aller à la fin du fichier
    fseek(fichier, 0, SEEK_END);

    // Obtenir la position = taille du fichier
    long tailleFichier = ftell(fichier);
    printf("   Taille de 'numbers.bin' : %ld bytes\n", tailleFichier);

    // Retourner au début
    rewind(fichier);                                // Équivalent à fseek(fichier, 0, SEEK_SET)

    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 6 : Lire tout un fichier en mémoire (pattern maldev)
    // -------------------------------------------------------------------------
    printf("[6] Lire tout un fichier en memoire\n");

    fichier = fopen("test_output.txt", "rb");

    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // 1. Obtenir la taille
    fseek(fichier, 0, SEEK_END);
    long fileSize = ftell(fichier);
    rewind(fichier);

    // 2. Allouer un buffer de la bonne taille
    char* buffer = (char*)malloc(fileSize + 1);     // +1 pour le \0
    if (buffer == NULL) {
        printf("   Erreur allocation memoire\n");
        fclose(fichier);
        return 1;
    }

    // 3. Lire tout le fichier d'un coup
    size_t bytesRead = fread(buffer, 1, fileSize, fichier);
    buffer[bytesRead] = '\0';                       // Terminer la string

    printf("   Contenu complet (%ld bytes) :\n", fileSize);
    printf("---\n%s---\n", buffer);

    // 4. Libérer la mémoire
    free(buffer);
    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 7 : Écrire une structure dans un fichier
    // -------------------------------------------------------------------------
    printf("[7] Ecrire une structure dans un fichier\n");

    typedef struct {
        char nom[50];
        int age;
        float taille;
    } Personne;

    Personne alice = {"Alice", 25, 1.65f};

    fichier = fopen("personne.bin", "wb");
    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    // Écrire TOUTE la structure d'un coup
    fwrite(&alice, sizeof(Personne), 1, fichier);
    printf("   Structure 'Personne' ecrite dans 'personne.bin'\n");

    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 8 : Lire une structure depuis un fichier
    // -------------------------------------------------------------------------
    printf("[8] Lire une structure depuis un fichier\n");

    Personne personneLue = {0};

    fichier = fopen("personne.bin", "rb");
    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    fread(&personneLue, sizeof(Personne), 1, fichier);

    printf("   Nom    : %s\n", personneLue.nom);
    printf("   Age    : %d\n", personneLue.age);
    printf("   Taille : %.2f\n", personneLue.taille);

    fclose(fichier);
    printf("\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 9 : Append (ajouter à la fin)
    // -------------------------------------------------------------------------
    printf("[9] Append - ajouter a la fin d'un fichier\n");

    fichier = fopen("test_output.txt", "a");        // Mode "a" = append
    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    fprintf(fichier, "Ligne ajoutee avec append\n");
    fclose(fichier);
    printf("   Ligne ajoutee a 'test_output.txt'\n\n");

    // -------------------------------------------------------------------------
    // EXEMPLE 10 : fseek pour naviguer dans un fichier
    // -------------------------------------------------------------------------
    printf("[10] Navigation avec fseek\n");

    fichier = fopen("numbers.bin", "rb");
    if (fichier == NULL) {
        printf("   Erreur ouverture\n");
        return 1;
    }

    int value;

    // Lire le 3ème entier (index 2)
    fseek(fichier, 2 * sizeof(int), SEEK_SET);      // Position = 2 * 4 bytes
    fread(&value, sizeof(int), 1, fichier);
    printf("   Element [2] = %d\n", value);

    // Lire le dernier entier
    fseek(fichier, -sizeof(int), SEEK_END);         // -4 bytes depuis la fin
    fread(&value, sizeof(int), 1, fichier);
    printf("   Dernier element = %d\n", value);

    fclose(fichier);
    printf("\n");

    /*
     * =========================================================================
     * RÉSUMÉ :
     * =========================================================================
     *
     * 1. OUVRIR UN FICHIER :
     *    FILE* f = fopen("nom.txt", "mode");
     *    TOUJOURS vérifier si f != NULL !
     *
     * 2. MODES :
     *    "r"  = lecture texte
     *    "w"  = écriture texte (écrase)
     *    "a"  = ajout texte
     *    "rb" = lecture binaire
     *    "wb" = écriture binaire
     *
     * 3. LECTURE :
     *    - fread() pour binaire
     *    - fgets() pour texte ligne par ligne
     *
     * 4. ÉCRITURE :
     *    - fwrite() pour binaire
     *    - fprintf() pour texte formaté
     *
     * 5. NAVIGATION :
     *    - fseek() pour se déplacer
     *    - ftell() pour connaître la position
     *    - rewind() pour retourner au début
     *
     * 6. FERMER :
     *    fclose(f); TOUJOURS !
     *
     * =========================================================================
     */

    /*
     * =========================================================================
     * MALDEV PREVIEW :
     * =========================================================================
     *
     * En maldev, on utilise File I/O pour :
     *
     * 1. CHARGER UN SHELLCODE :
     *    FILE* f = fopen("shellcode.bin", "rb");
     *    fseek(f, 0, SEEK_END);
     *    size_t size = ftell(f);
     *    rewind(f);
     *    unsigned char* shellcode = malloc(size);
     *    fread(shellcode, 1, size, f);
     *    fclose(f);
     *
     * 2. ANALYSER UN PE :
     *    FILE* f = fopen("notepad.exe", "rb");
     *    IMAGE_DOS_HEADER dosHeader;
     *    fread(&dosHeader, sizeof(dosHeader), 1, f);
     *    if (dosHeader.e_magic != 0x5A4D) {  // "MZ"
     *        printf("Pas un PE valide !\n");
     *    }
     *
     * 3. EXFILTRER DES DONNÉES :
     *    FILE* f = fopen("credentials.txt", "a");
     *    fprintf(f, "User: %s, Pass: %s\n", user, pass);
     *    fclose(f);
     *
     * 4. PATCHER UN EXÉCUTABLE :
     *    FILE* f = fopen("target.exe", "r+b");
     *    fseek(f, offset_entrypoint, SEEK_SET);
     *    fwrite(patch, 1, patchSize, f);
     *    fclose(f);
     *
     * ATTENTION : En vrai maldev, on utilise souvent les API Windows natives :
     *   - CreateFile() au lieu de fopen()
     *   - ReadFile() au lieu de fread()
     *   - WriteFile() au lieu de fwrite()
     *
     * Mais le principe reste le MÊME !
     *
     * Prochaine leçon : Fichiers binaires et parsing (PE headers !) !
     *
     * =========================================================================
     */

    printf("=== FIN DE LA LESSON 03 ===\n");
    return 0;
}

/*
 * =============================================================================
 * EXERCICE POUR TOI :
 * =============================================================================
 *
 * 1. Crée un fichier "users.txt" avec 3 lignes :
 *    alice:password123
 *    bob:secret456
 *    charlie:qwerty789
 *
 * 2. Lis le fichier ligne par ligne
 *
 * 3. Pour chaque ligne, sépare le nom et le mot de passe (strchr ou strtok)
 *
 * 4. Affiche : "User: alice, Password: password123"
 *
 * 5. Écris les résultats dans "users_parsed.txt"
 *
 * On se retrouve dans ex02-config-parser.c pour pratiquer ça !
 *
 * =============================================================================
 */
