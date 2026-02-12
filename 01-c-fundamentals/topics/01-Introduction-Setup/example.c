/*
 * =============================================================================
 * Module 01 : Hello World - Exemple complet
 * =============================================================================
 *
 * PRÉREQUIS POUR COMPRENDRE CE CODE :
 * -----------------------------------
 * Si tu ne connais pas ces concepts, lis d'abord la Partie 0 de cours.md !
 *
 * - BINAIRE : Système à 2 chiffres (0,1). L'ordinateur ne comprend que ça.
 *   Exemple : 5 en binaire = 101
 *
 * - HEXADÉCIMAL : Système à 16 chiffres (0-9 puis A-F où A=10, F=15).
 *   Plus compact que le binaire. Utilisé partout en programmation système.
 *   Exemple : 255 en hexa = FF (car F=15, donc 15*16 + 15 = 255)
 *   Notation : 0xFF ou 0xff (le préfixe 0x indique "c'est de l'hexa")
 *
 * - ASCII : Table qui assigne un nombre à chaque caractère.
 *   Exemple : 'A' = 65 = 0x41, 'a' = 97 = 0x61
 *
 * - OCTET (byte) : 8 bits. Peut stocker 256 valeurs (0 à 255, ou 0x00 à 0xFF).
 *
 * Ce fichier démontre les concepts fondamentaux du Module 01 :
 * - Structure d'un programme C
 * - Utilisation de printf avec différents spécificateurs
 * - Analyse de ce qui finit dans le binaire
 *
 * Compilation :
 *   Linux/macOS : gcc example.c -o example
 *   Windows     : cl example.c /Fe:example.exe
 *
 * Analyse du binaire :
 *   strings example | grep -i "secret\|password\|connect"
 *   nm example
 *   ldd example (Linux)
 *
 * =============================================================================
 */

// stdio.h : Standard Input/Output
// Fournit printf(), scanf(), etc.
// ATTENTION : Les strings passées à printf sont visibles dans le binaire !
#include <stdio.h>

// stdint.h : Types entiers de taille fixe
// uint8_t, uint32_t, etc. - utile pour la portabilité
#include <stdint.h>


/*
 * -----------------------------------------------------------------------------
 * Fonction : afficher_infos_systeme
 * -----------------------------------------------------------------------------
 * Démontre l'utilisation des spécificateurs de format printf
 * et comment récupérer des infos sur l'environnement d'exécution.
 */
void afficher_infos_systeme(void) {
    printf("\n[*] === Informations systeme ===\n\n");

    // %zu : size_t (résultat de sizeof)
    // sizeof retourne la taille en octets d'un type
    printf("    Taille des types de base :\n");
    printf("    - char   : %zu octet(s)\n", sizeof(char));
    printf("    - short  : %zu octets\n", sizeof(short));
    printf("    - int    : %zu octets\n", sizeof(int));
    printf("    - long   : %zu octets\n", sizeof(long));
    printf("    - void*  : %zu octets (architecture %zu bits)\n",
           sizeof(void*), sizeof(void*) * 8);

    printf("\n");
}


/*
 * -----------------------------------------------------------------------------
 * Fonction : demo_formats_printf
 * -----------------------------------------------------------------------------
 * Montre les différents spécificateurs de format disponibles.
 * Ces connaissances sont essentielles pour le debugging et l'affichage
 * d'adresses mémoire lors de l'analyse de binaires.
 *
 * RAPPEL HEXADÉCIMAL (pour débutants) :
 * -------------------------------------
 * L'hexadécimal (base 16) utilise : 0-9 puis A-F (A=10, B=11, C=12, D=13, E=14, F=15)
 *
 * Pourquoi l'utiliser ?
 * - Plus compact que le binaire : FF au lieu de 11111111
 * - 1 chiffre hexa = 4 bits exactement
 * - Standard en programmation système et sécurité
 *
 * Exemples de conversion :
 *   Décimal 255 = Hexa FF = Binaire 11111111
 *   Décimal 16  = Hexa 10 = Binaire 00010000
 *   Décimal 10  = Hexa A  = Binaire 00001010
 */
void demo_formats_printf(void) {
    printf("[*] === Demonstration des formats printf ===\n\n");

    // Variables de démonstration
    // On choisit 255 car c'est la valeur max d'un octet (8 bits tous à 1)
    // En hexa : FF (F=15, donc FF = 15*16 + 15 = 255)
    int nombre = 255;

    // Les nombres négatifs utilisent le "complément à deux" en mémoire
    // On verra ça en détail dans le module sur les variables
    int negatif = -42;

    // Un caractère est stocké comme un nombre (code ASCII)
    // 'A' = 65 en décimal = 0x41 en hexa
    char caractere = 'A';

    // Une string est une suite de caractères terminée par '\0' (valeur 0)
    // "Hello" = 'H'(72) 'e'(101) 'l'(108) 'l'(108) 'o'(111) '\0'(0)
    char *chaine = "Hello";

    // Un pointeur stocke une ADRESSE MÉMOIRE
    // C'est juste un nombre qui indique OÙ se trouve une donnée en RAM
    void *pointeur = &nombre;  // &nombre = "l'adresse de nombre"

    // ==================== AFFICHAGE DES ENTIERS ====================
    printf("    Entiers :\n");

    // %d = decimal (base 10) avec signe (peut être négatif)
    printf("    - %%d (decimal signe)     : %d\n", negatif);

    // %u = decimal non signé (toujours positif, 0 à 4294967295 sur 32 bits)
    printf("    - %%u (decimal non signe) : %u\n", nombre);

    // %x = hexadécimal en minuscules
    // 255 en hexa = ff (car 15*16 + 15 = 255, et F=15)
    printf("    - %%x (hexa minuscule)    : %x\n", nombre);

    // %X = hexadécimal en MAJUSCULES (plus lisible, convention courante)
    printf("    - %%X (hexa majuscule)    : %X\n", nombre);

    // %08X = hexa sur 8 caractères, complété par des 0 à gauche
    // Utile pour afficher des adresses/valeurs de façon alignée
    // 255 = 000000FF (au lieu de juste FF)
    printf("    - %%08X (hexa, 8 chars, padding 0) : %08X\n", nombre);

    // ==================== CARACTÈRES ET STRINGS ====================
    printf("\n    Caracteres et strings :\n");

    // %c = affiche le CARACTÈRE correspondant au code ASCII
    printf("    - %%c (caractere)         : %c\n", caractere);

    // On peut passer directement le code ASCII (65 = 'A')
    // Utile pour comprendre la table ASCII
    printf("    - %%c (code ASCII 65)     : %c\n", 65);

    // %s = affiche une string (suite de caractères jusqu'au '\0')
    printf("    - %%s (string)            : %s\n", chaine);

    // ==================== POINTEURS (ADRESSES MÉMOIRE) ====================
    printf("\n    Pointeurs :\n");

    // %p = affiche une adresse mémoire en hexadécimal
    // Format typique : 0x7ffd12345678 (adresse sur 48 bits en x86_64)
    //
    // POURQUOI EN HEXA ?
    // - La RAM est organisée en octets (8 bits chacun)
    // - Chaque octet a une adresse unique
    // - L'hexa est compact : 0x7FFF vaut mieux que 32767 ou 111111111111111
    // - On peut facilement voir les limites des pages mémoire (0x1000 = 4096 octets)
    printf("    - %%p (adresse)           : %p\n", pointeur);

    // On peut aussi afficher l'adresse d'une FONCTION
    // Cela montre où le code de main() est chargé en mémoire
    // Note : les adresses changent à chaque exécution (ASLR - protection de sécurité)
    printf("    - Adresse de main()      : %p\n", (void*)&main);

    printf("\n");
}


/*
 * -----------------------------------------------------------------------------
 * Fonction : demo_strings_visibles
 * -----------------------------------------------------------------------------
 * IMPORTANT : Cette fonction illustre un problème de sécurité courant.
 *
 * Les strings littérales sont stockées dans la section .rodata du binaire
 * et sont visibles en clair avec la commande 'strings'.
 *
 * Après compilation, teste :
 *   strings example | grep -i "c2\|server\|secret"
 *
 * Tu verras ces strings apparaître en clair !
 */
void demo_strings_visibles(void) {
    printf("[*] === Probleme des strings visibles ===\n\n");

    // ATTENTION : Ces strings seront visibles dans le binaire !
    printf("    Cette string est visible : 'Connecting to C2 server...'\n");
    printf("    Celle-ci aussi : 'Password: SuperSecret123'\n");

    // Affichage du warning
    printf("\n    [!] Apres compilation, execute :\n");
    printf("        strings example | grep -iE 'c2|secret|password'\n");
    printf("        Tu verras ces strings en clair !\n");

    printf("\n");
}


/*
 * -----------------------------------------------------------------------------
 * Fonction : demo_codes_retour
 * -----------------------------------------------------------------------------
 * Les codes de retour permettent la communication entre processus.
 * Convention :
 *   0   = Succès
 *   1+  = Erreur (le numéro peut indiquer le type d'erreur)
 *
 * Utilisation en shell :
 *   ./example && echo "Succes"    # Exécute echo si example retourne 0
 *   ./example || echo "Echec"     # Exécute echo si example retourne != 0
 */
void demo_codes_retour(void) {
    printf("[*] === Codes de retour ===\n\n");

    printf("    Convention :\n");
    printf("    - return 0  : Succes (programme termine normalement)\n");
    printf("    - return 1+ : Erreur (le numero indique le type)\n");

    printf("\n    Utilisation en shell :\n");
    printf("    $ ./prog && echo 'OK'     # echo si retour = 0\n");
    printf("    $ ./prog || echo 'FAIL'   # echo si retour != 0\n");
    printf("    $ echo $?                  # Affiche le code de retour\n");

    printf("\n");
}


/*
 * -----------------------------------------------------------------------------
 * Fonction principale : main
 * -----------------------------------------------------------------------------
 * Point d'entrée CONVENTIONNEL du programme.
 *
 * Note technique :
 * Le vrai point d'entrée est _start (fourni par le CRT).
 * _start initialise l'environnement puis appelle main().
 *
 * argc : Nombre d'arguments (toujours >= 1)
 * argv : Tableau des arguments
 *        argv[0] = nom du programme
 *        argv[1] = premier argument (si présent)
 *        ...
 */
int main(int argc, char *argv[]) {

    // Banner
    printf("\n");
    printf("=============================================================\n");
    printf("  Module 01 : Hello World - Demonstration complete\n");
    printf("=============================================================\n");

    // Affichage des arguments (utile pour comprendre argc/argv)
    printf("\n[*] Arguments recus : %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("    argv[%d] = \"%s\"\n", i, argv[i]);
    }

    // Démonstrations
    afficher_infos_systeme();
    demo_formats_printf();
    demo_strings_visibles();
    demo_codes_retour();

    // Résumé
    printf("=============================================================\n");
    printf("  Fin de la demonstration\n");
    printf("=============================================================\n");

    printf("\n[*] Analyse ce binaire avec :\n");
    printf("    file example\n");
    printf("    strings example | head -20\n");
    printf("    nm example | head -20\n");
    printf("    ldd example\n\n");

    // Code de retour : 0 = succès
    // Récupérable avec : echo $? (Linux/macOS) ou echo %ERRORLEVEL% (Windows)
    return 0;
}
