/*
 * ============================================================================
 * LESSON 05 : Chaines de caracteres (Strings)
 * ============================================================================
 *
 * OBJECTIF : Manipuler les strings en C (tableaux de char)
 * PREREQUIS : Lessons 01-04
 * COMPILE  : cl 05-strings.c
 *
 * ============================================================================
 * CONCEPT CLE :
 *
 * En C, une string n'est PAS un type special.
 * C'est juste un TABLEAU DE CHAR termine par '\0' (null terminator).
 *
 * "Hello" = {'H', 'e', 'l', 'l', 'o', '\0'}
 *
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>  // Pour strlen, strcpy, strcmp, etc.
#include <stdlib.h>  // Pour malloc

int main()
{
    printf("=== STRINGS EN C ===\n\n");

    // ========================================================================
    // PARTIE 1 : DECLARATION DE STRINGS
    // ========================================================================

    printf("--- PARTIE 1 : Declaration ---\n\n");

    // Methode 1 : Tableau de char avec initialisation
    char str1[] = "Hello";  // Taille automatique (6 avec '\0')

    // Methode 2 : Tableau explicite
    char str2[10] = "World";  // 10 bytes reserves, 6 utilises

    // Methode 3 : Pointeur vers string litterale (LECTURE SEULE !)
    const char* str3 = "ReadOnly";  // Pointe vers zone memoire constante

    // Methode 4 : Caractere par caractere
    char str4[6];
    str4[0] = 'M';
    str4[1] = 'a';
    str4[2] = 'n';
    str4[3] = 'u';
    str4[4] = 'a';
    str4[5] = 'l';
    // OUBLI DU '\0' = PROBLEME !

    printf("str1 = \"%s\" (taille tableau = %zu)\n", str1, sizeof(str1));
    printf("str2 = \"%s\" (taille tableau = %zu)\n", str2, sizeof(str2));
    printf("str3 = \"%s\"\n", str3);
    // str4 sans '\0' = affichage aleatoire, ne pas afficher


    // ========================================================================
    // PARTIE 2 : LE NULL TERMINATOR '\0'
    // ========================================================================

    printf("\n--- PARTIE 2 : Null terminator ---\n\n");

    char demo[] = "ABC";

    printf("String : \"%s\"\n", demo);
    printf("Bytes  : ");

    for (int i = 0; i <= 3; i++)  // Inclut le '\0'
    {
        if (demo[i] == '\0')
            printf("'\\0' ");
        else
            printf("'%c' ", demo[i]);
    }
    printf("\n");

    printf("Codes ASCII : ");
    for (int i = 0; i <= 3; i++)
    {
        printf("%d ", demo[i]);
    }
    printf("\n");

    // '\0' = caractere NULL = valeur 0
    // C'est ce qui permet aux fonctions de savoir ou la string finit


    // ========================================================================
    // PARTIE 3 : FONCTIONS DE STRING.H
    // ========================================================================

    printf("\n--- PARTIE 3 : Fonctions string.h ---\n\n");

    char source[] = "Hello World";
    char dest[50];

    // strlen : longueur (sans le '\0')
    printf("strlen(\"%s\") = %zu\n", source, strlen(source));

    // strcpy : copie
    strcpy(dest, source);
    printf("strcpy : dest = \"%s\"\n", dest);

    // strcat : concatenation
    strcat(dest, " !");
    printf("strcat : dest = \"%s\"\n", dest);

    // strcmp : comparaison (0 si egal)
    printf("strcmp(\"abc\", \"abc\") = %d (egal)\n", strcmp("abc", "abc"));
    printf("strcmp(\"abc\", \"abd\") = %d (different)\n", strcmp("abc", "abd"));

    // strchr : chercher un caractere
    char* found = strchr(source, 'W');
    if (found)
        printf("strchr : 'W' trouve a position %td\n", found - source);

    // strstr : chercher une sous-chaine
    char* sub = strstr(source, "World");
    if (sub)
        printf("strstr : \"World\" trouve a position %td\n", sub - source);


    // ========================================================================
    // PARTIE 4 : STRINGS ET POINTEURS
    // ========================================================================

    printf("\n--- PARTIE 4 : Strings et pointeurs ---\n\n");

    char message[] = "Pointer";
    char* ptr = message;

    printf("message = \"%s\"\n", message);
    printf("ptr     = \"%s\"\n", ptr);

    // Parcourir avec pointeur
    printf("Caracteres : ");
    while (*ptr != '\0')
    {
        printf("%c ", *ptr);
        ptr++;
    }
    printf("\n");


    // ========================================================================
    // PARTIE 5 : ALLOCATION DYNAMIQUE DE STRINGS
    // ========================================================================

    printf("\n--- PARTIE 5 : Strings dynamiques ---\n\n");

    // Allouer une string dynamiquement
    char* dynamic = malloc(20);
    if (dynamic == NULL)
    {
        printf("Allocation failed\n");
        return 1;
    }

    strcpy(dynamic, "Dynamic string");
    printf("dynamic = \"%s\"\n", dynamic);

    // strdup : duplique une string (malloc + strcpy)
    char* copie = strdup("Duplicated");
    printf("copie   = \"%s\"\n", copie);

    free(dynamic);
    free(copie);


    // ========================================================================
    // PARTIE 6 : MANIPULATION CARACTERE PAR CARACTERE
    // ========================================================================

    printf("\n--- PARTIE 6 : Manipulation ---\n\n");

    char texte[] = "hello world";

    // Convertir en majuscules (ASCII : 'a'-'z' = 97-122, 'A'-'Z' = 65-90)
    printf("Original   : \"%s\"\n", texte);

    for (int i = 0; texte[i] != '\0'; i++)
    {
        if (texte[i] >= 'a' && texte[i] <= 'z')
        {
            texte[i] = texte[i] - 32;  // Convertit en majuscule
        }
    }

    printf("Majuscules : \"%s\"\n", texte);


    // ========================================================================
    // PARTIE 7 : MALDEV - XOR SUR STRING
    // ========================================================================

    printf("\n--- PARTIE 7 : XOR (maldev) ---\n\n");

    // Les malwares cachent les strings avec XOR
    char secret[] = "cmd.exe";
    char key = 0x41;  // Cle XOR

    printf("Original : \"%s\"\n", secret);

    // Chiffrer
    for (int i = 0; secret[i] != '\0'; i++)
    {
        secret[i] ^= key;
    }

    printf("XOR 0x%02X : \"", key);
    for (int i = 0; i < 7; i++)
    {
        printf("\\x%02X", (unsigned char)secret[i]);
    }
    printf("\"\n");

    // Dechiffrer (XOR est reversible)
    for (int i = 0; secret[i] != '\0'; i++)
    {
        secret[i] ^= key;
    }

    printf("Dechiffre: \"%s\"\n", secret);


    return 0;
}

/*
 * ============================================================================
 * RESUME :
 *
 * String = tableau de char termine par '\0'
 *
 * FONCTIONS UTILES :
 *   strlen(s)        -> longueur (sans '\0')
 *   strcpy(d, s)     -> copie s dans d
 *   strcat(d, s)     -> concatene s a la fin de d
 *   strcmp(a, b)     -> compare (0 si egal)
 *   strchr(s, c)     -> cherche caractere c
 *   strstr(s, sub)   -> cherche sous-chaine
 *   strdup(s)        -> duplique (malloc + strcpy)
 *
 * SECURITE :
 *   Preferer strncpy, strncat (avec limite) pour eviter buffer overflow
 *
 * ============================================================================
 * MALDEV USAGE :
 *
 * 1. Cacher des strings (API names, URLs, paths) :
 *    - XOR encoding
 *    - Stack strings (construction caractere par caractere)
 *    - Chiffrement RC4/AES
 *
 * 2. Parser des reponses C2 :
 *    char* cmd = strstr(response, "COMMAND:");
 *
 * 3. Construire des paths dynamiquement :
 *    char path[MAX_PATH];
 *    sprintf(path, "%s\\malware.exe", temp_dir);
 *
 * ============================================================================
 */
