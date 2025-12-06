#include <stdio.h>
#include <string.h>

/*
 * Programme : Strings (Chaînes de caractères)
 * Description : Démonstration des manipulations de strings
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== STRINGS EN C ===\n\n");

    // 1. Déclaration et initialisation
    printf("1. Déclaration et initialisation\n");
    char str1[] = "Hello";
    char str2[20] = "World";
    char* str3 = "Pointer";

    printf("   str1 : %s\n", str1);
    printf("   str2 : %s\n", str2);
    printf("   str3 : %s\n\n", str3);

    // 2. Accès caractère par caractère
    printf("2. Accès caractère par caractère\n");
    char name[] = "Alice";
    printf("   name[0] = %c\n", name[0]);  // 'A'
    printf("   name[4] = %c\n", name[4]);  // 'e'
    printf("   name[5] = %d (null terminator)\n\n", name[5]);  // 0

    // 3. Affichage caractère par caractère
    printf("3. Affichage caractère par caractère\n   ");
    for (int i = 0; name[i] != '\0'; i++) {
        printf("%c ", name[i]);
    }
    printf("\n\n");

    // 4. Longueur avec strlen
    printf("4. Longueur avec strlen\n");
    char text[] = "Hello World";
    int len = strlen(text);
    printf("   \"%s\" a %d caractères\n", text, len);
    printf("   sizeof : %lu bytes (avec \\0)\n\n", sizeof(text));

    // 5. Copier une string (strcpy)
    printf("5. Copier avec strcpy\n");
    char src[] = "Linux";
    char dst[20];

    strcpy(dst, src);
    printf("   Source : %s\n", src);
    printf("   Copie  : %s\n\n", dst);

    // 6. Copie sécurisée (strncpy)
    printf("6. Copie sécurisée avec strncpy\n");
    char buffer[10];
    strncpy(buffer, "VeryLongString", sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Force null terminator
    printf("   Copie tronquée : %s\n\n", buffer);

    // 7. Concaténer (strcat)
    printf("7. Concaténation avec strcat\n");
    char greeting[50] = "Hello";
    char addition[] = " World";

    strcat(greeting, addition);
    printf("   Résultat : %s\n\n", greeting);

    // 8. Comparer des strings (strcmp)
    printf("8. Comparaison avec strcmp\n");
    char pass1[] = "admin123";
    char pass2[] = "admin123";
    char pass3[] = "user456";

    if (strcmp(pass1, pass2) == 0) {
        printf("   pass1 == pass2 : Identiques\n");
    }

    if (strcmp(pass1, pass3) != 0) {
        printf("   pass1 != pass3 : Différentes\n\n");
    }

    // 9. Rechercher un caractère (strchr)
    printf("9. Rechercher un caractère avec strchr\n");
    char email[] = "user@domain.com";
    char* at = strchr(email, '@');

    if (at != NULL) {
        printf("   Trouvé '@' à la position : %ld\n", at - email);
        printf("   Domaine : %s\n\n", at + 1);
    }

    // 10. Rechercher une sous-chaîne (strstr)
    printf("10. Rechercher une sous-chaîne avec strstr\n");
    char url[] = "https://example.com/admin/login";
    char* admin = strstr(url, "admin");

    if (admin != NULL) {
        printf("   'admin' trouvé : %s\n\n", admin);
    }

    // 11. Convertir en majuscules (manuel)
    printf("11. Conversion en majuscules\n");
    char lower[] = "hello";
    printf("   Avant : %s\n", lower);

    for (int i = 0; lower[i] != '\0'; i++) {
        if (lower[i] >= 'a' && lower[i] <= 'z') {
            lower[i] = lower[i] - 32;  // ou lower[i] - ('a' - 'A')
        }
    }

    printf("   Après : %s\n\n", lower);

    // 12. Compter les occurrences
    printf("12. Compter les occurrences\n");
    char sentence[] = "hello world hello";
    char target = 'l';
    int count = 0;

    for (int i = 0; sentence[i] != '\0'; i++) {
        if (sentence[i] == target) {
            count++;
        }
    }

    printf("   Occurrences de '%c' : %d\n\n", target, count);

    // 13. Inverser une string
    printf("13. Inverser une string\n");
    char reverse[] = "Hello";
    int reverse_len = strlen(reverse);

    printf("   Avant : %s\n", reverse);

    for (int i = 0; i < reverse_len / 2; i++) {
        char temp = reverse[i];
        reverse[i] = reverse[reverse_len - 1 - i];
        reverse[reverse_len - 1 - i] = temp;
    }

    printf("   Après : %s\n\n", reverse);

    // 14. Initialiser avec memset
    printf("14. Initialiser avec memset\n");
    char buf[10];
    memset(buf, 'A', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("   Buffer : %s\n\n", buf);

    // 15. Exemple Red Team : Parser une commande
    printf("15. Red Team : Parser une commande\n");
    char command[] = "GET /admin/login HTTP/1.1";
    char* method = strtok(command, " ");
    char* path = strtok(NULL, " ");
    char* protocol = strtok(NULL, " ");

    printf("   Méthode  : %s\n", method);
    printf("   Chemin   : %s\n", path);
    printf("   Protocole: %s\n\n", protocol);

    // 16. Exemple Red Team : Validation basique
    printf("16. Red Team : Validation de payload\n");
    char payload[] = "<?php system($_GET['cmd']); ?>";

    if (strstr(payload, "<?php") != NULL) {
        printf("   [!] PHP code détecté dans le payload!\n");
    }

    if (strstr(payload, "system") != NULL) {
        printf("   [!] Fonction 'system' détectée!\n");
    }

    printf("\n[+] Programme terminé avec succès.\n");
    return 0;
}
