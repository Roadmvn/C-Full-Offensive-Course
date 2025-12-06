==============================================
  MODULE 09 - STRINGS - SOLUTIONS
==============================================

Exercice 1 : Longueur
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char text[] = "Cybersecurity";
    int len = strlen(text);
    printf("Longueur : %d\n", len);  // 13
    return 0;
}


Exercice 2 : Copie
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char src[] = "Hello";
    char dst[20];

    strcpy(dst, src);
    printf("dst : %s\n", dst);  // "Hello"
    return 0;
}


Exercice 3 : Concaténation
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char str1[50] = "Red";
    char str2[] = "Team";

    strcat(str1, str2);
    printf("Résultat : %s\n", str1);  // "RedTeam"
    return 0;
}


Exercice 4 : Comparaison
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char pass1[] = "admin";
    char pass2[] = "admin";

    if (strcmp(pass1, pass2) == 0) {
        printf("Identiques\n");
    } else {
        printf("Différentes\n");
    }
    return 0;
}


Exercice 5 : Recherche de caractère
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char email[] = "hacker@domain.com";
    char* pos = strchr(email, '@');

    if (pos != NULL) {
        int index = pos - email;
        printf("Position de '@' : %d\n", index);  // 6
    }
    return 0;
}


Exercice 6 : Recherche de sous-chaîne
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char url[] = "https://example.com/admin/panel";
    char* found = strstr(url, "admin");

    if (found != NULL) {
        printf("Trouvé\n");
    } else {
        printf("Non trouvé\n");
    }
    return 0;
}


Exercice 7 : Compter les occurrences
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char text[] = "banana";
    char target = 'a';
    int count = 0;

    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] == target) {
            count++;
        }
    }

    printf("Occurrences de '%c' : %d\n", target, count);  // 3
    return 0;
}


Exercice 8 : Inverser une string
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char word[] = "Reverse";
    int len = strlen(word);

    printf("Avant : %s\n", word);

    // Inversion
    for (int i = 0; i < len / 2; i++) {
        char temp = word[i];
        word[i] = word[len - 1 - i];
        word[len - 1 - i] = temp;
    }

    printf("Après : %s\n", word);  // "esreveR"
    return 0;
}

==============================================
  NOTES :
  - String = tableau de char terminé par \0
  - strcmp() pour comparer (pas ==)
  - strcpy() pour copier (pas =)
  - strlen() retourne la longueur SANS \0
  - Attention aux buffer overflows (utiliser strncpy, strncat)
==============================================
