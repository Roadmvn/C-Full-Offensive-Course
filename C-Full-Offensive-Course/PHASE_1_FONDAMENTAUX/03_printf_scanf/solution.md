==============================================
  MODULE 03 - PRINTF ET SCANF - SOLUTIONS
==============================================

✓ Exercice 1 : Formatage basique
------------------------------
#include <stdio.h>

int main() {
    int num = 255;

    printf("Décimal : %d\n", num);
    printf("Hexa    : 0x%X\n", num);
    printf("Octal   : %o\n", num);

    return 0;
}


✓ Exercice 2 : Largeur et padding
------------------------------
#include <stdio.h>

int main() {
    int num = 42;

    printf("Aligné droite : %10d\n", num);   // "        42"
    printf("Aligné gauche : %-10d\n", num);  // "42        "
    printf("Padding 0     : %05d\n", num);   // "00042"

    return 0;
}


✓ Exercice 3 : Précision des floats
------------------------------
#include <stdio.h>

int main() {
    float price = 19.99;

    printf("0 décimale  : %.0f\n", price);  // 20
    printf("1 décimale  : %.1f\n", price);  // 20.0
    printf("3 décimales : %.3f\n", price);  // 19.990

    return 0;
}


✓ Exercice 4 : Lecture d'un entier
------------------------------
#include <stdio.h>

int main() {
    int port;

    printf("Entre un port : ");
    scanf("%d", &port);

    printf("Port choisi : %d (0x%X en hexa)\n", port, port);

    return 0;
}


✓ Exercice 5 : Lecture de plusieurs valeurs
------------------------------
#include <stdio.h>

int main() {
    int x, y, z;

    printf("Entre 3 nombres (séparés par des espaces) : ");
    scanf("%d %d %d", &x, &y, &z);

    int somme = x + y + z;
    printf("Somme : %d + %d + %d = %d\n", x, y, z, somme);

    return 0;
}


✓ Exercice 6 : fgets() sécurisé
------------------------------
#include <stdio.h>
#include <string.h>

int main() {
    char nom[21];  // 20 caractères + \0

    printf("Entre ton nom (max 20 car) : ");
    fgets(nom, sizeof(nom), stdin);

    // Enlève le '\n' à la fin
    nom[strcspn(nom, "\n")] = 0;

    printf("Bienvenue, %s !\n", nom);

    return 0;
}

Note : fgets() inclut le '\n' dans le buffer, il faut le retirer.
strcspn(nom, "\n") trouve la position du '\n' et le remplace par '\0'.


✓ Exercice 7 : Shellcode display
------------------------------
#include <stdio.h>

int main() {
    unsigned char payload[] = {0x48, 0x31, 0xDB, 0xCC};

    printf("Shellcode : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02X", payload[i]);
    }
    printf("\n");

    return 0;
}

Résultat : Shellcode : \x48\x31\xDB\xCC


✓ Exercice 8 : Calculateur interactif
------------------------------
#include <stdio.h>

int main() {
    int a, b;
    char op;

    printf("Entre le premier nombre : ");
    scanf("%d", &a);

    printf("Entre le second nombre : ");
    scanf("%d", &b);

    // Nettoyage du buffer
    while (getchar() != '\n');

    printf("Entre l'opérateur (+, -, *, /) : ");
    scanf("%c", &op);

    printf("Résultat : ");

    if (op == '+') {
        printf("%d + %d = %d\n", a, b, a + b);
    } else if (op == '-') {
        printf("%d - %d = %d\n", a, b, a - b);
    } else if (op == '*') {
        printf("%d * %d = %d\n", a, b, a * b);
    } else if (op == '/') {
        if (b != 0) {
            printf("%d / %d = %d\n", a, b, a / b);
        } else {
            printf("Erreur : division par zéro\n");
        }
    } else {
        printf("Opérateur invalide\n");
    }

    return 0;
}

Note : On nettoie le buffer avec while(getchar() != '\n'); avant de lire
le caractère, sinon scanf() pourrait lire le '\n' restant.


==============================================
  POINTS CLÉS
==============================================

1. printf() :
   - %d, %x, %f, %s, %c, %p
   - Modificateurs : %10d, %-10d, %05d, %.2f

2. scanf() :
   - TOUJOURS utiliser & devant la variable (sauf tableaux)
   - scanf("%s", ...) est DANGEREUX (buffer overflow)

3. fgets() :
   - Plus sûr que scanf() pour les strings
   - Limite la taille de l'input
   - Inclut le '\n', il faut le retirer

4. Nettoyage du buffer :
   - while (getchar() != '\n'); après un scanf()
   - Évite les problèmes de '\n' restants

5. Sécurité :
   - Toujours limiter la taille des inputs
   - Valider les données utilisateur
   - Jamais printf(user_input) → format string attack !

==============================================
