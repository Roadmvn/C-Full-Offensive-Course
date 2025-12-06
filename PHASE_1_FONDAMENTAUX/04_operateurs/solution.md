==============================================
  MODULE 04 - OPÉRATEURS - SOLUTIONS
==============================================

✓ Exercice 1 : Arithmétique de base
------------------------------
#include <stdio.h>

int main() {
    int a = 15, b = 4;

    printf("a + b = %d\n", a + b);  // 19
    printf("a - b = %d\n", a - b);  // 11
    printf("a * b = %d\n", a * b);  // 60
    printf("a / b = %d\n", a / b);  // 3 (division entière)
    printf("a %% b = %d\n", a % b);  // 3 (reste)

    return 0;
}


✓ Exercice 2 : Division entière vs flottante
------------------------------
#include <stdio.h>

int main() {
    int x = 7, y = 2;

    printf("Division entière  : %d\n", x / y);           // 3
    printf("Division flottante: %.2f\n", (float)x / y);  // 3.50

    return 0;
}


✓ Exercice 3 : Pré vs Post incrémentation
------------------------------
#include <stdio.h>

int main() {
    int counter = 10;

    printf("counter = %d\n", counter);           // 10
    printf("counter++ = %d\n", counter++);       // 10 (retourne PUIS incrémente)
    printf("counter après = %d\n", counter);     // 11
    printf("++counter = %d\n", ++counter);       // 12 (incrémente PUIS retourne)
    printf("counter après = %d\n", counter);     // 12

    return 0;
}


✓ Exercice 4 : Comparaisons
------------------------------
#include <stdio.h>

int main() {
    int a, b;

    printf("Entre le premier nombre : ");
    scanf("%d", &a);

    printf("Entre le second nombre : ");
    scanf("%d", &b);

    if (a > b) {
        printf("Le premier (%d) est plus grand\n", a);
    } else if (b > a) {
        printf("Le second (%d) est plus grand\n", b);
    } else {
        printf("Les deux nombres sont égaux\n");
    }

    return 0;
}


✓ Exercice 5 : Logique AND/OR
------------------------------
#include <stdio.h>

int main() {
    int age;

    printf("Entre ton âge : ");
    scanf("%d", &age);

    if (age >= 18 && age <= 65) {
        printf("Tu es dans la tranche 18-65 ans\n");
    }

    if (age < 18 || age > 65) {
        printf("Tu es hors de la tranche 18-65 ans\n");
    }

    return 0;
}


✓ Exercice 6 : Opérateurs composés
------------------------------
#include <stdio.h>

int main() {
    int score = 100;

    printf("Score initial : %d\n", score);

    score += 50;
    printf("Après += 50   : %d\n", score);  // 150

    score *= 2;
    printf("Après *= 2    : %d\n", score);  // 300

    score /= 3;
    printf("Après /= 3    : %d\n", score);  // 100

    score %= 10;
    printf("Après %%= 10   : %d\n", score);  // 0

    return 0;
}


✓ Exercice 7 : Ternaire
------------------------------
#include <stdio.h>

int main() {
    int num;

    printf("Entre un nombre : ");
    scanf("%d", &num);

    // Utilisation de l'opérateur ternaire
    char* result = (num % 2 == 0) ? "pair" : "impair";

    printf("Le nombre est %s\n", result);

    return 0;
}

// Alternative sans ternaire :
#include <stdio.h>

int main() {
    int num;
    printf("Entre un nombre : ");
    scanf("%d", &num);

    if (num % 2 == 0) {
        printf("Le nombre est pair\n");
    } else {
        printf("Le nombre est impair\n");
    }

    return 0;
}


✓ Exercice 8 : Calcul d'offset (style offensif)
------------------------------
#include <stdio.h>

int main() {
    unsigned int base_addr = 0x00400000;
    unsigned int offset = 0x1234;

    unsigned int final_addr = base_addr + offset;
    unsigned int page_number = offset / 4096;      // 4096 = 0x1000
    unsigned int offset_in_page = offset % 4096;

    printf("Base address      : 0x%08X\n", base_addr);
    printf("Offset            : 0x%08X\n", offset);
    printf("Final address     : 0x%08X\n", final_addr);
    printf("Page number       : %u\n", page_number);
    printf("Offset in page    : 0x%08X\n", offset_in_page);

    return 0;
}

Résultat :
Base address      : 0x00400000
Offset            : 0x00001234
Final address     : 0x00401234
Page number       : 1
Offset in page    : 0x00000234


==============================================
  POINTS CLÉS
==============================================

1. Division entière : 7 / 2 = 3 (pas 3.5)
   Pour avoir 3.5, caster en float

2. Post vs Pré incrémentation :
   x++ : retourne la valeur PUIS incrémente
   ++x : incrémente PUIS retourne la valeur

3. Modulo (%) : utile pour :
   - Tester pair/impair : n % 2
   - Calculer offset dans une page
   - Limiter un index : i % MAX_SIZE

4. Opérateurs composés : += -= *= /= %=
   Raccourcis pour x = x + y

5. Ternaire : condition ? vrai : faux
   Compact mais moins lisible pour les cas complexes

==============================================
