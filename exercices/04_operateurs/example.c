#include <stdio.h>

int main() {
    // Opérateurs arithmétiques
    int a = 15, b = 4;
    printf("Arithmétiques :\n");
    printf("%d + %d = %d\n", a, b, a + b);   // 19
    printf("%d - %d = %d\n", a, b, a - b);   // 11
    printf("%d * %d = %d\n", a, b, a * b);   // 60
    printf("%d / %d = %d\n", a, b, a / b);   // 3 (division entière)
    printf("%d %% %d = %d\n", a, b, a % b);  // 3 (reste/modulo)

    // Incrémentation/décrémentation
    int x = 10;
    printf("\nIncrémentation :\n");
    printf("x = %d\n", x);
    printf("x++ = %d, puis x = %d\n", x++, x);  // Post-incrémentation
    printf("++x = %d\n", ++x);                   // Pré-incrémentation

    // Opérateurs de comparaison
    printf("\nComparaison :\n");
    printf("10 == 10 : %d\n", 10 == 10);  // 1 (vrai)
    printf("10 != 5  : %d\n", 10 != 5);   // 1 (vrai)
    printf("10 > 5   : %d\n", 10 > 5);    // 1 (vrai)
    printf("10 < 5   : %d\n", 10 < 5);    // 0 (faux)

    // Opérateurs logiques
    int age = 25;
    printf("\nLogiques :\n");
    printf("age >= 18 && age <= 65 : %d\n", age >= 18 && age <= 65);  // 1
    printf("age < 18 || age > 65   : %d\n", age < 18 || age > 65);    // 0
    printf("!(age < 18)            : %d\n", !(age < 18));              // 1

    // Opérateurs d'affectation composés
    int val = 100;
    printf("\nAffectation :\n");
    printf("val = %d\n", val);
    val += 20;  // val = val + 20
    printf("Après val += 20 : %d\n", val);
    val *= 2;   // val = val * 2
    printf("Après val *= 2 : %d\n", val);

    return 0;
}
