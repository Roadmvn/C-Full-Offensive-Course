#include <stdio.h>

int main() {
    // Types de base en C

    // int : nombres entiers
    int age = 25;
    printf("Age : %d ans\n", age);

    // char : un seul caractère
    char initiale = 'A';
    printf("Initiale : %c\n", initiale);

    // float : nombres à virgule
    float taille = 1.75;
    printf("Taille : %.2f m\n", taille);

    // double : nombres à virgule (plus précis)
    double pi = 3.14159265359;
    printf("Pi : %.10f\n", pi);

    // Taille des types en mémoire
    printf("\nTailles en mémoire :\n");
    printf("int : %zu bytes\n", sizeof(int));
    printf("char : %zu bytes\n", sizeof(char));
    printf("float : %zu bytes\n", sizeof(float));
    printf("double : %zu bytes\n", sizeof(double));

    // Opérations simples
    int a = 10;
    int b = 3;
    printf("\nOpérations : %d et %d\n", a, b);
    printf("Addition : %d\n", a + b);
    printf("Soustraction : %d\n", a - b);
    printf("Multiplication : %d\n", a * b);
    printf("Division : %d\n", a / b);  // Division entière
    printf("Modulo : %d\n", a % b);    // Reste

    return 0;
}
