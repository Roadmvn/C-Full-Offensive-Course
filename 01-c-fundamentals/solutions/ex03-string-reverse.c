/*
 * SOLUTION - Exercice 03 : String Reverse
 */

#include <stdio.h>

int main()
{
    printf("=== STRING REVERSE ===\n\n");

    char str[] = "HELLO";

    printf("String originale : %s\n", str);

    // Calculer la longueur
    int len = 0;
    while (str[len] != '\0')
    {
        len++;
    }

    printf("Longueur : %d\n", len);

    // Inverser en place
    int i = 0;
    int j = len - 1;

    while (i < j)
    {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;

        i++;
        j--;
    }

    printf("String inversee  : %s\n", str);

    return 0;
}
