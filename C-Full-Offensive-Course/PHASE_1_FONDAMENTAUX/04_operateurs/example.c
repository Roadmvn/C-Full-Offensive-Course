#include <stdio.h>

/*
 * Programme : Opérateurs
 * Description : Démonstration de tous les opérateurs en C
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== OPÉRATEURS ARITHMÉTIQUES ===\n");
    int a = 10, b = 3;
    printf("a = %d, b = %d\n", a, b);
    printf("a + b = %d\n", a + b);
    printf("a - b = %d\n", a - b);
    printf("a * b = %d\n", a * b);
    printf("a / b = %d (division entière)\n", a / b);
    printf("a %% b = %d (modulo/reste)\n\n", a % b);

    // Incrémentation / Décrémentation
    int x = 5;
    printf("x = %d\n", x);
    printf("x++ = %d (post-incrémentation, retourne puis incrémente)\n", x++);
    printf("x   = %d\n", x);
    printf("++x = %d (pré-incrémentation, incrémente puis retourne)\n\n", ++x);

    // ===============================
    printf("=== OPÉRATEURS RELATIONNELS ===\n");
    int c = 10, d = 20;
    printf("c = %d, d = %d\n", c, d);
    printf("c == d : %d\n", c == d);  // 0 (faux)
    printf("c != d : %d\n", c != d);  // 1 (vrai)
    printf("c > d  : %d\n", c > d);   // 0
    printf("c < d  : %d\n", c < d);   // 1
    printf("c >= d : %d\n", c >= d);  // 0
    printf("c <= d : %d\n\n", c <= d);  // 1

    // ===============================
    printf("=== OPÉRATEURS LOGIQUES ===\n");
    int age = 25;
    int is_admin = 1;

    printf("age = %d, is_admin = %d\n", age, is_admin);
    printf("(age >= 18) && is_admin : %d (ET logique)\n", (age >= 18) && is_admin);
    printf("(age < 18) || is_admin  : %d (OU logique)\n", (age < 18) || is_admin);
    printf("!is_admin               : %d (NON logique)\n\n", !is_admin);

    // ===============================
    printf("=== OPÉRATEURS D'AFFECTATION ===\n");
    int val = 10;
    printf("val = %d\n", val);

    val += 5;  // val = val + 5
    printf("val += 5 : %d\n", val);

    val *= 2;  // val = val * 2
    printf("val *= 2 : %d\n", val);

    val /= 3;  // val = val / 3
    printf("val /= 3 : %d\n", val);

    val %= 5;  // val = val % 5
    printf("val %%= 5 : %d\n\n", val);

    // ===============================
    printf("=== OPÉRATEUR TERNAIRE ===\n");
    int port = 443;
    char* service = (port == 443) ? "HTTPS" : "HTTP";
    printf("Port %d : %s\n\n", port, service);

    // ===============================
    printf("=== PRIORITÉ DES OPÉRATEURS ===\n");
    int result1 = 5 + 3 * 2;       // * avant +
    int result2 = (5 + 3) * 2;     // Parenthèses en premier

    printf("5 + 3 * 2     = %d (multiplication d'abord)\n", result1);
    printf("(5 + 3) * 2   = %d (parenthèses d'abord)\n\n", result2);

    // ===============================
    printf("=== EXEMPLE OFFENSIF : Calcul d'offset ===\n");
    int byte_offset = 0x1234;
    int page_size = 0x1000;  // 4096 bytes

    int page_num = byte_offset / page_size;
    int offset_in_page = byte_offset % page_size;

    printf("Byte offset    : 0x%X\n", byte_offset);
    printf("Page number    : %d\n", page_num);
    printf("Offset in page : 0x%X\n", offset_in_page);

    return 0;
}
