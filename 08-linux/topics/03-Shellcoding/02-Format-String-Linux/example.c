/*
 * OBJECTIF  : Comprendre les vulnerabilites de format string sous Linux
 * PREREQUIS : Bases C, printf, layout memoire (stack)
 * COMPILE   : gcc -o example example.c -Wno-format-security
 *
 * Ce programme demontre les format string attacks : lecture de la
 * stack, fuite d'adresses, ecriture en memoire avec %n, et les
 * protections contre ce type de vulnerabilite.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Etape 1 : La vulnerabilite format string
 * printf(user_input) au lieu de printf("%s", user_input)
 */
static void explain_format_string(void) {
    printf("[*] Etape 1 : Qu'est-ce qu'une format string vulnerability ?\n\n");

    printf("    Code SECURISE   : printf(\"%%s\", user_input);\n");
    printf("    Code VULNERABLE : printf(user_input);\n\n");

    printf("    Si user_input = \"%%x.%%x.%%x\", printf lit la STACK !\n");
    printf("    Les specifiers %%x, %%p, %%s, %%n sont interpretes.\n\n");

    printf("    Specifiers utiles pour l'attaque :\n");
    printf("    %%x  : Lit un int (4 octets) de la stack en hexadecimal\n");
    printf("    %%p  : Lit un pointeur (8 octets)\n");
    printf("    %%s  : Lit une chaine a l'adresse pointee sur la stack\n");
    printf("    %%n  : ECRIT le nombre de caracteres affiches a l'adresse\n");
    printf("    %%N$x : Accede directement au N-ieme argument\n\n");
}

/*
 * Etape 2 : Lire la stack avec %p
 */
static void demo_stack_leak(void) {
    printf("[*] Etape 2 : Fuite de la stack avec %%p\n\n");

    /* Variables locales sur la stack */
    int secret_a = 0xDEADBEEF;
    int secret_b = 0xCAFEBABE;
    char buffer[64];

    printf("    Variables sur la stack :\n");
    printf("      secret_a = 0x%X a %p\n", secret_a, (void *)&secret_a);
    printf("      secret_b = 0x%X a %p\n", secret_b, (void *)&secret_b);
    printf("      buffer   a %p\n\n", (void *)buffer);

    /* Simuler une format string vulnerability */
    snprintf(buffer, sizeof(buffer), "%%p.%%p.%%p.%%p.%%p.%%p.%%p.%%p");
    printf("    Format string : \"%s\"\n", buffer);
    printf("    Resultat      : ");

    /* Afficher ce que printf lirait de la stack */
    printf("%p.%p.%p.%p.%p.%p\n\n",
           (void *)(uintptr_t)secret_a,
           (void *)(uintptr_t)secret_b,
           (void *)buffer,
           (void *)&secret_a,
           (void *)&secret_b,
           (void *)demo_stack_leak);

    printf("    [!] Des adresses et valeurs de la stack ont fuite !\n");
    printf("    Cela permet de contourner ASLR (info leak)\n\n");
}

/*
 * Etape 3 : Acces direct aux arguments avec $
 */
static void demo_direct_access(void) {
    printf("[*] Etape 3 : Acces direct avec %%N$p\n\n");

    printf("    %%1$p = 1er argument sur la stack\n");
    printf("    %%2$p = 2eme argument\n");
    printf("    %%6$p = 6eme argument\n\n");

    /* Variables locales empilees */
    int a = 0x41414141;
    int b = 0x42424242;
    int c = 0x43434343;

    printf("    a=0x%X, b=0x%X, c=0x%X\n\n", a, b, c);
    printf("    En exploitation reelle, on scanne les positions :\n");
    printf("    for i in range(1, 20):\n");
    printf("        payload = f\"%%{i}$p\"\n");
    printf("        send(payload)  # Lire chaque position de la stack\n\n");
}

/*
 * Etape 4 : Ecriture avec %n (concept)
 */
static void explain_write_with_n(void) {
    printf("[*] Etape 4 : Ecriture en memoire avec %%n (concept)\n\n");

    printf("    %%n ecrit le nombre de caracteres affiches jusqu'ici\n");
    printf("    a l'adresse pointee par l'argument correspondant.\n\n");

    /* Demonstration safe de %n */
    int count = 0;
    printf("    Avant %%n : count = %d\n", count);
    printf("    Hello%n World\n", &count);
    printf("    Apres %%n : count = %d (5 = longueur de \"    Hello\")\n\n", count);

    printf("    Exploitation :\n");
    printf("    1. Placer l'adresse cible sur la stack (dans le buffer)\n");
    printf("    2. Utiliser %%N$n pour ecrire a cette adresse\n");
    printf("    3. Controler la valeur ecrite avec %%Nc (padding)\n\n");

    printf("    Exemple (32 bits) :\n");
    printf("    payload = addr + \"%%08x\" * offset + \"%%n\"\n");
    printf("    Ecrit le nombre total de caracteres affiches a 'addr'\n\n");
}

/*
 * Etape 5 : Programme vulnerable complet
 */
static void show_vulnerable_example(void) {
    printf("[*] Etape 5 : Programme vulnerable et exploitation\n\n");

    printf("    // format_vuln.c\n");
    printf("    #include <stdio.h>\n\n");
    printf("    int is_admin = 0;\n\n");
    printf("    void check_admin(void) {\n");
    printf("        if (is_admin) {\n");
    printf("            printf(\"Access granted!\\n\");\n");
    printf("            // system(\"/bin/sh\");\n");
    printf("        }\n");
    printf("    }\n\n");
    printf("    int main(void) {\n");
    printf("        char buf[256];\n");
    printf("        printf(\"Input: \");\n");
    printf("        fgets(buf, sizeof(buf), stdin);\n");
    printf("        printf(buf);  // VULNERABLE !\n");
    printf("        check_admin();\n");
    printf("        return 0;\n");
    printf("    }\n\n");

    printf("    Exploitation :\n");
    printf("    1. Leak ASLR   : echo '%%p.%%p.%%p.%%p' | ./format_vuln\n");
    printf("    2. Trouver is_admin : objdump -t ./format_vuln | grep is_admin\n");
    printf("    3. Ecrire via %%n : modifier is_admin a une valeur != 0\n\n");
}

/*
 * Etape 6 : Protections
 */
static void explain_protections(void) {
    printf("[*] Etape 6 : Protections contre les format strings\n\n");

    printf("    1. TOUJOURS utiliser : printf(\"%%s\", user_input)\n");
    printf("       JAMAIS           : printf(user_input)\n\n");
    printf("    2. Flags de compilation :\n");
    printf("       -Wformat -Wformat-security -Werror=format-security\n\n");
    printf("    3. FORTIFY_SOURCE :\n");
    printf("       gcc -D_FORTIFY_SOURCE=2 -> detecte les %%n dangereux\n\n");
    printf("    4. read-only .got (Full RELRO) :\n");
    printf("       Empeche la redirection via GOT overwrite\n\n");
}

int main(void) {
    printf("[*] Demo : Format String Vulnerability Linux\n\n");

    explain_format_string();
    demo_stack_leak();
    demo_direct_access();
    explain_write_with_n();
    show_vulnerable_example();
    explain_protections();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
