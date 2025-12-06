#include <stdio.h>

/*
 * Programme : Conditions
 * Description : Démonstration des structures conditionnelles
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== CONDITIONS EN C ===\n\n");

    // 1. if simple
    printf("1. if simple\n");
    int age = 22;
    if (age >= 18) {
        printf("   Vous êtes majeur.\n\n");
    }

    // 2. if-else
    printf("2. if-else\n");
    int port = 22;
    if (port == 22) {
        printf("   Service : SSH\n\n");
    } else {
        printf("   Service : Inconnu\n\n");
    }

    // 3. if-else if-else
    printf("3. if-else if-else\n");
    int status_code = 200;
    if (status_code == 200) {
        printf("   HTTP 200 : OK\n");
    } else if (status_code == 404) {
        printf("   HTTP 404 : Not Found\n");
    } else if (status_code == 500) {
        printf("   HTTP 500 : Internal Server Error\n");
    } else {
        printf("   Code inconnu\n");
    }
    printf("\n");

    // 4. Opérateurs de comparaison
    printf("4. Opérateurs de comparaison\n");
    int a = 10, b = 20;
    printf("   a = %d, b = %d\n", a, b);
    printf("   a == b : %s\n", (a == b) ? "vrai" : "faux");
    printf("   a != b : %s\n", (a != b) ? "vrai" : "faux");
    printf("   a < b  : %s\n", (a < b) ? "vrai" : "faux");
    printf("   a > b  : %s\n\n", (a > b) ? "vrai" : "faux");

    // 5. Opérateurs logiques (&&, ||, !)
    printf("5. Opérateurs logiques\n");
    int privilege = 1;  // 1 = admin, 0 = user
    int authenticated = 1;

    if (authenticated && privilege == 1) {
        printf("   [+] Accès admin autorisé\n");
    }

    if (port == 80 || port == 443) {
        printf("   [+] Port HTTP/HTTPS détecté\n");
    }

    if (!authenticated) {
        printf("   [-] Non authentifié\n");
    } else {
        printf("   [+] Authentifié\n");
    }
    printf("\n");

    // 6. switch-case
    printf("6. switch-case\n");
    char protocol = 'T';  // T=TCP, U=UDP, I=ICMP

    switch (protocol) {
        case 'T':
            printf("   Protocole : TCP\n");
            break;
        case 'U':
            printf("   Protocole : UDP\n");
            break;
        case 'I':
            printf("   Protocole : ICMP\n");
            break;
        default:
            printf("   Protocole : Inconnu\n");
            break;
    }
    printf("\n");

    // 7. switch avec entiers (type de paquet)
    printf("7. switch avec entiers\n");
    int packet_type = 2;

    switch (packet_type) {
        case 1:
            printf("   Type : SYN\n");
            break;
        case 2:
            printf("   Type : ACK\n");
            break;
        case 3:
            printf("   Type : FIN\n");
            break;
        default:
            printf("   Type : Autre\n");
            break;
    }
    printf("\n");

    // 8. Opérateur ternaire
    printf("8. Opérateur ternaire\n");
    int x = 15, y = 30;
    int max = (x > y) ? x : y;
    printf("   max(%d, %d) = %d\n", x, y, max);

    char* access = (privilege == 1) ? "GRANTED" : "DENIED";
    printf("   Accès : %s\n\n", access);

    // 9. Conditions imbriquées
    printf("9. Conditions imbriquées\n");
    int target_os = 1;  // 1=Linux, 2=Windows
    int arch = 64;      // 32 ou 64 bits

    if (target_os == 1) {
        if (arch == 64) {
            printf("   Cible : Linux x64\n");
        } else {
            printf("   Cible : Linux x86\n");
        }
    } else if (target_os == 2) {
        if (arch == 64) {
            printf("   Cible : Windows x64\n");
        } else {
            printf("   Cible : Windows x86\n");
        }
    }
    printf("\n");

    // 10. Valeurs "vraies" et "fausses"
    printf("10. Valeurs vraies/fausses en C\n");
    if (1) {
        printf("   1 est vrai\n");
    }
    if (42) {
        printf("   42 est vrai\n");
    }
    if (0) {
        printf("   0 est vrai\n");  // Ne s'affiche jamais
    } else {
        printf("   0 est faux\n");
    }
    printf("\n");

    // 11. Vérification de pointeur
    printf("11. Vérification de pointeur\n");
    int* ptr1 = NULL;
    int value = 100;
    int* ptr2 = &value;

    if (ptr1) {
        printf("   ptr1 est valide\n");
    } else {
        printf("   ptr1 est NULL\n");
    }

    if (ptr2) {
        printf("   ptr2 est valide : %d\n\n", *ptr2);
    }

    // 12. Exemple Red Team : Sandbox detection
    printf("12. Exemple Red Team : Détection de sandbox\n");
    int cpu_cores = 4;
    int ram_gb = 8;
    int disk_gb = 500;

    if (cpu_cores < 2 || ram_gb < 4 || disk_gb < 80) {
        printf("   [!] Environnement suspect détecté (sandbox?)\n");
        printf("   [!] Arrêt du payload pour éviter l'analyse.\n");
        // Dans un vrai malware : exit(0);
    } else {
        printf("   [+] Environnement réel détecté.\n");
        printf("   [+] Exécution du payload...\n");
    }

    printf("\n[+] Programme terminé avec succès.\n");
    return 0;
}
