#include <stdio.h>

/*
 * Programme : Tableaux (Arrays)
 * Description : Démonstration des tableaux en C
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== TABLEAUX EN C ===\n\n");

    // 1. Déclaration et initialisation
    printf("1. Déclaration et initialisation\n");
    int ports[4] = {80, 443, 22, 21};
    printf("   ports[0] = %d\n", ports[0]);
    printf("   ports[1] = %d\n", ports[1]);
    printf("   ports[2] = %d\n", ports[2]);
    printf("   ports[3] = %d\n\n", ports[3]);

    // 2. Initialisation automatique
    printf("2. Taille automatique\n");
    int numbers[] = {10, 20, 30, 40, 50};  // Taille déduite = 5
    printf("   Premier : %d\n", numbers[0]);
    printf("   Dernier : %d\n\n", numbers[4]);

    // 3. Initialisation partielle
    printf("3. Initialisation partielle\n");
    int arr[5] = {1, 2};  // {1, 2, 0, 0, 0}
    for (int i = 0; i < 5; i++) {
        printf("   arr[%d] = %d\n", i, arr[i]);
    }
    printf("\n");

    // 4. Modifier des éléments
    printf("4. Modification d'éléments\n");
    int values[3] = {100, 200, 300};
    printf("   Avant : values[1] = %d\n", values[1]);
    values[1] = 999;
    printf("   Après : values[1] = %d\n\n", values[1]);

    // 5. Parcourir avec une boucle
    printf("5. Parcourir avec boucle for\n");
    int scores[5] = {85, 92, 78, 95, 88};
    for (int i = 0; i < 5; i++) {
        printf("   Score[%d] = %d\n", i, scores[i]);
    }
    printf("\n");

    // 6. Taille avec sizeof
    printf("6. Taille avec sizeof\n");
    int data[] = {10, 20, 30, 40, 50, 60};
    int size = sizeof(data) / sizeof(data[0]);
    printf("   sizeof(data) = %lu bytes\n", sizeof(data));
    printf("   sizeof(data[0]) = %lu bytes\n", sizeof(data[0]));
    printf("   Nombre d'éléments : %d\n\n", size);

    // 7. Somme des éléments
    printf("7. Somme des éléments\n");
    int nums[] = {5, 10, 15, 20, 25};
    int sum = 0;
    int nums_size = sizeof(nums) / sizeof(nums[0]);

    for (int i = 0; i < nums_size; i++) {
        sum += nums[i];
    }
    printf("   Somme : %d\n\n", sum);

    // 8. Recherche d'un élément
    printf("8. Recherche dans un tableau\n");
    int target_port = 443;
    int found = 0;
    int port_list[] = {80, 8080, 443, 22, 3389};
    int port_count = sizeof(port_list) / sizeof(port_list[0]);

    for (int i = 0; i < port_count; i++) {
        if (port_list[i] == target_port) {
            printf("   Port %d trouvé à l'index %d\n", target_port, i);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("   Port %d non trouvé\n", target_port);
    }
    printf("\n");

    // 9. Minimum et maximum
    printf("9. Minimum et maximum\n");
    int temps[] = {23, 18, 31, 15, 27};
    int temps_size = sizeof(temps) / sizeof(temps[0]);
    int min = temps[0];
    int max = temps[0];

    for (int i = 1; i < temps_size; i++) {
        if (temps[i] < min) min = temps[i];
        if (temps[i] > max) max = temps[i];
    }

    printf("   Min : %d°C\n", min);
    printf("   Max : %d°C\n\n", max);

    // 10. Tableaux 2D (matrices)
    printf("10. Tableaux 2D (matrice 3x3)\n");
    int matrix[3][3] = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9}
    };

    for (int i = 0; i < 3; i++) {
        printf("   ");
        for (int j = 0; j < 3; j++) {
            printf("%d ", matrix[i][j]);
        }
        printf("\n");
    }
    printf("\n");

    // 11. Accès élément 2D
    printf("11. Accès élément 2D\n");
    printf("   matrix[1][2] = %d\n\n", matrix[1][2]);  // Ligne 1, colonne 2

    // 12. Tableau de caractères (string)
    printf("12. Tableau de caractères\n");
    char username[] = "root";
    printf("   Username : %s\n", username);
    printf("   Longueur : %lu caractères\n\n", sizeof(username) - 1);  // -1 pour \0

    // 13. Copier un tableau (boucle)
    printf("13. Copier un tableau\n");
    int src[5] = {1, 2, 3, 4, 5};
    int dst[5];

    for (int i = 0; i < 5; i++) {
        dst[i] = src[i];
    }

    printf("   Source : ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", src[i]);
    }
    printf("\n");

    printf("   Copie  : ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", dst[i]);
    }
    printf("\n\n");

    // 14. Exemple Red Team : Shellcode storage
    printf("14. Red Team : Shellcode storage\n");
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0x31, 0xc0,              // xor eax, eax
        0x50,                    // push eax
        0xff, 0xe4               // jmp esp
    };
    int shellcode_size = sizeof(shellcode);

    printf("   Shellcode (%d bytes) :\n   ", shellcode_size);
    for (int i = 0; i < shellcode_size; i++) {
        printf("\\x%02x", shellcode[i]);
        if ((i + 1) % 8 == 0) printf("\n   ");
    }
    printf("\n\n");

    // 15. Exemple Red Team : Liste d'IPs (simulé)
    printf("15. Red Team : Liste d'IP\n");
    unsigned int ips[] = {
        0xC0A80101,  // 192.168.1.1
        0xC0A80102,  // 192.168.1.2
        0xC0A80103   // 192.168.1.3
    };
    int ip_count = sizeof(ips) / sizeof(ips[0]);

    for (int i = 0; i < ip_count; i++) {
        unsigned int ip = ips[i];
        printf("   IP[%d] : %d.%d.%d.%d\n", i,
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
    }

    printf("\n[+] Programme terminé avec succès.\n");
    return 0;
}
