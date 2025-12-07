==============================================
  MODULE 06 - CONDITIONS - SOLUTIONS
==============================================

Exercice 1 : if simple
------------------------------
#include <stdio.h>
int main() {
    int port = 443;
    if (port == 443) {
        printf("HTTPS détecté\n");
    }
    return 0;
}


Exercice 2 : if-else
------------------------------
#include <stdio.h>
int main() {
    int privilege = 0;
    if (privilege == 1) {
        printf("Admin\n");
    } else {
        printf("User\n");
    }
    return 0;
}


Exercice 3 : if-else if-else
------------------------------
#include <stdio.h>
int main() {
    int error_code = 404;

    if (error_code == 200) {
        printf("Success\n");
    } else if (error_code == 404) {
        printf("Not Found\n");
    } else if (error_code == 500) {
        printf("Server Error\n");
    } else {
        printf("Unknown\n");
    }
    return 0;
}


Exercice 4 : Opérateurs logiques (&&)
------------------------------
#include <stdio.h>
int main() {
    int authenticated = 1;
    int has_admin_role = 1;

    if (authenticated && has_admin_role) {
        printf("Accès autorisé\n");
    } else {
        printf("Accès refusé\n");
    }
    return 0;
}


Exercice 5 : Opérateurs logiques (||)
------------------------------
#include <stdio.h>
int main() {
    int port = 22;
    if (port == 22 || port == 23) {
        printf("Service SSH/Telnet\n");
    }
    return 0;
}


Exercice 6 : switch-case simple
------------------------------
#include <stdio.h>
int main() {
    int protocol = 6;

    switch (protocol) {
        case 6:
            printf("TCP\n");
            break;
        case 17:
            printf("UDP\n");
            break;
        case 1:
            printf("ICMP\n");
            break;
        default:
            printf("Protocole inconnu\n");
            break;
    }
    return 0;
}


Exercice 7 : Opérateur ternaire
------------------------------
#include <stdio.h>
int main() {
    int a = 15, b = 30;
    int min = (a < b) ? a : b;
    printf("Minimum : %d\n", min);  // 15
    return 0;
}


Exercice 8 : Détection d'architecture
------------------------------
#include <stdio.h>
int main() {
    int arch_bits = 64;

    if (arch_bits == 32) {
        printf("x86\n");
    } else if (arch_bits == 64) {
        printf("x64\n");
    } else {
        printf("Architecture inconnue\n");
    }
    return 0;
}

==============================================
  NOTES :
  - switch est plus lisible que if-else pour tester une variable contre plusieurs valeurs
  - Opérateur ternaire : condition ? si_vrai : si_faux
  - Ne pas oublier break dans switch (sinon fall-through)
==============================================
