==============================================
  MODULE 01 - HELLO WORLD - SOLUTIONS
==============================================

✓ Exercice 1 : Hello de base
------------------------------
#include <stdio.h>

int main() {
    printf("Bonjour, je suis un Red Teamer en formation.\n");
    return 0;
}


✓ Exercice 2 : Plusieurs lignes
------------------------------
#include <stdio.h>

int main() {
    printf("Module 01\n");
    printf("Hello World\n");
    printf("C Programming\n");
    return 0;
}

// Alternative (une seule ligne) :
#include <stdio.h>

int main() {
    printf("Module 01\nHello World\nC Programming\n");
    return 0;
}


✓ Exercice 3 : Variables et printf
------------------------------
#include <stdio.h>

int main() {
    int port = 4444;
    char* service = "reverse_shell";

    printf("Service: %s sur le port: %d\n", service, port);
    return 0;
}


✓ Exercice 4 : Formatage hexa
------------------------------
#include <stdio.h>

int main() {
    int payload_size = 512;

    printf("Taille: %d bytes (0x%x)\n", payload_size, payload_size);
    return 0;
}


✓ Exercice 5 : Adresse mémoire
------------------------------
#include <stdio.h>

int main() {
    int secret = 1337;

    printf("Variable 'secret' stockée à l'adresse : %p\n", (void*)&secret);
    return 0;
}

Note : & = opérateur "adresse de"
      %p = format pour afficher un pointeur


✓ Exercice 6 : Tabulation
------------------------------
#include <stdio.h>

int main() {
    printf("IP\t\tPort\tStatus\n");
    printf("192.168.1.10\t80\tOPEN\n");
    printf("192.168.1.10\t443\tOPEN\n");
    return 0;
}


✓ Exercice 7 : Caractère par caractère
------------------------------
#include <stdio.h>

int main() {
    printf("%c", 'H');
    printf("%c", 'A');
    printf("%c", 'C');
    printf("%c", 'K');
    printf("\n");  // Retour à la ligne à la fin
    return 0;
}


✓ Exercice 8 : Code de retour personnalisé
------------------------------
#include <stdio.h>

int main() {
    printf("Erreur : connexion échouée\n");
    return 1;  // Code d'erreur
}

Test :
$ gcc exercice8.c -o exercice8
$ ./exercice8
Erreur : connexion échouée
$ echo $?
1

Explication :
- return 0 = succès (convention UNIX)
- return 1+ = erreur
- Le code de retour est récupérable via $? (shell)


==============================================
  POINTS CLÉS À RETENIR
==============================================

1. printf() utilise des "format specifiers" :
   %d = int
   %s = string
   %c = char
   %x = hexa
   %p = pointeur

2. Caractères spéciaux :
   \n = nouvelle ligne
   \t = tabulation
   \\ = backslash
   \" = guillemet

3. return 0 = succès, autre = erreur

4. & = opérateur "adresse de" (on verra les pointeurs plus tard)

==============================================
