==============================================
  MODULE 02 - VARIABLES ET TYPES - SOLUTIONS
==============================================

✓ Exercice 1 : Déclaration basique
------------------------------
#include <stdio.h>

int main() {
    int pid = 1337;
    char grade = 'A';
    float cpu_usage = 75.5;

    printf("PID: %d\n", pid);
    printf("Grade: %c\n", grade);
    printf("CPU Usage: %.1f%%\n", cpu_usage);  // %.1f = 1 décimale

    return 0;
}


✓ Exercice 2 : sizeof()
------------------------------
#include <stdio.h>

int main() {
    printf("Taille de char    : %lu bytes\n", sizeof(char));
    printf("Taille de int     : %lu bytes\n", sizeof(int));
    printf("Taille de long    : %lu bytes\n", sizeof(long));
    printf("Taille de double  : %lu bytes\n", sizeof(double));
    printf("Taille de void*   : %lu bytes\n", sizeof(void*));

    return 0;
}

Résultat typique (x64) :
char    : 1 byte
int     : 4 bytes
long    : 8 bytes
double  : 8 bytes
void*   : 8 bytes (architecture 64 bits)


✓ Exercice 3 : Unsigned vs Signed
------------------------------
#include <stdio.h>

int main() {
    int signed_num = -50;
    unsigned int unsigned_num = 50;

    printf("Signé    : %d\n", signed_num);
    printf("Non signé: %u\n", unsigned_num);

    // Explication :
    // unsigned ne peut stocker que des valeurs positives (0 à 2^32-1)
    // signed peut stocker du négatif (-2^31 à 2^31-1)

    return 0;
}


✓ Exercice 4 : Overflow test
------------------------------
#include <stdio.h>

int main() {
    unsigned char max_byte = 255;

    printf("Avant : %u\n", max_byte);
    max_byte = max_byte + 1;  // Overflow !
    printf("Après : %u\n", max_byte);

    return 0;
}

Résultat :
Avant : 255
Après : 0

Explication : unsigned char = 1 byte (0-255)
255 + 1 = 256, mais 256 ne tient pas sur 1 byte
→ Wraps around à 0 (overflow circulaire)


✓ Exercice 5 : Constantes
------------------------------
#include <stdio.h>

int main() {
    const int MAX_CONNECTIONS = 100;

    printf("Max connexions : %d\n", MAX_CONNECTIONS);

    // Décommente la ligne suivante pour tester
    // MAX_CONNECTIONS = 200;  // ERREUR DE COMPILATION !

    return 0;
}

Erreur du compilateur :
error: assignment of read-only variable 'MAX_CONNECTIONS'

Explication : const empêche toute modification après initialisation.


✓ Exercice 6 : Format hexadécimal
------------------------------
#include <stdio.h>

int main() {
    int shellcode_addr = 0x41414141;  // "AAAA" en ASCII

    printf("Hexadécimal : 0x%X\n", shellcode_addr);
    printf("Décimal     : %d\n", shellcode_addr);
    printf("Unsigned    : %u\n", shellcode_addr);

    return 0;
}

Résultat :
Hexadécimal : 0x41414141
Décimal     : 1094795585
Unsigned    : 1094795585


✓ Exercice 7 : Bytes array
------------------------------
#include <stdio.h>

int main() {
    unsigned char payload[] = {0x48, 0x31, 0xC0, 0x90};

    printf("Payload : ");
    for (int i = 0; i < 4; i++) {
        printf("\\x%02X ", payload[i]);
    }
    printf("\n");

    return 0;
}

Résultat :
Payload : \x48 \x31 \xC0 \x90

Note : %02X signifie "hexa sur 2 chiffres minimum"


✓ Exercice 8 : Type casting
------------------------------
#include <stdio.h>

int main() {
    int big_num = 300;
    char small_num = (char)big_num;  // Cast explicite

    printf("big_num   (int)  : %d\n", big_num);
    printf("small_num (char) : %d\n", small_num);

    return 0;
}

Résultat :
big_num   (int)  : 300
small_num (char) : 44

Explication :
300 en binaire = 0000 0001 0010 1100
char = 1 byte  = seuls les 8 bits de droite sont gardés
                 0010 1100 = 44 en décimal

→ C'est un overflow ! (300 ne tient pas sur 1 byte)


==============================================
  POINTS CLÉS
==============================================

1. unsigned char = parfait pour les bytes bruts (shellcode)
2. sizeof() = taille en bytes (architecture-dépendant)
3. Overflow = wraparound (255 + 1 = 0)
4. Cast = conversion de type (peut causer des pertes de données)
5. Hexa (%X) = format préféré en offensive security

==============================================
