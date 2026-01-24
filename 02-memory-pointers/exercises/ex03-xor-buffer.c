/*
 * EXERCICE 03 : XOR Buffer (Maldev style)
 * DIFFICULTE : ⭐⭐⭐
 *
 * OBJECTIF : Chiffrer et dechiffrer un buffer avec XOR
 * C'est une technique REELLE utilisee par les malwares !
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// TODO: Implemente cette fonction
// Elle doit XOR chaque byte du buffer avec la cle
void xor_buffer(unsigned char* buffer, size_t len, unsigned char key)
{
    // Ton code ici
    // INDICE: buffer[i] ^= key; ou *(buffer + i) ^= key;

}

// Fonction pour afficher un buffer en hex
void print_hex(unsigned char* buffer, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

int main()
{
    // Message secret a cacher
    char original[] = "cmd.exe";
    size_t len = strlen(original);

    // Copie pour travailler dessus
    unsigned char* buffer = malloc(len + 1);
    memcpy(buffer, original, len + 1);

    unsigned char key = 0x41;  // Cle XOR

    printf("=== XOR BUFFER ===\n\n");

    printf("Original (texte): %s\n", buffer);
    printf("Original (hex)  : ");
    print_hex(buffer, len);

    // Chiffrer
    xor_buffer(buffer, len, key);

    printf("\nApres XOR 0x%02X  : ", key);
    print_hex(buffer, len);

    // A ce stade, le texte ne devrait plus etre lisible
    printf("Comme texte     : %s (illisible)\n", buffer);

    // Dechiffrer (XOR est son propre inverse)
    xor_buffer(buffer, len, key);

    printf("\nApres re-XOR    : ");
    print_hex(buffer, len);
    printf("Recupere        : %s\n", buffer);

    // Verification
    if (strcmp((char*)buffer, original) == 0)
    {
        printf("\n[OK] XOR fonctionne ! Le message est recupere.\n");
    }
    else
    {
        printf("\n[ERREUR] Le message n'a pas ete correctement recupere.\n");
    }

    free(buffer);
    return 0;
}

/*
 * BONUS : Modifie pour utiliser une cle multi-bytes
 * Exemple : key[] = {0x41, 0x42, 0x43};
 *           buffer[i] ^= key[i % key_len];
 */
