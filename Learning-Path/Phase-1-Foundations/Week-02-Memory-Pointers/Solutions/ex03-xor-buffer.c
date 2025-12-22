/*
 * SOLUTION - Exercice 03 : XOR Buffer
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void xor_buffer(unsigned char* buffer, size_t len, unsigned char key)
{
    for (size_t i = 0; i < len; i++)
    {
        buffer[i] ^= key;
        // Equivalent: *(buffer + i) ^= key;
    }
}

// Version avec pointeur
void xor_buffer_ptr(unsigned char* buffer, size_t len, unsigned char key)
{
    unsigned char* end = buffer + len;
    while (buffer < end)
    {
        *buffer ^= key;
        buffer++;
    }
}

void print_hex(unsigned char* buffer, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02X ", buffer[i]);
    printf("\n");
}

int main()
{
    char original[] = "cmd.exe";
    size_t len = strlen(original);

    unsigned char* buffer = malloc(len + 1);
    memcpy(buffer, original, len + 1);

    unsigned char key = 0x41;

    printf("Original : %s\n", buffer);
    print_hex(buffer, len);

    xor_buffer(buffer, len, key);
    printf("\nChiffre  : ");
    print_hex(buffer, len);

    xor_buffer(buffer, len, key);
    printf("Dechiffre: %s\n", buffer);

    free(buffer);
    return 0;
}
