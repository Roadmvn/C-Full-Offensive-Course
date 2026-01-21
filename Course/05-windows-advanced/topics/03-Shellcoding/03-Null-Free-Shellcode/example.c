/**
 * Null-Free Shellcode - Vérification
 */
#include <stdio.h>
#include <string.h>

// Shellcode AVEC nulls (problématique)
unsigned char with_nulls[] = "\x48\xc7\xc0\x01\x00\x00\x00";

// Shellcode SANS nulls (fonctionnel)
unsigned char null_free[] = "\x48\x31\xc0\x48\xff\xc0";

int has_null_bytes(unsigned char *sc, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (sc[i] == 0x00) return 1;
    }
    return 0;
}

int main(void) {
    printf("Shellcode avec nulls: %s\n", 
           has_null_bytes(with_nulls, 7) ? "OUI (problème!)" : "NON");
    printf("Shellcode null-free: %s\n", 
           has_null_bytes(null_free, 6) ? "OUI" : "NON (OK!)");
    return 0;
}
