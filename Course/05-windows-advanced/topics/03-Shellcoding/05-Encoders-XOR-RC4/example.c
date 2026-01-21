/**
 * XOR et RC4 Encoder
 */
#include <stdio.h>
#include <string.h>

void xor_encode(unsigned char *d, size_t l, unsigned char k) {
    for (size_t i = 0; i < l; i++) d[i] ^= k;
}

int main(void) {
    unsigned char sc[] = "Hello Shellcode!";
    size_t len = strlen((char*)sc);
    
    printf("Original: %s\n", sc);
    xor_encode(sc, len, 0x41);
    printf("Encoded: "); 
    for (size_t i = 0; i < len; i++) printf("%02x ", sc[i]);
    printf("\n");
    xor_encode(sc, len, 0x41);
    printf("Decoded: %s\n", sc);
    
    return 0;
}
