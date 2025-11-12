// EDUCATIONAL ONLY - Simple XOR Packer/Unpacker
// AVERTISSEMENT : Ne jamais utiliser pour malware reel

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define MAX_SIZE (10 * 1024 * 1024)  // 10MB max

typedef struct {
    uint32_t magic;           // 0x5041434B ('PACK')
    uint32_t original_size;
    uint32_t packed_size;
    uint32_t checksum;
    uint8_t key_length;
    uint8_t key[32];
    uint32_t reserved[4];
} PackHeader;

// Calculer entropie d'un buffer
double calculate_entropy(unsigned char* data, size_t len) {
    if (len == 0) return 0.0;

    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Generer cle aleatoire
void generate_key(uint8_t* key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rand() % 256;
    }
}

// XOR encryption/decryption (symetrique)
void xor_crypt(unsigned char* data, size_t len, uint8_t* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Checksum simple
uint32_t calculate_checksum(unsigned char* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        sum = (sum << 1) | (sum >> 31);  // Rotate left
    }
    return sum;
}

// Lire fichier complet
unsigned char* read_file(const char* filename, size_t* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (*size > MAX_SIZE) {
        printf("[!] File too large (max %d bytes)\n", MAX_SIZE);
        fclose(f);
        return NULL;
    }

    unsigned char* buffer = malloc(*size);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(buffer, 1, *size, f);
    fclose(f);

    if (read != *size) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

// Pack fichier avec XOR encryption
int pack_file(const char* input, const char* output) {
    printf("[*] Packing: %s -> %s\n", input, output);

    size_t original_size;
    unsigned char* data = read_file(input, &original_size);
    if (!data) {
        printf("[!] Failed to read input file\n");
        return -1;
    }

    printf("[+] Original size: %zu bytes\n", original_size);

    // Calculer entropie originale
    double entropy_before = calculate_entropy(data, original_size);
    printf("[+] Original entropy: %.2f\n", entropy_before);

    // Generer cle aleatoire
    PackHeader header = {0};
    header.magic = 0x5041434B;
    header.original_size = original_size;
    header.key_length = 16;
    generate_key(header.key, header.key_length);

    // XOR encryption
    xor_crypt(data, original_size, header.key, header.key_length);

    header.packed_size = original_size;  // XOR ne change pas taille
    header.checksum = calculate_checksum(data, original_size);

    // Calculer entropie apres encryption
    double entropy_after = calculate_entropy(data, original_size);
    printf("[+] Packed entropy: %.2f\n", entropy_after);

    // Ecrire fichier packe
    FILE* out = fopen(output, "wb");
    if (!out) {
        perror("fopen output");
        free(data);
        return -1;
    }

    fwrite(&header, sizeof(header), 1, out);
    fwrite(data, 1, original_size, out);
    fclose(out);
    free(data);

    printf("[+] Packing successful\n");
    printf("[+] Key (hex): ");
    for (int i = 0; i < header.key_length; i++) {
        printf("%02X", header.key[i]);
    }
    printf("\n");

    return 0;
}

// Unpack fichier
int unpack_file(const char* input, const char* output) {
    printf("[*] Unpacking: %s -> %s\n", input, output);

    FILE* f = fopen(input, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    // Lire header
    PackHeader header;
    if (fread(&header, sizeof(header), 1, f) != 1) {
        printf("[!] Failed to read header\n");
        fclose(f);
        return -1;
    }

    // Valider magic
    if (header.magic != 0x5041434B) {
        printf("[!] Invalid packed file (bad magic: 0x%X)\n", header.magic);
        fclose(f);
        return -1;
    }

    printf("[+] Valid packed file detected\n");
    printf("[+] Original size: %u bytes\n", header.original_size);
    printf("[+] Key length: %u bytes\n", header.key_length);

    // Lire donnees packees
    unsigned char* data = malloc(header.packed_size);
    if (!data) {
        fclose(f);
        return -1;
    }

    if (fread(data, 1, header.packed_size, f) != header.packed_size) {
        printf("[!] Failed to read packed data\n");
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Verifier checksum AVANT decryption
    uint32_t checksum = calculate_checksum(data, header.packed_size);
    if (checksum != header.checksum) {
        printf("[!] Checksum mismatch (file corrupted?)\n");
        free(data);
        return -1;
    }
    printf("[+] Checksum valid\n");

    // Decrypter (XOR symetrique)
    xor_crypt(data, header.packed_size, header.key, header.key_length);

    // Ecrire fichier unpacke
    FILE* out = fopen(output, "wb");
    if (!out) {
        perror("fopen output");
        free(data);
        return -1;
    }

    fwrite(data, 1, header.original_size, out);
    fclose(out);
    free(data);

    printf("[+] Unpacking successful\n");
    return 0;
}

// Analyser fichier (packed vs unpacked)
void analyze_file(const char* filename) {
    printf("\n[*] Analyzing: %s\n", filename);

    size_t size;
    unsigned char* data = read_file(filename, &size);
    if (!data) return;

    double entropy = calculate_entropy(data, size);
    printf("[+] File size: %zu bytes\n", size);
    printf("[+] Entropy: %.2f ", entropy);

    if (entropy > 7.5) {
        printf("(HIGH - likely packed/encrypted)\n");
    } else if (entropy > 6.0) {
        printf("(MEDIUM - possibly compressed)\n");
    } else {
        printf("(LOW - likely plaintext/unpacked)\n");
    }

    // Check si fichier packe avec notre format
    PackHeader* header = (PackHeader*)data;
    if (header->magic == 0x5041434B) {
        printf("[+] Packed file detected (custom format)\n");
        printf("    Original size: %u bytes\n", header->original_size);
    }

    free(data);
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    printf("========================================\n");
    printf("  Simple XOR Packer/Unpacker\n");
    printf("========================================\n");
    printf("AVERTISSEMENT : Educational purpose only\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Pack:    %s pack <input> <output>\n", argv[0]);
        printf("  Unpack:  %s unpack <input> <output>\n", argv[0]);
        printf("  Analyze: %s analyze <file>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "pack") == 0 && argc == 4) {
        return pack_file(argv[2], argv[3]);
    } else if (strcmp(argv[1], "unpack") == 0 && argc == 4) {
        return unpack_file(argv[2], argv[3]);
    } else if (strcmp(argv[1], "analyze") == 0 && argc == 3) {
        analyze_file(argv[2]);
        return 0;
    } else {
        printf("[!] Invalid arguments\n");
        return 1;
    }

    return 0;
}
