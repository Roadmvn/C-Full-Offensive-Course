/**
 * API Hashing - ROR13
 */
#include <stdio.h>
#include <stdint.h>

uint32_t ror13_hash(const char *name) {
    uint32_t hash = 0;
    while (*name) {
        hash = ((hash >> 13) | (hash << 19)) + *name++;
    }
    return hash;
}

int main(void) {
    printf("LoadLibraryA: 0x%08X\n", ror13_hash("LoadLibraryA"));
    printf("GetProcAddress: 0x%08X\n", ror13_hash("GetProcAddress"));
    printf("WinExec: 0x%08X\n", ror13_hash("WinExec"));
    printf("ExitProcess: 0x%08X\n", ror13_hash("ExitProcess"));
    return 0;
}
