// EDUCATIONAL ONLY - Code Cave Finder & PE Patcher
// AVERTISSEMENT : Ne jamais utiliser sur systemes non autorises

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
// Definitions PE pour compilation non-Windows
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
} IMAGE_NT_HEADERS32;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;
#endif

typedef struct {
    uint32_t offset;
    uint32_t size;
    uint32_t rva;
    char section[9];
} CodeCave;

// Lire fichier complet en memoire
unsigned char* read_file(const char* filename, size_t* filesize) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* buffer = malloc(*filesize);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    fread(buffer, 1, *filesize, f);
    fclose(f);
    return buffer;
}

// Trouver code caves dans section
int find_caves_in_section(unsigned char* data, IMAGE_SECTION_HEADER* section,
                          CodeCave* caves, int max_caves, int min_size) {
    int count = 0;
    uint32_t start = section->PointerToRawData;
    uint32_t end = start + section->SizeOfRawData;

    uint32_t cave_start = 0;
    int in_cave = 0;

    for (uint32_t i = start; i < end && count < max_caves; i++) {
        if (data[i] == 0x00 || data[i] == 0x90 || data[i] == 0xCC) {
            if (!in_cave) {
                cave_start = i;
                in_cave = 1;
            }
        } else {
            if (in_cave) {
                uint32_t cave_size = i - cave_start;
                if (cave_size >= min_size) {
                    caves[count].offset = cave_start;
                    caves[count].size = cave_size;
                    caves[count].rva = section->VirtualAddress +
                                      (cave_start - section->PointerToRawData);
                    strncpy(caves[count].section, (char*)section->Name, 8);
                    caves[count].section[8] = '\0';
                    count++;
                }
                in_cave = 0;
            }
        }
    }

    return count;
}

// Analyser PE et trouver toutes les caves
int find_all_caves(const char* filename, CodeCave* caves, int max_caves, int min_size) {
    size_t filesize;
    unsigned char* data = read_file(filename, &filesize);
    if (!data) return -1;

    // Verifier DOS header
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Not a valid PE file (invalid DOS signature)\n");
        free(data);
        return -1;
    }

    // Verifier NT header
    IMAGE_NT_HEADERS32* nt_headers =
        (IMAGE_NT_HEADERS32*)(data + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Not a valid PE file (invalid NT signature)\n");
        free(data);
        return -1;
    }

    printf("[+] PE file validated\n");
    printf("[+] Number of sections: %d\n", nt_headers->FileHeader.NumberOfSections);

    // Iterer sur sections
    IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)
        ((unsigned char*)nt_headers + sizeof(IMAGE_NT_HEADERS32));

    int total_caves = 0;
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections && total_caves < max_caves; i++) {
        printf("\n[*] Analyzing section: %.8s\n", section[i].Name);
        printf("    Raw Size: 0x%X, Virtual Size: 0x%X\n",
               section[i].SizeOfRawData, section[i].VirtualSize);

        int found = find_caves_in_section(data, &section[i],
                                         &caves[total_caves],
                                         max_caves - total_caves, min_size);
        printf("    Found %d caves (>= %d bytes)\n", found, min_size);
        total_caves += found;
    }

    free(data);
    return total_caves;
}

// Afficher caves trouvees
void display_caves(CodeCave* caves, int count) {
    printf("\n[+] Total caves found: %d\n\n", count);
    printf("%-10s %-12s %-12s %-12s %-10s\n",
           "Index", "Section", "File Offset", "RVA", "Size");
    printf("----------------------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        printf("%-10d %-12s 0x%08X      0x%08X   %d bytes\n",
               i, caves[i].section, caves[i].offset, caves[i].rva, caves[i].size);
    }
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  PE Code Cave Finder (Educational)\n");
    printf("========================================\n\n");
    printf("AVERTISSEMENT : Usage educatif uniquement\n\n");

    if (argc < 2) {
        printf("Usage: %s <pe_file> [min_cave_size]\n", argv[0]);
        printf("Example: %s target.exe 100\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    int min_size = (argc > 2) ? atoi(argv[2]) : 50;

    printf("[*] Target: %s\n", filename);
    printf("[*] Minimum cave size: %d bytes\n\n", min_size);

    CodeCave caves[256];
    int count = find_all_caves(filename, caves, 256, min_size);

    if (count < 0) {
        printf("[!] Failed to analyze PE file\n");
        return 1;
    }

    display_caves(caves, count);

    printf("\n[*] Analysis complete\n");
    printf("[!] Remember: Code cave injection for educational purposes only!\n");

    return 0;
}
