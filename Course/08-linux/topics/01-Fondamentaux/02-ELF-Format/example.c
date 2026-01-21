#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

void parse_elf(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }
    
    struct stat st;
    fstat(fd, &st);
    
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return;
    }
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    
    // Vérifier magic
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        printf("Not an ELF file\n");
        goto cleanup;
    }
    
    printf("=== ELF HEADER ===\n");
    printf("Class: %s\n", ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? "64-bit" : "32-bit");
    printf("Entry point: 0x%lx\n", ehdr->e_entry);
    printf("Program headers: %d\n", ehdr->e_phnum);
    printf("Section headers: %d\n", ehdr->e_shnum);
    
    // Parser sections
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)map + ehdr->e_shoff);
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    char *shstrtab_data = (char *)map + shstrtab->sh_offset;
    
    printf("\n=== SECTIONS ===\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {
        printf("[%2d] %-15s  Addr: 0x%016lx  Size: 0x%lx\n",
               i,
               shstrtab_data + shdr[i].sh_name,
               shdr[i].sh_addr,
               shdr[i].sh_size);
    }
    
cleanup:
    munmap(map, st.st_size);
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }
    
    parse_elf(argv[1]);
    return 0;
}
