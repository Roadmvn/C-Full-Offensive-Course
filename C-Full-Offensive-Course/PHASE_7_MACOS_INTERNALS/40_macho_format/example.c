#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach-o/loader.h>

void parse_macho(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }
    
    struct stat st;
    fstat(fd, &st);
    
    void *file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return;
    }
    
    struct mach_header_64 *header = (struct mach_header_64*)file;
    
    printf("=== MACH-O PARSER ===\n\n");
    
    if (header->magic == MH_MAGIC_64) {
        printf("Magic: 0x%x (64-bit)\n", header->magic);
        printf("CPU Type: %d\n", header->cputype);
        printf("CPU Subtype: %d\n", header->cpusubtype);
        printf("File Type: %d\n", header->filetype);
        printf("Number of Load Commands: %d\n", header->ncmds);
        printf("Flags: 0x%x\n\n", header->flags);
        
        struct load_command *lc = (struct load_command*)(header + 1);
        
        for (uint32_t i = 0; i < header->ncmds; i++) {
            printf("Load Command %d:\n", i + 1);
            printf("  Type: 0x%x\n", lc->cmd);
            printf("  Size: %d\n", lc->cmdsize);
            
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64*)lc;
                printf("  Segment: %s\n", seg->segname);
                printf("  VM Address: 0x%llx\n", seg->vmaddr);
                printf("  VM Size: 0x%llx\n", seg->vmsize);
                printf("  Sections: %d\n", seg->nsects);
            }
            
            printf("\n");
            lc = (struct load_command*)((char*)lc + lc->cmdsize);
        }
    } else {
        printf("Not a valid Mach-O 64-bit binary\n");
    }
    
    munmap(file, st.st_size);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <mach-o_binary>\n", argv[0]);
        return 1;
    }
    
    parse_macho(argv[1]);
    
    return 0;
}

