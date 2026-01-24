/*
 * Linux Anti-Debug
 * BPFDoor/Symbiote patterns
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <fcntl.h>
#include <dlfcn.h>

// ============================================================================
// PTRACE CHECK
// ============================================================================

int chk_ptrace(void)
{
    if(ptrace(0, 0, 0, 0) < 0) return 1;  // PTRACE_TRACEME
    ptrace(17, 0, 0, 0);  // PTRACE_DETACH
    return 0;
}

int chk_ptrace_fork(void)
{
    int pid = fork();
    if(pid == 0) _exit(0);

    if(ptrace(16, pid, 0, 0) < 0) {  // PTRACE_ATTACH
        waitpid(pid, 0, 0);
        return 1;
    }

    waitpid(pid, 0, 0);
    ptrace(17, pid, 0, 0);
    return 0;
}

// ============================================================================
// TRACERPID CHECK
// ============================================================================

int chk_tracer(void)
{
    char buf[4096];
    int fd = open("/proc/self/status", 0);
    if(fd < 0) return 0;

    int n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    buf[n] = 0;

    char* p = buf;
    while(*p) {
        if(p[0]=='T' && p[1]=='r' && p[2]=='a' && p[3]=='c' &&
           p[4]=='e' && p[5]=='r' && p[6]=='P' && p[7]=='i' && p[8]=='d') {
            p += 10;
            while(*p == '\t' || *p == ' ') p++;
            int pid = 0;
            while(*p >= '0' && *p <= '9') { pid = pid*10 + *p - '0'; p++; }
            return pid != 0;
        }
        p++;
    }
    return 0;
}

// ============================================================================
// PARENT CHECK
// ============================================================================

int chk_parent(void)
{
    char p[64], buf[256];
    int ppid = getppid();

    char* s = p;
    char* fmt = "/proc/";
    while(*fmt) *s++ = *fmt++;
    int t = ppid, d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = ppid;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
    fmt = "/comm";
    while(*fmt) *s++ = *fmt++;
    *s = 0;

    int fd = open(p, 0);
    if(fd < 0) return 0;

    int n = read(fd, buf, 255);
    close(fd);
    buf[n] = 0;

    char* dbg[] = {"gdb", "ltrace", "strace", "lldb", "radare2", "r2", "ida", 0};
    for(int i = 0; dbg[i]; i++) {
        char* a = buf;
        char* b = dbg[i];
        while(*a && *b && *a == *b) { a++; b++; }
        if(!*b && (*a == 0 || *a == '\n')) return 1;
    }
    return 0;
}

// ============================================================================
// ENV CHECK
// ============================================================================

int chk_env(void)
{
    int fd = open("/proc/self/environ", 0);
    if(fd < 0) return 0;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf)-1);
    close(fd);

    char* p = buf;
    while(p < buf + n) {
        if(p[0]=='L' && p[1]=='D' && p[2]=='_' && p[3]=='P')
            return 1;  // LD_PRELOAD
        if(p[0]=='L' && p[1]=='D' && p[2]=='_' && p[3]=='D')
            return 1;  // LD_DEBUG
        while(*p) p++;
        p++;
    }
    return 0;
}

// ============================================================================
// TIMING CHECK
// ============================================================================

int chk_timing(void)
{
    struct timeval t1, t2;
    gettimeofday(&t1, 0);

    volatile int x = 0;
    for(int i = 0; i < 100000; i++) x++;

    gettimeofday(&t2, 0);

    long us = (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
    return us > 100000;  // >100ms = suspicious
}

unsigned long long rdtsc(void)
{
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}

int chk_rdtsc(void)
{
    unsigned long long t1 = rdtsc();

    volatile int x = 0;
    for(int i = 0; i < 100; i++) x++;

    unsigned long long t2 = rdtsc();
    return (t2 - t1) > 10000000;
}

// ============================================================================
// SIGTRAP CHECK
// ============================================================================

static volatile int g_trap = 0;

void trap_h(int s) { g_trap = 1; }

int chk_sigtrap(void)
{
    g_trap = 0;
    signal(5, trap_h);  // SIGTRAP
    __asm__("int $3");
    return g_trap == 0;
}

// ============================================================================
// BREAKPOINT CHECK
// ============================================================================

int chk_bp(void* f)
{
    unsigned char* c = (unsigned char*)f;
    for(int i = 0; i < 16; i++)
        if(c[i] == 0xCC) return 1;
    return 0;
}

// ============================================================================
// FD CHECK
// ============================================================================

int chk_fd(void)
{
    int n = 0;
    for(int fd = 0; fd < 256; fd++) {
        char p[32];
        char* s = p;
        char* fmt = "/proc/self/fd/";
        while(*fmt) *s++ = *fmt++;
        int t = fd, d = 1;
        if(t == 0) { *s++ = '0'; } else {
            while(t >= 10) { d *= 10; t /= 10; }
            t = fd;
            while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
        }
        *s = 0;

        if(access(p, 0) == 0) n++;
    }
    return n > 10;
}

// ============================================================================
// VM CHECK - CPUID
// ============================================================================

int chk_cpuid(void)
{
    unsigned int eax, ebx, ecx, edx;
    __asm__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    return (ecx >> 31) & 1;
}

// ============================================================================
// VM CHECK - DMI
// ============================================================================

int chk_vm(void)
{
    char* files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        0
    };

    for(int i = 0; files[i]; i++) {
        int fd = open(files[i], 0);
        if(fd < 0) continue;

        char buf[256];
        int n = read(fd, buf, 255);
        close(fd);
        buf[n] = 0;

        char* vm[] = {"VirtualBox", "VMware", "QEMU", "KVM", 0};
        for(int j = 0; vm[j]; j++) {
            char* a = buf;
            while(*a) {
                char* b = vm[j];
                char* c = a;
                while(*b && *c && *b == *c) { b++; c++; }
                if(!*b) return 1;
                a++;
            }
        }
    }
    return 0;
}

// ============================================================================
// LD_PRELOAD HOOK DETECT
// ============================================================================

int chk_hooks(void)
{
    void* libc = dlopen("libc.so.6", 2);
    void* real = dlsym(libc, "malloc");
    void* curr = dlsym((void*)-1, "malloc");  // RTLD_NEXT
    return real != curr;
}

// ============================================================================
// SELF-TRACE PREVENTION
// ============================================================================

void self_trace(void)
{
    if(fork() == 0) {
        int ppid = getppid();
        ptrace(16, ppid, 0, 0);  // PTRACE_ATTACH
        waitpid(ppid, 0, 0);

        while(1) {
            ptrace(7, ppid, 0, 0);  // PTRACE_CONT
            waitpid(ppid, 0, 0);
        }
    }
    usleep(100000);
}

// ============================================================================
// SANDBOX DETECT
// ============================================================================

int chk_sandbox(void)
{
    // Low uptime
    int fd = open("/proc/uptime", 0);
    if(fd >= 0) {
        char buf[64];
        read(fd, buf, 63);
        close(fd);

        int up = 0;
        char* p = buf;
        while(*p >= '0' && *p <= '9') { up = up*10 + *p - '0'; p++; }
        if(up < 300) return 1;  // <5min
    }

    // Low process count
    int cnt = 0;
    for(int pid = 1; pid < 1000; pid++) {
        char p[32];
        char* s = p;
        char* fmt = "/proc/";
        while(*fmt) *s++ = *fmt++;
        int t = pid, d = 1;
        while(t >= 10) { d *= 10; t /= 10; }
        t = pid;
        while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
        *s = 0;

        if(access(p, 0) == 0) cnt++;
    }
    if(cnt < 20) return 1;

    return 0;
}

// ============================================================================
// EOF
// ============================================================================
