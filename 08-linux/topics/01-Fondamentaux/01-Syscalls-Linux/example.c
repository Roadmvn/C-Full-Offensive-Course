#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

// Syscall direct avec inline assembly
long my_syscall_write(int fd, const void *buf, size_t count) {
    long ret;
    __asm__ volatile (
        "mov $1, %%rax\n"      // syscall number (write = 1)
        "mov %1, %%rdi\n"      // arg1: fd
        "mov %2, %%rsi\n"      // arg2: buf
        "mov %3, %%rdx\n"      // arg3: count
        "syscall\n"
        "mov %%rax, %0\n"      // return value
        : "=r" (ret)
        : "r" ((long)fd), "r" (buf), "r" (count)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    return ret;
}

// Avec syscall()
void demo_syscall() {
    const char *msg = "Hello via syscall!\n";
    syscall(SYS_write, STDOUT_FILENO, msg, 19);
}

// Avec inline asm
void demo_inline_asm() {
    const char *msg = "Hello via inline asm!\n";
    my_syscall_write(STDOUT_FILENO, msg, 22);
}

// getpid direct
pid_t my_getpid() {
    long ret;
    __asm__ volatile (
        "mov $39, %%rax\n"
        "syscall\n"
        : "=a" (ret)
        :
        : "rcx", "r11", "memory"
    );
    return (pid_t)ret;
}

int main() {
    printf("=== LINUX SYSCALLS ===\n");
    
    demo_syscall();
    demo_inline_asm();
    
    printf("PID (libc): %d\n", getpid());
    printf("PID (syscall): %d\n", my_getpid());
    
    return 0;
}
