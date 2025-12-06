#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>

#define BSD_SYSCALL_OFFSET 0x2000000

// BSD syscall direct
long bsd_syscall_write(int fd, const void *buf, size_t count) {
    long ret;
    long syscall_num = BSD_SYSCALL_OFFSET + 4;  // write = 4
    
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "syscall\n"
        "movq %%rax, %0\n"
        : "=r" (ret)
        : "r" (syscall_num), "r" ((long)fd), "r" (buf), "r" (count)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    
    return ret;
}

// Mach trap: task_self
mach_port_t my_task_self() {
    mach_port_t ret;
    
    __asm__ volatile (
        "movq $-28, %%rax\n"  // task_self_trap
        "syscall\n"
        "movl %%eax, %0\n"
        : "=r" (ret)
        :
        : "rax", "rcx", "r11", "memory"
    );
    
    return ret;
}

void demo_bsd_syscall() {
    const char *msg = "Hello via BSD syscall!\n";
    bsd_syscall_write(STDOUT_FILENO, msg, 23);
}

void demo_mach_trap() {
    printf("=== MACH TRAPS ===\n");
    
    mach_port_t task1 = mach_task_self();
    printf("task_self (libc): %d\n", task1);
    
    mach_port_t task2 = my_task_self();
    printf("task_self (trap): %d\n", task2);
}

int main() {
    printf("=== macOS SYSCALLS ===\n\n");
    demo_bsd_syscall();
    demo_mach_trap();
    return 0;
}

/*
 * Compilation:
 * clang -arch arm64 example.c -o example
 * ou
 * clang -arch x86_64 example.c -o example
 */
