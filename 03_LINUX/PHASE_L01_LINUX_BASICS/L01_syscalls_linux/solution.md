# MODULE 37 : LINUX SYSCALLS - SOLUTIONS

## Exercice 1
```c
#include <sys/syscall.h>
#include <unistd.h>

syscall(SYS_write, 1, "Hello\n", 6);
char buf[10];
syscall(SYS_read, 0, buf, 10);
int pid = syscall(SYS_getpid);
```

## Exercice 2
```c
long my_write(int fd, const void *buf, size_t count) {
    long ret;
    __asm__ volatile (
        "mov $1, %%rax\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "syscall\n"
        : "=a" (ret)
        : "r" ((long)fd), "r" (buf), "r" (count)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```

## Exercice 4 - Bypass hook
```c
// hook.c (LD_PRELOAD)
ssize_t write(int fd, const void *buf, size_t count) {
    const char *msg = "[HOOKED]\n";
    syscall(SYS_write, fd, msg, 9);
    return syscall(SYS_write, fd, buf, count);
}

// Compile: gcc -shared -fPIC hook.c -o hook.so
// Test: LD_PRELOAD=./hook.so ./program
```
