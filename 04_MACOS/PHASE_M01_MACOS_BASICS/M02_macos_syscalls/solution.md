# MODULE 42 : macOS SYSCALLS - SOLUTIONS

## BSD write syscall
```c
#define SYS_write (0x2000000 + 4)

long my_write(int fd, const void *buf, size_t count) {
    long ret;
    __asm__ volatile (
        "movq %1, %%rax\n"    // syscall number
        "movq %2, %%rdi\n"    // fd
        "movq %3, %%rsi\n"    // buf
        "movq %4, %%rdx\n"    // count
        "syscall\n"
        : "=a" (ret)
        : "r" ((long)SYS_write), "r" ((long)fd), 
          "r" (buf), "r" (count)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```

## getpid
```c
#define SYS_getpid (0x2000000 + 20)

pid_t my_getpid() {
    long ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "syscall\n"
        : "=a" (ret)
        : "r" ((long)SYS_getpid)
        : "rcx", "r11"
    );
    return (pid_t)ret;
}
```

## Mach traps
```c
// task_self
#define TASK_SELF_TRAP -28

mach_port_t my_task_self() {
    mach_port_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "syscall\n"
        : "=a" (ret)
        : "r" ((long)TASK_SELF_TRAP)
        : "rcx", "r11"
    );
    return ret;
}
```

## Hook bypass
```c
// hook.c (DYLD_INSERT_LIBRARIES)
ssize_t write(int fd, const void *buf, size_t count) {
    const char *msg = "[HOOKED]\n";
    // Utiliser syscall direct pour éviter récursion
    __asm__ volatile (
        "movq $0x2000004, %%rax\n"
        "movq %0, %%rdi\n"
        "leaq %1, %%rsi\n"
        "movq $9, %%rdx\n"
        "syscall\n"
        :
        : "r" ((long)fd), "m" (*msg)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11"
    );
    
    // Vrai write
    return bsd_syscall_write(fd, buf, count);
}

// Compilation:
// clang -shared -fPIC hook.c -o hook.dylib
// DYLD_INSERT_LIBRARIES=./hook.dylib ./program
```
