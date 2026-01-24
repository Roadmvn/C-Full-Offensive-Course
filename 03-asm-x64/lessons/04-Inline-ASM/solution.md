# Solutions : Assembleur Inline

## Solution 1 : Swap XOR

```c
void swap_xor(uint64_t *a, uint64_t *b) {
    __asm__ __volatile__(
        "mov rax, [%0]\n\t"
        "xor rax, [%1]\n\t"
        "mov [%0], rax\n\t"
        "xor rax, [%0]\n\t"
        "xor [%0], rax\n\t"
        "mov [%1], rax"
        :: "r"(a), "r"(b) : "rax", "memory"
    );
}
```

## Solution 2 : Popcount

```c
int popcount_asm(uint64_t val) {
    int count;
    __asm__(
        "xor eax, eax\n\t"
        "1: test %1, %1\n\t"
        "jz 2f\n\t"
        "mov rbx, %1\n\t"
        "and rbx, 1\n\t"
        "add eax, ebx\n\t"
        "shr %1, 1\n\t"
        "jmp 1b\n\t"
        "2: mov %0, eax"
        : "=r"(count), "+r"(val) :: "rax", "rbx", "cc"
    );
    return count;
}
```

## Solution 3 : Syscall getpid

```c
pid_t getpid_asm(void) {
    pid_t pid;
    __asm__ __volatile__(
        "mov rax, 39\n\t"  // sys_getpid
        "syscall"
        : "=a"(pid) :: "rcx", "r11"
    );
    return pid;
}
```

## Solution 4 : Anti-debug

```c
int is_debugged(void) {
    long ret;
    __asm__ __volatile__(
        "mov rax, 101\n\t"     // sys_ptrace
        "xor rdi, rdi\n\t"     // PTRACE_TRACEME
        "xor rsi, rsi\n\t"
        "xor rdx, rdx\n\t"
        "xor r10, r10\n\t"
        "syscall"
        : "=a"(ret) :: "rdi", "rsi", "rdx", "r10", "rcx", "r11"
    );
    return ret < 0;  // -1 = debugged
}
```

## Solution 5 : Shellcode XOR decoder

```c
void decode_shellcode(unsigned char *sc, size_t len, unsigned char key) {
    __asm__ __volatile__(
        "mov rcx, %1\n\t"
        "mov rsi, %0\n\t"
        "1: xor byte ptr [rsi], %2\n\t"
        "inc rsi\n\t"
        "loop 1b"
        :: "r"(sc), "r"(len), "r"(key)
        : "rcx", "rsi", "memory", "cc"
    );
}
```
