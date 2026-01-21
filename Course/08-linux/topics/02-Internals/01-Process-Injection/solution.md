# MODULE L09 : PROCESS INJECTION - SOLUTIONS

## Exercice 1 : Attacher/Détacher
```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    printf("[+] Attached\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
```

## Exercice 2 : Lire registres
```c
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    struct user_regs_struct regs;

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    printf("RIP: 0x%llx\n", regs.rip);
    printf("RSP: 0x%llx\n", regs.rsp);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
```

## Exercice 4 : Écrire mémoire
```c
int write_memory(pid_t pid, unsigned long addr, void *data, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        long word = *(long*)((char*)data + i);
        ptrace(PTRACE_POKEDATA, pid, addr + i, word);
    }
    return 0;
}
```

## Exercice 6 : process_vm_writev
```c
#include <sys/uio.h>

int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 16);

    char data[] = "Test data";
    struct iovec local = {.iov_base = data, .iov_len = sizeof(data)};
    struct iovec remote = {.iov_base = (void*)addr, .iov_len = sizeof(data)};

    process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return 0;
}
```
