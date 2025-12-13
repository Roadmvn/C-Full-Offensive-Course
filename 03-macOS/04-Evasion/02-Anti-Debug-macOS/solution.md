# SOLUTION : Anti-Debug macOS

## Exercice 1 : Détecter debugger avec sysctl

```c
// detect_debugger.c
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int is_debugger_present() {
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    info.kp_proc.p_flag = 0;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    if (sysctl(mib, 4, &info, &size, NULL, 0) == -1) {
        perror("sysctl");
        return 0;
    }

    // Vérifier flag P_TRACED
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int main() {
    if (is_debugger_present()) {
        printf("[-] Debugger detected! Exiting...\n");
        return 1;
    }

    printf("[+] No debugger detected\n");
    printf("[*] Normal execution continues...\n");

    return 0;
}
```

**Test** :
```bash
./detect_debugger           # No debugger
lldb ./detect_debugger      # Debugger detected
```

---

## Exercice 2 : ptrace anti-debug

```c
// ptrace_anti_debug.c
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>

void anti_debug_ptrace() {
    // PT_DENY_ATTACH empêche attachement de debugger
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
        perror("ptrace");
        return;
    }

    printf("[+] ptrace PT_DENY_ATTACH enabled\n");
    printf("[+] Debugger cannot attach to this process\n");
}

int main() {
    anti_debug_ptrace();

    // Code sensible ici
    printf("[*] Executing sensitive code...\n");
    sleep(10);

    return 0;
}
```

**Test** :
```bash
./ptrace_anti_debug &
PID=$!

# Essayer d'attacher lldb
lldb -p $PID
# Erreur: "unable to attach"
```

---

## Exercice 3 : Timing checks (detect stepping)

```c
// timing_check.c
#include <stdio.h>
#include <mach/mach_time.h>
#include <stdlib.h>

#define THRESHOLD_SECONDS 1

uint64_t get_nanoseconds() {
    static mach_timebase_info_data_t info;
    if (info.denom == 0) {
        mach_timebase_info(&info);
    }

    uint64_t now = mach_absolute_time();
    return (now * info.numer) / info.denom;
}

int detect_debugger_timing() {
    uint64_t start = get_nanoseconds();

    // Instruction simple
    volatile int x = 1 + 1;

    uint64_t end = get_nanoseconds();
    uint64_t diff = end - start;

    // Convertir en secondes
    double seconds = diff / 1000000000.0;

    if (seconds > THRESHOLD_SECONDS) {
        printf("[-] Debugger detected (timing anomaly: %.3f sec)\n", seconds);
        return 1;
    }

    return 0;
}

int main() {
    printf("[*] Performing timing check...\n");

    if (detect_debugger_timing()) {
        printf("[-] Execution stopped\n");
        exit(1);
    }

    printf("[+] Timing check passed\n");
    return 0;
}
```

---

## Exercice 4 : Exception handling anti-debug

```c
// exception_anti_debug.c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

jmp_buf jump_buffer;

void sigtrap_handler(int sig) {
    printf("[+] SIGTRAP caught - debugger present\n");
    exit(1);
}

void check_breakpoint() {
    signal(SIGTRAP, sigtrap_handler);

    // Générer breakpoint
    __asm__("int $3");

    // Si on arrive ici, pas de debugger
    printf("[+] No debugger (breakpoint not hit)\n");
}

int main() {
    check_breakpoint();
    return 0;
}
```

---

## Exercice 5 : Check parent process (lldb/gdb)

```c
// check_parent.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libproc.h>
#include <string.h>

int is_debugger_parent() {
    pid_t ppid = getppid();

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(ppid, pathbuf, sizeof(pathbuf));

    printf("[*] Parent process: %s (PID %d)\n", pathbuf, ppid);

    // Vérifier si parent est debugger
    if (strstr(pathbuf, "lldb") || strstr(pathbuf, "gdb") ||
        strstr(pathbuf, "debugserver")) {
        return 1;
    }

    return 0;
}

int main() {
    if (is_debugger_parent()) {
        printf("[-] Debugger detected as parent!\n");
        exit(1);
    }

    printf("[+] Normal parent process\n");
    return 0;
}
```

---

## Exercice 6 : Anti-debug multi-techniques

```c
// anti_debug_complete.c
#include <sys/sysctl.h>
#include <sys/ptrace.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int check_sysctl() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);

    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int check_timing() {
    uint64_t start = mach_absolute_time();
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x++;
    uint64_t end = mach_absolute_time();

    return (end - start) > 100000000; // Threshold
}

void anti_debug_init() {
    // 1. ptrace
    ptrace(PT_DENY_ATTACH, 0, 0, 0);

    // 2. sysctl
    if (check_sysctl()) {
        printf("[-] sysctl: Debugger detected\n");
        exit(1);
    }

    // 3. Timing
    if (check_timing()) {
        printf("[-] Timing: Debugger detected\n");
        exit(1);
    }

    printf("[+] All anti-debug checks passed\n");
}

int main() {
    anti_debug_init();

    // Code sensible
    printf("[*] Executing payload...\n");

    // Check périodique
    while (1) {
        if (check_sysctl()) {
            printf("[-] Debugger attached during execution!\n");
            exit(1);
        }

        sleep(1);
        printf(".");
        fflush(stdout);
    }

    return 0;
}
```

---

## Exercice 7 : Obfuscation anti-analysis

```c
// obfuscated.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// XOR string encryption
void decrypt_string(char *str, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Anti-disassembly: fake functions
__attribute__((always_inline))
inline void fake_func1() { asm("nop"); }

__attribute__((always_inline))
inline void fake_func2() { asm("nop"); }

int main() {
    // String chiffrée
    char msg[] = {0x0B, 0x1A, 0x1D, 0x1D, 0x18, 0x53, 0x38, 0x18, 0x15, 0x1D, 0x1B, 0x42};
    decrypt_string(msg, sizeof(msg), 0x69);

    printf("%s\n", msg); // "Hello World!"

    // Confuse disassembler
    fake_func1();
    fake_func2();

    return 0;
}
```

---

## Exercice 8 : Bypass anti-debug (Blue Team / Reversing)

**Method 1: Patch ptrace call**

```bash
# Ouvrir dans lldb
lldb ./ptrace_anti_debug

# Find ptrace call
(lldb) image lookup -n ptrace
# Address: 0x...

# Breakpoint avant ptrace
(lldb) b main

# Run et skip ptrace
(lldb) run
(lldb) ni  # step jusqu'à ptrace
(lldb) thread return 0  # Force return 0
(lldb) continue
```

**Method 2: Modifier binary**

```bash
# Hex edit ptrace call to NOP
hexdump -C ptrace_anti_debug | grep ptrace
# Offset: 0x1234

# Patch (remplacer par NOP: 0x90)
printf '\x90\x90\x90\x90' | dd of=ptrace_anti_debug bs=1 seek=$((0x1234)) conv=notrunc
```

**Method 3: LD_PRELOAD hook (ne fonctionne pas sur macOS SIP)**

```c
// ptrace_hook.c
int ptrace(int request, pid_t pid, caddr_t addr, int data) {
    // Return success sans faire appel réel
    return 0;
}
```

---

## Resources

- [ptrace man page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html)
- [Anti-Debug Tricks](https://github.com/yellowbyte/analysis-of-anti-analysis)
- [P_TRACED flag](https://opensource.apple.com/source/xnu/xnu-792.13.8/bsd/sys/proc.h)
