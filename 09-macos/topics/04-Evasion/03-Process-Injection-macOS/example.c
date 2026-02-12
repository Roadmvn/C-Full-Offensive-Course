/*
 * OBJECTIF  : Comprendre l'injection de processus sur macOS
 * PREREQUIS : Bases C, Mach IPC, task_for_pid, AMFI
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre les techniques d'injection de processus
 * sur macOS : task_for_pid, thread injection, mach_vm_*,
 * protections et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>

/*
 * Etape 1 : Architecture d'injection macOS
 */
static void explain_injection_architecture(void) {
    printf("[*] Etape 1 : Architecture d'injection macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Injecteur                                │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ 1. task_for_pid(target)           │    │\n");
    printf("    │  │ 2. mach_vm_allocate(target)       │    │\n");
    printf("    │  │ 3. mach_vm_write(shellcode)       │    │\n");
    printf("    │  │ 4. mach_vm_protect(RX)            │    │\n");
    printf("    │  │ 5. thread_create_running()        │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    │                                          │\n");
    printf("    │  Processus cible                         │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ Code injecte s'execute dans       │    │\n");
    printf("    │  │ l'espace memoire de la cible      │    │\n");
    printf("    │  │ avec ses privileges                │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Prerequis :\n");
    printf("    - Root ou com.apple.system-task-ports\n");
    printf("    - SIP desactive (pour les processus Apple)\n");
    printf("    - get-task-allow sur la cible (dev builds)\n\n");
}

/*
 * Etape 2 : task_for_pid
 */
static void demo_task_for_pid(void) {
    printf("[*] Etape 2 : task_for_pid\n\n");

    printf("    Obtenir le task port d'un processus :\n");
    printf("    ───────────────────────────────────\n");

    /* Demo sur nous-memes */
    mach_port_t self_task = mach_task_self();
    printf("    Notre task port : %d\n\n", self_task);

    printf("    task_for_pid sur un autre processus :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mach_port_t task;\n");
    printf("    kern_return_t kr = task_for_pid(\n");
    printf("        mach_task_self(),\n");
    printf("        target_pid,\n");
    printf("        &task);\n\n");
    printf("    if (kr == KERN_SUCCESS) {\n");
    printf("        // On a le task port !\n");
    printf("        // On peut lire/ecrire la memoire\n");
    printf("    } else {\n");
    printf("        // KERN_FAILURE = pas les droits\n");
    printf("    }\n\n");

    /* Informations sur notre tache */
    struct task_basic_info info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(self_task, TASK_BASIC_INFO,
                                 (task_info_t)&info, &count);
    if (kr == KERN_SUCCESS) {
        printf("    Infos de notre tache :\n");
        printf("      Resident size : %u bytes\n", (unsigned)info.resident_size);
        printf("      Virtual size  : %u bytes\n", (unsigned)info.virtual_size);
        printf("      Suspend count : %d\n", info.suspend_count);
    }
    printf("\n");
}

/*
 * Etape 3 : Allocation et ecriture memoire
 */
static void explain_memory_operations(void) {
    printf("[*] Etape 3 : Operations memoire distantes\n\n");

    printf("    Allouer de la memoire dans la cible :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mach_vm_address_t addr = 0;\n");
    printf("    mach_vm_allocate(task, &addr, size,\n");
    printf("        VM_FLAGS_ANYWHERE);\n\n");

    printf("    Ecrire dans la cible :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mach_vm_write(task, addr,\n");
    printf("        (vm_offset_t)shellcode,\n");
    printf("        shellcode_size);\n\n");

    printf("    Changer les permissions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mach_vm_protect(task, addr, size,\n");
    printf("        FALSE,\n");
    printf("        VM_PROT_READ | VM_PROT_EXECUTE);\n\n");

    printf("    Lire la memoire de la cible :\n");
    printf("    ───────────────────────────────────\n");
    printf("    vm_offset_t data;\n");
    printf("    mach_msg_type_number_t dataCnt;\n");
    printf("    mach_vm_read(task, addr, size,\n");
    printf("        &data, &dataCnt);\n\n");

    /* Demo sur notre propre memoire */
    printf("    Demo : allocation dans notre propre tache :\n");
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_allocate(
        mach_task_self(), &addr, 4096, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) {
        printf("      Alloue 4096 octets a 0x%llx\n", (unsigned long long)addr);
        const char *msg = "Hello from injected memory!";
        memcpy((void *)addr, msg, strlen(msg) + 1);
        printf("      Ecrit : \"%s\"\n", (char *)addr);
        mach_vm_deallocate(mach_task_self(), addr, 4096);
        printf("      Memoire liberee\n");
    }
    printf("\n");
}

/*
 * Etape 4 : Thread injection
 */
static void explain_thread_injection(void) {
    printf("[*] Etape 4 : Thread injection\n\n");

    printf("    Creer un thread dans le processus cible :\n");
    printf("    ───────────────────────────────────\n\n");

    printf("    ARM64 (Apple Silicon) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    arm_thread_state64_t state = {0};\n");
    printf("    state.__pc = (uint64_t)addr;  // shellcode\n");
    printf("    state.__sp = (uint64_t)stack_addr;\n");
    printf("    state.__x[0] = (uint64_t)arg;  // argument\n\n");
    printf("    thread_act_t thread;\n");
    printf("    thread_create_running(task,\n");
    printf("        ARM_THREAD_STATE64,\n");
    printf("        (thread_state_t)&state,\n");
    printf("        ARM_THREAD_STATE64_COUNT,\n");
    printf("        &thread);\n\n");

    printf("    x86_64 (Intel) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    x86_thread_state64_t state = {0};\n");
    printf("    state.__rip = (uint64_t)addr;\n");
    printf("    state.__rsp = (uint64_t)stack_addr;\n");
    printf("    state.__rdi = (uint64_t)arg;\n\n");
    printf("    thread_create_running(task,\n");
    printf("        x86_THREAD_STATE64,\n");
    printf("        (thread_state_t)&state,\n");
    printf("        x86_THREAD_STATE64_COUNT,\n");
    printf("        &thread);\n\n");
}

/*
 * Etape 5 : Techniques alternatives
 */
static void explain_alternatives(void) {
    printf("[*] Etape 5 : Techniques alternatives\n\n");

    printf("    1. DYLD_INSERT_LIBRARIES :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Plus simple mais limite\n");
    printf("    -> Voir module Dylib Injection\n\n");

    printf("    2. dlopen() injection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Injecter un call a dlopen()\n");
    printf("    -> Le thread charge la dylib\n");
    printf("    -> La dylib execute dans le processus\n\n");

    printf("    3. Electrode (Frida-like) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Injection + runtime patching\n");
    printf("    -> JavaScript engine dans le processus\n\n");

    printf("    4. Thread hijacking :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Suspendre un thread existant\n");
    printf("    -> Modifier son PC/RIP\n");
    printf("    -> Reprendre l'execution\n\n");

    /* Lister nos threads */
    printf("    Threads de notre processus :\n");
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
    if (kr == KERN_SUCCESS) {
        printf("      Nombre de threads : %u\n", count);
        for (mach_msg_type_number_t i = 0; i < count && i < 5; i++) {
            printf("      Thread[%u] : port %d\n", i, threads[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threads,
                      count * sizeof(thread_act_t));
    }
    printf("\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Protections macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Protection            | Effet\n");
    printf("    ──────────────────────|──────────────────────\n");
    printf("    SIP                   | Bloque sur processus Apple\n");
    printf("    AMFI                  | Verifie entitlements\n");
    printf("    Hardened Runtime      | Bloque injection\n");
    printf("    Library Validation    | Dylibs non signees refusees\n");
    printf("    task_for_pid restrict | Necessite root + entitlement\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Endpoint Security (task_for_pid events)\n");
    printf("    - Monitorer les appels Mach\n");
    printf("    - Surveiller les allocations memoire\n");
    printf("    - Verifier les threads inattendus\n\n");

    printf("    Commandes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Threads d'un processus\n");
    printf("    sample <pid> 1\n\n");
    printf("    # Memoire d'un processus\n");
    printf("    vmmap <pid>\n\n");
    printf("    # Regions memoire RWX (suspect)\n");
    printf("    vmmap <pid> | grep 'rwx'\n\n");
}

int main(void) {
    printf("[*] Demo : Process Injection macOS\n\n");

    explain_injection_architecture();
    demo_task_for_pid();
    explain_memory_operations();
    explain_thread_injection();
    explain_alternatives();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
