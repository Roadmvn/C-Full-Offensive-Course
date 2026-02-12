/*
 * OBJECTIF  : Comprendre les techniques anti-debug sur macOS
 * PREREQUIS : Bases C, ptrace, sysctl, securite macOS
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre les techniques anti-debugging macOS :
 * ptrace(PT_DENY_ATTACH), sysctl, timing, flags CS,
 * et contournements.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/sysctl.h>

/*
 * Etape 1 : Techniques anti-debug macOS
 */
static void explain_antidebug_techniques(void) {
    printf("[*] Etape 1 : Techniques anti-debug macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Anti-Debug Techniques macOS              │\n");
    printf("    │                                          │\n");
    printf("    │  1. ptrace(PT_DENY_ATTACH)  : kernel     │\n");
    printf("    │  2. sysctl(P_TRACED)        : detection  │\n");
    printf("    │  3. Timing checks           : mesure     │\n");
    printf("    │  4. isatty() / ttyname()    : terminal   │\n");
    printf("    │  5. AmIBeingDebugged()      : Foundation │\n");
    printf("    │  6. task_get_exception_ports: Mach       │\n");
    printf("    │  7. CS flags check          : AMFI       │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : ptrace(PT_DENY_ATTACH)
 */
static void demo_ptrace_deny(void) {
    printf("[*] Etape 2 : ptrace(PT_DENY_ATTACH)\n\n");

    printf("    Technique la plus classique sur macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <sys/ptrace.h>\n\n");
    printf("    // Empeche tout debugger de s'attacher\n");
    printf("    ptrace(PT_DENY_ATTACH, 0, 0, 0);\n");
    printf("    // Si un debugger est deja attache -> SIGKILL\n\n");

    printf("    Particularites macOS :\n");
    printf("    - PT_DENY_ATTACH = 31\n");
    printf("    - Appel direct au kernel via syscall\n");
    printf("    - Tue le processus si debugger present\n\n");

    printf("    Appel via syscall (pour eviter la libc) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // x86_64 :\n");
    printf("    __asm__(\"mov $26, %%%%eax\\n\"  // SYS_ptrace\n");
    printf("           \"mov $31, %%%%edi\\n\"  // PT_DENY_ATTACH\n");
    printf("           \"xor %%%%esi, %%%%esi\\n\"\n");
    printf("           \"xor %%%%edx, %%%%edx\\n\"\n");
    printf("           \"syscall\");\n\n");

    printf("    // ARM64 :\n");
    printf("    __asm__(\"mov x0, #31\\n\"     // PT_DENY_ATTACH\n");
    printf("           \"mov x1, #0\\n\"\n");
    printf("           \"mov x2, #0\\n\"\n");
    printf("           \"mov x3, #0\\n\"\n");
    printf("           \"mov x16, #26\\n\"    // SYS_ptrace\n");
    printf("           \"svc #0x80\");\n\n");
}

/*
 * Etape 3 : Detection via sysctl
 */
static void demo_sysctl_detection(void) {
    printf("[*] Etape 3 : Detection via sysctl\n\n");

    printf("    Verifier le flag P_TRACED :\n");
    printf("    ───────────────────────────────────\n");

    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };

    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == 0) {
        int traced = (info.kp_proc.p_flag & 0x800) != 0; /* P_TRACED */
        printf("    PID     : %d\n", getpid());
        printf("    P_TRACED: %s\n\n",
               traced ? "OUI (debugger detecte !)" : "NON (pas de debugger)");
    }

    printf("    Code complet :\n");
    printf("    ───────────────────────────────────\n");
    printf("    int is_debugged(void) {\n");
    printf("        struct kinfo_proc info;\n");
    printf("        size_t size = sizeof(info);\n");
    printf("        int mib[] = {\n");
    printf("            CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()\n");
    printf("        };\n");
    printf("        sysctl(mib, 4, &info, &size, NULL, 0);\n");
    printf("        return (info.kp_proc.p_flag & P_TRACED) != 0;\n");
    printf("    }\n\n");
}

/*
 * Etape 4 : Timing checks
 */
static void demo_timing_check(void) {
    printf("[*] Etape 4 : Timing checks\n\n");

    printf("    Un debugger ralentit l'execution :\n");
    printf("    ───────────────────────────────────\n");

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Operation simple */
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) x += i;

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);
    long elapsed_ms = elapsed_ns / 1000000;

    printf("    Boucle 1M iterations : %ld ms\n", elapsed_ms);
    if (elapsed_ms > 500)
        printf("    [!] Suspicieusement lent (debugger ?)\n");
    else
        printf("    [OK] Vitesse normale\n");
    printf("\n");

    printf("    Technique mach_absolute_time :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <mach/mach_time.h>\n");
    printf("    uint64_t start = mach_absolute_time();\n");
    printf("    // ... code sensible ...\n");
    printf("    uint64_t end = mach_absolute_time();\n");
    printf("    // Si delta > seuil -> debugger detecte\n\n");
}

/*
 * Etape 5 : Exception ports et Mach
 */
static void explain_exception_ports(void) {
    printf("[*] Etape 5 : Detection via exception ports\n\n");

    printf("    Les debuggers utilisent des exception ports :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <mach/mach.h>\n\n");
    printf("    mach_msg_type_number_t count = 0;\n");
    printf("    exception_mask_t masks[EXC_TYPES_COUNT];\n");
    printf("    mach_port_t ports[EXC_TYPES_COUNT];\n");
    printf("    exception_behavior_t behaviors[EXC_TYPES_COUNT];\n");
    printf("    thread_state_flavor_t flavors[EXC_TYPES_COUNT];\n\n");

    printf("    task_get_exception_ports(\n");
    printf("        mach_task_self(),\n");
    printf("        EXC_MASK_ALL,\n");
    printf("        masks, &count, ports, behaviors, flavors);\n\n");
    printf("    // Si un port est non-null -> debugger attache\n");
    printf("    for (int i = 0; i < count; i++) {\n");
    printf("        if (ports[i] != MACH_PORT_NULL) {\n");
    printf("            printf(\"Debugger detecte !\\n\");\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("    Autre detection : isatty\n");
    printf("    ───────────────────────────────────\n");
    printf("    if (isatty(STDOUT_FILENO)) {\n");
    printf("        // Execution depuis un terminal\n");
    printf("    }\n");
    printf("    // Certains debuggers redirigent stdout\n\n");
}

/*
 * Etape 6 : Contournements et detection
 */
static void explain_bypasses(void) {
    printf("[*] Etape 6 : Contournements et detection\n\n");

    printf("    Contournements pour les analystes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Patcher ptrace(PT_DENY_ATTACH)\n");
    printf("       -> NOP le call ou retourner 0\n");
    printf("       -> lldb: process handle -p true -s false SIGSEGV\n\n");

    printf("    2. Patcher sysctl\n");
    printf("       -> Hook sysctl pour masquer P_TRACED\n\n");

    printf("    3. Frida/Cycript\n");
    printf("       -> Injection dynamique\n");
    printf("       -> Bypass automatique des anti-debug\n\n");

    printf("    4. LLDB specifiques :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Ignorer ptrace\n");
    printf("    lldb -n target\n");
    printf("    (lldb) breakpoint set -n ptrace\n");
    printf("    (lldb) thread return 0  # au breakpoint\n\n");

    printf("    Detection pour les defenseurs :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Presense d'anti-debug = indicateur de malware\n");
    printf("    - Combiner plusieurs techniques est suspect\n");
    printf("    - Surveiller les appels ptrace/sysctl\n");
    printf("    - Analyser statiquement le binaire\n\n");
}

int main(void) {
    printf("[*] Demo : Anti-Debug macOS\n\n");

    explain_antidebug_techniques();
    demo_ptrace_deny();
    demo_sysctl_detection();
    demo_timing_check();
    explain_exception_ports();
    explain_bypasses();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
