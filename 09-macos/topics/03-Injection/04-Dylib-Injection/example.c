/*
 * OBJECTIF  : Comprendre l'injection de dylib sur macOS
 * PREREQUIS : Bases C, Mach-O, dyld, code signing
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre les techniques d'injection de dylib :
 * DYLD_INSERT_LIBRARIES, dylib hijacking, task_for_pid,
 * protections et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

/*
 * Etape 1 : Architecture dyld macOS
 */
static void explain_dyld_architecture(void) {
    printf("[*] Etape 1 : Architecture dyld (dynamic linker)\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Execution d'un binaire Mach-O            │\n");
    printf("    │                                          │\n");
    printf("    │  1. Kernel charge le Mach-O              │\n");
    printf("    │  2. Kernel charge dyld (/usr/lib/dyld)   │\n");
    printf("    │  3. dyld parse les load commands         │\n");
    printf("    │     ├── LC_LOAD_DYLIB (dependances)     │\n");
    printf("    │     ├── LC_RPATH (chemins de recherche)  │\n");
    printf("    │     └── LC_MAIN (point d'entree)        │\n");
    printf("    │  4. dyld charge les dylibs               │\n");
    printf("    │  5. dyld resout les symboles             │\n");
    printf("    │  6. dyld execute les constructeurs        │\n");
    printf("    │  7. Transfert au main()                  │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Variables d'environnement dyld :\n");
    printf("    ───────────────────────────────────\n");
    printf("    DYLD_INSERT_LIBRARIES : injecter une dylib\n");
    printf("    DYLD_LIBRARY_PATH     : chemin de recherche\n");
    printf("    DYLD_FRAMEWORK_PATH   : chemin frameworks\n");
    printf("    DYLD_PRINT_LIBRARIES  : debug chargement\n\n");
}

/*
 * Etape 2 : DYLD_INSERT_LIBRARIES
 */
static void explain_dyld_insert(void) {
    printf("[*] Etape 2 : DYLD_INSERT_LIBRARIES\n\n");

    printf("    Technique d'injection la plus simple :\n");
    printf("    ───────────────────────────────────\n");
    printf("    DYLD_INSERT_LIBRARIES=/path/evil.dylib /target\n\n");

    printf("    Code de la dylib malveillante :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // evil.c\n");
    printf("    // clang -shared -o evil.dylib evil.c\n");
    printf("    #include <stdio.h>\n\n");
    printf("    __attribute__((constructor))\n");
    printf("    void inject(void) {\n");
    printf("        printf(\"[!] Code injecte !\\n\");\n");
    printf("        // Le code s'execute AVANT le main()\n");
    printf("    }\n\n");

    printf("    Restrictions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    DYLD_INSERT_LIBRARIES est IGNORE si :\n");
    printf("    - Le binaire est setuid/setgid\n");
    printf("    - Le binaire a le flag CS_RESTRICT\n");
    printf("    - Le binaire a Library Validation\n");
    printf("    - Le binaire a le hardened runtime\n");
    printf("    - SIP est active (pour les binaires Apple)\n\n");

    /* Verifier la variable */
    const char *dyld_insert = getenv("DYLD_INSERT_LIBRARIES");
    printf("    DYLD_INSERT_LIBRARIES actuel : %s\n\n",
           dyld_insert ? dyld_insert : "(non defini)");
}

/*
 * Etape 3 : Dylib hijacking
 */
static void explain_dylib_hijacking(void) {
    printf("[*] Etape 3 : Dylib hijacking\n\n");

    printf("    Principe : placer une dylib malveillante\n");
    printf("    la ou l'application la cherche en premier\n\n");

    printf("    Ordre de recherche dyld :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. DYLD_LIBRARY_PATH (si pas restrict)\n");
    printf("    2. LC_RPATH du binaire\n");
    printf("    3. Chemin absolu dans LC_LOAD_DYLIB\n");
    printf("    4. DYLD_FALLBACK_LIBRARY_PATH\n");
    printf("    5. /usr/local/lib, /usr/lib\n\n");

    printf("    Types de hijacking :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Weak dylib hijacking\n");
    printf("       -> LC_LOAD_WEAK_DYLIB : pas d'erreur si absent\n");
    printf("       -> Placer la dylib au chemin attendu\n\n");
    printf("    2. Rpath hijacking\n");
    printf("       -> Le binaire cherche @rpath/lib.dylib\n");
    printf("       -> Placer la dylib dans un rpath prioritaire\n\n");
    printf("    3. Proxy dylib\n");
    printf("       -> Remplacer la dylib legitime\n");
    printf("       -> Re-exporter les symboles originaux\n");
    printf("       -> Ajouter du code malveillant\n\n");

    printf("    Trouver les cibles vulnerables :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Lister les dylibs chargees\n");
    printf("    otool -L /path/to/binary\n\n");
    printf("    # Trouver les weak dylibs\n");
    printf("    otool -l /path/to/binary | grep -A2 LOAD_WEAK\n\n");
    printf("    # Trouver les rpaths\n");
    printf("    otool -l /path/to/binary | grep -A2 LC_RPATH\n\n");
}

/*
 * Etape 4 : Injection via task_for_pid
 */
static void explain_task_injection(void) {
    printf("[*] Etape 4 : Injection via task_for_pid\n\n");

    printf("    task_for_pid permet d'obtenir le task port\n");
    printf("    d'un processus pour injecter du code :\n\n");

    printf("    Code d'injection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <mach/mach.h>\n\n");
    printf("    mach_port_t task;\n");
    printf("    kern_return_t kr;\n\n");
    printf("    // Obtenir le task port\n");
    printf("    kr = task_for_pid(mach_task_self(), target_pid, &task);\n");
    printf("    if (kr != KERN_SUCCESS) {\n");
    printf("        // Necessite root ou entitlement special\n");
    printf("        return;\n");
    printf("    }\n\n");
    printf("    // Allouer de la memoire dans le processus cible\n");
    printf("    mach_vm_address_t addr = 0;\n");
    printf("    mach_vm_allocate(task, &addr, size,\n");
    printf("        VM_FLAGS_ANYWHERE);\n\n");
    printf("    // Ecrire le code/path de la dylib\n");
    printf("    mach_vm_write(task, addr, (vm_offset_t)data, size);\n\n");
    printf("    // Creer un thread distant\n");
    printf("    thread_act_t thread;\n");
    printf("    thread_create_running(task, ARM_THREAD_STATE64,\n");
    printf("        (thread_state_t)&state, count, &thread);\n\n");

    printf("    Restrictions :\n");
    printf("    - Necessite root ou com.apple.system-task-ports\n");
    printf("    - SIP bloque sur les processus Apple\n");
    printf("    - AMFI verifie les entitlements\n\n");
}

/*
 * Etape 5 : Dylibs chargees dans le processus courant
 */
static void demo_loaded_dylibs(void) {
    printf("[*] Etape 5 : Dylibs chargees (processus courant)\n\n");

    uint32_t count = _dyld_image_count();
    printf("    Nombre de dylibs chargees : %u\n\n", count);

    printf("    Premieres dylibs :\n");
    for (uint32_t i = 0; i < count && i < 15; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            printf("      [%2u] %s\n", i, name);
        }
    }
    if (count > 15) printf("      ... (%u autres)\n", count - 15);
    printf("\n");

    /* Tester dlopen */
    printf("    Test dlopen (chargement dynamique) :\n");
    void *handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
    if (handle) {
        printf("      libSystem.B.dylib : charge avec succes\n");
        dlclose(handle);
    } else {
        printf("      Erreur : %s\n", dlerror());
    }
    printf("\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Protections Apple :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Protection          | Effet\n");
    printf("    ────────────────────|──────────────────────────\n");
    printf("    Library Validation  | Dylibs meme TeamID requis\n");
    printf("    Hardened Runtime    | Bloque DYLD_INSERT\n");
    printf("    CS_RESTRICT         | Variables DYLD ignorees\n");
    printf("    SIP                 | Protege binaires systeme\n");
    printf("    AMFI                | Verifie signatures dylibs\n\n");

    printf("    Commandes de detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Verifier les dylibs d'un processus\n");
    printf("    vmmap <pid> | grep dylib\n\n");
    printf("    # Verifier les variables DYLD\n");
    printf("    env | grep DYLD\n\n");
    printf("    # Verifier les flags d'un binaire\n");
    printf("    codesign -dvvv /path/binary 2>&1 | grep flags\n\n");

    printf("    Outils :\n");
    printf("    - dylib-hijack-scanner (Patrick Wardle)\n");
    printf("    - Objective-See tools\n");
    printf("    - Endpoint Security (ES_EVENT_TYPE_AUTH_EXEC)\n");
    printf("    - dtrace pour tracer dyld\n\n");
}

int main(void) {
    printf("[*] Demo : Dylib Injection macOS\n\n");

    explain_dyld_architecture();
    explain_dyld_insert();
    explain_dylib_hijacking();
    explain_task_injection();
    demo_loaded_dylibs();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
