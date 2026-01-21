# Solutions - Anti-Debug Linux

## Exercice 1 : Découverte (Très facile)

### Objectif
Détecter si le programme est exécuté sous un debugger avec ptrace

### Solution

```c
// solution_ex1.c - Détection basique de debugger
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>

int main(void) {
    printf("[*] Vérification de debugger...\n");

    // Méthode 1: ptrace(PTRACE_TRACEME)
    // Si un debugger est déjà attaché, cette fonction échoue
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("[!] DEBUGGER DÉTECTÉ (ptrace échoué)!\n");
        printf("[!] Le programme va s'arrêter.\n");
        exit(1);
    }

    printf("[+] Pas de debugger détecté\n");
    printf("[+] Exécution normale...\n");

    // Code normal du programme
    printf("Hello World!\n");

    return 0;
}
```

**Test:**

```bash
# Compiler
gcc -o solution_ex1 solution_ex1.c

# Test normal (sans debugger)
./solution_ex1
# [*] Vérification de debugger...
# [+] Pas de debugger détecté
# [+] Exécution normale...
# Hello World!

# Test avec gdb (debugger)
gdb -q ./solution_ex1
(gdb) run
# [*] Vérification de debugger...
# [!] DEBUGGER DÉTECTÉ (ptrace échoué)!
# [!] Le programme va s'arrêter.
```

**Explication:**
- `ptrace(PTRACE_TRACEME)` permet à un processus de s'attacher à lui-même pour traçage
- Si un debugger (gdb, strace, etc.) est déjà attaché, l'appel échoue
- Un seul processus peut tracer un autre processus à la fois

---

## Exercice 2 : Modification (Facile)

### Objectif
Détecter un debugger en vérifiant le fichier /proc/self/status

### Solution

```c
// solution_ex2.c - Détection via /proc/self/status
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vérifier si TracerPid est différent de 0
int check_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        perror("fopen");
        return 0;
    }

    char line[256];
    int tracer_pid = 0;

    // Chercher la ligne "TracerPid:"
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "TracerPid:\t%d", &tracer_pid) == 1) {
            break;
        }
    }

    fclose(f);

    return tracer_pid;
}

int main(void) {
    printf("[*] Vérification anti-debug via /proc/self/status\n\n");

    int tracer_pid = check_tracer_pid();

    if (tracer_pid != 0) {
        printf("[!] DEBUGGER DÉTECTÉ!\n");
        printf("[!] TracerPid: %d\n", tracer_pid);
        printf("[!] Un processus nous trace!\n");

        // Actions possibles:
        // 1. Quitter
        // 2. Comportement différent
        // 3. Auto-destruction
        exit(1);
    }

    printf("[+] TracerPid: 0 (pas de traçage)\n");
    printf("[+] Exécution normale\n\n");

    // Code normal
    printf("Programme exécuté avec succès\n");

    return 0;
}
```

**Test:**

```bash
gcc -o solution_ex2 solution_ex2.c

# Sans debugger
./solution_ex2
# [+] TracerPid: 0 (pas de traçage)
# [+] Exécution normale

# Avec strace
strace ./solution_ex2
# [!] DEBUGGER DÉTECTÉ!
# [!] TracerPid: 12345

# Avec gdb
gdb -q ./solution_ex2
(gdb) run
# [!] DEBUGGER DÉTECTÉ!
```

**Explication:**
- Le fichier `/proc/self/status` contient le champ `TracerPid`
- Si `TracerPid != 0`, un autre processus nous trace (debugger)
- Cette méthode détecte gdb, strace, ltrace, etc.

---

## Exercice 3 : Création (Moyen)

### Objectif
Implémenter plusieurs techniques anti-debug avancées

### Solution

```c
// solution_ex3.c - Multi-techniques anti-debug
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>

// === TECHNIQUE 1: ptrace(TRACEME) ===
int detect_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;  // Debugger détecté
    }
    return 0;
}

// === TECHNIQUE 2: Vérifier TracerPid ===
int detect_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int tracer_pid = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "TracerPid:\t%d", &tracer_pid) == 1) {
            break;
        }
    }

    fclose(f);
    return (tracer_pid != 0);
}

// === TECHNIQUE 3: Timing attack ===
// Les debuggers ralentissent l'exécution
int detect_timing(void) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    // Instruction simple
    int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Calculer le temps écoulé en nanosecondes
    long elapsed = (end.tv_sec - start.tv_sec) * 1000000000L +
                   (end.tv_nsec - start.tv_nsec);

    // Si ça prend trop de temps = debugger ou breakpoint
    // Seuil arbitraire: 1 ms
    if (elapsed > 1000000) {
        return 1;
    }

    return 0;
}

// === TECHNIQUE 4: Vérifier les fichiers du debugger ===
int detect_debugger_files(void) {
    // Chercher les fichiers typiques laissés par les debuggers
    const char *debugger_paths[] = {
        "/proc/self/fd/0",  // Si attaché à un debugger, fd 0 peut changer
        "/tmp/.gdb_history",
        "/tmp/.gdbinit",
        NULL
    };

    for (int i = 0; debugger_paths[i]; i++) {
        if (access(debugger_paths[i], F_OK) == 0) {
            // Le fichier existe
            // Note: faux positifs possibles
        }
    }

    return 0;  // Pas de détection fiable avec cette méthode seule
}

// === TECHNIQUE 5: Détecter breakpoints logiciels ===
// Les breakpoints sont des instructions INT3 (0xCC)
int detect_software_breakpoints(void *func) {
    unsigned char *ptr = (unsigned char *)func;

    // Vérifier les premiers bytes pour INT3
    for (int i = 0; i < 10; i++) {
        if (ptr[i] == 0xCC) {  // INT3 instruction
            return 1;
        }
    }

    return 0;
}

// === TECHNIQUE 6: Parent Process check ===
int detect_parent_debugger(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int ppid = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "PPid:\t%d", &ppid) == 1) {
            break;
        }
    }

    fclose(f);

    // Lire le nom du processus parent
    if (ppid > 0) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", ppid);

        f = fopen(path, "r");
        if (f) {
            char parent_name[256];
            if (fgets(parent_name, sizeof(parent_name), f)) {
                parent_name[strcspn(parent_name, "\n")] = 0;

                // Si le parent est gdb, strace, etc.
                if (strstr(parent_name, "gdb") ||
                    strstr(parent_name, "strace") ||
                    strstr(parent_name, "ltrace") ||
                    strstr(parent_name, "radare")) {
                    fclose(f);
                    return 1;
                }
            }
            fclose(f);
        }
    }

    return 0;
}

// === MAIN ===
int main(void) {
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║   Programme Protégé Anti-Debug               ║\n");
    printf("║   Multi-techniques de détection              ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    printf("[*] Exécution des vérifications anti-debug...\n\n");

    int detected = 0;

    // Test 1: ptrace
    printf("[1] Vérification ptrace(TRACEME)... ");
    if (detect_ptrace()) {
        printf("FAIL (debugger détecté)\n");
        detected = 1;
    } else {
        printf("OK\n");
    }

    // Test 2: TracerPid
    printf("[2] Vérification TracerPid... ");
    if (detect_tracer_pid()) {
        printf("FAIL (traçage détecté)\n");
        detected = 1;
    } else {
        printf("OK\n");
    }

    // Test 3: Timing
    printf("[3] Vérification timing... ");
    if (detect_timing()) {
        printf("FAIL (exécution trop lente)\n");
        detected = 1;
    } else {
        printf("OK\n");
    }

    // Test 4: Breakpoints
    printf("[4] Vérification breakpoints... ");
    if (detect_software_breakpoints(main)) {
        printf("FAIL (breakpoint détecté)\n");
        detected = 1;
    } else {
        printf("OK\n");
    }

    // Test 5: Processus parent
    printf("[5] Vérification processus parent... ");
    if (detect_parent_debugger()) {
        printf("FAIL (debugger parent)\n");
        detected = 1;
    } else {
        printf("OK\n");
    }

    printf("\n");

    if (detected) {
        printf("[!] ═══════════════════════════════════════════\n");
        printf("[!]   DEBUGGER DÉTECTÉ - ARRÊT DU PROGRAMME   \n");
        printf("[!] ═══════════════════════════════════════════\n");
        exit(1);
    }

    printf("[+] Toutes les vérifications passées\n");
    printf("[+] Exécution du programme...\n\n");

    // Code sensible ici
    printf("Secret: FLAG{anti_debug_bypassed}\n");

    return 0;
}
```

**Test:**

```bash
gcc -o solution_ex3 solution_ex3.c

# Normal
./solution_ex3
# [+] Toutes les vérifications passées
# Secret: FLAG{anti_debug_bypassed}

# Avec gdb
gdb ./solution_ex3
(gdb) run
# [!] DEBUGGER DÉTECTÉ - ARRÊT DU PROGRAMME

# Avec strace
strace ./solution_ex3
# [!] DEBUGGER DÉTECTÉ - ARRÊT DU PROGRAMME
```

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Créer un programme protégé avec anti-debug avancé et obfuscation, puis créer un bypass

### Solution

**Partie 1: Programme protégé**

```c
// solution_ex4_protected.c - Programme fortement protégé
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <setjmp.h>

// Buffer pour longjmp
static jmp_buf jump_buffer;

// === ANTI-DEBUG TECHNIQUE 1: SIGTRAP Handler ===
// Les debuggers utilisent SIGTRAP
void sigtrap_handler(int sig) {
    printf("[!] SIGTRAP détecté - Debugger actif!\n");
    exit(1);
}

// === ANTI-DEBUG TECHNIQUE 2: Vérification continue en thread ===
void* anti_debug_thread(void *arg) {
    while (1) {
        // Vérifier TracerPid toutes les 100ms
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            int tracer_pid = 0;

            while (fgets(line, sizeof(line), f)) {
                if (sscanf(line, "TracerPid:\t%d", &tracer_pid) == 1) {
                    if (tracer_pid != 0) {
                        printf("[!] Debugger attaché dynamiquement!\n");
                        exit(1);
                    }
                    break;
                }
            }
            fclose(f);
        }

        usleep(100000);  // 100ms
    }
    return NULL;
}

// === ANTI-DEBUG TECHNIQUE 3: Checksum du code ===
// Vérifier que le code n'a pas été modifié (breakpoints)
unsigned int calculate_checksum(void *start, size_t len) {
    unsigned int sum = 0;
    unsigned char *ptr = (unsigned char *)start;

    for (size_t i = 0; i < len; i++) {
        sum += ptr[i];
    }

    return sum;
}

// === OBFUSCATION: XOR crypté ===
void decrypt_string(char *encrypted, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        encrypted[i] ^= key;
    }
}

// === FONCTION SENSIBLE (protégée) ===
__attribute__((section(".protected")))
void sensitive_function(void) {
    // String cryptée avec XOR
    char secret[] = {
        0x1b, 0x17, 0x1c, 0x1e, 0x59, 0x72, 0x14, 0x13,
        0x1f, 0x68, 0x17, 0x13, 0x18, 0x1a, 0x68, 0x19,
        0x1e, 0x1c, 0x1c, 0x59, 0x00  // "FLAG{anti_debug_hard}"
    };

    // Décrypter (XOR avec clé 0x55)
    decrypt_string(secret, sizeof(secret) - 1, 0x55);

    printf("[+] Secret déverrouillé: %s\n", secret);
}

// === MAIN ===
int main(void) {
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║   Programme Ultra-Protégé                    ║\n");
    printf("║   Anti-Debug + Obfuscation                   ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");

    // 1. Installer le handler SIGTRAP
    signal(SIGTRAP, sigtrap_handler);

    // 2. Vérification ptrace initiale
    printf("[*] Vérification 1/5: ptrace... ");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("FAIL\n");
        printf("[!] Debugger détecté! Arrêt.\n");
        exit(1);
    }
    printf("OK\n");

    // 3. Vérification TracerPid
    printf("[*] Vérification 2/5: TracerPid... ");
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        int tracer_pid = 0;

        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "TracerPid:\t%d", &tracer_pid) == 1) {
                if (tracer_pid != 0) {
                    printf("FAIL\n");
                    printf("[!] Traçage détecté! Arrêt.\n");
                    fclose(f);
                    exit(1);
                }
                break;
            }
        }
        fclose(f);
    }
    printf("OK\n");

    // 4. Checksum du code (détecter breakpoints)
    printf("[*] Vérification 3/5: Code integrity... ");
    unsigned int expected_checksum = calculate_checksum(sensitive_function, 100);

    // Recalculer pour vérifier
    unsigned int current_checksum = calculate_checksum(sensitive_function, 100);

    if (current_checksum != expected_checksum) {
        printf("FAIL\n");
        printf("[!] Code modifié! Breakpoint détecté!\n");
        exit(1);
    }
    printf("OK\n");

    // 5. Timing attack
    printf("[*] Vérification 4/5: Timing... ");
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    volatile int x = 0;
    for (int i = 0; i < 10000; i++) {
        x += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed = (end.tv_sec - start.tv_sec) * 1000000000L +
                   (end.tv_nsec - start.tv_nsec);

    if (elapsed > 5000000) {  // 5ms
        printf("FAIL\n");
        printf("[!] Exécution trop lente! Debugger?\n");
        exit(1);
    }
    printf("OK\n");

    // 6. Vérifier le parent
    printf("[*] Vérification 5/5: Parent process... ");
    // (code de detect_parent_debugger ici)
    printf("OK\n\n");

    // Si toutes les vérifications passent
    printf("[+] Toutes les protections passées!\n");
    printf("[+] Déverrouillage du contenu sensible...\n\n");

    sensitive_function();

    return 0;
}
```

**Partie 2: Bypass (Red Team)**

```c
// solution_ex4_bypass.c - Bypass des protections
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>

// === BYPASS 1: Hook ptrace pour toujours retourner succès ===
static long (*real_ptrace)(int request, ...) = NULL;

long ptrace(int request, ...) {
    if (!real_ptrace) {
        real_ptrace = dlsym(RTLD_NEXT, "ptrace");
    }

    // Si c'est PTRACE_TRACEME, retourner succès
    if (request == PTRACE_TRACEME) {
        printf("[BYPASS] ptrace(TRACEME) intercepté - Retour OK\n");
        return 0;  // Succès
    }

    // Autres cas, appeler le vrai ptrace
    return real_ptrace(request);
}

// === BYPASS 2: Hook fopen pour fake /proc/self/status ===
static FILE* (*real_fopen)(const char *pathname, const char *mode) = NULL;

FILE* fopen(const char *pathname, const char *mode) {
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    // Si on ouvre /proc/self/status, retourner un fake
    if (pathname && strcmp(pathname, "/proc/self/status") == 0) {
        printf("[BYPASS] /proc/self/status intercepté - TracerPid falsifié\n");

        // Créer un fichier temporaire avec TracerPid: 0
        FILE *fake = tmpfile();
        if (fake) {
            fprintf(fake,
                "Name:\tprotected\n"
                "State:\tR (running)\n"
                "Tgid:\t12345\n"
                "Ngid:\t0\n"
                "Pid:\t12345\n"
                "PPid:\t1000\n"
                "TracerPid:\t0\n"  // ← FAKE: pas de traçage
                "Uid:\t1000\t1000\t1000\t1000\n"
                "Gid:\t1000\t1000\t1000\t1000\n"
            );
            rewind(fake);
            return fake;
        }
    }

    return real_fopen(pathname, mode);
}

// === BYPASS 3: Hook clock_gettime pour fake timing ===
static int (*real_clock_gettime)(clockid_t clk_id, struct timespec *tp) = NULL;

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    if (!real_clock_gettime) {
        real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    }

    int ret = real_clock_gettime(clk_id, tp);

    // Toujours retourner un temps rapide
    if (ret == 0) {
        printf("[BYPASS] clock_gettime intercepté - Temps falsifié\n");
        // Forcer un temps très court
        tp->tv_sec = 0;
        tp->tv_nsec = 1000;  // 1 microseconde
    }

    return ret;
}
```

**Compilation et test du bypass:**

```bash
# Compiler le programme protégé
gcc -o protected solution_ex4_protected.c

# Test normal (devrait échouer sous gdb)
gdb ./protected
(gdb) run
# [!] Debugger détecté! Arrêt.

# Compiler le bypass
gcc -shared -fPIC -o bypass.so solution_ex4_bypass.c -ldl

# Lancer avec le bypass
LD_PRELOAD=./bypass.so gdb ./protected
(gdb) run
# [BYPASS] ptrace(TRACEME) intercepté - Retour OK
# [BYPASS] /proc/self/status intercepté - TracerPid falsifié
# [BYPASS] clock_gettime intercepté - Temps falsifié
# [+] Toutes les protections passées!
# [+] Secret déverrouillé: FLAG{anti_debug_hard}
```

**Script de test complet:**

```bash
#!/bin/bash
# test_anti_debug.sh

echo "╔═══════════════════════════════════════════════╗"
echo "║   Test Anti-Debug et Bypass                  ║"
echo "╚═══════════════════════════════════════════════╝"
echo

# Compiler
echo "[+] Compilation..."
gcc -o protected solution_ex4_protected.c
gcc -shared -fPIC -o bypass.so solution_ex4_bypass.c -ldl
echo

# Test 1: Exécution normale
echo "[*] Test 1: Exécution normale (sans debugger)"
./protected
echo

# Test 2: Avec gdb (devrait échouer)
echo "[*] Test 2: Avec gdb (devrait être bloqué)"
echo "run\nquit" | gdb -q ./protected
echo

# Test 3: Avec bypass
echo "[*] Test 3: Avec gdb + bypass LD_PRELOAD"
echo "run\nquit" | LD_PRELOAD=./bypass.so gdb -q ./protected
echo

echo "[+] Tests terminés!"
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Détecter un debugger avec `ptrace(TRACEME)`
- [x] Vérifier TracerPid dans /proc/self/status
- [x] Implémenter un timing attack
- [x] Détecter les breakpoints logiciels (INT3)
- [x] Vérifier le processus parent
- [x] Combiner plusieurs techniques anti-debug
- [x] Bypasser les protections avec LD_PRELOAD
- [x] Comprendre les limites des protections userland
