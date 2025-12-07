/*
 * ═══════════════════════════════════════════════════════════════════════
 * MODULE 30 : TECHNIQUES ANTI-DEBUGGING
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Description :
 *   Ce module démontre différentes techniques de détection de débogage
 *   sur Windows et Linux. Ces techniques permettent à un programme de
 *   détecter s'il est exécuté sous un débogueur.
 *
 * AVERTISSEMENT LÉGAL :
 *   Ces techniques sont présentées UNIQUEMENT à des fins éducatives.
 *   L'utilisateur est SEUL RESPONSABLE de l'usage qu'il en fait.
 *   Toute utilisation malveillante est STRICTEMENT INTERDITE.
 *
 * Techniques démontrées :
 *   1. IsDebuggerPresent (Windows)
 *   2. PEB->BeingDebugged Check (Windows)
 *   3. ptrace Self-Attach (Linux)
 *   4. RDTSC Timing Checks (Cross-platform)
 *   5. Hardware Breakpoint Detection (Windows)
 *
 * Compilation :
 *   Windows: gcc -o anti_debug main.c
 *   Linux:   gcc -o anti_debug main.c
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #include <winternl.h>
#else
    #include <sys/ptrace.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 1 : RDTSC TIMING CHECKS (CROSS-PLATFORM)
 * ═══════════════════════════════════════════════════════════════════════ */

// Lecture du compteur de cycles CPU (Time Stamp Counter)
static inline uint64_t rdtsc(void) {
#ifdef _WIN32
    return __rdtsc();
#elif defined(__x86_64__) || defined(__i386__)
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    // Fallback pour architectures non-x86
    return 0;
#endif
}

// Fonction simple pour mesurer le temps
void dummy_function(void) {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) {
        x += i;
    }
}

int check_rdtsc_timing(void) {
    uint64_t start, end, elapsed;
    const uint64_t threshold = 10000;  // Seuil de détection

    start = rdtsc();
    dummy_function();
    end = rdtsc();

    elapsed = end - start;

    printf("  Cycles CPU mesurés : %llu\n", (unsigned long long)elapsed);

    if (elapsed > threshold) {
        printf("  ALERTE : Temps d'exécution anormal (> %llu cycles)\n",
               (unsigned long long)threshold);
        return 1;  // Débogueur probablement détecté
    }

    return 0;
}

void demo_rdtsc_timing(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("1. RDTSC TIMING CHECKS\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Principe :\n");
    printf("  - Mesure le temps d'exécution avec l'instruction RDTSC\n");
    printf("  - Les breakpoints ralentissent considérablement l'exécution\n");
    printf("  - Détection si le temps dépasse un seuil\n\n");

    printf("Test de timing :\n");
    int detected = check_rdtsc_timing();

    if (detected) {
        printf("\n[!] DÉBOGUEUR PROBABLEMENT DÉTECTÉ (timing anormal)\n");
    } else {
        printf("\n[✓] Aucun débogueur détecté (timing normal)\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 : TECHNIQUES WINDOWS
 * ═══════════════════════════════════════════════════════════════════════ */

#ifdef _WIN32

// IsDebuggerPresent - API Windows standard
int check_IsDebuggerPresent(void) {
    if (IsDebuggerPresent()) {
        return 1;
    }
    return 0;
}

void demo_IsDebuggerPresent(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("2. IsDebuggerPresent (WINDOWS)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - API Windows native (kernel32.dll)\n");
    printf("  - Vérifie le flag BeingDebugged du PEB\n");
    printf("  - Technique la plus simple et commune\n\n");

    printf("Test :\n");
    if (check_IsDebuggerPresent()) {
        printf("  [!] DÉBOGUEUR DÉTECTÉ via IsDebuggerPresent()\n");
    } else {
        printf("  [✓] Aucun débogueur détecté\n");
    }

    printf("\nContournement :\n");
    printf("  - Patcher IsDebuggerPresent pour retourner FALSE\n");
    printf("  - Modifier le PEB en mémoire\n");
    printf("  - Utiliser des plugins comme ScyllaHide\n");
}

// PEB->BeingDebugged - Vérification directe
int check_PEB_BeingDebugged(void) {
    BOOL found = FALSE;

#ifdef _WIN64
    // En 64-bit, le PEB est à GS:[0x60]
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    // En 32-bit, le PEB est à FS:[0x30]
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (pPeb && pPeb->BeingDebugged) {
        found = TRUE;
    }

    return found;
}

void demo_PEB_BeingDebugged(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("3. PEB->BeingDebugged CHECK (WINDOWS)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - Accès direct au Process Environment Block (PEB)\n");
    printf("  - Vérification du flag BeingDebugged (offset +0x02)\n");
    printf("  - Plus difficile à patcher qu'IsDebuggerPresent\n\n");

    printf("Structure PEB :\n");
    printf("  PEB (64-bit: GS:[0x60], 32-bit: FS:[0x30])\n");
    printf("  ├── BeingDebugged (offset +0x02)\n");
    printf("  ├── NtGlobalFlag (offset +0x68/+0xBC)\n");
    printf("  └── Autres champs...\n\n");

    printf("Test :\n");
    if (check_PEB_BeingDebugged()) {
        printf("  [!] DÉBOGUEUR DÉTECTÉ via PEB->BeingDebugged\n");
    } else {
        printf("  [✓] Aucun débogueur détecté\n");
    }
}

// NtQueryInformationProcess - API non documentée
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

int check_NtQueryInformationProcess(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQIP) return 0;

    DWORD dwDebugPort = 0;
    NTSTATUS status = NtQIP(
        GetCurrentProcess(),
        ProcessDebugPort,  // 0x07
        &dwDebugPort,
        sizeof(DWORD),
        NULL
    );

    if (status == 0 && dwDebugPort != 0) {
        return 1;  // Débogueur détecté
    }

    return 0;
}

void demo_NtQueryInformationProcess(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("4. NtQueryInformationProcess (WINDOWS)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - API non documentée de ntdll.dll\n");
    printf("  - Permet d'obtenir des informations sur le processus\n");
    printf("  - ProcessDebugPort (0x07) : retourne handle du debug port\n\n");

    printf("Classes d'information utiles :\n");
    printf("  - ProcessDebugPort (0x07)\n");
    printf("  - ProcessDebugObjectHandle (0x1E)\n");
    printf("  - ProcessDebugFlags (0x1F)\n\n");

    printf("Test :\n");
    if (check_NtQueryInformationProcess()) {
        printf("  [!] DÉBOGUEUR DÉTECTÉ via NtQueryInformationProcess\n");
    } else {
        printf("  [✓] Aucun débogueur détecté\n");
    }
}

// Hardware Breakpoint Detection
int check_hardware_breakpoints(void) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return 0;  // Erreur, on considère pas de débogueur
    }

    // Vérifier les registres DR0-DR3 (adresses des breakpoints)
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        return 1;  // Hardware breakpoint détecté
    }

    return 0;
}

void demo_hardware_breakpoints(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("5. HARDWARE BREAKPOINT DETECTION (WINDOWS)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - Vérification des registres de débogage matériel (DR0-DR7)\n");
    printf("  - DR0-DR3 : Adresses des breakpoints matériels\n");
    printf("  - DR6 : Status register\n");
    printf("  - DR7 : Control register\n\n");

    printf("Test :\n");
    if (check_hardware_breakpoints()) {
        printf("  [!] HARDWARE BREAKPOINT DÉTECTÉ\n");
    } else {
        printf("  [✓] Aucun hardware breakpoint détecté\n");
    }

    printf("\nNote : Maximum 4 hardware breakpoints simultanés (DR0-DR3)\n");
}

#endif  // _WIN32

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 3 : TECHNIQUES LINUX
 * ═══════════════════════════════════════════════════════════════════════ */

#ifndef _WIN32

// ptrace self-attach
int check_ptrace_self(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;  // Déjà tracé par un débogueur
    }
    return 0;
}

void demo_ptrace_self(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("2. PTRACE SELF-ATTACH (LINUX)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - Tentative d'attachement à soi-même avec ptrace\n");
    printf("  - Un processus ne peut être tracé que par un seul traceur\n");
    printf("  - Si déjà sous débogueur, ptrace(PTRACE_TRACEME) échoue\n\n");

    printf("Test :\n");
    if (check_ptrace_self()) {
        printf("  [!] DÉBOGUEUR DÉTECTÉ via ptrace\n");
    } else {
        printf("  [✓] Aucun débogueur détecté\n");
    }

    printf("\nContournement :\n");
    printf("  - LD_PRELOAD pour hooker ptrace\n");
    printf("  - Modification du noyau\n");
    printf("  - Utilisation de débogueurs alternatifs\n");
}

// Vérification du fichier /proc/self/status
int check_proc_status(void) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int tracer_pid = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            sscanf(line, "TracerPid: %d", &tracer_pid);
            break;
        }
    }

    fclose(f);

    return (tracer_pid != 0);
}

void demo_proc_status(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("3. /proc/self/status CHECK (LINUX)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - Lecture du fichier /proc/self/status\n");
    printf("  - Vérification du champ TracerPid\n");
    printf("  - TracerPid != 0 indique un processus traceur\n\n");

    printf("Test :\n");
    if (check_proc_status()) {
        printf("  [!] DÉBOGUEUR DÉTECTÉ via /proc/self/status\n");
    } else {
        printf("  [✓] Aucun débogueur détecté (TracerPid: 0)\n");
    }
}

// Détection via LD_PRELOAD
int check_ld_preload(void) {
    char* ld_preload = getenv("LD_PRELOAD");
    if (ld_preload != NULL && strlen(ld_preload) > 0) {
        return 1;  // LD_PRELOAD défini (suspicion de hooking)
    }
    return 0;
}

void demo_ld_preload(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("4. LD_PRELOAD DETECTION (LINUX)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description :\n");
    printf("  - Vérification de la variable d'environnement LD_PRELOAD\n");
    printf("  - Utilisée pour charger des bibliothèques avant les autres\n");
    printf("  - Souvent utilisée pour hooker des fonctions\n\n");

    printf("Test :\n");
    if (check_ld_preload()) {
        printf("  [!] LD_PRELOAD DÉTECTÉ (suspicion de hooking)\n");
        printf("  LD_PRELOAD = %s\n", getenv("LD_PRELOAD"));
    } else {
        printf("  [✓] LD_PRELOAD non défini\n");
    }
}

#endif  // !_WIN32

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 4 : TECHNIQUES COMBINÉES
 * ═══════════════════════════════════════════════════════════════════════ */

int comprehensive_debugger_check(void) {
    int detected = 0;

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("VÉRIFICATION COMPLÈTE ANTI-DEBUGGING\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    // Test RDTSC (cross-platform)
    printf("[1] Test RDTSC Timing... ");
    if (check_rdtsc_timing()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

#ifdef _WIN32
    // Tests Windows
    printf("[2] Test IsDebuggerPresent... ");
    if (check_IsDebuggerPresent()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

    printf("[3] Test PEB->BeingDebugged... ");
    if (check_PEB_BeingDebugged()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

    printf("[4] Test NtQueryInformationProcess... ");
    if (check_NtQueryInformationProcess()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

    printf("[5] Test Hardware Breakpoints... ");
    if (check_hardware_breakpoints()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

#else
    // Tests Linux
    printf("[2] Test ptrace self-attach... ");
    if (check_ptrace_self()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

    printf("[3] Test /proc/self/status... ");
    if (check_proc_status()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }

    printf("[4] Test LD_PRELOAD... ");
    if (check_ld_preload()) {
        printf("DÉTECTÉ\n");
        detected++;
    } else {
        printf("OK\n");
    }
#endif

    printf("\n");
    return detected;
}

/* ═══════════════════════════════════════════════════════════════════════
 * FONCTION PRINCIPALE
 * ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║         MODULE 30 : TECHNIQUES ANTI-DEBUGGING                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\nAVERTISSEMENT LÉGAL :\n");
    printf("Ces techniques sont présentées à des fins ÉDUCATIVES uniquement.\n");
    printf("Toute utilisation malveillante est STRICTEMENT INTERDITE.\n");
    printf("L'utilisateur est SEUL RESPONSABLE de l'usage qu'il en fait.\n");

#ifdef _WIN32
    printf("\nPlateforme : WINDOWS\n");
#else
    printf("\nPlateforme : LINUX/UNIX\n");
#endif

    // Démonstrations individuelles
    demo_rdtsc_timing();

#ifdef _WIN32
    demo_IsDebuggerPresent();
    demo_PEB_BeingDebugged();
    demo_NtQueryInformationProcess();
    demo_hardware_breakpoints();
#else
    demo_ptrace_self();
    demo_proc_status();
    demo_ld_preload();
#endif

    // Vérification complète
    int detections = comprehensive_debugger_check();

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("RÉSULTAT FINAL\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    if (detections > 0) {
        printf("[!!!] DÉBOGUEUR DÉTECTÉ (%d technique(s) positive(s))\n", detections);
        printf("\nRéaction possible :\n");
        printf("  - Quitter le programme\n");
        printf("  - Altérer le comportement\n");
        printf("  - Signaler l'incident\n");
    } else {
        printf("[OK] Aucun débogueur détecté\n");
        printf("Exécution normale du programme.\n");
    }

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Programme terminé.\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}
