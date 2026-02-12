/*
 * OBJECTIF  : Comprendre l'architecture beacon sur macOS
 * PREREQUIS : Bases C, HTTP, securite macOS, persistence
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre l'architecture d'un beacon macOS :
 * fingerprinting systeme, communication, stealth,
 * particularites macOS, et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <pwd.h>

/*
 * Etape 1 : Architecture beacon macOS
 */
static void explain_beacon_architecture(void) {
    printf("[*] Etape 1 : Architecture beacon macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Beacon macOS                             │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ 1. Fingerprint systeme            │    │\n");
    printf("    │  │ 2. Check-in initial               │    │\n");
    printf("    │  │ 3. Boucle beacon                  │    │\n");
    printf("    │  │    ├── Sleep + Jitter             │    │\n");
    printf("    │  │    ├── GET /tasks (poll)           │    │\n");
    printf("    │  │    ├── Executer commande           │    │\n");
    printf("    │  │    └── POST /results               │    │\n");
    printf("    │  │ 4. Persistence (LaunchAgent)       │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    │                                          │\n");
    printf("    │  Specificites macOS :                     │\n");
    printf("    │  - NSURLSession pour le reseau            │\n");
    printf("    │  - osascript pour l'interaction           │\n");
    printf("    │  - LaunchAgent pour la persistence        │\n");
    printf("    │  - Keychain pour les credentials          │\n");
    printf("    │  - TCC pour les permissions               │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Fingerprinting macOS
 */
static void demo_fingerprint(void) {
    printf("[*] Etape 2 : Fingerprinting macOS\n\n");

    /* Hostname */
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    printf("    Hostname      : %s\n", hostname);

    /* Username */
    struct passwd *pw = getpwuid(getuid());
    printf("    Username      : %s\n", pw ? pw->pw_name : "inconnu");
    printf("    UID           : %d\n", getuid());
    printf("    PID           : %d\n", getpid());

    /* OS version via uname */
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("    System        : %s %s\n", uts.sysname, uts.release);
        printf("    Machine       : %s\n", uts.machine);
    }

    /* Version macOS via sysctl */
    char osversion[64] = {0};
    size_t len = sizeof(osversion);
    if (sysctlbyname("kern.osproductversion", osversion, &len, NULL, 0) == 0) {
        printf("    macOS version : %s\n", osversion);
    }

    /* Modele hardware */
    char model[128] = {0};
    len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, NULL, 0) == 0) {
        printf("    Modele        : %s\n", model);
    }

    /* CPU */
    char cpu[256] = {0};
    len = sizeof(cpu);
    if (sysctlbyname("machdep.cpu.brand_string", cpu, &len, NULL, 0) == 0) {
        printf("    CPU           : %s\n", cpu);
    }

    /* RAM */
    uint64_t memsize = 0;
    len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) == 0) {
        printf("    RAM           : %llu GB\n", memsize / (1024*1024*1024));
    }

    /* Home directory */
    const char *home = getenv("HOME");
    printf("    Home          : %s\n", home ? home : "inconnu");
    printf("\n");

    /* Informations complementaires via sw_vers */
    printf("    Informations sw_vers :\n");
    FILE *fp = popen("sw_vers 2>/dev/null", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 3 : Sleep et jitter
 */
static void demo_sleep_jitter(void) {
    printf("[*] Etape 3 : Sleep et jitter\n\n");

    printf("    Le jitter rend le beacon moins previsible :\n");
    printf("    ───────────────────────────────────\n");
    printf("    sleep_base = 60 secondes\n");
    printf("    jitter     = 30%% (0.3)\n\n");

    srand((unsigned)time(NULL));

    int base_sleep = 60;
    double jitter_pct = 0.3;

    printf("    Intervalles calcules (simulation) :\n");
    for (int i = 0; i < 5; i++) {
        int jitter_max = (int)(base_sleep * jitter_pct);
        int actual = base_sleep + (rand() % (2 * jitter_max + 1)) - jitter_max;
        printf("      Iteration %d : %d secondes\n", i + 1, actual);
    }
    printf("\n");

    printf("    Code :\n");
    printf("    int calc_sleep(int base, double jitter) {\n");
    printf("        int range = (int)(base * jitter);\n");
    printf("        return base + (rand() %% (2*range+1)) - range;\n");
    printf("    }\n\n");
}

/*
 * Etape 4 : Execution de commandes macOS
 */
static void demo_command_execution(void) {
    printf("[*] Etape 4 : Execution de commandes macOS\n\n");

    printf("    Methodes d'execution :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. popen()     : pipe vers un shell\n");
    printf("    2. system()    : execution simple\n");
    printf("    3. posix_spawn : plus discret\n");
    printf("    4. osascript   : AppleScript\n");
    printf("    5. NSTask      : API Cocoa\n\n");

    /* Demo popen */
    printf("    Execution via popen(\"id\") :\n");
    FILE *fp = popen("id 2>&1", "r");
    if (fp) {
        char output[512] = {0};
        fgets(output, sizeof(output), fp);
        output[strcspn(output, "\n")] = '\0';
        printf("      %s\n\n", output);
        pclose(fp);
    }

    /* Demo osascript */
    printf("    Execution via osascript :\n");
    printf("    ───────────────────────────────────\n");
    printf("    osascript -e 'do shell script \"whoami\"'\n");
    printf("    # Avantage : peut demander des privileges\n");
    printf("    osascript -e 'do shell script \"cmd\" with \\\n");
    printf("        administrator privileges'\n\n");

    /* Demo posix_spawn */
    printf("    posix_spawn (plus stealth) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <spawn.h>\n");
    printf("    extern char **environ;\n");
    printf("    pid_t pid;\n");
    printf("    char *argv[] = {\"/bin/sh\", \"-c\", \"whoami\", NULL};\n");
    printf("    posix_spawn(&pid, \"/bin/sh\", NULL, NULL, argv, environ);\n");
    printf("    waitpid(pid, NULL, 0);\n\n");
}

/*
 * Etape 5 : Persistence macOS
 */
static void explain_persistence(void) {
    printf("[*] Etape 5 : Persistence macOS pour beacon\n\n");

    printf("    LaunchAgent (niveau utilisateur) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ~/Library/LaunchAgents/com.user.agent.plist\n\n");
    printf("    <?xml version=\"1.0\"?>\n");
    printf("    <plist version=\"1.0\">\n");
    printf("    <dict>\n");
    printf("        <key>Label</key>\n");
    printf("        <string>com.user.agent</string>\n");
    printf("        <key>ProgramArguments</key>\n");
    printf("        <array>\n");
    printf("            <string>/path/to/beacon</string>\n");
    printf("        </array>\n");
    printf("        <key>RunAtLoad</key>\n");
    printf("        <true/>\n");
    printf("        <key>KeepAlive</key>\n");
    printf("        <true/>\n");
    printf("        <key>StandardOutPath</key>\n");
    printf("        <string>/dev/null</string>\n");
    printf("    </dict>\n");
    printf("    </plist>\n\n");

    printf("    Autres methodes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Methode           | Privilege | Survie reboot\n");
    printf("    ──────────────────|───────────|──────────────\n");
    printf("    LaunchAgent       | User      | Oui\n");
    printf("    LaunchDaemon      | Root      | Oui\n");
    printf("    Login Items       | User      | Oui\n");
    printf("    crontab           | User      | Oui\n");
    printf("    .zshrc / .bashrc  | User      | Oui (si shell)\n");
    printf("    Dylib hijack      | Depends   | Oui (si app)\n\n");

    /* Lister les LaunchAgents utilisateur */
    printf("    LaunchAgents utilisateur installes :\n");
    char cmd[512];
    const char *home = getenv("HOME");
    if (home) {
        snprintf(cmd, sizeof(cmd), "ls '%s/Library/LaunchAgents/' 2>/dev/null | head -8", home);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            int count = 0;
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                printf("      %s\n", line);
                count++;
            }
            pclose(fp);
            if (count == 0) printf("      (aucun)\n");
        }
    }
    printf("\n");
}

/*
 * Etape 6 : Detection et defense
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et defense\n\n");

    printf("    Indicateurs de beacon macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Connexions HTTP/HTTPS periodiques\n");
    printf("    - Processus inconnu avec reseau\n");
    printf("    - LaunchAgent/Daemon suspect\n");
    printf("    - Binaire non signe ou ad-hoc\n");
    printf("    - Execution de osascript anormale\n\n");

    printf("    Commandes de detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Connexions reseau\n");
    printf("    lsof -i -n -P | grep ESTABLISHED\n\n");
    printf("    # Processus suspects\n");
    printf("    ps aux | grep -v '/System\\|/usr/libexec'\n\n");
    printf("    # LaunchAgents\n");
    printf("    launchctl list | grep -v 'com.apple'\n\n");
    printf("    # Binaires non signes\n");
    printf("    codesign -v /path/suspect 2>&1\n\n");

    printf("    Outils recommandes :\n");
    printf("    - KnockKnock : persistence items\n");
    printf("    - BlockBlock : alertes persistence\n");
    printf("    - LuLu : firewall applicatif\n");
    printf("    - Oversight : camera/micro monitoring\n");
    printf("    - Endpoint Security Framework\n\n");
}

int main(void) {
    printf("[*] Demo : Beacon macOS\n\n");

    explain_beacon_architecture();
    demo_fingerprint();
    demo_sleep_jitter();
    demo_command_execution();
    explain_persistence();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
