/*
 * =============================================================================
 * SIP - System Integrity Protection Checker
 * =============================================================================
 *
 * Description : Vérifier l'état de SIP et tester les chemins protégés
 *
 * Compilation :
 *   clang example.c -o sip_checker
 *
 * Usage :
 *   ./sip_checker
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/csr.h>     // Pour csr_check() et les flags CSR
#include <fcntl.h>       // Pour open()
#include <errno.h>       // Pour errno et les codes d'erreur
#include <unistd.h>      // Pour close(), unlink()
#include <string.h>      // Pour strerror()

// Couleurs ANSI pour rendre la sortie plus claire
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define RESET   "\x1b[0m"

/*
 * Affiche une bannière de présentation
 */
void print_banner() {
    printf(BLUE);
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║     macOS SIP (System Integrity Protection)  ║\n");
    printf("║              Status Checker                  ║\n");
    printf("╚═══════════════════════════════════════════════╝\n");
    printf(RESET);
    printf("\n");
}

/*
 * Vérifie un flag CSR spécifique
 *
 * flag : Le flag CSR à vérifier (ex: CSR_ALLOW_UNRESTRICTED_FS)
 * name : Nom descriptif du flag pour l'affichage
 *
 * Retourne : 1 si le flag est ENABLED (protection active), 0 si DISABLED
 */
int check_csr_flag(uint32_t flag, const char *name) {
    // csr_check() retourne 0 si le flag est DÉSACTIVÉ (protection OFF)
    // et une valeur non-nulle si le flag est ACTIVÉ (protection ON)
    int result = csr_check(flag);

    if (result == 0) {
        // Flag désactivé = protection OFF = DANGER
        printf("  " RED "[!]" RESET " %-35s " RED "DISABLED" RESET "\n", name);
        return 0;
    } else {
        // Flag activé = protection ON = SÉCURISÉ
        printf("  " GREEN "[+]" RESET " %-35s " GREEN "ENABLED" RESET "\n", name);
        return 1;
    }
}

/*
 * Vérifie tous les flags SIP importants
 */
void check_all_sip_flags() {
    printf(YELLOW "[*]" RESET " Checking SIP configuration flags:\n\n");

    int total = 0;
    int enabled = 0;

    // Vérifier chaque flag et compter combien sont activés
    total++; enabled += check_csr_flag(CSR_ALLOW_UNTRUSTED_KEXTS, "KEXT Loading Protection");
    total++; enabled += check_csr_flag(CSR_ALLOW_UNRESTRICTED_FS, "Filesystem Protection");
    total++; enabled += check_csr_flag(CSR_ALLOW_TASK_FOR_PID, "task_for_pid() Protection");
    total++; enabled += check_csr_flag(CSR_ALLOW_KERNEL_DEBUGGER, "Kernel Debugger Protection");
    total++; enabled += check_csr_flag(CSR_ALLOW_UNRESTRICTED_DTRACE, "DTrace Protection");
    total++; enabled += check_csr_flag(CSR_ALLOW_UNRESTRICTED_NVRAM, "NVRAM Protection");

    // Afficher un score de sécurité
    printf("\n");
    printf("  Security Score: %d/%d protections enabled (%.1f%%)\n",
           enabled, total, (enabled * 100.0) / total);
    printf("\n");
}

/*
 * Teste si on peut écrire dans un chemin donné
 * Cela permet de détecter les chemins protégés par SIP
 *
 * path : Chemin à tester
 */
void test_path(const char *path) {
    // Tenter d'ouvrir le fichier en écriture
    // O_WRONLY = écriture seule
    // O_CREAT = créer si n'existe pas
    // O_EXCL = échouer si existe déjà
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);

    if (fd == -1) {
        // L'ouverture a échoué, vérifier pourquoi
        if (errno == EACCES || errno == EPERM || errno == EROFS) {
            // Permission refusée = protégé par SIP
            printf("  " GREEN "[+]" RESET " %-40s " GREEN "PROTECTED" RESET "\n", path);
        } else if (errno == EEXIST) {
            // Fichier existe déjà
            printf("  " YELLOW "[?]" RESET " %-40s " YELLOW "EXISTS" RESET "\n", path);
        } else {
            // Autre erreur
            printf("  " YELLOW "[?]" RESET " %-40s " YELLOW "Error: %s" RESET "\n",
                   path, strerror(errno));
        }
    } else {
        // L'ouverture a réussi = chemin non protégé
        printf("  " RED "[!]" RESET " %-40s " RED "WRITABLE" RESET "\n", path);
        close(fd);
        unlink(path);  // Supprimer le fichier de test
    }
}

/*
 * Teste plusieurs chemins pour identifier lesquels sont protégés
 */
void test_protected_paths() {
    printf(YELLOW "[*]" RESET " Testing filesystem protection:\n\n");

    const char *paths[] = {
        // Chemins protégés par SIP
        "/System/test_sip",
        "/usr/bin/test_sip",
        "/usr/lib/test_sip",
        "/sbin/test_sip",

        // Chemins NON protégés
        "/usr/local/bin/test_sip",
        "/tmp/test_sip",
        "/var/tmp/test_sip",

        NULL  // Marque la fin du tableau
    };

    // Parcourir tous les chemins
    for (int i = 0; paths[i] != NULL; i++) {
        test_path(paths[i]);
    }

    printf("\n");
}

/*
 * Affiche des recommandations pour un attaquant Red Team
 */
void print_recommendations() {
    printf(YELLOW "[*]" RESET " Red Team Recommendations:\n\n");

    // Vérifier si SIP FS est activé
    if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0) {
        // SIP activé = utiliser des chemins alternatifs
        printf("  " GREEN "[+]" RESET " SIP is protecting system files\n");
        printf("  " BLUE "[i]" RESET " Use these paths for persistence:\n");
        printf("      - ~/Library/LaunchAgents/\n");
        printf("      - /usr/local/bin/\n");
        printf("      - /tmp/ (volatile)\n");
        printf("      - Third-party app directories\n\n");

        printf("  " BLUE "[i]" RESET " Injection techniques:\n");
        printf("      - DYLD_INSERT_LIBRARIES on non-system apps\n");
        printf("      - Target processes without restricted entitlements\n");
        printf("      - Use user-level LaunchAgents/Daemons\n\n");
    } else {
        // SIP désactivé = accès complet au système
        printf("  " RED "[!]" RESET " SIP filesystem protection is DISABLED\n");
        printf("  " BLUE "[i]" RESET " Full system access possible:\n");
        printf("      - Modify system binaries\n");
        printf("      - Install kernel extensions (KEXT)\n");
        printf("      - Deep persistence in /System/\n\n");
    }
}

/*
 * Affiche un exemple de création de LaunchAgent pour la persistence
 */
void show_persistence_example() {
    printf(YELLOW "[*]" RESET " Persistence Example (SIP-safe):\n\n");

    printf("  Create LaunchAgent in user directory:\n\n");
    printf(BLUE);
    printf("  cat > ~/Library/LaunchAgents/com.example.agent.plist <<EOF\n");
    printf("  <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    printf("  <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \n");
    printf("         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    printf("  <plist version=\"1.0\">\n");
    printf("  <dict>\n");
    printf("      <key>Label</key>\n");
    printf("      <string>com.example.agent</string>\n");
    printf("      <key>ProgramArguments</key>\n");
    printf("      <array>\n");
    printf("          <string>/usr/local/bin/agent</string>\n");
    printf("      </array>\n");
    printf("      <key>RunAtLoad</key>\n");
    printf("      <true/>\n");
    printf("      <key>KeepAlive</key>\n");
    printf("      <true/>\n");
    printf("  </dict>\n");
    printf("  </plist>\n");
    printf("  EOF\n");
    printf(RESET);
    printf("\n");
    printf("  Load with: launchctl load ~/Library/LaunchAgents/com.example.agent.plist\n\n");
}

/*
 * Fonction principale
 */
int main(int argc, char *argv[]) {
    print_banner();

    // Phase 1: Vérifier les flags SIP
    check_all_sip_flags();

    // Phase 2: Tester les chemins protégés
    test_protected_paths();

    // Phase 3: Recommandations Red Team
    print_recommendations();

    // Phase 4: Exemple de persistence
    show_persistence_example();

    printf(GREEN "[✓]" RESET " SIP check complete.\n\n");

    return 0;
}
