# Solutions - Secure Boot

## Exercice 1 : Vérifier l'état de Secure Boot (Très facile)

**Objectif** : Écrire un programme C qui vérifie si Secure Boot est activé sur le système.

### Solution

```c
/*
 * Vérification de l'état de Secure Boot
 *
 * Compilation : gcc -o check_secureboot check_secureboot.c
 * Usage : sudo ./check_secureboot
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Fonction pour lire une variable UEFI
int read_uefi_variable(const char* var_name, uint8_t* value) {
    char path[256];

    // Construire le chemin vers la variable UEFI dans /sys/firmware/efi/efivars/
    snprintf(path, sizeof(path), "/sys/firmware/efi/efivars/%s", var_name);

    FILE* f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    // Lire les 4 premiers bytes (attributes) puis la valeur
    uint32_t attributes;
    fread(&attributes, 4, 1, f);
    fread(value, 1, 1, f);

    fclose(f);
    return 0;
}

int main() {
    printf("[*] Vérification de l'état de Secure Boot\n");
    printf("[*] ==========================================\n\n");

    uint8_t secure_boot = 0;
    uint8_t setup_mode = 0;

    // Vérifier si Secure Boot est activé
    if (read_uefi_variable("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", &secure_boot) == 0) {
        printf("[+] SecureBoot trouvé : %s\n", secure_boot == 1 ? "ENABLED" : "DISABLED");
    } else {
        printf("[-] Impossible de lire la variable SecureBoot (root requis)\n");
    }

    // Vérifier si le système est en Setup Mode
    if (read_uefi_variable("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", &setup_mode) == 0) {
        printf("[+] SetupMode : %s\n", setup_mode == 1 ? "YES (Secure Boot désactivé)" : "NO");
    }

    printf("\n[*] Analyse :\n");
    if (secure_boot == 1 && setup_mode == 0) {
        printf("    Secure Boot est ACTIF et configuré correctement\n");
    } else if (setup_mode == 1) {
        printf("    ATTENTION : Système en Setup Mode (vulnérable)\n");
    } else {
        printf("    Secure Boot est INACTIF\n");
    }

    return 0;
}
```

**Explication** :
- On lit les variables UEFI depuis `/sys/firmware/efi/efivars/`
- La variable `SecureBoot` indique si Secure Boot est activé (1) ou non (0)
- La variable `SetupMode` indique si le système est en mode configuration (1 = dangereux, 0 = normal)
- Le GUID `8be4df61-93ca-11d2-aa0d-00e098032b8c` est le GUID global UEFI standard

---

## Exercice 2 : Parser la signature d'un binaire UEFI (Facile)

**Objectif** : Extraire et afficher les informations de signature d'un bootloader UEFI.

### Solution

```c
/*
 * Extraction de signature Authenticode d'un binaire PE/UEFI
 *
 * Compilation : gcc -o parse_signature parse_signature.c
 * Usage : ./parse_signature /boot/efi/EFI/BOOT/BOOTX64.EFI
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Structures PE/COFF
typedef struct {
    uint16_t e_magic;    // "MZ"
    uint8_t  e_pad[58];
    uint32_t e_lfanew;   // Offset vers PE header
} __attribute__((packed)) DOS_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} __attribute__((packed)) DATA_DIRECTORY;

// Fonction pour extraire la signature Authenticode
void extract_signature(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Erreur ouverture fichier");
        return;
    }

    // Lire DOS header
    DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1) {
        printf("[-] Erreur lecture DOS header\n");
        fclose(f);
        return;
    }

    // Vérifier signature MZ
    if (dos.e_magic != 0x5A4D) {
        printf("[-] Pas un fichier PE valide (signature MZ manquante)\n");
        fclose(f);
        return;
    }

    printf("[+] DOS Header trouvé (MZ signature)\n");
    printf("[+] Offset PE Header : 0x%X\n", dos.e_lfanew);

    // Aller au PE header
    fseek(f, dos.e_lfanew, SEEK_SET);

    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, f);
    if (pe_sig != 0x00004550) { // "PE\0\0"
        printf("[-] Signature PE invalide\n");
        fclose(f);
        return;
    }

    printf("[+] PE Signature trouvée\n");

    // Lire COFF header pour déterminer le type (PE32 ou PE32+)
    fseek(f, dos.e_lfanew + 24, SEEK_SET);

    uint16_t magic;
    fread(&magic, 2, 1, f);

    int dd_offset;
    if (magic == 0x010B) { // PE32
        printf("[+] Format : PE32 (32-bit)\n");
        dd_offset = dos.e_lfanew + 24 + 92;
    } else if (magic == 0x020B) { // PE32+
        printf("[+] Format : PE32+ (64-bit)\n");
        dd_offset = dos.e_lfanew + 24 + 108;
    } else {
        printf("[-] Format PE inconnu\n");
        fclose(f);
        return;
    }

    // Certificate Table = Data Directory #4
    fseek(f, dd_offset + (4 * 8), SEEK_SET);

    DATA_DIRECTORY cert_dir;
    fread(&cert_dir, sizeof(cert_dir), 1, f);

    if (cert_dir.Size == 0) {
        printf("\n[-] AUCUNE SIGNATURE trouvée (binaire non signé)\n");
    } else {
        printf("\n[+] SIGNATURE TROUVÉE :\n");
        printf("    Offset fichier : 0x%X\n", cert_dir.VirtualAddress);
        printf("    Taille         : %u bytes\n", cert_dir.Size);

        // Extraire les premiers bytes pour analyse
        uint8_t* sig = malloc(cert_dir.Size);
        fseek(f, cert_dir.VirtualAddress, SEEK_SET);
        fread(sig, cert_dir.Size, 1, f);

        printf("\n[+] Premiers 32 bytes de la signature (PKCS#7) :\n    ");
        for (int i = 0; i < 32 && i < cert_dir.Size; i++) {
            printf("%02X ", sig[i]);
            if ((i + 1) % 16 == 0) printf("\n    ");
        }
        printf("\n");

        // Vérifier signature PKCS#7
        if (sig[0] == 0x30 && sig[1] == 0x82) {
            printf("[+] Format PKCS#7 valide détecté\n");
        }

        free(sig);
    }

    fclose(f);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <bootloader.efi>\n", argv[0]);
        printf("Exemple: %s /boot/efi/EFI/BOOT/BOOTX64.EFI\n", argv[0]);
        return 1;
    }

    printf("[*] Analyse de signature UEFI\n");
    printf("[*] ==========================================\n\n");

    extract_signature(argv[1]);

    printf("\n[*] Analyse terminée\n");
    return 0;
}
```

**Explication** :
- On parse la structure PE/COFF du binaire UEFI
- Le DOS Header contient l'offset vers le PE Header
- Le PE Header contient les Data Directories
- La Data Directory #4 (Certificate Table) pointe vers la signature Authenticode
- La signature est au format PKCS#7 (commence par `30 82`)

---

## Exercice 3 : Simuler un bypass Secure Boot via MOK (Moyen)

**Objectif** : Démontrer comment un attaquant avec accès root peut ajouter sa propre clé MOK.

### Solution

```c
/*
 * Simulation d'ajout de clé MOK malveillante
 *
 * ATTENTION : À des fins éducatives uniquement !
 * Nécessite root et mokutil installé.
 *
 * Compilation : gcc -o mok_attack mok_attack.c
 * Usage : sudo ./mok_attack
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

void print_banner() {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║   MOK Attack Simulator - Secure Boot Bypass Demo     ║\n");
    printf("║   --------------------------------------------------- ║\n");
    printf("║   ÉDUCATIF UNIQUEMENT - NE PAS UTILISER SANS          ║\n");
    printf("║   AUTORISATION EXPLICITE                              ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

// Vérifier si mokutil est disponible
int check_mokutil() {
    struct stat buffer;
    return (stat("/usr/bin/mokutil", &buffer) == 0);
}

// Générer une paire de clés RSA
int generate_key_pair() {
    printf("[*] Génération de la paire de clés RSA...\n");

    int ret = system("openssl req -new -x509 -newkey rsa:2048 -keyout /tmp/attacker_MOK.key "
                    "-out /tmp/attacker_MOK.crt -nodes -days 365 "
                    "-subj '/CN=Attacker MOK/O=RedTeam/C=FR' 2>/dev/null");

    if (ret != 0) {
        printf("[-] Échec génération de clés\n");
        return -1;
    }

    printf("[+] Clés générées :\n");
    printf("    Clé privée : /tmp/attacker_MOK.key\n");
    printf("    Certificat : /tmp/attacker_MOK.crt\n");

    return 0;
}

// Signer un bootloader avec la clé
int sign_bootloader() {
    printf("\n[*] Création d'un bootloader malveillant...\n");

    // Créer un bootloader EFI basique (stub)
    FILE* f = fopen("/tmp/malicious.efi", "wb");
    if (!f) {
        printf("[-] Impossible de créer le bootloader\n");
        return -1;
    }

    // Écrire un header PE minimal (stub non fonctionnel, juste pour la démo)
    uint8_t pe_stub[] = {
        0x4D, 0x5A, 0x90, 0x00,  // MZ signature
        // ... (simplifié pour la démo)
    };
    fwrite(pe_stub, sizeof(pe_stub), 1, f);
    fclose(f);

    printf("[+] Stub bootloader créé\n");

    // Signer avec sbsign
    printf("[*] Signature du bootloader avec la clé attaquant...\n");
    int ret = system("sbsign --key /tmp/attacker_MOK.key --cert /tmp/attacker_MOK.crt "
                    "/tmp/malicious.efi --output /tmp/malicious_signed.efi 2>/dev/null");

    if (ret != 0) {
        printf("[-] Échec signature (sbsign non installé ?)\n");
        return -1;
    }

    printf("[+] Bootloader signé : /tmp/malicious_signed.efi\n");

    return 0;
}

// Importer la clé dans MOK
int import_mok() {
    printf("\n[*] Import de la clé dans MOK...\n");
    printf("[!] ATTENTION : Cette action modifiera le MOK de votre système\n");
    printf("[?] Continuer ? (y/N) : ");

    char response;
    scanf(" %c", &response);

    if (response != 'y' && response != 'Y') {
        printf("[-] Opération annulée\n");
        return -1;
    }

    printf("\n[*] Exécution de mokutil --import...\n");
    int ret = system("mokutil --import /tmp/attacker_MOK.crt");

    if (ret != 0) {
        printf("[-] Échec import MOK\n");
        return -1;
    }

    printf("\n[+] Clé importée avec succès !\n");
    printf("[*] Au prochain reboot :\n");
    printf("    1. MOK Manager s'affichera\n");
    printf("    2. Sélectionner 'Enroll MOK'\n");
    printf("    3. Entrer le mot de passe choisi\n");
    printf("    4. Reboot → Clé installée\n");
    printf("\n[!] Une fois installée, /tmp/malicious_signed.efi sera accepté par Secure Boot\n");

    return 0;
}

int main() {
    if (getuid() != 0) {
        printf("[-] Ce programme nécessite les privilèges root\n");
        return 1;
    }

    print_banner();

    if (!check_mokutil()) {
        printf("[-] mokutil n'est pas installé\n");
        printf("    Installer avec : sudo apt install mokutil\n");
        return 1;
    }

    printf("[*] Démonstration d'attaque Secure Boot via MOK\n");
    printf("[*] ==========================================\n\n");

    // Étape 1 : Générer les clés
    if (generate_key_pair() != 0) {
        return 1;
    }

    // Étape 2 : Signer un bootloader
    if (sign_bootloader() != 0) {
        printf("[!] Signature échouée, mais les clés sont générées\n");
    }

    // Étape 3 : Importer dans MOK
    if (import_mok() != 0) {
        return 1;
    }

    printf("\n[*] Simulation terminée\n");
    printf("\n[*] Résumé de l'attaque :\n");
    printf("    1. Attaquant obtient accès root\n");
    printf("    2. Génère une clé MOK personnelle\n");
    printf("    3. Importe la clé via mokutil\n");
    printf("    4. Au reboot, enroll la clé (interaction physique requise)\n");
    printf("    5. Peut maintenant signer et booter des binaires malveillants\n");
    printf("    6. Secure Boot est contourné\n");

    return 0;
}
```

**Explication de l'attaque** :
1. L'attaquant génère une paire de clés RSA avec OpenSSL
2. Il signe un bootloader malveillant avec sa clé privée
3. Il importe le certificat dans MOK avec `mokutil --import`
4. Au prochain reboot, il enroll la clé (nécessite interaction physique)
5. Secure Boot fait confiance à cette clé → le bootkit est accepté

**Mitigation** :
- MOK enrollment nécessite un mot de passe (interaction physique)
- TPM + Measured Boot détectera la modification
- UEFI password empêche le boot sur un autre device

---

## Exercice 4 : Détecter un Setup Mode malveillant (Difficile)

**Objectif** : Créer un outil qui détecte si Secure Boot a été désactivé en effaçant la PK.

### Solution

```c
/*
 * Détection de Setup Mode malveillant (Secure Boot bypass)
 *
 * Compilation : gcc -o detect_setup_mode detect_setup_mode.c
 * Usage : sudo ./detect_setup_mode
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define UEFI_VARS_PATH "/sys/firmware/efi/efivars"

// Vérifier si une variable UEFI existe
int uefi_var_exists(const char* var_name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", UEFI_VARS_PATH, var_name);

    struct stat st;
    return (stat(path, &st) == 0);
}

// Lire une variable UEFI (1 byte)
int read_uefi_var_byte(const char* var_name, uint8_t* value) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", UEFI_VARS_PATH, var_name);

    FILE* f = fopen(path, "rb");
    if (!f) return -1;

    // Skip attributes (4 bytes)
    fseek(f, 4, SEEK_SET);
    fread(value, 1, 1, f);

    fclose(f);
    return 0;
}

// Analyser l'état de Secure Boot
void analyze_secure_boot_state() {
    printf("\n[*] Analyse de l'état de Secure Boot\n");
    printf("=====================================\n\n");

    uint8_t secure_boot = 0;
    uint8_t setup_mode = 0;
    int pk_exists = 0;
    int kek_exists = 0;
    int db_exists = 0;

    // Vérifier SecureBoot
    if (read_uefi_var_byte("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", &secure_boot) == 0) {
        printf("[+] SecureBoot       : %s\n", secure_boot ? "ENABLED" : "DISABLED");
    } else {
        printf("[-] SecureBoot       : Non lisible\n");
    }

    // Vérifier SetupMode
    if (read_uefi_var_byte("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", &setup_mode) == 0) {
        printf("[%c] SetupMode        : %s\n",
               setup_mode ? '!' : '+',
               setup_mode ? "YES (DANGER)" : "NO");
    } else {
        printf("[-] SetupMode        : Non lisible\n");
    }

    // Vérifier présence des clés
    pk_exists = uefi_var_exists("PK-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    kek_exists = uefi_var_exists("KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    db_exists = uefi_var_exists("db-d719b2cb-3d3a-4596-a3bc-dad00e67656f");

    printf("[%c] PK (Platform Key): %s\n", pk_exists ? '+' : '!', pk_exists ? "Présente" : "ABSENTE");
    printf("[%c] KEK              : %s\n", kek_exists ? '+' : '!', kek_exists ? "Présente" : "ABSENTE");
    printf("[%c] db (Allowed Keys): %s\n", db_exists ? '+' : '!', db_exists ? "Présente" : "ABSENTE");

    // Analyse de sécurité
    printf("\n[*] Évaluation de sécurité\n");
    printf("==========================\n\n");

    int threat_level = 0;

    if (setup_mode == 1) {
        printf("[!!] ALERTE CRITIQUE : Système en Setup Mode\n");
        printf("     → Secure Boot est DÉSACTIVÉ\n");
        printf("     → N'importe quel bootloader peut démarrer\n");
        printf("     → Possible attaque de suppression de PK\n");
        threat_level = 3;
    }

    if (!pk_exists) {
        printf("[!!] ALERTE CRITIQUE : PK absente\n");
        printf("     → La Platform Key a été supprimée\n");
        printf("     → Ceci est anormal sur un système configuré\n");
        printf("     → Possible compromission firmware\n");
        threat_level = 3;
    }

    if (secure_boot == 0 && setup_mode == 0) {
        printf("[!] AVERTISSEMENT : Secure Boot désactivé mais pas en Setup Mode\n");
        printf("    → Peut être légitime (désactivé dans le BIOS)\n");
        printf("    → Ou résultat d'une attaque\n");
        threat_level = (threat_level < 2) ? 2 : threat_level;
    }

    if (secure_boot == 1 && pk_exists && !setup_mode) {
        printf("[+] STATUT SAIN : Secure Boot actif et correctement configuré\n");
        threat_level = 0;
    }

    // Niveau de menace
    printf("\n[*] Niveau de menace : ");
    switch (threat_level) {
        case 0:
            printf("FAIBLE (système sain)\n");
            break;
        case 1:
            printf("MODÉRÉ (vérifier configuration)\n");
            break;
        case 2:
            printf("ÉLEVÉ (investigation recommandée)\n");
            break;
        case 3:
            printf("CRITIQUE (compromission probable)\n");
            break;
    }

    // Recommandations
    if (threat_level >= 2) {
        printf("\n[*] Recommandations\n");
        printf("===================\n\n");

        if (setup_mode == 1) {
            printf("1. Réactiver Secure Boot dans le BIOS/UEFI\n");
            printf("2. Restaurer les clés PK/KEK/db par défaut\n");
            printf("3. Vérifier l'intégrité du firmware (chipsec)\n");
        }

        if (!pk_exists) {
            printf("1. Vérifier les logs système pour modifications suspectes\n");
            printf("2. Vérifier /var/log/audit/audit.log pour accès à efivars\n");
            printf("3. Envisager une réinstallation du firmware\n");
        }

        printf("4. Activer TPM + Measured Boot pour détection future\n");
        printf("5. Protéger efivars : mount -o remount,ro /sys/firmware/efi/efivars\n");
    }
}

int main() {
    if (getuid() != 0) {
        printf("[-] Ce programme nécessite les privilèges root\n");
        return 1;
    }

    printf("[*] Détecteur de Setup Mode malveillant\n");
    printf("[*] =====================================\n");

    analyze_secure_boot_state();

    printf("\n[*] Analyse terminée\n");

    return 0;
}
```

**Explication** :
- Le programme vérifie l'état de toutes les variables Secure Boot
- Il détecte si le système est en Setup Mode (signe d'attaque)
- Il vérifie la présence de la PK (si absente = suppression malveillante)
- Il fournit une évaluation de sécurité et des recommandations

**Indicateurs d'attaque** :
- `SetupMode = 1` : Système en mode configuration (anormal)
- PK absente : La clé racine a été supprimée
- Secure Boot désactivé malgré clés présentes : Modification suspecte

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu peux :

- [x] Expliquer la chaîne de confiance Secure Boot (PK → KEK → db → bootloader)
- [x] Identifier les points de bypass (shim, MOK, Setup Mode, BootHole)
- [x] Parser la structure PE/COFF et extraire une signature Authenticode
- [x] Analyser les variables UEFI pour détecter des compromissions
- [x] Comprendre les attaques réelles (BlackLotus, BootHole)
- [x] Appliquer les mitigations (dbx updates, UEFI password, TPM)

**Module suivant** : [SPI Flash](../03-SPI-Flash/)
