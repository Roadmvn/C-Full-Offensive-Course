# Solutions - Hardware Implants

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre les concepts de base des implants hardware

**Solution** :

```bash
# Compilation
gcc example.c -o hardware_implants

# Exécution
./hardware_implants
```

**Résultat attendu** :
```
[*] Module : Hardware Implants
[*] ==========================================

[+] Exemple terminé avec succès
```

**Explication** : Introduction aux backdoors matériels et à leur détection.

---

## Exercice 2 : Énumération des périphériques (Facile)

**Objectif** : Créer un outil pour lister tous les devices hardware

**Solution** :

```c
/*
 * Hardware Device Enumerator
 * Liste tous les périphériques pour détecter des implants suspects
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

// Couleurs pour l'affichage
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RESET   "\x1b[0m"

// Lire le contenu d'un fichier sysfs
void read_sysfs_file(const char* path, char* buffer, size_t size) {
    FILE* f = fopen(path, "r");
    if (f) {
        if (fgets(buffer, size, f) == NULL) {
            buffer[0] = '\0';
        }
        // Supprimer le \n final
        buffer[strcspn(buffer, "\n")] = '\0';
        fclose(f);
    } else {
        buffer[0] = '\0';
    }
}

// Énumérer les périphériques USB
void enumerate_usb_devices() {
    printf("\n[*] Périphériques USB:\n");
    printf("==========================================\n");

    DIR* dir = opendir("/sys/bus/usb/devices");
    if (!dir) {
        printf("[-] Impossible d'ouvrir /sys/bus/usb/devices\n");
        return;
    }

    struct dirent* entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        // Ignorer . et ..
        if (entry->d_name[0] == '.') continue;

        char path[512];
        char vendor[256] = "Unknown";
        char product[256] = "Unknown";
        char serial[256] = "N/A";

        // Lire vendor ID
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", entry->d_name);
        read_sysfs_file(path, vendor, sizeof(vendor));

        // Lire product ID
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", entry->d_name);
        read_sysfs_file(path, product, sizeof(product));

        // Lire serial
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/serial", entry->d_name);
        read_sysfs_file(path, serial, sizeof(serial));

        // Afficher uniquement si on a des infos valides
        if (strlen(vendor) > 0 && strlen(product) > 0) {
            count++;
            printf("[%d] %s\n", count, entry->d_name);
            printf("    Vendor:  %s\n", vendor);
            printf("    Product: %s\n", product);
            printf("    Serial:  %s\n", serial);

            // Détecter des patterns suspects
            // Keylogger USB souvent sans serial ou vendor inconnu
            if (strlen(serial) == 0 || strcmp(serial, "N/A") == 0) {
                printf("    %s[!] SUSPECT: Pas de numéro de série%s\n",
                       COLOR_YELLOW, COLOR_RESET);
            }
        }
    }

    closedir(dir);
    printf("\n[+] Total: %d périphériques USB\n", count);
}

// Énumérer les périphériques PCI
void enumerate_pci_devices() {
    printf("\n[*] Périphériques PCI/PCIe:\n");
    printf("==========================================\n");

    FILE* fp = popen("lspci 2>/dev/null", "r");
    if (!fp) {
        printf("[-] lspci non disponible\n");
        return;
    }

    char line[512];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        count++;
        printf("[%d] %s", count, line);

        // Détecter des devices suspects
        if (strstr(line, "Unknown") || strstr(line, "unrecognized")) {
            printf("    %s[!] SUSPECT: Device non reconnu%s\n",
                   COLOR_RED, COLOR_RESET);
        }
    }

    pclose(fp);
    printf("\n[+] Total: %d périphériques PCI\n", count);
}

// Vérifier les devices block (disques, USB)
void enumerate_block_devices() {
    printf("\n[*] Périphériques de stockage:\n");
    printf("==========================================\n");

    FILE* fp = popen("lsblk -o NAME,SIZE,TYPE,VENDOR,MODEL 2>/dev/null", "r");
    if (!fp) {
        printf("[-] lsblk non disponible\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }

    pclose(fp);
}

// Vérifier les devices network
void enumerate_network_devices() {
    printf("\n[*] Interfaces réseau:\n");
    printf("==========================================\n");

    FILE* fp = popen("ip link show 2>/dev/null", "r");
    if (!fp) {
        printf("[-] ip non disponible\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);

        // Détecter interface en mode promiscuous (suspect)
        if (strstr(line, "PROMISC")) {
            printf("    %s[!] SUSPECT: Mode promiscuous actif%s\n",
                   COLOR_RED, COLOR_RESET);
        }
    }

    pclose(fp);
}

int main() {
    printf("[*] Hardware Implant Detector\n");
    printf("[*] ==========================================\n");

    // Vérifier si root (nécessaire pour certaines opérations)
    if (geteuid() != 0) {
        printf("\n%s[!] ATTENTION: Exécuter en root pour plus d'informations%s\n",
               COLOR_YELLOW, COLOR_RESET);
    }

    // Énumérer tous les types de devices
    enumerate_usb_devices();
    enumerate_pci_devices();
    enumerate_block_devices();
    enumerate_network_devices();

    // Recommandations
    printf("\n[*] Recommandations de sécurité:\n");
    printf("==========================================\n");
    printf("1. Vérifier tous les devices USB inconnus\n");
    printf("2. Comparer avec un inventaire de référence\n");
    printf("3. Inspecter physiquement les câbles suspects\n");
    printf("4. Vérifier l'intégrité du BIOS/UEFI\n");
    printf("5. Utiliser des serrures physiques (port locks)\n");

    return 0;
}
```

**Compilation et exécution** :
```bash
gcc hardware_enum.c -o hardware_enum
sudo ./hardware_enum
```

---

## Exercice 3 : Détection d'implants USB (Moyen)

**Objectif** : Créer un moniteur en temps réel pour détecter les nouveaux devices USB

**Solution** :

```c
/*
 * USB Monitoring Tool
 * Détecte les nouveaux périphériques USB en temps réel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/inotify.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

// Obtenir l'heure actuelle formatée
void get_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

// Lire info USB
void get_usb_info(const char* device, char* info, size_t size) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "udevadm info --name=%s 2>/dev/null | grep -E 'ID_VENDOR=|ID_MODEL='",
             device);

    FILE* fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        info[0] = '\0';
        while (fgets(line, sizeof(line), fp)) {
            strcat(info, line);
        }
        pclose(fp);
    } else {
        strcpy(info, "Unknown");
    }
}

// Analyser si le device est suspect
int is_suspicious_device(const char* device) {
    char cmd[512];
    int suspicious = 0;

    // Vérifier si c'est un HID (clavier/souris)
    snprintf(cmd, sizeof(cmd),
             "udevadm info --name=%s 2>/dev/null | grep -q 'ID_USB_DRIVER=usbhid'",
             device);

    if (system(cmd) == 0) {
        // C'est un HID - vérifier s'il y a déjà un clavier
        FILE* fp = popen("ls /dev/input/by-id/*kbd* 2>/dev/null | wc -l", "r");
        if (fp) {
            int count;
            fscanf(fp, "%d", &count);
            if (count > 1) {
                // Plus d'un clavier = suspect (keylogger?)
                suspicious = 1;
            }
            pclose(fp);
        }
    }

    return suspicious;
}

int main() {
    printf("[*] USB Monitoring Tool - Hardware Implant Detection\n");
    printf("[*] ==========================================\n\n");

    // Initialiser inotify
    int fd = inotify_init();
    if (fd < 0) {
        perror("[-] Erreur inotify_init");
        return 1;
    }

    // Surveiller /dev pour les nouveaux devices
    int wd = inotify_add_watch(fd, "/dev", IN_CREATE);
    if (wd < 0) {
        perror("[-] Erreur inotify_add_watch");
        return 1;
    }

    printf("[+] Monitoring actif sur /dev\n");
    printf("[+] Détection des nouveaux périphériques USB...\n");
    printf("[+] Appuyez sur Ctrl+C pour arrêter\n\n");

    char buffer[BUF_LEN];

    while (1) {
        int length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("[-] Erreur read");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            if (event->len) {
                // Filtrer uniquement les devices USB (sd*, tty*)
                if (strncmp(event->name, "sd", 2) == 0 ||
                    strncmp(event->name, "tty", 3) == 0) {

                    char timestamp[64];
                    get_timestamp(timestamp, sizeof(timestamp));

                    printf("[%s] Nouveau device détecté: /dev/%s\n",
                           timestamp, event->name);

                    // Obtenir les infos
                    char info[512];
                    char device[256];
                    snprintf(device, sizeof(device), "/dev/%s", event->name);
                    get_usb_info(device, info, sizeof(info));

                    if (strlen(info) > 0) {
                        printf("    Infos: %s", info);
                    }

                    // Analyser si suspect
                    if (is_suspicious_device(device)) {
                        printf("    \x1b[31m[!] ALERTE: Device potentiellement suspect!\x1b[0m\n");
                        printf("    Raison: Multiple HID devices détectés\n");
                        printf("    Action recommandée: Inspecter physiquement\n");
                    }

                    printf("\n");
                }
            }

            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);

    return 0;
}
```

**Critères de réussite** :
- Monitoring en temps réel des nouveaux devices
- Détection des patterns suspects (multiple keyboards)
- Alertes en cas de device anormal

---

## Exercice 4 : Vérification d'intégrité BIOS (Difficile)

**Objectif** : Créer un outil pour détecter les modifications du firmware BIOS/UEFI

**Contexte** :
Les implants hardware avancés peuvent modifier le BIOS/UEFI pour établir une persistence qui survit à la réinstallation de l'OS.

**Solution** :

```c
/*
 * BIOS/UEFI Integrity Checker
 * Détecte les modifications du firmware
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>

// Calculer SHA256 d'un fichier
int calculate_sha256(const char* filename, unsigned char* hash) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[8192];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&sha256, buffer, bytes);
    }

    SHA256_Final(hash, &sha256);
    fclose(file);

    return 0;
}

// Convertir hash en string hexadécimal
void hash_to_string(unsigned char* hash, char* output) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
}

// Dumper le BIOS ROM
int dump_bios_rom(const char* output_file) {
    printf("[+] Dump de la ROM BIOS...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "flashrom -p internal -r %s 2>/dev/null",
             output_file);

    int ret = system(cmd);

    if (ret != 0) {
        printf("[-] Erreur: flashrom n'est pas installé ou pas de permissions\n");
        printf("    Installer: sudo apt install flashrom\n");
        return -1;
    }

    printf("[+] ROM sauvegardée dans: %s\n", output_file);
    return 0;
}

// Vérifier les variables UEFI suspectes
void check_uefi_variables() {
    printf("\n[*] Vérification des variables UEFI:\n");
    printf("==========================================\n");

    FILE* fp = popen("efivar -l 2>/dev/null", "r");
    if (!fp) {
        printf("[-] efivar non disponible\n");
        return;
    }

    char line[512];
    int count = 0;
    int suspicious = 0;

    while (fgets(line, sizeof(line), fp)) {
        count++;

        // Rechercher des patterns suspects
        if (strstr(line, "Boot") && strstr(line, "Unknown")) {
            printf("\x1b[33m[!] Variable suspecte: %s\x1b[0m", line);
            suspicious++;
        }
    }

    pclose(fp);

    printf("\n[+] Total: %d variables UEFI\n", count);
    if (suspicious > 0) {
        printf("\x1b[31m[!] %d variable(s) suspecte(s) détectée(s)\x1b[0m\n", suspicious);
    }
}

// Vérifier les boot options
void check_boot_options() {
    printf("\n[*] Options de boot:\n");
    printf("==========================================\n");

    FILE* fp = popen("efibootmgr 2>/dev/null", "r");
    if (!fp) {
        printf("[-] efibootmgr non disponible\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);

        // Détecter des entrées suspectes
        if (strstr(line, "PXE") || strstr(line, "Network")) {
            printf("    \x1b[33m[!] Boot réseau activé (peut être suspect)\x1b[0m\n");
        }
    }

    pclose(fp);
}

// Comparer avec un hash de référence
int verify_integrity(const char* rom_file, const char* reference_hash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hash_str[65];

    if (calculate_sha256(rom_file, hash) != 0) {
        printf("[-] Erreur lors du calcul du hash\n");
        return -1;
    }

    hash_to_string(hash, hash_str);

    printf("\n[*] Vérification d'intégrité:\n");
    printf("==========================================\n");
    printf("Hash actuel:    %s\n", hash_str);
    printf("Hash référence: %s\n", reference_hash);

    if (strcmp(hash_str, reference_hash) == 0) {
        printf("\x1b[32m[+] BIOS INTÈGRE - Aucune modification détectée\x1b[0m\n");
        return 0;
    } else {
        printf("\x1b[31m[!] ALERTE: BIOS MODIFIÉ!\x1b[0m\n");
        printf("\x1b[31m[!] Possible implant firmware détecté!\x1b[0m\n");
        return 1;
    }
}

int main(int argc, char* argv[]) {
    printf("[*] BIOS/UEFI Integrity Checker\n");
    printf("[*] ==========================================\n\n");

    // Vérifier les permissions root
    if (geteuid() != 0) {
        printf("\x1b[31m[-] Erreur: Ce programme doit être exécuté en root\x1b[0m\n");
        return 1;
    }

    const char* rom_file = "/tmp/bios_current.rom";

    // Option 1: Créer une baseline
    if (argc > 1 && strcmp(argv[1], "--baseline") == 0) {
        printf("[*] Mode: Création de baseline\n\n");

        if (dump_bios_rom(rom_file) != 0) {
            return 1;
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        char hash_str[65];

        calculate_sha256(rom_file, hash);
        hash_to_string(hash, hash_str);

        printf("\n[*] Hash de référence (à sauvegarder):\n");
        printf("%s\n", hash_str);

        // Sauvegarder dans un fichier
        FILE* f = fopen("/etc/bios_baseline.txt", "w");
        if (f) {
            fprintf(f, "%s\n", hash_str);
            fclose(f);
            printf("[+] Baseline sauvegardée dans /etc/bios_baseline.txt\n");
        }

        return 0;
    }

    // Option 2: Vérifier l'intégrité
    printf("[*] Mode: Vérification d'intégrité\n\n");

    // Lire le hash de référence
    char reference_hash[65] = {0};
    FILE* f = fopen("/etc/bios_baseline.txt", "r");
    if (f) {
        fgets(reference_hash, sizeof(reference_hash), f);
        reference_hash[strcspn(reference_hash, "\n")] = '\0';
        fclose(f);
    } else {
        printf("[-] Pas de baseline trouvée\n");
        printf("    Exécuter: sudo %s --baseline\n", argv[0]);
        return 1;
    }

    // Dumper et vérifier
    if (dump_bios_rom(rom_file) != 0) {
        return 1;
    }

    verify_integrity(rom_file, reference_hash);

    // Vérifications additionnelles
    check_uefi_variables();
    check_boot_options();

    printf("\n[*] Recommandations:\n");
    printf("==========================================\n");
    printf("1. Activer Secure Boot si disponible\n");
    printf("2. Mettre un mot de passe BIOS\n");
    printf("3. Désactiver boot réseau (PXE) si non utilisé\n");
    printf("4. Vérifier régulièrement l'intégrité du firmware\n");
    printf("5. Sceller physiquement le boîtier (tamper seals)\n");

    return 0;
}
```

**Compilation** :
```bash
gcc bios_checker.c -o bios_checker -lssl -lcrypto
```

**Usage** :
```bash
# Créer une baseline de référence
sudo ./bios_checker --baseline

# Vérifier l'intégrité
sudo ./bios_checker
```

**Bonus - Détection BadUSB** :

```bash
#!/bin/bash
# Script de détection BadUSB

echo "[*] BadUSB Detection Script"
echo "=========================================="

# Lister tous les HID devices
echo -e "\n[*] HID Devices détectés:"
find /sys/bus/usb/devices -name "product" -exec cat {} \; | grep -i keyboard

# Vérifier les devices qui se présentent comme storage ET keyboard
echo -e "\n[*] Recherche de devices multi-fonction suspects..."
for dev in /sys/bus/usb/devices/*; do
    if [ -f "$dev/product" ]; then
        product=$(cat "$dev/product" 2>/dev/null)

        # Vérifier si le device a plusieurs interfaces
        interfaces=$(ls "$dev" | grep -c ":")

        if [ "$interfaces" -gt 1 ]; then
            echo "[!] Device suspect: $product (multiples interfaces)"
            ls "$dev" | grep ":"
        fi
    fi
done

echo -e "\n[+] Scan terminé"
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer les différents types d'implants hardware
- [ ] Énumérer et auditer les périphériques d'un système
- [ ] Détecter des devices USB suspects en temps réel
- [ ] Vérifier l'intégrité du BIOS/UEFI
- [ ] Identifier les contre-mesures (physical security, monitoring)

## Notes importantes

- **Accès physique = game over** : Les implants hardware nécessitent un accès physique
- **Supply chain risk** : Attaque possible pendant fabrication/transport
- **Détection difficile** : Inspection visuelle et firmware analysis nécessaires
- **Cas réels** : NSA ANT catalog, BadUSB, O.MG Cable
