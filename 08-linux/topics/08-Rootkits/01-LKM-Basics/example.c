/*
 * OBJECTIF  : Comprendre les Loadable Kernel Modules (LKM) Linux
 * PREREQUIS : Bases C, syscalls, architecture kernel
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les concepts des LKM : structure d'un module
 * kernel, compilation, chargement, et comment les modules sont
 * utilises comme base des rootkits kernel.
 * NOTE : Le code LKM reel necessite les headers kernel et un Makefile
 * special. Ce programme montre les concepts en userspace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <errno.h>

/*
 * Etape 1 : Qu'est-ce qu'un LKM ?
 */
static void explain_lkm(void) {
    printf("[*] Etape 1 : Loadable Kernel Modules (LKM)\n\n");

    printf("    Un LKM est du code charge dynamiquement dans le kernel :\n\n");

    printf("    ┌──────────────────────────────────────────────┐\n");
    printf("    │              KERNEL LINUX                     │\n");
    printf("    │                                              │\n");
    printf("    │  ┌──────────┐ ┌──────────┐ ┌──────────┐     │\n");
    printf("    │  │ Core     │ │ Built-in │ │ Loaded   │     │\n");
    printf("    │  │ kernel   │ │ drivers  │ │ modules  │     │\n");
    printf("    │  │          │ │          │ │  (LKM)   │     │\n");
    printf("    │  │ scheduler│ │ ext4, fs │ │ insmod   │     │\n");
    printf("    │  │ mm, net  │ │ virtio   │ │ rmmod    │     │\n");
    printf("    │  └──────────┘ └──────────┘ └──────────┘     │\n");
    printf("    │                              ^               │\n");
    printf("    │                    insmod / modprobe          │\n");
    printf("    └──────────────────────────────────────────────┘\n\n");

    printf("    Commandes :\n");
    printf("    - insmod module.ko  : charger un module\n");
    printf("    - rmmod module      : decharger un module\n");
    printf("    - modprobe module   : charger avec dependances\n");
    printf("    - lsmod             : lister les modules charges\n");
    printf("    - modinfo module.ko : informations sur un module\n\n");
}

/*
 * Etape 2 : Structure d'un module kernel
 */
static void show_module_structure(void) {
    printf("[*] Etape 2 : Structure d'un LKM minimal\n\n");

    printf("    // hello.c - Module kernel minimal\n");
    printf("    #include <linux/module.h>\n");
    printf("    #include <linux/kernel.h>\n");
    printf("    #include <linux/init.h>\n\n");

    printf("    MODULE_LICENSE(\"GPL\");\n");
    printf("    MODULE_AUTHOR(\"Auteur\");\n");
    printf("    MODULE_DESCRIPTION(\"Module de demonstration\");\n\n");

    printf("    // Fonction d'initialisation (appelee a insmod)\n");
    printf("    static int __init hello_init(void) {\n");
    printf("        printk(KERN_INFO \"Hello kernel!\\n\");\n");
    printf("        return 0;  // 0 = succes\n");
    printf("    }\n\n");

    printf("    // Fonction de nettoyage (appelee a rmmod)\n");
    printf("    static void __exit hello_exit(void) {\n");
    printf("        printk(KERN_INFO \"Goodbye kernel!\\n\");\n");
    printf("    }\n\n");

    printf("    module_init(hello_init);\n");
    printf("    module_exit(hello_exit);\n\n");

    printf("    Makefile :\n");
    printf("    obj-m += hello.o\n");
    printf("    all:\n");
    printf("    \tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\n");
    printf("    clean:\n");
    printf("    \tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n\n");
}

/*
 * Etape 3 : APIs kernel disponibles dans un LKM
 */
static void explain_kernel_apis(void) {
    printf("[*] Etape 3 : APIs kernel accessibles depuis un LKM\n\n");

    printf("    API                  | Usage offensif\n");
    printf("    ─────────────────────|──────────────────────────────────\n");
    printf("    kallsyms_lookup_name | Trouver l'adresse de n'importe quelle\n");
    printf("                         | fonction kernel (syscall table, etc.)\n");
    printf("    register_kprobe      | Hooker des fonctions kernel (kprobes)\n");
    printf("    register_ftrace_fn   | Hooking via ftrace\n");
    printf("    set_memory_rw        | Rendre la memoire kernel writable\n");
    printf("    copy_from_user       | Lire la memoire userspace\n");
    printf("    copy_to_user         | Ecrire dans la memoire userspace\n");
    printf("    current              | Acceder au task_struct du processus\n");
    printf("    for_each_process     | Iterer sur tous les processus\n");
    printf("    filp_open/vfs_read   | Lire/ecrire des fichiers depuis kernel\n");
    printf("    seq_operations       | Hooker /proc entries\n\n");

    printf("    Un LKM a un acces TOTAL au kernel :\n");
    printf("    - Modifier la syscall table\n");
    printf("    - Intercepter des appels reseau\n");
    printf("    - Cacher des processus et fichiers\n");
    printf("    - Installer des backdoors invisibles\n\n");
}

/*
 * Etape 4 : Lister les modules actuellement charges
 */
static void list_loaded_modules(void) {
    printf("[*] Etape 4 : Modules actuellement charges\n\n");

    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) {
        printf("    (impossible de lire /proc/modules)\n\n");
        return;
    }

    printf("    %-30s %-10s %s\n", "Module", "Taille", "Utilise par");
    printf("    %-30s %-10s %s\n", "──────────────────────────────",
           "──────────", "───────────");

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < 15) {
        char name[64] = {0};
        long size = 0;
        int refcount = 0;
        char deps[256] = {0};

        sscanf(line, "%63s %ld %d %255[^\n]", name, &size, &refcount, deps);
        printf("    %-30s %-10ld %s\n", name, size, deps);
        count++;
    }
    if (count >= 15)
        printf("    ... (tronque)\n");
    fclose(fp);

    /* Compter le total */
    fp = fopen("/proc/modules", "r");
    if (fp) {
        int total = 0;
        while (fgets(line, sizeof(line), fp)) total++;
        fclose(fp);
        printf("\n    Total : %d modules charges\n\n", total);
    }
}

/*
 * Etape 5 : Verifier les protections contre les LKM malveillants
 */
static void check_lkm_protections(void) {
    printf("[*] Etape 5 : Protections contre les LKM malveillants\n\n");

    /* Verifier si les modules peuvent etre charges */
    FILE *fp = fopen("/proc/sys/kernel/modules_disabled", "r");
    if (fp) {
        int val = 0;
        if (fscanf(fp, "%d", &val) == 1)
            printf("    modules_disabled : %d (%s)\n", val,
                   val ? "CHARGE DE MODULES DESACTIVE" : "modules autorises");
        fclose(fp);
    }

    /* Verifier la signature des modules */
    fp = fopen("/proc/config.gz", "r");
    if (!fp) {
        /* Alternative */
        struct utsname uts;
        if (uname(&uts) == 0) {
            char path[256];
            snprintf(path, sizeof(path), "/boot/config-%s", uts.release);
            fp = fopen(path, "r");
        }
    }

    printf("    Module signing : ");
    if (fp) {
        char line[256];
        int sig_found = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "CONFIG_MODULE_SIG=y")) {
                printf("ACTIVE\n");
                sig_found = 1;
                break;
            }
        }
        if (!sig_found)
            printf("non trouve (ou desactive)\n");
        fclose(fp);
    } else {
        printf("(impossible de verifier)\n");
    }

    /* Verifier Secure Boot */
    if (access("/sys/firmware/efi/efivars", F_OK) == 0)
        printf("    Secure Boot : EFI present (Secure Boot possible)\n");
    else
        printf("    Secure Boot : pas d'EFI detecte\n");

    /* Verifier lockdown */
    fp = fopen("/sys/kernel/security/lockdown", "r");
    if (fp) {
        char val[64] = {0};
        if (fgets(val, sizeof(val), fp)) {
            val[strcspn(val, "\n")] = '\0';
            printf("    Lockdown mode : %s\n", val);
        }
        fclose(fp);
    }
    printf("\n");
}

/*
 * Etape 6 : Comment un rootkit utilise les LKM
 */
static void explain_rootkit_lkm(void) {
    printf("[*] Etape 6 : LKM comme base de rootkit\n\n");

    printf("    Un rootkit LKM combine plusieurs techniques :\n\n");

    printf("    1. Hooking de la syscall table\n");
    printf("       -> Intercepter open, read, write, getdents64\n\n");

    printf("    2. Masquage de processus\n");
    printf("       -> Supprimer des entries de la task_list\n\n");

    printf("    3. Masquage de fichiers\n");
    printf("       -> Filtrer les resultats de getdents64()\n\n");

    printf("    4. Masquage reseau\n");
    printf("       -> Hook de seq_show pour /proc/net/tcp\n\n");

    printf("    5. Auto-masquage du module\n");
    printf("       -> list_del() sur la liste des modules\n");
    printf("       -> Le module n'apparait plus dans lsmod\n\n");

    printf("    6. Backdoor\n");
    printf("       -> Hook de sys_kill pour recevoir des commandes\n");
    printf("       -> Signal magic pour activer/desactiver\n\n");

    printf("    Code d'auto-masquage :\n");
    printf("    static int __init rootkit_init(void) {\n");
    printf("        list_del(&THIS_MODULE->list);  // Plus dans /proc/modules\n");
    printf("        return 0;\n");
    printf("    }\n\n");
}

int main(void) {
    printf("[*] Demo : LKM Basics (Loadable Kernel Modules)\n\n");

    explain_lkm();
    show_module_structure();
    explain_kernel_apis();
    list_loaded_modules();
    check_lkm_protections();
    explain_rootkit_lkm();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
