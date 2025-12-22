# Solutions - LKM Basics

## Solution Exercice 1 : Découverte (Très facile)

**Objectif** : Créer et charger un module kernel basique

### Code complet : hello_lkm.c

```c
/*
 * hello_lkm.c - Module kernel basique de démonstration
 *
 * Compilation :
 *   Créer d'abord un Makefile
 *
 * Usage :
 *   sudo insmod hello_lkm.ko
 *   sudo rmmod hello_lkm
 *   dmesg | tail
 */

#include <linux/module.h>    // Requis pour tous les modules kernel
#include <linux/kernel.h>    // Requis pour KERN_INFO
#include <linux/init.h>      // Requis pour les macros __init et __exit

/*
 * Fonction d'initialisation du module
 * Appelée quand le module est chargé avec insmod
 *
 * __init est une macro qui indique que cette fonction est utilisée
 * uniquement au chargement et peut être supprimée de la mémoire après
 */
static int __init hello_init(void) {
    // printk est l'équivalent kernel de printf
    // KERN_INFO définit le niveau de log (info, warning, error, etc.)
    printk(KERN_INFO "[*] Hello LKM: Module chargé dans le kernel\n");
    printk(KERN_INFO "[*] Hello LKM: Initialisation réussie\n");

    // Retourner 0 indique un chargement réussi
    // Toute valeur non-nulle indique une erreur
    return 0;
}

/*
 * Fonction de nettoyage du module
 * Appelée quand le module est déchargé avec rmmod
 *
 * __exit indique que cette fonction est utilisée uniquement
 * lors du déchargement du module
 */
static void __exit hello_exit(void) {
    printk(KERN_INFO "[*] Hello LKM: Module déchargé du kernel\n");
    printk(KERN_INFO "[*] Hello LKM: Nettoyage effectué\n");
}

/*
 * Macros qui enregistrent les fonctions d'initialisation et de sortie
 * Le kernel sait ainsi quelles fonctions appeler lors du chargement/déchargement
 */
module_init(hello_init);  // Enregistre la fonction d'initialisation
module_exit(hello_exit);  // Enregistre la fonction de nettoyage

/*
 * Métadonnées du module
 * Ces informations sont visibles avec la commande 'modinfo'
 */
MODULE_LICENSE("GPL");                          // Type de licence (GPL requis pour certaines fonctions kernel)
MODULE_AUTHOR("Votre Nom");                     // Auteur du module
MODULE_DESCRIPTION("Module kernel de base");    // Description courte
MODULE_VERSION("1.0");                          // Version du module
```

### Makefile

```makefile
# Makefile pour compiler un module kernel Linux
# Le système de build du kernel (kbuild) gère la compilation

# obj-m indique que nous voulons compiler un module (.ko)
# Le nom avant .o deviendra le nom du fichier .ko
obj-m += hello_lkm.o

# Récupère la version du kernel en cours d'exécution
KVERSION = $(shell uname -r)

# Chemin vers les sources/headers du kernel
KDIR = /lib/modules/$(KVERSION)/build

# Répertoire de travail actuel
PWD = $(shell pwd)

# Cible par défaut : compile le module
all:
	# -C change de répertoire vers KDIR (sources kernel)
	# M=$(PWD) indique où se trouve notre module
	# modules est la cible à construire
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Cible de nettoyage : supprime les fichiers générés
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.* .*.cmd Module.symvers modules.order

# Cible pour installer le module (optionnel)
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
```

### Étapes de compilation et test

```bash
# 1. Compiler le module
make

# 2. Vérifier que le .ko a été créé
ls -lh hello_lkm.ko

# 3. Obtenir des informations sur le module
modinfo hello_lkm.ko

# 4. Charger le module dans le kernel
sudo insmod hello_lkm.ko

# 5. Vérifier que le module est chargé
lsmod | grep hello_lkm

# 6. Voir les messages du kernel (logs d'initialisation)
dmesg | tail -n 10

# 7. Décharger le module
sudo rmmod hello_lkm

# 8. Vérifier les messages de déchargement
dmesg | tail -n 5
```

### Résultat attendu

```
[*] Hello LKM: Module chargé dans le kernel
[*] Hello LKM: Initialisation réussie
[*] Hello LKM: Module déchargé du kernel
[*] Hello LKM: Nettoyage effectué
```

---

## Solution Exercice 2 : Modification (Facile)

**Objectif** : Ajouter des paramètres au module

### Code complet : param_lkm.c

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>  // Pour les paramètres de module

/*
 * Déclaration de variables pour les paramètres
 * Ces variables seront configurables lors du chargement du module
 */
static char *name = "Anonymous";     // Paramètre chaîne de caractères
static int count = 1;                // Paramètre entier

/*
 * module_param() enregistre une variable comme paramètre du module
 *
 * Syntaxe : module_param(nom_variable, type, permissions)
 *
 * Types possibles : int, long, short, uint, ulong, ushort, charp (char*), bool
 * Permissions : 0 = non visible dans sysfs, 0444 = lecture seule, 0664 = lecture/écriture
 */
module_param(name, charp, 0644);
MODULE_PARM_DESC(name, "Nom à afficher dans le message");

module_param(count, int, 0644);
MODULE_PARM_DESC(count, "Nombre de fois à afficher le message");

static int __init param_init(void) {
    int i;

    printk(KERN_INFO "[*] Param LKM: Module chargé avec paramètres\n");

    // Affiche le message 'count' fois avec le nom spécifié
    for (i = 0; i < count; i++) {
        printk(KERN_INFO "[*] Message %d: Bonjour %s!\n", i + 1, name);
    }

    return 0;
}

static void __exit param_exit(void) {
    printk(KERN_INFO "[*] Param LKM: Au revoir %s!\n", name);
}

module_init(param_init);
module_exit(param_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre Nom");
MODULE_DESCRIPTION("Module avec paramètres configurables");
MODULE_VERSION("1.0");
```

### Test avec paramètres

```bash
# Charger avec paramètres par défaut
sudo insmod param_lkm.ko

# Charger avec paramètres personnalisés
sudo insmod param_lkm.ko name="Alice" count=3

# Voir les paramètres dans sysfs
cat /sys/module/param_lkm/parameters/name
cat /sys/module/param_lkm/parameters/count

# Modifier un paramètre à chaud (si permissions le permettent)
echo "Bob" | sudo tee /sys/module/param_lkm/parameters/name
```

---

## Solution Exercice 3 : Création (Moyen)

**Objectif** : Créer un module avec /proc interface

### Code complet : proc_lkm.c

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>    // Pour l'interface /proc
#include <linux/uaccess.h>    // Pour copy_to_user, copy_from_user
#include <linux/version.h>

#define PROCFS_NAME "lkm_info"
#define BUFFER_SIZE 256

static struct proc_dir_entry *our_proc_file;
static char proc_buffer[BUFFER_SIZE];

/*
 * Fonction appelée quand on lit le fichier /proc
 * Equivalent de la lecture d'un fichier depuis l'espace utilisateur
 */
static ssize_t procfile_read(struct file *file, char __user *buffer,
                             size_t count, loff_t *offset) {
    char message[BUFFER_SIZE];
    int len;

    // Si on a déjà lu (offset non nul), retourner 0 (EOF)
    if (*offset > 0) {
        return 0;
    }

    // Prépare le message à envoyer à l'utilisateur
    len = snprintf(message, BUFFER_SIZE,
                  "Module LKM Info\n"
                  "===============\n"
                  "Version: 1.0\n"
                  "Statut: Actif\n"
                  "Contenu buffer: %s\n",
                  proc_buffer[0] ? proc_buffer : "(vide)");

    // Copie les données de l'espace kernel vers l'espace utilisateur
    // copy_to_user est nécessaire car on ne peut pas accéder directement
    // à la mémoire utilisateur depuis le kernel
    if (copy_to_user(buffer, message, len)) {
        return -EFAULT;  // Erreur si la copie échoue
    }

    *offset = len;  // Met à jour la position dans le fichier
    return len;     // Retourne le nombre d'octets lus
}

/*
 * Fonction appelée quand on écrit dans le fichier /proc
 * Permet à l'utilisateur d'envoyer des données au module
 */
static ssize_t procfile_write(struct file *file, const char __user *buffer,
                              size_t count, loff_t *offset) {
    size_t len = count;

    // Limite la taille pour éviter le dépassement de buffer
    if (len >= BUFFER_SIZE) {
        len = BUFFER_SIZE - 1;
    }

    // Copie les données de l'espace utilisateur vers l'espace kernel
    if (copy_from_user(proc_buffer, buffer, len)) {
        return -EFAULT;
    }

    // Assure la terminaison de la chaîne
    proc_buffer[len] = '\0';

    printk(KERN_INFO "[*] Proc LKM: Reçu: %s\n", proc_buffer);

    return len;
}

/*
 * Structure qui définit les opérations sur le fichier /proc
 * Selon la version du kernel, la structure peut différer
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops proc_file_fops = {
    .proc_read = procfile_read,
    .proc_write = procfile_write,
};
#else
static const struct file_operations proc_file_fops = {
    .read = procfile_read,
    .write = procfile_write,
};
#endif

static int __init proc_init(void) {
    // Initialise le buffer
    memset(proc_buffer, 0, BUFFER_SIZE);

    // Crée le fichier /proc/lkm_info avec permissions 0666 (lecture/écriture pour tous)
    our_proc_file = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_fops);

    if (!our_proc_file) {
        printk(KERN_ERR "[!] Proc LKM: Impossible de créer /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "[*] Proc LKM: /proc/%s créé\n", PROCFS_NAME);
    return 0;
}

static void __exit proc_exit(void) {
    // Supprime le fichier /proc lors du déchargement
    proc_remove(our_proc_file);
    printk(KERN_INFO "[*] Proc LKM: /proc/%s supprimé\n", PROCFS_NAME);
}

module_init(proc_init);
module_exit(proc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre Nom");
MODULE_DESCRIPTION("Module avec interface /proc");
MODULE_VERSION("1.0");
```

### Test de l'interface /proc

```bash
# Charger le module
sudo insmod proc_lkm.ko

# Lire le fichier /proc
cat /proc/lkm_info

# Écrire dans le fichier /proc
echo "Test message" | sudo tee /proc/lkm_info

# Relire pour voir le changement
cat /proc/lkm_info

# Décharger le module
sudo rmmod proc_lkm
```

---

## Solution Exercice 4 : Challenge (Difficile)

**Objectif** : Module avec device character et IOCTL

### Code complet : chardev_lkm.c

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>          // Pour file_operations
#include <linux/cdev.h>        // Pour character device
#include <linux/device.h>      // Pour class_create
#include <linux/uaccess.h>     // Pour copy_to_user

#define DEVICE_NAME "lkm_dev"
#define CLASS_NAME "lkm_class"
#define BUFFER_SIZE 1024

static int major_number;
static struct class *chardev_class = NULL;
static struct device *chardev_device = NULL;
static char device_buffer[BUFFER_SIZE];
static int buffer_size = 0;

/*
 * Fonction appelée quand le device est ouvert
 */
static int dev_open(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "[*] CharDev LKM: Device ouvert\n");
    return 0;
}

/*
 * Fonction appelée quand on lit depuis le device
 */
static ssize_t dev_read(struct file *filep, char __user *buffer,
                       size_t len, loff_t *offset) {
    int bytes_to_read = buffer_size - *offset;

    if (bytes_to_read <= 0) {
        return 0;  // EOF
    }

    if (bytes_to_read > len) {
        bytes_to_read = len;
    }

    if (copy_to_user(buffer, device_buffer + *offset, bytes_to_read)) {
        return -EFAULT;
    }

    *offset += bytes_to_read;
    printk(KERN_INFO "[*] CharDev LKM: %d octets lus\n", bytes_to_read);

    return bytes_to_read;
}

/*
 * Fonction appelée quand on écrit dans le device
 */
static ssize_t dev_write(struct file *filep, const char __user *buffer,
                        size_t len, loff_t *offset) {
    int bytes_to_write = len;

    if (bytes_to_write > BUFFER_SIZE - 1) {
        bytes_to_write = BUFFER_SIZE - 1;
    }

    if (copy_from_user(device_buffer, buffer, bytes_to_write)) {
        return -EFAULT;
    }

    device_buffer[bytes_to_write] = '\0';
    buffer_size = bytes_to_write;

    printk(KERN_INFO "[*] CharDev LKM: %d octets écrits: %s\n",
           bytes_to_write, device_buffer);

    return bytes_to_write;
}

/*
 * Fonction appelée quand le device est fermé
 */
static int dev_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "[*] CharDev LKM: Device fermé\n");
    return 0;
}

/*
 * Structure définissant les opérations du character device
 */
static struct file_operations fops = {
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

static int __init chardev_init(void) {
    printk(KERN_INFO "[*] CharDev LKM: Initialisation\n");

    // Enregistre le character device et obtient un major number
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ERR "[!] CharDev LKM: Échec enregistrement major number\n");
        return major_number;
    }
    printk(KERN_INFO "[*] CharDev LKM: Major number: %d\n", major_number);

    // Crée la classe de device
    chardev_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(chardev_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ERR "[!] CharDev LKM: Échec création classe\n");
        return PTR_ERR(chardev_class);
    }

    // Crée le device (/dev/lkm_dev)
    chardev_device = device_create(chardev_class, NULL,
                                   MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(chardev_device)) {
        class_destroy(chardev_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ERR "[!] CharDev LKM: Échec création device\n");
        return PTR_ERR(chardev_device);
    }

    printk(KERN_INFO "[*] CharDev LKM: Device créé: /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit chardev_exit(void) {
    device_destroy(chardev_class, MKDEV(major_number, 0));
    class_unregister(chardev_class);
    class_destroy(chardev_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "[*] CharDev LKM: Nettoyage effectué\n");
}

module_init(chardev_init);
module_exit(chardev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre Nom");
MODULE_DESCRIPTION("Character device driver");
MODULE_VERSION("1.0");
```

### Test du character device

```bash
# Charger le module
sudo insmod chardev_lkm.ko

# Vérifier la création du device
ls -l /dev/lkm_dev

# Écrire dans le device
echo "Hello from userspace" | sudo tee /dev/lkm_dev

# Lire depuis le device
sudo cat /dev/lkm_dev

# Test avec un programme C
cat > test_dev.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/dev/lkm_dev", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "Test message", 12);

    char buf[100];
    lseek(fd, 0, SEEK_SET);
    int n = read(fd, buf, sizeof(buf));
    buf[n] = '\0';
    printf("Lu: %s\n", buf);

    close(fd);
    return 0;
}
EOF

gcc test_dev.c -o test_dev
sudo ./test_dev
```

---

## Critères de réussite

- Module se compile sans erreur ni warning
- Module se charge et se décharge proprement
- Pas de kernel panic ou d'erreurs dans dmesg
- Les fonctionnalités implémentées fonctionnent correctement
- Le code est bien commenté et compréhensible

## Notes importantes

1. **Sécurité** : Toujours tester dans une VM, un module kernel bugué peut crasher le système
2. **Permissions** : Les opérations sur les modules nécessitent les droits root
3. **Versions** : Certaines API kernel changent entre versions, adapter si nécessaire
4. **Debugging** : Utiliser dmesg, printk avec différents niveaux de log
5. **Nettoyage** : Toujours décharger les modules de test pour éviter les fuites mémoire
