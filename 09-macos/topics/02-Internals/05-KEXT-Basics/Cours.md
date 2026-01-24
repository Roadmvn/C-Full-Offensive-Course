# Kernel Extensions (KEXT) - Fondamentaux

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'architecture des Kernel Extensions sur macOS
- [ ] Développer une KEXT simple en C/C++
- [ ] Charger et décharger des KEXT dans le kernel
- [ ] Implémenter la communication entre user space et kernel space
- [ ] Analyser les risques et applications offensives des KEXT

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C et C++
- Les concepts de programmation système (pointeurs, mémoire, processus)
- L'architecture kernel/user space
- Les bases du debugging et de l'analyse système

## Introduction

Les Kernel Extensions (KEXT) sont des modules de code qui s'exécutent dans l'espace kernel de macOS, avec le niveau de privilège le plus élevé du système. Elles permettent d'étendre les fonctionnalités du noyau sans avoir à le recompiler.

### Pourquoi ce sujet est important ?

Imaginez le kernel comme le cerveau du système d'exploitation. Une KEXT est comme un implant qui modifie directement le fonctionnement du cerveau. Elle peut tout voir, tout contrôler, mais un bug peut faire crasher tout le système.

Pour un opérateur Red Team, les KEXT représentent :
- **Le niveau de persistance ultime** : Survit aux redémarrages, difficile à détecter
- **Le contrôle total** : Accès à toute la mémoire, tous les processus
- **L'invisibilité** : Peut masquer sa présence et celle d'autres malwares

**Note importante** : Depuis macOS Big Sur (11.0), Apple a considérablement renforcé les restrictions sur les KEXT, favorisant les System Extensions. Cependant, comprendre les KEXT reste crucial pour :
- Analyser des malwares legacy
- Comprendre les mécanismes de sécurité kernel
- Développer des outils de forensics bas niveau

## Concepts fondamentaux

### Concept 1 : Architecture kernel/user space sur macOS

```
┌─────────────────────────────────────────────────────────┐
│                    User Space (Ring 3)                  │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │   App    │  │   App    │  │   App    │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │             │             │                    │
│       └─────────────┼─────────────┘                    │
│                     │                                  │
│                     │ System Calls                     │
│                     │ (syscall, ioctl, etc.)           │
├─────────────────────┼──────────────────────────────────┤
│                     ▼                                  │
│  ┌────────────────────────────────────────────────┐   │
│  │          BSD Layer (POSIX)                     │   │
│  │  (file systems, networking, process mgmt)      │   │
│  └───────────────────┬────────────────────────────┘   │
│                      │                                 │
│  ┌───────────────────▼────────────────────────────┐   │
│  │              Mach Kernel                       │   │
│  │  (IPC, threads, virtual memory, scheduling)    │   │
│  └───────────────────┬────────────────────────────┘   │
│                      │                                 │
│      ┌───────────────┼───────────────┐                │
│      ▼               ▼               ▼                │
│  ┌────────┐    ┌─────────┐    ┌─────────┐           │
│  │  KEXT  │    │  KEXT   │    │  KEXT   │           │
│  │ (I/O)  │    │ (Net)   │    │ (Custom)│           │
│  └────┬───┘    └────┬────┘    └────┬────┘           │
│       │             │              │                  │
│       └─────────────┼──────────────┘                  │
│                     ▼                                  │
│  ┌──────────────────────────────────────────────┐    │
│  │           I/O Kit Framework                   │    │
│  │  (device drivers, hardware abstraction)       │    │
│  └──────────────────────────────────────────────┘    │
│                                                       │
│                 Kernel Space (Ring 0)                 │
└───────────────────────────────────────────────────────┘
                         │
                         ▼
                   ┌──────────┐
                   │ Hardware │
                   └──────────┘
```

### Concept 2 : Structure d'une KEXT

Une KEXT macOS est composée de plusieurs éléments :

```
MyKext.kext/
├── Contents/
│   ├── Info.plist          # Métadonnées et configuration
│   ├── MacOS/
│   │   └── MyKext          # Binaire kernel compilé
│   ├── Resources/          # Ressources optionnelles
│   └── _CodeSignature/     # Signature code (obligatoire)
```

**Info.plist** (configuration minimale) :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.mykext</string>

    <key>CFBundleName</key>
    <string>MyKext</string>

    <key>CFBundleVersion</key>
    <string>1.0</string>

    <key>OSBundleLibraries</key>
    <dict>
        <key>com.apple.kpi.libkern</key>
        <string>19.0</string>
        <key>com.apple.kpi.mach</key>
        <string>19.0</string>
    </dict>

    <key>OSKernelResource</key>
    <true/>
</dict>
</plist>
```

### Concept 3 : Cycle de vie d'une KEXT

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   1. DÉVELOPPEMENT                                  │
│      ├─ Écriture du code C/C++                     │
│      ├─ Création de l'Info.plist                   │
│      └─ Compilation avec Xcode ou clang            │
│                      │                              │
│                      ▼                              │
│   2. SIGNATURE                                      │
│      ├─ Code signing avec certificat valide        │
│      └─ Notarization (macOS 10.15+)                │
│                      │                              │
│                      ▼                              │
│   3. INSTALLATION                                   │
│      ├─ Copie dans /Library/Extensions/ ou         │
│      │   /System/Library/Extensions/               │
│      └─ Permissions appropriées                    │
│                      │                              │
│                      ▼                              │
│   4. CHARGEMENT                                     │
│      ├─ kextload (manuel)                          │
│      ├─ kextutil (test)                            │
│      └─ Automatique au boot                        │
│                      │                              │
│                      ▼                              │
│   5. EXÉCUTION                                      │
│      ├─ kern_return_t start()                      │
│      ├─ Enregistrement de services                 │
│      └─ Opération normale                          │
│                      │                              │
│                      ▼                              │
│   6. DÉCHARGEMENT                                   │
│      ├─ kextunload                                 │
│      └─ kern_return_t stop()                       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Concept 4 : I/O Kit et architecture orientée objet

macOS utilise I/O Kit, un framework C++ pour le développement de drivers. Les KEXT héritent généralement de classes I/O Kit :

```
IOService (classe de base)
    │
    ├─ IOUserClient (communication user ↔ kernel)
    │
    ├─ IONetworkController (networking)
    │
    ├─ IOStorageController (stockage)
    │
    └─ IOHIDDevice (périphériques d'entrée)
```

## Mise en pratique

### Étape 1 : KEXT minimaliste - "Hello World"

Créons une KEXT basique qui log un message au démarrage :

```cpp
// HelloKext.cpp
#include <IOKit/IOLib.h>
#include <libkern/c++/OSObject.h>

// Déclaration de la classe
class com_example_HelloKext : public OSObject
{
    OSDeclareDefaultStructors(com_example_HelloKext)
};

// Définition de la classe
OSDefineMetaClassAndStructors(com_example_HelloKext, OSObject)

// Point d'entrée au chargement
extern "C" kern_return_t kern_start(kmod_info_t *ki, void *data)
{
    IOLog("HelloKext: Chargement de la KEXT...\n");
    IOLog("HelloKext: Version du kernel: %s\n", osrelease);
    return KERN_SUCCESS;
}

// Point de sortie au déchargement
extern "C" kern_return_t kern_stop(kmod_info_t *ki, void *data)
{
    IOLog("HelloKext: Déchargement de la KEXT...\n");
    return KERN_SUCCESS;
}
```

**Info.plist pour HelloKext :**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.HelloKext</string>

    <key>CFBundleName</key>
    <string>HelloKext</string>

    <key>CFBundleVersion</key>
    <string>1.0.0</string>

    <key>CFBundlePackageType</key>
    <string>KEXT</string>

    <key>CFBundleExecutable</key>
    <string>HelloKext</string>

    <key>OSBundleLibraries</key>
    <dict>
        <key>com.apple.kpi.libkern</key>
        <string>19.0</string>
    </dict>
</dict>
</plist>
```

**Compilation (ligne de commande) :**
```bash
# Créer la structure de la KEXT
mkdir -p HelloKext.kext/Contents/MacOS

# Compiler
clang++ -arch x86_64 -std=c++11 \
    -nostdlib -lkmod -lkmodc++ -lcc_kext \
    -Xlinker -kext \
    -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers \
    -o HelloKext.kext/Contents/MacOS/HelloKext \
    HelloKext.cpp

# Copier Info.plist
cp Info.plist HelloKext.kext/Contents/

# Définir les permissions
sudo chown -R root:wheel HelloKext.kext
sudo chmod -R 755 HelloKext.kext

# Charger la KEXT (nécessite SIP désactivé)
sudo kextload -v HelloKext.kext

# Vérifier dans les logs
log show --predicate 'eventMessage contains "HelloKext"' --last 1m

# Décharger
sudo kextunload -v HelloKext.kext
```

### Étape 2 : KEXT avec IOUserClient (communication user/kernel)

Cette KEXT permet à un programme user space de communiquer avec le kernel :

```cpp
// SimpleKext.cpp
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOLib.h>

// Classe principale du service
class SimpleKext : public IOService
{
    OSDeclareDefaultStructors(SimpleKext)

public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
};

// Classe pour la communication user space
class SimpleKextUserClient : public IOUserClient
{
    OSDeclareDefaultStructors(SimpleKextUserClient)

private:
    SimpleKext *fProvider;
    task_t fTask;

public:
    virtual bool initWithTask(task_t owningTask, void *securityID,
                             UInt32 type, OSDictionary *properties) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;

    virtual IOReturn clientClose() override;
    virtual IOReturn clientDied() override;

    // Méthodes appelables depuis user space
    static IOReturn sMethodOne(SimpleKextUserClient *target, void *reference,
                               IOExternalMethodArguments *args);
    static IOReturn sMethodTwo(SimpleKextUserClient *target, void *reference,
                               IOExternalMethodArguments *args);

protected:
    virtual IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args,
                                    IOExternalMethodDispatch *dispatch, OSObject *target,
                                    void *reference) override;
};

// Implémentation SimpleKext
OSDefineMetaClassAndStructors(SimpleKext, IOService)

bool SimpleKext::start(IOService *provider)
{
    IOLog("SimpleKext: Démarrage du service\n");

    if (!IOService::start(provider)) {
        return false;
    }

    // Publier le service pour que les clients puissent se connecter
    registerService();

    return true;
}

void SimpleKext::stop(IOService *provider)
{
    IOLog("SimpleKext: Arrêt du service\n");
    IOService::stop(provider);
}

// Implémentation SimpleKextUserClient
OSDefineMetaClassAndStructors(SimpleKextUserClient, IOUserClient)

bool SimpleKextUserClient::initWithTask(task_t owningTask, void *securityID,
                                       UInt32 type, OSDictionary *properties)
{
    if (!IOUserClient::initWithTask(owningTask, securityID, type, properties)) {
        return false;
    }

    fTask = owningTask;
    fProvider = NULL;

    return true;
}

bool SimpleKextUserClient::start(IOService *provider)
{
    if (!IOUserClient::start(provider)) {
        return false;
    }

    fProvider = OSDynamicCast(SimpleKext, provider);
    if (!fProvider) {
        return false;
    }

    return true;
}

void SimpleKextUserClient::stop(IOService *provider)
{
    IOUserClient::stop(provider);
}

IOReturn SimpleKextUserClient::clientClose()
{
    if (!isInactive()) {
        terminate();
    }

    return kIOReturnSuccess;
}

IOReturn SimpleKextUserClient::clientDied()
{
    return clientClose();
}

// Méthode 1 : Recevoir un entier depuis user space
IOReturn SimpleKextUserClient::sMethodOne(SimpleKextUserClient *target,
                                         void *reference,
                                         IOExternalMethodArguments *args)
{
    uint64_t input = args->scalarInput[0];
    IOLog("SimpleKext: Méthode 1 appelée avec valeur: %llu\n", input);

    // Retourner une valeur (input * 2)
    args->scalarOutput[0] = input * 2;
    args->scalarOutputCount = 1;

    return kIOReturnSuccess;
}

// Méthode 2 : Lire/écrire un buffer
IOReturn SimpleKextUserClient::sMethodTwo(SimpleKextUserClient *target,
                                         void *reference,
                                         IOExternalMethodArguments *args)
{
    if (args->structureInputSize > 0) {
        const char *input = (const char *)args->structureInput;
        IOLog("SimpleKext: Méthode 2 - Buffer reçu: %s\n", input);

        // Copier le buffer en output (pour démonstration)
        if (args->structureOutputSize >= args->structureInputSize) {
            memcpy(args->structureOutput, input, args->structureInputSize);
            args->structureOutputSize = args->structureInputSize;
        }
    }

    return kIOReturnSuccess;
}

// Table de dispatch des méthodes
static const IOExternalMethodDispatch sMethods[2] = {
    {
        (IOExternalMethodAction)&SimpleKextUserClient::sMethodOne,
        1,  // nombre d'arguments scalaires en entrée
        1,  // nombre d'arguments scalaires en sortie
        0,  // taille du buffer en entrée
        0   // taille du buffer en sortie
    },
    {
        (IOExternalMethodAction)&SimpleKextUserClient::sMethodTwo,
        0,      // scalaires
        0,
        256,    // buffer entrée (max 256 bytes)
        256     // buffer sortie (max 256 bytes)
    }
};

IOReturn SimpleKextUserClient::externalMethod(uint32_t selector,
                                              IOExternalMethodArguments *args,
                                              IOExternalMethodDispatch *dispatch,
                                              OSObject *target,
                                              void *reference)
{
    if (selector >= 2) {
        return kIOReturnBadArgument;
    }

    dispatch = (IOExternalMethodDispatch *)&sMethods[selector];
    target = this;
    reference = NULL;

    return IOUserClient::externalMethod(selector, args, dispatch, target, reference);
}
```

**Client user space pour tester la KEXT :**

```c
// client.c
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    kern_return_t ret;
    io_service_t service;
    io_connect_t connect;

    // Trouver le service
    service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                         IOServiceMatching("SimpleKext"));
    if (!service) {
        printf("Erreur: Service SimpleKext non trouvé\n");
        return 1;
    }

    printf("Service trouvé!\n");

    // Ouvrir une connexion
    ret = IOServiceOpen(service, mach_task_self(), 0, &connect);
    IOObjectRelease(service);

    if (ret != KERN_SUCCESS) {
        printf("Erreur: IOServiceOpen failed: %d\n", ret);
        return 1;
    }

    printf("Connexion établie!\n");

    // Appeler la méthode 1 (scalaire)
    uint64_t input = 42;
    uint64_t output = 0;
    uint32_t outputCount = 1;

    ret = IOConnectCallScalarMethod(connect, 0,  // sélecteur 0
                                    &input, 1,    // 1 argument en entrée
                                    &output, &outputCount);

    if (ret == KERN_SUCCESS) {
        printf("Méthode 1: Input=%llu, Output=%llu\n", input, output);
    } else {
        printf("Erreur méthode 1: %d\n", ret);
    }

    // Appeler la méthode 2 (buffer)
    char inputBuf[256] = "Hello from user space!";
    char outputBuf[256] = {0};
    size_t outputSize = sizeof(outputBuf);

    ret = IOConnectCallStructMethod(connect, 1,  // sélecteur 1
                                    inputBuf, strlen(inputBuf) + 1,
                                    outputBuf, &outputSize);

    if (ret == KERN_SUCCESS) {
        printf("Méthode 2: Reçu: %s\n", outputBuf);
    } else {
        printf("Erreur méthode 2: %d\n", ret);
    }

    // Fermer la connexion
    IOServiceClose(connect);

    printf("Terminé!\n");
    return 0;
}
```

**Compilation du client :**
```bash
clang -framework IOKit -framework CoreFoundation -o client client.c
./client
```

### Étape 3 : KEXT de hooking - Intercepter des syscalls

**ATTENTION** : Cet exemple est purement éducatif. Le hooking de syscalls est une technique utilisée par des rootkits.

```cpp
// SyscallHook.cpp
#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/sysctl.h>

// Prototype de la fonction syscall originale
typedef int (*open_func_t)(proc_t, struct open_args *, int *);

// Pointeur vers la syscall originale
static open_func_t original_open = NULL;

// Notre hook pour open()
static int hooked_open(proc_t p, struct open_args *uap, int *retval)
{
    char path[MAXPATHLEN];
    size_t len;

    // Copier le chemin depuis user space
    if (copyinstr(uap->path, path, MAXPATHLEN, &len) == 0) {
        // Logger tous les appels à open()
        printf("SyscallHook: PID %d ouvre: %s\n",
               proc_pid(p), path);

        // Optionnel: bloquer l'accès à certains fichiers
        if (strstr(path, "/etc/master.passwd") != NULL) {
            printf("SyscallHook: Accès bloqué à %s\n", path);
            return EACCES;  // Permission denied
        }
    }

    // Appeler la syscall originale
    return original_open(p, uap, retval);
}

// Table des syscalls (adresse à trouver dynamiquement)
extern struct sysent *_sysent;

kern_return_t kern_start(kmod_info_t *ki, void *d)
{
    printf("SyscallHook: Installation du hook...\n");

    // Sauvegarder le pointeur original
    // Note: Ceci est une simplification, dans la réalité il faut:
    // 1. Désactiver la protection en écriture de la table
    // 2. Trouver l'adresse de _sysent
    // 3. Modifier l'entrée de la syscall

    // original_open = (open_func_t)_sysent[SYS_open].sy_call;
    // _sysent[SYS_open].sy_call = (sy_call_t *)hooked_open;

    printf("SyscallHook: Hook installé\n");
    return KERN_SUCCESS;
}

kern_return_t kern_stop(kmod_info_t *ki, void *d)
{
    printf("SyscallHook: Restauration de la syscall...\n");

    // Restaurer la syscall originale
    // _sysent[SYS_open].sy_call = (sy_call_t *)original_open;

    printf("SyscallHook: Hook désinstallé\n");
    return KERN_SUCCESS;
}
```

**Note** : Ce code est incomplet intentionnellement. Le hooking de syscalls sur macOS moderne nécessite de contourner plusieurs protections (KPP/KTRR, zone MAP_JIT, etc.).

### Étape 4 : Debugging d'une KEXT avec LLDB

```bash
# Sur la machine cible (avec KEXT chargée)
sudo nvram boot-args="debug=0x144 -v"
sudo reboot

# Après redémarrage, activer le debugging kernel
sudo systemsetup -setwaitforstartupafterpowerfailure on

# Sur la machine de développement
lldb
(lldb) kdp-remote <IP_de_la_cible>

# Mettre un breakpoint
(lldb) b SimpleKext::start
(lldb) continue

# Charger la KEXT sur la machine cible
sudo kextload SimpleKext.kext

# Le breakpoint sera hit sur la machine de dev
(lldb) bt
(lldb) register read
(lldb) memory read $rsp
```

## Application offensive

### Contexte Red Team

Les KEXT sont l'arme ultime pour la persistance et le contrôle sur macOS, mais elles présentent des défis majeurs :

**Avantages :**
- **Contrôle total** : Accès à toute la mémoire kernel et user space
- **Invisibilité** : Peut masquer fichiers, processus, connexions réseau
- **Persistance** : Survit aux redémarrages
- **Anti-forensics** : Peut altérer les logs et les outils d'investigation

**Obstacles modernes :**
1. **System Integrity Protection (SIP)** : Empêche la modification du système
2. **Kernel Extension Approvals** : L'utilisateur doit approuver manuellement chaque KEXT
3. **Notarization** : Apple doit signer la KEXT (depuis Catalina)
4. **Secure Boot** : Vérifie l'intégrité du bootloader et du kernel
5. **Deprecation** : Apple pousse vers les System Extensions (user space)

**Techniques Red Team (contexte légal uniquement) :**

1. **Exploitation de KEXT légitimes**
   - Chercher des vulnérabilités dans des KEXT tierces
   - Abuser de fonctionnalités mal sécurisées

2. **KEXT signing avec certificats volés**
   - Obtenir un certificat de développeur Apple valide
   - Signer la KEXT malveillante

3. **Bypass de SIP via bootrom exploits**
   - Exploiter des vulnérabilités hardware (ex: checkm8, checkra1n)
   - Désactiver SIP au niveau bootloader

### Considérations OPSEC

**Détection des KEXT :**

```bash
# Lister toutes les KEXT chargées
kextstat | grep -v com.apple

# Vérifier les signatures
kextutil -print-diagnostics /Library/Extensions/Suspicious.kext

# Analyser les dépendances
kextlibs /Library/Extensions/Suspicious.kext

# Monitorer le chargement en temps réel
log stream --predicate 'eventMessage contains "kext"' --level debug
```

**Indicateurs de compromission :**
- KEXT non signée ou avec signature invalide
- KEXT dans un emplacement inhabituel (hors /System/Library/Extensions/)
- Chargement de KEXT à des heures inhabituelles
- KEXT avec des dépendances suspectes
- Modifications de la table des syscalls

**Contre-mesures pour Red Team :**
1. **Signature valide** : Utiliser un certificat Apple Developer valide
2. **Mimétisme** : Nommer la KEXT comme un driver légitime
3. **Chargement au boot** : Moins suspect qu'un chargement dynamique
4. **Code minimal** : Moins de code = moins de surface d'analyse
5. **Obfuscation** : Compliquer l'analyse statique

## Résumé

- Les KEXT sont des modules kernel qui s'exécutent avec le plus haut niveau de privilèges sur macOS
- Elles utilisent I/O Kit (C++) et peuvent communiquer avec user space via IOUserClient
- Le cycle de vie d'une KEXT : développement, signature, installation, chargement, exécution, déchargement
- Depuis macOS Catalina, Apple impose des restrictions très strictes (SIP, notarization, user approval)
- Les KEXT représentent le niveau de persistance ultime mais sont devenues extrêmement difficiles à déployer
- Pour la Red Team moderne, les System Extensions (user space) sont une alternative plus viable
- Le debugging de KEXT nécessite une configuration spéciale (KDP, lldb remote)
- Comprendre les KEXT reste crucial pour l'analyse forensics et la compréhension des défenses kernel

## Ressources complémentaires

- [Apple - Kernel Programming Guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/)
- [I/O Kit Fundamentals](https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/)
- [Kernel Extensions Deprecation](https://developer.apple.com/support/kernel-extensions/)
- [Jonathan Levin - *Mac OS X and iOS Internals*](http://newosxbook.com/)
- [Patrick Wardle - Kernel Extension Research](https://objective-see.org/blog.html)
- [macOS Kernel Extensions Development Tutorial](https://pewpewthespells.com/blog/kext_loading.html)
- [XNU Source Code](https://opensource.apple.com/source/xnu/)

---

**Navigation**
- [Module précédent](../M10_endpoint_security/)
- [Module suivant](../M12_amfi/)
