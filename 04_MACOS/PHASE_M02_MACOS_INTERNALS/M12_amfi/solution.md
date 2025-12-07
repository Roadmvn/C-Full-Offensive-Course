# SOLUTION : AMFI (Apple Mobile File Integrity)

## Exercice 1 : Vérifier l'état AMFI

```bash
# Vérifier si AMFI est actif
nvram boot-args

# Status AMFI
csrutil status

# Voir configuration AMFI
sudo sysctl -a | grep -i amfi
```

**Sortie attendue** :
```
vm.vm_do_collapse_compressor: 1
debug.amfi: 1
debug.amfi.verbose: 0
```

---

## Exercice 2 : Désactiver AMFI (Recovery Mode requis)

```bash
# 1. Reboot en Recovery Mode (Cmd+R au boot)

# 2. Ouvrir Terminal

# 3. Désactiver SIP et AMFI
csrutil disable
csrutil authenticated-root disable

# 4. Désactiver AMFI spécifiquement
nvram boot-args="amfi_get_out_of_my_way=1"

# 5. Reboot
reboot

# 6. Vérifier
nvram boot-args
# Sortie: amfi_get_out_of_my_way=1
```

**ATTENTION** : Ceci désactive une protection majeure. À utiliser uniquement en environnement de test.

---

## Exercice 3 : Vérifier signature et entitlements

```c
// check_signature.c
#include <Security/SecCode.h>
#include <Security/SecRequirement.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

void check_code_signature(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)path, strlen(path), false);

    if (!url) {
        printf("[-] Invalid path\n");
        return;
    }

    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);

    if (status != errSecSuccess) {
        printf("[-] Failed to create code object: %d\n", status);
        CFRelease(url);
        return;
    }

    // Vérifier signature
    status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, NULL);

    if (status == errSecSuccess) {
        printf("[+] Signature VALID\n");
    } else {
        printf("[-] Signature INVALID: %d\n", status);
    }

    // Extraire informations de signature
    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);

    if (status == errSecSuccess && info) {
        printf("\n[*] Signing Information:\n");

        // Identifier
        CFStringRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
        if (identifier) {
            char buf[256];
            CFStringGetCString(identifier, buf, sizeof(buf), kCFStringEncodingUTF8);
            printf("  Identifier: %s\n", buf);
        }

        // Team ID
        CFStringRef teamID = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
        if (teamID) {
            char buf[256];
            CFStringGetCString(teamID, buf, sizeof(buf), kCFStringEncodingUTF8);
            printf("  Team ID: %s\n", buf);
        }

        // Entitlements
        CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
        if (entitlements) {
            printf("  Entitlements: %ld keys\n", CFDictionaryGetCount(entitlements));
        }

        CFRelease(info);
    }

    CFRelease(code);
    CFRelease(url);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_binary>\n", argv[0]);
        return 1;
    }

    printf("[*] Checking signature for: %s\n\n", argv[1]);
    check_code_signature(argv[1]);

    return 0;
}
```

**Compilation** :
```bash
clang check_signature.c -o check_signature -framework Security -framework CoreFoundation

# Test
./check_signature /bin/ls
./check_signature /Applications/Safari.app
```

---

## Exercice 4 : Dumper entitlements

```c
// dump_entitlements.c
#include <Security/SecCode.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

void dump_entitlements(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)path, strlen(path), false);

    SecStaticCodeRef code = NULL;
    SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);

    CFDictionaryRef info = NULL;
    SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);

    if (info) {
        CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);

        if (entitlements) {
            printf("[*] Entitlements for %s:\n\n", path);

            CFIndex count = CFDictionaryGetCount(entitlements);
            CFStringRef *keys = malloc(count * sizeof(CFStringRef));
            CFDictionaryGetKeysAndValues(entitlements, (const void **)keys, NULL);

            for (CFIndex i = 0; i < count; i++) {
                char key_buf[256];
                CFStringGetCString(keys[i], key_buf, sizeof(key_buf), kCFStringEncodingUTF8);
                printf("  - %s\n", key_buf);
            }

            free(keys);
        } else {
            printf("[-] No entitlements found\n");
        }

        CFRelease(info);
    }

    if (code) CFRelease(code);
    if (url) CFRelease(url);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    dump_entitlements(argv[1]);
    return 0;
}
```

**Compilation** :
```bash
clang dump_entitlements.c -o dump_entitlements -framework Security -framework CoreFoundation

# Exemples
./dump_entitlements /Applications/Safari.app
./dump_entitlements /System/Applications/Messages.app
```

**Entitlements intéressants RED TEAM** :
- `com.apple.security.cs.allow-unsigned-executable-memory` : permet JIT
- `com.apple.security.cs.disable-library-validation` : charge dylibs non signées
- `com.apple.security.cs.allow-dyld-environment-variables` : DYLD_INSERT_LIBRARIES
- `com.apple.private.security.clear-library-validation` : bypass library validation

---

## Exercice 5 : Vérifier trust cache

```bash
# Voir trust cache (binaires Apple de confiance)
sudo bputil -d

# Liste des code signatures cached
sudo codesign --verify --verbose /System/Applications/*.app

# Vérifier si binaire est dans trust cache
codesign -dv /bin/ls 2>&1 | grep "adhoc\|Apple"
```

---

## Exercice 6 : RED TEAM - Bypass library validation

**Scénario** : Injecter dylib dans app sans entitlement `disable-library-validation`.

**Méthode 1 : DYLD_INSERT_LIBRARIES (si app l'autorise)** :

```c
// malicious.c
#include <stdio.h>

__attribute__((constructor))
void init() {
    printf("[+] Malicious dylib loaded!\n");
    // Payload ici
}
```

```bash
# Compiler en dylib
clang -dynamiclib malicious.c -o malicious.dylib

# Tester (ne fonctionne que si app a entitlement approprié)
DYLD_INSERT_LIBRARIES=./malicious.dylib /Applications/Target.app/Contents/MacOS/Target
```

**Méthode 2 : Re-signer l'app avec nos entitlements** :

```bash
# 1. Extraire entitlements originaux
codesign -d --entitlements entitlements.plist /Applications/Target.app

# 2. Ajouter notre entitlement
# Éditer entitlements.plist :
# <key>com.apple.security.cs.disable-library-validation</key>
# <true/>

# 3. Re-signer (nécessite SIP off et AMFI désactivé)
sudo codesign -f -s - --entitlements entitlements.plist /Applications/Target.app

# 4. Injecter dylib
DYLD_INSERT_LIBRARIES=./malicious.dylib /Applications/Target.app/Contents/MacOS/Target
```

**Méthode 3 : Hijack dylib (recherche avancée)** :

```c
// find_writable_dylibs.c
#include <mach-o/dyld.h>
#include <stdio.h>
#include <sys/stat.h>

int main() {
    uint32_t count = _dyld_image_count();

    printf("[*] Searching for writable dylibs...\n\n");

    for (uint32_t i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);
        struct stat st;

        if (stat(image_name, &st) == 0) {
            // Check if writable by user
            if (st.st_mode & S_IWUSR) {
                printf("[!] WRITABLE: %s\n", image_name);
                printf("    Permissions: %o\n", st.st_mode & 0777);
            }
        }
    }

    return 0;
}
```

---

## Exercice 7 : Forcer chargement code non signé

**AMFI disabled requis** :

```c
// unsigned_loader.c
#include <dlfcn.h>
#include <stdio.h>

int main() {
    // Charger dylib non signée (AMFI off requis)
    void *handle = dlopen("./unsigned.dylib", RTLD_NOW);

    if (handle) {
        printf("[+] Unsigned dylib loaded successfully!\n");

        // Appeler fonction
        void (*func)() = dlsym(handle, "malicious_function");
        if (func) {
            func();
        }

        dlclose(handle);
    } else {
        printf("[-] Failed to load: %s\n", dlerror());
    }

    return 0;
}
```

**Avec AMFI actif** :
```
[-] Failed to load: dlopen(./unsigned.dylib, 0x0001):
    code signature invalid
```

**Avec AMFI désactivé** :
```
[+] Unsigned dylib loaded successfully!
```

---

## Exercice 8 : Détecter AMFI bypass (Blue Team)

```c
// detect_amfi_bypass.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>

int check_amfi() {
    int amfi_enabled;
    size_t size = sizeof(amfi_enabled);

    if (sysctlbyname("debug.amfi", &amfi_enabled, &size, NULL, 0) == 0) {
        return amfi_enabled;
    }

    return -1;
}

int check_boot_args() {
    char boot_args[256];
    size_t size = sizeof(boot_args);

    if (sysctlbyname("kern.bootargs", boot_args, &size, NULL, 0) == 0) {
        if (strstr(boot_args, "amfi_get_out_of_my_way")) {
            return 1; // AMFI bypassed
        }
    }

    return 0;
}

int main() {
    printf("[*] AMFI Security Check\n\n");

    int amfi = check_amfi();
    if (amfi == 1) {
        printf("[+] AMFI is ENABLED\n");
    } else if (amfi == 0) {
        printf("[-] AMFI is DISABLED (COMPROMISED!)\n");
    } else {
        printf("[-] Unable to check AMFI status\n");
    }

    if (check_boot_args()) {
        printf("[-] AMFI bypass detected in boot-args!\n");
    } else {
        printf("[+] Boot args clean\n");
    }

    return 0;
}
```

**Compilation** :
```bash
clang detect_amfi_bypass.c -o detect_amfi_bypass
./detect_amfi_bypass
```

---

## RED TEAM : AMFI bypass techniques (recherche)

**1. Kernel patch (jailbreak style)** :
- Modifier AMFI dans kernel memory
- Nécessite exploit kernel
- Très détectable

**2. Boot args manipulation** :
- `amfi_get_out_of_my_way=1`
- Nécessite accès Recovery Mode
- Facile à détecter

**3. Library validation bypass** :
- Re-signer avec entitlements permissifs
- Injecter code via dylib hijacking
- Détection : vérifier signatures

**4. Trust cache injection (avancé)** :
- Ajouter hash malveillant au trust cache
- Nécessite kernel write
- Très complexe

---

## Resources

- [AMFI Internals](https://Knight.sc/reverse%20engineering/2019/02/20/mac-os-x-amfi-internals.html)
- [Code Signing Bypass](https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/)
- [Library Validation](https://pewpewthespells.com/blog/blocking_code_injection_on_ios_and_os_x.html)
