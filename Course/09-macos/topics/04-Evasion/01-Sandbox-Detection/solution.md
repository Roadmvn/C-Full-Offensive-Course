# SOLUTION : Sandbox Detection macOS

## Exercice 1 : Détecter App Sandbox

```c
// detect_sandbox.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>

int is_sandboxed() {
    // Méthode 1: Vérifier variable d'environnement
    char *app_sandbox = getenv("APP_SANDBOX_CONTAINER_ID");
    if (app_sandbox) {
        return 1;
    }

    // Méthode 2: Vérifier chemins sandbox
    char home[MAXPATHLEN];
    if (confstr(_CS_DARWIN_USER_DIR, home, sizeof(home)) > 0) {
        if (strstr(home, "Containers")) {
            return 1;
        }
    }

    return 0;
}

int main() {
    if (is_sandboxed()) {
        printf("[-] Running in App Sandbox\n");
        printf("[*] Container ID: %s\n", getenv("APP_SANDBOX_CONTAINER_ID"));
    } else {
        printf("[+] Not sandboxed\n");
    }

    return 0;
}
```

---

## Exercice 2 : Tester restrictions sandbox

```c
// test_sandbox_restrictions.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void test_file_access() {
    printf("[*] Testing file access...\n");

    // Tenter d'accéder à /etc/passwd
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        printf("[+] Can read /etc/passwd\n");
        close(fd);
    } else {
        printf("[-] Cannot read /etc/passwd (sandboxed)\n");
    }

    // Tenter d'écrire dans /tmp
    fd = open("/tmp/sandbox_test.txt", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        printf("[+] Can write to /tmp\n");
        close(fd);
        unlink("/tmp/sandbox_test.txt");
    } else {
        printf("[-] Cannot write to /tmp (sandboxed)\n");
    }
}

void test_network_access() {
    printf("\n[*] Testing network access...\n");

    int ret = system("curl -I https://google.com > /dev/null 2>&1");
    if (ret == 0) {
        printf("[+] Network access allowed\n");
    } else {
        printf("[-] Network access blocked (sandboxed)\n");
    }
}

int main() {
    test_file_access();
    test_network_access();
    return 0;
}
```

---

## Exercice 3 : Vérifier entitlements

```c
// check_entitlements.c
#include <Security/SecCode.h>
#include <Security/SecRequirement.h>
#include <stdio.h>

void check_sandbox_entitlement() {
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);

    if (status != errSecSuccess) {
        printf("[-] Failed to get code reference\n");
        return;
    }

    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);

    if (status == errSecSuccess && info) {
        CFDictionaryRef entitlements = CFDictionaryGetValue(info,
                                                           kSecCodeInfoEntitlementsDict);

        if (entitlements) {
            // Vérifier entitlement sandbox
            CFBooleanRef sandboxed = CFDictionaryGetValue(entitlements,
                                    CFSTR("com.apple.security.app-sandbox"));

            if (sandboxed && CFBooleanGetValue(sandboxed)) {
                printf("[-] App has sandbox entitlement\n");

                // Vérifier autres entitlements
                CFBooleanRef network = CFDictionaryGetValue(entitlements,
                        CFSTR("com.apple.security.network.client"));

                if (network && CFBooleanGetValue(network)) {
                    printf("[+] Network client entitlement present\n");
                }
            } else {
                printf("[+] No sandbox entitlement\n");
            }
        }

        CFRelease(info);
    }

    CFRelease(code);
}

int main() {
    check_sandbox_entitlement();
    return 0;
}
```

**Compilation** :
```bash
clang check_entitlements.c -o check_entitlements -framework Security
./check_entitlements
```

---

## Exercice 4 : Sandbox escape test (container)

```c
// sandbox_escape_test.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void try_escape_methods() {
    printf("[*] Testing sandbox escape methods...\n\n");

    // Test 1: AppleScript injection
    printf("[1] Trying AppleScript...\n");
    int ret = system("osascript -e 'tell application \"Finder\" to activate'");
    if (ret == 0) {
        printf("[+] AppleScript executed\n");
    } else {
        printf("[-] AppleScript blocked\n");
    }

    // Test 2: URL scheme handler
    printf("\n[2] Trying URL handler...\n");
    ret = system("open 'file:///etc/passwd'");
    if (ret == 0) {
        printf("[+] URL handler allowed\n");
    } else {
        printf("[-] URL handler blocked\n");
    }

    // Test 3: Spawn process
    printf("\n[3] Trying to spawn process...\n");
    ret = system("/bin/ls");
    if (ret == 0) {
        printf("[+] Can execute /bin/ls\n");
    } else {
        printf("[-] Cannot spawn process\n");
    }
}

int main() {
    try_escape_methods();
    return 0;
}
```

---

## Exercice 5 : Détecter VM/Sandbox (techniques anti-analysis)

```c
// detect_vm_sandbox.c
#include <stdio.h>
#include <sys/sysctl.h>
#include <string.h>

int detect_vm() {
    char model[256];
    size_t size = sizeof(model);

    if (sysctlbyname("hw.model", model, &size, NULL, 0) == 0) {
        if (strstr(model, "VMware") || strstr(model, "VirtualBox")) {
            return 1;
        }
    }

    return 0;
}

int detect_debugger() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }

    return 0;
}

int main() {
    printf("[*] Environment detection:\n\n");

    if (detect_vm()) {
        printf("[-] Running in VM\n");
    } else {
        printf("[+] Physical machine\n");
    }

    if (detect_debugger()) {
        printf("[-] Debugger detected\n");
    } else {
        printf("[+] No debugger\n");
    }

    return 0;
}
```

---

## Exercice 6 : Container path detection

```bash
# Script pour détecter sandbox container
#!/bin/bash

CONTAINER_PATH=~/Library/Containers

if [ -d "$CONTAINER_PATH" ]; then
    echo "[*] Sandbox containers found:"
    ls -la "$CONTAINER_PATH" | grep -v "^d" | tail -n +4
fi

# Détecter si on est dans un container
if [[ "$HOME" == *"/Containers/"* ]]; then
    echo "[-] Currently running in sandbox container"
    echo "[*] Container: $HOME"
fi
```

---

## Exercice 7 : Bypass sandbox (XPC exploitation)

```c
// xpc_bypass.c (concept)
#include <xpc/xpc.h>
#include <stdio.h>

void exploit_xpc_service() {
    // Connexion à service XPC privilégié
    xpc_connection_t conn = xpc_connection_create_mach_service(
        "com.apple.system.privileged",
        NULL,
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
    );

    if (!conn) {
        printf("[-] Failed to connect to XPC service\n");
        return;
    }

    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        // Handle response
    });

    xpc_connection_resume(conn);

    // Créer message malveillant
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "command", "bypass");

    // Envoyer
    xpc_connection_send_message(conn, message);

    printf("[*] XPC exploit attempt sent\n");
}

int main() {
    exploit_xpc_service();
    return 0;
}
```

**Note** : Ceci est un exemple conceptuel. Les vrais bypasses sandbox nécessitent des CVEs spécifiques.

---

## Resources

- [App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
- [Sandbox Escapes](https://googleprojectzero.blogspot.com/2021/01/macos-gatekeeper-bypass.html)
- [Container Detection](https://theevilbit.github.io/posts/macos_sandbox_escape/)
