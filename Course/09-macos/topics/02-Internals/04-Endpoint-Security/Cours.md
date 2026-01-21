# Endpoint Security Framework

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'architecture de l'Endpoint Security Framework d'Apple
- [ ] Créer et enregistrer des clients ES pour surveiller les événements système
- [ ] Implémenter des mécanismes de détection d'activité malveillante
- [ ] Analyser les événements pour identifier les comportements suspects
- [ ] Appliquer ces connaissances pour détecter des techniques offensives

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C et Objective-C
- La programmation système sur macOS
- Les concepts de XPC et IPC sur macOS
- Les entitlements et code signing

## Introduction

L'Endpoint Security Framework est l'API de surveillance système moderne d'Apple, introduite dans macOS 10.15 Catalina. Ce framework remplace les anciennes KEXT (Kernel Extensions) et fournit une interface sécurisée pour surveiller et répondre aux événements système en temps réel.

### Pourquoi ce sujet est important ?

Imaginez un gardien qui surveille toutes les entrées et sorties d'un bâtiment. L'Endpoint Security Framework joue ce rôle pour macOS : il observe chaque création de processus, chaque ouverture de fichier, chaque connexion réseau, et peut même bloquer ces actions si elles semblent suspectes.

Pour un opérateur Red Team, comprendre ce framework est crucial car c'est le principal mécanisme de détection utilisé par les EDR (Endpoint Detection and Response) sur macOS. Connaître son fonctionnement permet de :
- Comprendre comment les défenses détectent vos actions
- Développer des techniques d'évasion plus efficaces
- Créer des outils de détection pour tester les défenses

## Concepts fondamentaux

### Concept 1 : Architecture de l'Endpoint Security Framework

L'ES Framework fonctionne selon un modèle client-serveur avec plusieurs composants clés :

```
┌─────────────────────────────────────────────────────────┐
│                     User Space                          │
│                                                         │
│  ┌──────────────────┐         ┌──────────────────┐    │
│  │  ES Client App   │         │  ES Client App   │    │
│  │   (votre code)   │         │     (EDR)        │    │
│  └────────┬─────────┘         └────────┬─────────┘    │
│           │                            │               │
│           │ es_new_client()            │               │
│           ▼                            ▼               │
│  ┌─────────────────────────────────────────────────┐  │
│  │      EndpointSecurity.framework                 │  │
│  │  (libEndpointSecurity.dylib)                    │  │
│  └──────────────────┬──────────────────────────────┘  │
│                     │ XPC                              │
├─────────────────────┼──────────────────────────────────┤
│                     ▼                                  │
│  ┌─────────────────────────────────────────────────┐  │
│  │          endpointsecurityd                      │  │
│  │  (daemon système avec privilèges élevés)        │  │
│  └──────────────────┬──────────────────────────────┘  │
│                     │                                  │
├─────────────────────┼──────────────────────────────────┤
│     Kernel Space    │                                  │
│                     ▼                                  │
│  ┌─────────────────────────────────────────────────┐  │
│  │    Endpoint Security Kernel Extension           │  │
│  │         (Apple-signed KEXT)                     │  │
│  └──────────────────┬──────────────────────────────┘  │
│                     │                                  │
│         ┌───────────┼───────────┐                     │
│         ▼           ▼           ▼                     │
│    ┌────────┐  ┌────────┐  ┌────────┐               │
│    │ Process│  │  File  │  │Network │               │
│    │ Events │  │ Events │  │ Events │               │
│    └────────┘  └────────┘  └────────┘               │
└─────────────────────────────────────────────────────────┘
```

**Flux de données :**
1. Les événements système sont capturés par le KEXT au niveau kernel
2. Les événements sont transmis à `endpointsecurityd` (daemon système)
3. Le daemon distribue les événements aux clients enregistrés via XPC
4. Les clients peuvent répondre (autoriser/bloquer) pour les événements AUTH

### Concept 2 : Types d'événements et modes de notification

L'ES Framework supporte deux modes de notification :

**1. Événements NOTIFY (notification uniquement)**
```
Application → Action → Kernel → ES KEXT → Client (informé après l'action)
                          ↓
                    Action réussie
```

**2. Événements AUTH (autorisation requise)**
```
Application → Action → Kernel → ES KEXT → Client (décide)
                          ↓                    ↓
                      En attente        Allow / Deny
                          ↓                    ↓
                    Action réussie/bloquée ←──┘
```

**Catégories d'événements principales :**

| Catégorie | Exemples d'événements | Mode |
|-----------|----------------------|------|
| Process | `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_AUTH_EXEC` | AUTH/NOTIFY |
| File | `ES_EVENT_TYPE_NOTIFY_OPEN`, `ES_EVENT_TYPE_AUTH_OPEN` | AUTH/NOTIFY |
| Network | `ES_EVENT_TYPE_NOTIFY_SOCKET_BIND` | NOTIFY |
| Signal | `ES_EVENT_TYPE_NOTIFY_SIGNAL` | NOTIFY |
| Mach | `ES_EVENT_TYPE_NOTIFY_MACH_LOOKUP` | NOTIFY |

### Concept 3 : Structure des messages ES

Chaque événement est représenté par une structure `es_message_t` :

```
┌──────────────────────────────────────┐
│          es_message_t                │
├──────────────────────────────────────┤
│  version: uint32_t                   │  Version du message
│  time: struct timespec               │  Timestamp
│  mach_time: uint64_t                 │  Mach absolute time
│  deadline: uint64_t                  │  (AUTH seulement)
│  process: es_process_t*              │  Processus source
│  seq_num: uint64_t                   │  Numéro de séquence
│  action: es_action_t                 │  (AUTH seulement)
│  event_type: es_event_type_t         │  Type d'événement
│  event: union { ... }                │  Données spécifiques
└──────────────────────────────────────┘
         │
         └──> es_process_t
              ├─ audit_token: audit_token_t
              ├─ ppid: pid_t
              ├─ original_ppid: pid_t
              ├─ group_id: pid_t
              ├─ session_id: pid_t
              ├─ codesigning_flags: uint32_t
              ├─ is_platform_binary: bool
              ├─ is_es_client: bool
              ├─ executable: es_file_t*
              └─ ...
```

### Concept 4 : Entitlements et privilèges requis

Pour utiliser l'ES Framework, votre application doit :

1. **Avoir l'entitlement requis** dans son code signature :
   ```xml
   <key>com.apple.developer.endpoint-security.client</key>
   <true/>
   ```

2. **Être approuvée par l'utilisateur** via System Preferences > Security & Privacy > Full Disk Access

3. **Tourner avec des privilèges élevés** (généralement root ou via un daemon système)

## Mise en pratique

### Étape 1 : Créer un client ES basique

Voici un client ES minimal qui surveille les exécutions de processus :

```c
// es_client_demo.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>

// Callback appelé pour chaque événement
void event_handler(es_client_t *client, const es_message_t *message) {
    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC: {
            // Extraire les informations du processus
            es_process_t *proc = message->process;

            // Obtenir le chemin de l'exécutable
            es_string_token_t *path = &proc->executable->path;

            // Obtenir le PID
            audit_token_t token = proc->audit_token;
            pid_t pid = audit_token_to_pid(token);

            printf("[EXEC] PID: %d, Path: %.*s\n",
                   pid,
                   path->length,
                   path->data);

            // Afficher les arguments
            es_event_exec_t *exec = &message->event.exec;
            uint32_t arg_count = es_exec_arg_count(&exec->args);

            printf("       Args: ");
            for (uint32_t i = 0; i < arg_count; i++) {
                es_string_token_t arg = es_exec_arg(&exec->args, i);
                printf("%.*s ", arg.length, arg.data);
            }
            printf("\n");

            break;
        }
        default:
            break;
    }
}

int main(int argc, char *argv[]) {
    es_client_t *client = NULL;

    // Créer le client ES
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        event_handler(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Erreur lors de la création du client ES: %d\n", result);
        fprintf(stderr, "Vérifiez que vous avez l'entitlement et les permissions nécessaires.\n");
        return 1;
    }

    printf("Client ES créé avec succès.\n");

    // S'abonner aux événements EXEC
    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Erreur lors de l'abonnement aux événements.\n");
        es_delete_client(client);
        return 1;
    }

    printf("Surveillance des exécutions de processus...\n");
    printf("Appuyez sur Ctrl+C pour arrêter.\n\n");

    // Garder le programme en exécution
    dispatch_main();

    return 0;
}
```

**Compilation :**
```bash
# Créer un fichier d'entitlements
cat > entitlements.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>
EOF

# Compiler
clang -framework EndpointSecurity -framework Foundation \
      -o es_client_demo es_client_demo.c

# Signer avec entitlements (nécessite un certificat de développeur)
codesign --force --sign - \
         --entitlements entitlements.plist \
         es_client_demo

# Exécuter avec sudo
sudo ./es_client_demo
```

### Étape 2 : Implémenter un client AUTH pour bloquer des exécutions

Voici un client qui bloque l'exécution de binaires non signés :

```c
// es_auth_client.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>

void auth_handler(es_client_t *client, const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        es_process_t *proc = message->process;
        es_string_token_t *path = &proc->executable->path;

        // Vérifier si le binaire est signé par Apple
        bool is_platform = proc->is_platform_binary;
        bool is_signed = (proc->codesigning_flags & CS_SIGNED) != 0;
        bool is_valid = (proc->codesigning_flags & CS_VALID) != 0;

        pid_t pid = audit_token_to_pid(proc->audit_token);

        // Politique : bloquer les binaires non signés ou invalides
        bool should_allow = is_signed && is_valid;

        printf("[AUTH_EXEC] PID: %d, Path: %.*s\n",
               pid, path->length, path->data);
        printf("            Platform: %s, Signed: %s, Valid: %s -> %s\n",
               is_platform ? "YES" : "NO",
               is_signed ? "YES" : "NO",
               is_valid ? "YES" : "NO",
               should_allow ? "ALLOW" : "DENY");

        // Répondre à l'événement AUTH
        uint32_t flags = should_allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY;
        es_respond_auth_result(client, message, flags, false);
    }
}

int main(int argc, char *argv[]) {
    es_client_t *client = NULL;

    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        auth_handler(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Erreur création client: %d\n", result);
        return 1;
    }

    printf("Client ES AUTH créé.\n");

    // S'abonner aux événements AUTH_EXEC
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    if (es_subscribe(client, events, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Erreur abonnement.\n");
        es_delete_client(client);
        return 1;
    }

    printf("Blocage des binaires non signés activé.\n");
    printf("ATTENTION: Ceci peut bloquer des outils légitimes!\n\n");

    dispatch_main();
    return 0;
}
```

### Étape 3 : Surveiller les accès fichiers sensibles

```c
// file_monitor.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <string.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>

// Liste de chemins sensibles à surveiller
const char *sensitive_paths[] = {
    "/etc/passwd",
    "/etc/master.passwd",
    "/private/var/db/dslocal/nodes/Default/users/",
    "/Library/Keychains/",
    "/.ssh/",
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/"
};

bool is_sensitive_path(const char *path, size_t len) {
    for (int i = 0; i < sizeof(sensitive_paths) / sizeof(sensitive_paths[0]); i++) {
        if (strncmp(path, sensitive_paths[i], strlen(sensitive_paths[i])) == 0) {
            return true;
        }
    }
    return false;
}

void file_event_handler(es_client_t *client, const es_message_t *message) {
    es_process_t *proc = message->process;
    pid_t pid = audit_token_to_pid(proc->audit_token);
    es_string_token_t *proc_path = &proc->executable->path;

    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_OPEN: {
            es_event_open_t *open_event = &message->event.open;
            es_string_token_t *file_path = &open_event->file->path;

            if (is_sensitive_path(file_path->data, file_path->length)) {
                printf("[FILE_OPEN] PID: %d (%.*s)\n",
                       pid, proc_path->length, proc_path->data);
                printf("            Accessing: %.*s\n",
                       file_path->length, file_path->data);
                printf("            Flags: 0x%x\n", open_event->fflag);
            }
            break;
        }

        case ES_EVENT_TYPE_NOTIFY_WRITE: {
            es_event_write_t *write_event = &message->event.write;
            es_string_token_t *file_path = &write_event->target->path;

            if (is_sensitive_path(file_path->data, file_path->length)) {
                printf("[FILE_WRITE] PID: %d (%.*s)\n",
                       pid, proc_path->length, proc_path->data);
                printf("             Writing to: %.*s\n",
                       file_path->length, file_path->data);
            }
            break;
        }

        case ES_EVENT_TYPE_NOTIFY_CREATE: {
            es_event_create_t *create_event = &message->event.create;
            es_string_token_t *dest_path = &create_event->destination.new_path.dir->path;
            es_string_token_t *filename = &create_event->destination.new_path.filename;

            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%.*s/%.*s",
                     dest_path->length, dest_path->data,
                     filename->length, filename->data);

            if (is_sensitive_path(full_path, strlen(full_path))) {
                printf("[FILE_CREATE] PID: %d (%.*s)\n",
                       pid, proc_path->length, proc_path->data);
                printf("              Created: %s\n", full_path);
            }
            break;
        }

        default:
            break;
    }
}

int main(void) {
    es_client_t *client = NULL;

    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        file_event_handler(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Erreur création client: %d\n", result);
        return 1;
    }

    // S'abonner à plusieurs types d'événements fichiers
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK
    };

    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Erreur abonnement.\n");
        es_delete_client(client);
        return 1;
    }

    printf("Surveillance des fichiers sensibles activée.\n");
    printf("Chemins surveillés:\n");
    for (int i = 0; i < sizeof(sensitive_paths) / sizeof(sensitive_paths[0]); i++) {
        printf("  - %s\n", sensitive_paths[i]);
    }
    printf("\n");

    dispatch_main();
    return 0;
}
```

### Étape 4 : Détection de comportements suspects

Créons un détecteur de techniques Red Team courantes :

```c
// red_team_detector.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <string.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>

// Détection de shells inversés (reverse shells)
bool is_reverse_shell_indicator(const es_message_t *message) {
    if (message->event_type != ES_EVENT_TYPE_NOTIFY_EXEC) {
        return false;
    }

    es_event_exec_t *exec = &message->event.exec;
    es_string_token_t *path = &message->process->executable->path;

    // Vérifier si c'est bash, sh, zsh avec redirection réseau
    if (strstr(path->data, "/bash") ||
        strstr(path->data, "/sh") ||
        strstr(path->data, "/zsh")) {

        uint32_t arg_count = es_exec_arg_count(&exec->args);
        for (uint32_t i = 0; i < arg_count; i++) {
            es_string_token_t arg = es_exec_arg(&exec->args, i);
            // Rechercher des patterns de reverse shell
            if (strstr(arg.data, "/dev/tcp/") ||
                strstr(arg.data, "nc ") ||
                strstr(arg.data, "netcat")) {
                return true;
            }
        }
    }

    return false;
}

// Détection d'injection de dylib
bool is_dylib_injection(const es_message_t *message) {
    if (message->event_type != ES_EVENT_TYPE_NOTIFY_EXEC) {
        return false;
    }

    es_event_exec_t *exec = &message->event.exec;
    uint32_t env_count = es_exec_env_count(&exec->env);

    for (uint32_t i = 0; i < env_count; i++) {
        es_string_token_t env = es_exec_env(&exec->env, i);
        if (strncmp(env.data, "DYLD_INSERT_LIBRARIES=", 22) == 0) {
            return true;
        }
    }

    return false;
}

// Détection d'outils de dumping mémoire
bool is_memory_dumping_tool(const es_string_token_t *path) {
    const char *suspicious_tools[] = {
        "lldb", "gdb", "vmmap", "heap", "leaks", "memorymap"
    };

    for (int i = 0; i < sizeof(suspicious_tools) / sizeof(suspicious_tools[0]); i++) {
        if (strstr(path->data, suspicious_tools[i])) {
            return true;
        }
    }

    return false;
}

// Détection d'accès au keychain
bool is_keychain_access(const es_message_t *message) {
    if (message->event_type != ES_EVENT_TYPE_NOTIFY_EXEC) {
        return false;
    }

    es_string_token_t *path = &message->process->executable->path;

    if (strstr(path->data, "security") &&
        (strstr(path->data, "dump-keychain") || strstr(path->data, "find-generic-password"))) {
        return true;
    }

    return false;
}

void threat_detection_handler(es_client_t *client, const es_message_t *message) {
    es_process_t *proc = message->process;
    pid_t pid = audit_token_to_pid(proc->audit_token);
    es_string_token_t *path = &proc->executable->path;

    // Vérifier différents indicateurs de menace
    if (is_reverse_shell_indicator(message)) {
        printf("[ALERT] Possible reverse shell détecté!\n");
        printf("        PID: %d, Path: %.*s\n", pid, path->length, path->data);

        es_event_exec_t *exec = &message->event.exec;
        uint32_t arg_count = es_exec_arg_count(&exec->args);
        printf("        Args: ");
        for (uint32_t i = 0; i < arg_count; i++) {
            es_string_token_t arg = es_exec_arg(&exec->args, i);
            printf("%.*s ", arg.length, arg.data);
        }
        printf("\n\n");
    }

    if (is_dylib_injection(message)) {
        printf("[ALERT] Injection de dylib détectée!\n");
        printf("        PID: %d, Path: %.*s\n", pid, path->length, path->data);

        es_event_exec_t *exec = &message->event.exec;
        uint32_t env_count = es_exec_env_count(&exec->env);
        for (uint32_t i = 0; i < env_count; i++) {
            es_string_token_t env = es_exec_env(&exec->env, i);
            if (strncmp(env.data, "DYLD_INSERT_LIBRARIES=", 22) == 0) {
                printf("        %.*s\n", env.length, env.data);
            }
        }
        printf("\n");
    }

    if (is_memory_dumping_tool(path)) {
        printf("[WARNING] Outil de dumping mémoire détecté!\n");
        printf("          PID: %d, Path: %.*s\n", pid, path->length, path->data);
        printf("\n");
    }

    if (is_keychain_access(message)) {
        printf("[WARNING] Tentative d'accès au keychain détectée!\n");
        printf("          PID: %d, Path: %.*s\n", pid, path->length, path->data);
        printf("\n");
    }
}

int main(void) {
    es_client_t *client = NULL;

    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        threat_detection_handler(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Erreur création client: %d\n", result);
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_OPEN
    };

    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Erreur abonnement.\n");
        es_delete_client(client);
        return 1;
    }

    printf("=== Red Team Threat Detector ===\n");
    printf("Détection active pour:\n");
    printf("  - Reverse shells\n");
    printf("  - Injection de dylib (DYLD_INSERT_LIBRARIES)\n");
    printf("  - Outils de dumping mémoire\n");
    printf("  - Accès au keychain\n");
    printf("\n");

    dispatch_main();
    return 0;
}
```

## Application offensive

### Contexte Red Team

En tant qu'opérateur Red Team sur macOS, l'Endpoint Security Framework est votre principal adversaire. Voici comment cette connaissance s'applique :

**1. Reconnaissance défensive**

Avant toute opération, identifiez les clients ES actifs :
```bash
# Lister les processus avec l'entitlement ES
sudo codesign -d --entitlements - /path/to/suspicious/app

# Vérifier les processus qui communiquent avec endpointsecurityd
sudo lsof -c endpointsecurityd
```

**2. Techniques d'évasion**

- **Utiliser des binaires signés Apple** : Les EDR accordent souvent plus de confiance aux binaires platform
- **Living off the land** : Utilisez des outils système légitimes pour éviter les alertes
- **Masquage de process** : Adoptez des noms de processus qui ressemblent à des processus système

**3. Événements critiques à éviter**

Les événements suivants génèrent presque toujours des alertes :
- `ES_EVENT_TYPE_AUTH_EXEC` avec signature invalide
- `ES_EVENT_TYPE_NOTIFY_OPEN` sur `/Library/Keychains/`
- Utilisation de `DYLD_INSERT_LIBRARIES`
- Utilisation de `task_for_pid()` sur des processus sensibles

### Considérations OPSEC

**Détection du monitoring ES :**

```c
// check_es_monitoring.c
// Vérifie si des clients ES sont actifs
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // Méthode 1: Vérifier si endpointsecurityd a des connexions
    system("lsof -p $(pgrep endpointsecurityd) 2>/dev/null | grep -q STREAM && echo 'ES clients detected!' || echo 'No ES clients'");

    // Méthode 2: Tenter de créer un client ES
    // Si un client existe déjà avec les mêmes événements, la création échouera

    // Méthode 3: Analyser les processus avec l'entitlement
    system("ps aux | while read line; do "
           "pid=$(echo $line | awk '{print $2}'); "
           "codesign -d --entitlements :- /proc/$pid/file 2>/dev/null | "
           "grep -q 'endpoint-security.client' && echo \"ES Client: $line\"; "
           "done");

    return 0;
}
```

**Recommandations OPSEC :**

1. **Ne pas déclencher des volumes élevés d'événements** : Les EDR détectent les anomalies statistiques
2. **Espacer vos actions dans le temps** : Évitez les rafales d'activité suspecte
3. **Imiter des comportements légitimes** : Adoptez les patterns d'utilisation normaux
4. **Tester dans un environnement contrôlé** : Utilisez un Mac de test avec EDR pour valider vos techniques

**Contournement (pour recherche uniquement) :**

Théoriquement, certaines approches pourraient limiter la détection :
- Opérer depuis le kernel space (nécessite une vulnérabilité)
- Exploiter des bugs dans le KEXT ES lui-même
- Utiliser des techniques de désactivation du System Integrity Protection (SIP)

**AVERTISSEMENT** : Ces techniques sont illégales sans autorisation explicite et sont fournies uniquement à des fins éducatives pour comprendre les mécanismes de défense.

## Résumé

- L'Endpoint Security Framework est le mécanisme de surveillance système moderne d'Apple
- Il fonctionne via un modèle client-serveur avec communication XPC entre user space et kernel
- Les événements sont divisés en deux catégories : NOTIFY (notification) et AUTH (autorisation)
- Un client ES nécessite l'entitlement `com.apple.developer.endpoint-security.client`
- Les EDR sur macOS utilisent principalement l'ES Framework pour détecter les activités malveillantes
- Pour les opérations Red Team, comprendre ce framework est crucial pour développer des techniques d'évasion efficaces
- Les événements les plus surveillés sont : EXEC, OPEN, WRITE, FORK, TASK_FOR_PID
- La détection peut être basée sur des signatures (patterns connus) ou des anomalies (comportement inhabituel)

## Ressources complémentaires

- [Endpoint Security Framework - Apple Developer](https://developer.apple.com/documentation/endpointsecurity)
- [OBDEV - Little Snitch (exemple d'utilisation ES)](https://www.obdev.at/products/littlesnitch/)
- [Patrick Wardle - Objective-See Blog](https://objective-see.org/blog.html)
- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [ESF Playground - Outil de test ES](https://github.com/objective-see/ESF_Playground)
- [Mac4n6 - Forensics and ES](https://www.mac4n6.com/)
- [Jamf - Endpoint Security Framework Deep Dive](https://www.jamf.com/blog/endpoint-security-framework/)

---

**Navigation**
- [Module précédent](../M09_macos_security_model/)
- [Module suivant](../M11_kext_basics/)
