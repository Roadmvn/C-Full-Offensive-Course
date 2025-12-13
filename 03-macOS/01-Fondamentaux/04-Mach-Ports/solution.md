# Solutions - Mach Ports

Ce document contient les solutions complètes des exercices du module M04 - Mach Ports.

## Exercice 1 : Découverte - Créer et manipuler un port Mach (Très facile)

**Objectif** : Créer un port Mach, obtenir ses droits et afficher ses informations.

### Solution

```c
/*
 * exercice1_mach_port_creation.c
 *
 * Description : Création d'un port Mach avec droits RECEIVE et SEND
 *
 * Compilation :
 *   clang -o exercice1 exercice1_mach_port_creation.c
 *
 * Usage :
 *   ./exercice1
 */

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    mach_port_t port;
    kern_return_t kr;

    printf("[*] Exercice 1 : Création d'un port Mach\n");
    printf("==========================================\n\n");

    // Étape 1 : Allouer un nouveau port
    // mach_task_self() retourne le task port du processus actuel
    // MACH_PORT_RIGHT_RECEIVE signifie qu'on veut le droit de recevoir des messages
    kr = mach_port_allocate(
        mach_task_self(),           // Notre task (processus actuel)
        MACH_PORT_RIGHT_RECEIVE,    // Type de droit souhaité
        &port                       // Variable où stocker le port créé
    );

    // Vérifier si la création a réussi
    if (kr != KERN_SUCCESS) {
        printf("[-] Erreur lors de l'allocation du port : %s\n",
               mach_error_string(kr));
        return 1;
    }

    printf("[+] Port créé avec succès\n");
    printf("[+] Port name : 0x%x (%u)\n", port, port);
    printf("[+] Droits actuels : RECEIVE\n\n");

    // Étape 2 : Ajouter un droit SEND au port
    // Cela permet au port de s'envoyer des messages à lui-même
    kr = mach_port_insert_right(
        mach_task_self(),           // Notre task
        port,                       // Le port à modifier
        port,                       // Le port pour lequel créer le droit
        MACH_MSG_TYPE_MAKE_SEND     // Type de droit à créer
    );

    if (kr != KERN_SUCCESS) {
        printf("[-] Erreur lors de l'insertion du droit SEND : %s\n",
               mach_error_string(kr));
        return 1;
    }

    printf("[+] Droit SEND ajouté avec succès\n");
    printf("[+] Droits finaux : RECEIVE + SEND\n\n");

    // Étape 3 : Vérifier les droits du port
    mach_port_type_t port_type;
    kr = mach_port_type(mach_task_self(), port, &port_type);

    if (kr == KERN_SUCCESS) {
        printf("[*] Vérification des droits :\n");

        if (port_type & MACH_PORT_TYPE_SEND)
            printf("    - SEND : OUI\n");

        if (port_type & MACH_PORT_TYPE_RECEIVE)
            printf("    - RECEIVE : OUI\n");

        if (port_type & MACH_PORT_TYPE_SEND_ONCE)
            printf("    - SEND_ONCE : OUI\n");
    }

    printf("\n[+] Exercice terminé avec succès\n");

    // Nettoyage : détruire le port
    mach_port_destroy(mach_task_self(), port);

    return 0;
}
```

### Explications détaillées

1. **mach_port_allocate()** : Crée un nouveau port et donne automatiquement le droit RECEIVE au processus appelant. Un seul processus peut avoir le droit RECEIVE sur un port.

2. **mach_port_insert_right()** : Ajoute un droit supplémentaire au port. Ici, on ajoute SEND pour pouvoir envoyer des messages au port.

3. **mach_port_type()** : Interroge les droits actuels sur un port donné.

---

## Exercice 2 : Modification - Communication simple entre deux ports (Facile)

**Objectif** : Créer deux ports et envoyer un message de l'un à l'autre.

### Solution

```c
/*
 * exercice2_simple_message.c
 *
 * Description : Envoi et réception d'un message simple via Mach ports
 *
 * Compilation :
 *   clang -o exercice2 exercice2_simple_message.c
 */

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

// Structure du message : doit commencer par mach_msg_header_t
typedef struct {
    mach_msg_header_t header;    // En-tête obligatoire
    char data[256];              // Données à transmettre
} simple_message_t;

/*
 * Fonction pour envoyer un message sur un port
 *
 * @param port : Port de destination
 * @param text : Texte à envoyer
 */
void send_message(mach_port_t port, const char *text) {
    simple_message_t msg;

    // Initialiser la structure à zéro
    memset(&msg, 0, sizeof(msg));

    // Configuration de l'en-tête du message
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = port;      // Port destination
    msg.header.msgh_local_port = MACH_PORT_NULL;  // Pas de port de réponse
    msg.header.msgh_id = 1337;               // ID arbitraire du message

    // Copier les données
    strncpy(msg.data, text, sizeof(msg.data) - 1);

    // Envoyer le message
    kern_return_t kr = mach_msg(
        &msg.header,                // Pointeur vers le message
        MACH_SEND_MSG,              // Option : envoi uniquement
        msg.header.msgh_size,       // Taille du message à envoyer
        0,                          // Taille réception (0 = aucune)
        MACH_PORT_NULL,             // Port de réception (aucun)
        MACH_MSG_TIMEOUT_NONE,      // Timeout infini
        MACH_PORT_NULL              // Port de notification (aucun)
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Message envoyé : \"%s\"\n", text);
    } else {
        printf("[-] Erreur d'envoi : %s\n", mach_error_string(kr));
    }
}

/*
 * Fonction pour recevoir un message depuis un port
 *
 * @param port : Port d'écoute
 */
void receive_message(mach_port_t port) {
    simple_message_t msg;

    // Initialiser la structure
    memset(&msg, 0, sizeof(msg));

    // Recevoir le message
    kern_return_t kr = mach_msg(
        &msg.header,                // Buffer de réception
        MACH_RCV_MSG,               // Option : réception uniquement
        0,                          // Taille envoi (0 = aucune)
        sizeof(msg),                // Taille du buffer de réception
        port,                       // Port à écouter
        MACH_MSG_TIMEOUT_NONE,      // Timeout infini (bloquant)
        MACH_PORT_NULL              // Port de notification
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Message reçu (ID %d) : \"%s\"\n",
               msg.header.msgh_id, msg.data);
    } else {
        printf("[-] Erreur de réception : %s\n", mach_error_string(kr));
    }
}

int main() {
    mach_port_t port;
    kern_return_t kr;

    printf("[*] Exercice 2 : Communication via Mach ports\n");
    printf("=============================================\n\n");

    // Créer le port
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        printf("[-] Erreur allocation : %s\n", mach_error_string(kr));
        return 1;
    }

    // Ajouter droit SEND
    mach_port_insert_right(mach_task_self(), port, port,
                          MACH_MSG_TYPE_MAKE_SEND);

    printf("[+] Port créé : 0x%x\n\n", port);

    // Envoyer un message
    printf("[*] Envoi du message...\n");
    send_message(port, "Hello from Mach port!");

    // Recevoir le message
    printf("\n[*] Réception du message...\n");
    receive_message(port);

    printf("\n[+] Communication terminée avec succès\n");

    // Nettoyage
    mach_port_destroy(mach_task_self(), port);

    return 0;
}
```

### Explications détaillées

1. **Structure du message** : Tous les messages Mach doivent commencer par `mach_msg_header_t`. On peut ajouter nos données après.

2. **mach_msg()** : Fonction centrale pour envoyer ET recevoir. Le flag `MACH_SEND_MSG` ou `MACH_RCV_MSG` détermine l'opération.

3. **Bloquant vs Non-bloquant** : Avec `MACH_MSG_TIMEOUT_NONE`, l'appel est bloquant jusqu'à réception d'un message.

---

## Exercice 3 : Création - Énumération des ports d'un processus (Moyen)

**Objectif** : Lister tous les ports Mach du processus actuel et afficher leurs droits.

### Solution

```c
/*
 * exercice3_port_enumeration.c
 *
 * Description : Énumération des ports Mach d'un processus
 *
 * Compilation :
 *   clang -o exercice3 exercice3_port_enumeration.c
 */

#include <mach/mach.h>
#include <stdio.h>

/*
 * Fonction pour énumérer tous les ports d'un task
 *
 * @param task : Task à énumérer (mach_task_self() pour le processus actuel)
 */
void enumerate_ports(mach_port_t task) {
    mach_port_name_array_t names;      // Tableau des noms de ports
    mach_port_type_array_t types;      // Tableau des types de ports
    mach_msg_type_number_t names_count, types_count;

    printf("[*] Énumération des ports Mach...\n\n");

    // Obtenir la liste de tous les ports
    kern_return_t kr = mach_port_names(
        task,
        &names,           // Sortie : tableau des noms
        &names_count,     // Sortie : nombre de ports
        &types,           // Sortie : tableau des types
        &types_count      // Sortie : nombre de types
    );

    if (kr != KERN_SUCCESS) {
        printf("[-] Erreur énumération : %s\n", mach_error_string(kr));
        return;
    }

    printf("[+] Nombre de ports trouvés : %d\n\n", names_count);
    printf("%-10s | %-30s\n", "Port", "Droits");
    printf("----------|--------------------------------\n");

    // Parcourir tous les ports
    for (int i = 0; i < names_count; i++) {
        printf("0x%-8x | ", names[i]);

        // Afficher les droits de chaque port
        if (types[i] & MACH_PORT_TYPE_SEND)
            printf("SEND ");

        if (types[i] & MACH_PORT_TYPE_RECEIVE)
            printf("RECEIVE ");

        if (types[i] & MACH_PORT_TYPE_SEND_ONCE)
            printf("SEND_ONCE ");

        if (types[i] & MACH_PORT_TYPE_PORT_SET)
            printf("PORT_SET ");

        if (types[i] & MACH_PORT_TYPE_DEAD_NAME)
            printf("DEAD_NAME ");

        printf("\n");
    }

    // Libérer la mémoire allouée par mach_port_names()
    vm_deallocate(mach_task_self(),
                  (vm_address_t)names,
                  names_count * sizeof(mach_port_name_t));

    vm_deallocate(mach_task_self(),
                  (vm_address_t)types,
                  types_count * sizeof(mach_port_type_t));
}

int main() {
    printf("[*] Exercice 3 : Énumération des ports\n");
    printf("======================================\n\n");

    // Énumérer les ports du processus actuel
    enumerate_ports(mach_task_self());

    printf("\n[+] Énumération terminée\n");

    return 0;
}
```

### Explications détaillées

1. **mach_port_names()** : Retourne la liste complète de tous les ports accessibles par un task. Très utile pour la reconnaissance.

2. **Types de ports** :
   - `MACH_PORT_TYPE_SEND` : Droit d'envoi
   - `MACH_PORT_TYPE_RECEIVE` : Droit de réception
   - `MACH_PORT_TYPE_DEAD_NAME` : Port détruit mais référence encore présente

3. **vm_deallocate()** : Important de libérer la mémoire allouée par le kernel.

---

## Exercice 4 : Challenge - Service lookup via Bootstrap (Difficile)

**Objectif** : Utiliser le Bootstrap Server pour découvrir et se connecter à un service système.

### Solution

```c
/*
 * exercice4_bootstrap_lookup.c
 *
 * Description : Découverte de services via Bootstrap Server
 *
 * Compilation :
 *   clang -o exercice4 exercice4_bootstrap_lookup.c
 */

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>

/*
 * Fonction pour rechercher un service dans le Bootstrap Server
 *
 * @param service_name : Nom du service à rechercher
 * @return : Port du service si trouvé, MACH_PORT_NULL sinon
 */
mach_port_t lookup_service(const char *service_name) {
    mach_port_t service_port;
    kern_return_t kr;

    printf("[*] Recherche du service : %s\n", service_name);

    // Interroger le Bootstrap Server
    kr = bootstrap_look_up(
        bootstrap_port,     // Port bootstrap global (variable prédéfinie)
        service_name,       // Nom du service
        &service_port       // Port retourné
    );

    if (kr == KERN_SUCCESS) {
        printf("[+] Service trouvé !\n");
        printf("    Port : 0x%x\n", service_port);
        return service_port;
    } else if (kr == BOOTSTRAP_UNKNOWN_SERVICE) {
        printf("[-] Service introuvable\n");
    } else {
        printf("[-] Erreur : %s\n", mach_error_string(kr));
    }

    return MACH_PORT_NULL;
}

/*
 * Fonction pour énumérer des services système courants
 */
void enumerate_common_services() {
    printf("\n[*] Énumération de services système courants\n");
    printf("=============================================\n\n");

    // Liste de services macOS courants
    const char *services[] = {
        "com.apple.SecurityServer",
        "com.apple.WindowServer",
        "com.apple.system.notification_center",
        "com.apple.PowerManagement.control",
        "com.apple.tccd",
        "com.apple.audio.SystemSoundServer",
        NULL
    };

    int found = 0;
    int total = 0;

    // Tester chaque service
    for (int i = 0; services[i] != NULL; i++) {
        total++;
        mach_port_t port = lookup_service(services[i]);

        if (port != MACH_PORT_NULL) {
            found++;
        }

        printf("\n");
    }

    printf("========================================\n");
    printf("[*] Résumé : %d/%d services trouvés\n", found, total);
}

int main() {
    printf("[*] Exercice 4 : Bootstrap Server Lookup\n");
    printf("========================================\n\n");

    // Vérifier que le bootstrap port est disponible
    if (bootstrap_port == MACH_PORT_NULL) {
        printf("[-] Erreur : Bootstrap port non disponible\n");
        return 1;
    }

    printf("[+] Bootstrap port : 0x%x\n\n", bootstrap_port);

    // Énumérer les services
    enumerate_common_services();

    printf("\n[+] Challenge terminé avec succès\n");

    return 0;
}
```

### Explications détaillées

1. **Bootstrap Server** : Annuaire central où tous les services système s'enregistrent. C'est l'équivalent d'un DNS pour les services macOS.

2. **bootstrap_look_up()** : Fonction pour interroger le Bootstrap Server et obtenir le port d'un service par son nom.

3. **Applications en Red Team** : Cette technique permet de découvrir quels services sont actifs sur le système, ce qui aide à la reconnaissance post-exploitation.

### Application offensive

Ce code peut être utilisé pour :
- **Reconnaissance** : Identifier les services disponibles
- **Lateral movement** : Se connecter à des services pour pivoter
- **Privilege escalation** : Trouver des services vulnérables avec privilèges élevés

---

## Résumé des concepts clés

- **Mach Ports** = système IPC bas-niveau de macOS
- **Droits** : SEND (envoyer), RECEIVE (recevoir), SEND_ONCE (envoi unique)
- **mach_msg()** : Fonction centrale pour communication
- **Bootstrap Server** : Annuaire de services système
- **Énumération** : Technique de reconnaissance via `mach_port_names()`

## Compilation de tous les exercices

```bash
# Exercice 1
clang -o ex1 exercice1_mach_port_creation.c

# Exercice 2
clang -o ex2 exercice2_simple_message.c

# Exercice 3
clang -o ex3 exercice3_port_enumeration.c

# Exercice 4
clang -o ex4 exercice4_bootstrap_lookup.c

# Exécution
./ex1
./ex2
./ex3
./ex4
```

## Points importants pour Red Team

1. **Mach Ports = vecteur d'attaque** : Beaucoup de services système communiquent via Mach
2. **task_for_pid()** : Permet d'obtenir le task port d'un processus = contrôle total
3. **IPC Hijacking** : Intercepter ou usurper des services via Bootstrap
4. **Protections** : SIP, Hardened Runtime, entitlements limitent l'usage offensif

---

**Note** : Ces exercices sont à but pédagogique pour comprendre les mécanismes internes de macOS. L'utilisation de ces techniques dans un contexte réel nécessite une autorisation explicite.
