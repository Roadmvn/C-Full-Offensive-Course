/*
 * OBJECTIF  : Comprendre les Mach ports et l'IPC macOS
 * PREREQUIS : Bases C, architecture XNU, processus
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement des Mach ports :
 * creation de ports, envoi/reception de messages, droits,
 * et comment ils sont utilises pour l'IPC sur macOS.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/message.h>

/*
 * Etape 1 : Architecture des Mach ports
 */
static void explain_mach_ports(void) {
    printf("[*] Etape 1 : Architecture des Mach ports\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │           XNU KERNEL (Mach)               │\n");
    printf("    │                                          │\n");
    printf("    │  ┌──────────┐      ┌──────────┐         │\n");
    printf("    │  │ Task A   │      │ Task B   │         │\n");
    printf("    │  │ (Process)│      │ (Process)│         │\n");
    printf("    │  │          │      │          │         │\n");
    printf("    │  │ Port set │ MSG  │ Port set │         │\n");
    printf("    │  │ ┌──────┐ │─────>│ ┌──────┐ │         │\n");
    printf("    │  │ │Send R│ │      │ │Recv R│ │         │\n");
    printf("    │  │ └──────┘ │      │ └──────┘ │         │\n");
    printf("    │  └──────────┘      └──────────┘         │\n");
    printf("    │                                          │\n");
    printf("    │  Chaque port = file d'attente de messages│\n");
    printf("    │  Un seul recepteur, multiples emetteurs   │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Types de droits sur un port :\n");
    printf("    Droit         | Description\n");
    printf("    ──────────────|──────────────────────────────\n");
    printf("    RECEIVE       | Droit de lire les messages (unique)\n");
    printf("    SEND          | Droit d'envoyer des messages\n");
    printf("    SEND_ONCE     | Droit d'envoyer un seul message\n");
    printf("    PORT_SET      | Ensemble de ports (multiplex)\n");
    printf("    DEAD_NAME     | Le port a ete detruit\n\n");
}

/*
 * Etape 2 : Creer un Mach port
 */
static void demo_create_port(void) {
    printf("[*] Etape 2 : Creation d'un Mach port\n\n");

    mach_port_t port;
    kern_return_t kr;

    kr = mach_port_allocate(mach_task_self(),
                            MACH_PORT_RIGHT_RECEIVE, &port);

    if (kr != KERN_SUCCESS) {
        printf("    Erreur mach_port_allocate : %s\n\n",
               mach_error_string(kr));
        return;
    }

    printf("    Port cree : %d\n", port);

    /* Ajouter le droit d'envoi */
    kr = mach_port_insert_right(mach_task_self(), port, port,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr == KERN_SUCCESS)
        printf("    Droit SEND ajoute avec succes\n");

    /* Obtenir les informations sur le port */
    mach_port_type_t type;
    kr = mach_port_type(mach_task_self(), port, &type);
    if (kr == KERN_SUCCESS) {
        printf("    Type de port : 0x%x\n", type);
        if (type & MACH_PORT_TYPE_RECEIVE)
            printf("      -> RECEIVE right\n");
        if (type & MACH_PORT_TYPE_SEND)
            printf("      -> SEND right\n");
    }

    /* Detruire le port */
    mach_port_deallocate(mach_task_self(), port);
    printf("    Port dealloue\n\n");
}

/*
 * Etape 3 : Envoi et reception de messages
 */

/* Structure de message simple */
typedef struct {
    mach_msg_header_t header;
    char body[256];
    mach_msg_trailer_t trailer;
} simple_msg_t;

static void demo_send_receive(void) {
    printf("[*] Etape 3 : Envoi et reception de messages Mach\n\n");

    mach_port_t port;
    kern_return_t kr;

    /* Creer le port */
    kr = mach_port_allocate(mach_task_self(),
                            MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        printf("    Erreur creation port\n\n");
        return;
    }
    mach_port_insert_right(mach_task_self(), port, port,
                           MACH_MSG_TYPE_MAKE_SEND);

    /* Construire le message */
    printf("    Structure mach_msg_header_t :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mach_msg_bits_t    msgh_bits;       // droits\n");
    printf("    mach_msg_size_t    msgh_size;       // taille\n");
    printf("    mach_port_t        msgh_remote_port; // destination\n");
    printf("    mach_port_t        msgh_local_port;  // reply port\n");
    printf("    mach_msg_id_t      msgh_id;         // identifiant\n\n");

    /* Envoyer un message a soi-meme */
    mach_msg_header_t send_msg = {0};
    send_msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    send_msg.msgh_size = sizeof(send_msg);
    send_msg.msgh_remote_port = port;
    send_msg.msgh_local_port = MACH_PORT_NULL;
    send_msg.msgh_id = 42;

    kr = mach_msg(&send_msg, MACH_SEND_MSG, sizeof(send_msg),
                  0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);

    if (kr == KERN_SUCCESS)
        printf("    Message envoye (id=42)\n");
    else
        printf("    Erreur envoi : %s\n", mach_error_string(kr));

    /* Recevoir le message */
    mach_msg_header_t recv_msg = {0};
    kr = mach_msg(&recv_msg, MACH_RCV_MSG, 0, sizeof(recv_msg),
                  port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

    if (kr == KERN_SUCCESS)
        printf("    Message recu  (id=%d)\n", recv_msg.msgh_id);
    else
        printf("    Erreur reception : %s\n", mach_error_string(kr));

    mach_port_deallocate(mach_task_self(), port);
    printf("\n");
}

/*
 * Etape 4 : Ports systeme importants
 */
static void explain_system_ports(void) {
    printf("[*] Etape 4 : Ports systeme importants\n\n");

    printf("    Port                   | Usage\n");
    printf("    ───────────────────────|──────────────────────────\n");
    printf("    mach_task_self()       | Port de notre propre tache\n");
    printf("    mach_host_self()       | Port du host (privileges)\n");
    printf("    bootstrap port         | Connexion a launchd\n");
    printf("    task_for_pid port      | Controle d'un autre processus\n");
    printf("    thread_self()          | Port du thread courant\n\n");

    /* Afficher nos ports */
    printf("    Nos ports :\n");
    printf("    task_self  : %d\n", mach_task_self());
    printf("    host_self  : %d\n", mach_host_self());

    mach_port_t bootstrap;
    task_get_bootstrap_port(mach_task_self(), &bootstrap);
    printf("    bootstrap  : %d\n\n", bootstrap);

    printf("    task_for_pid() - Controle d'un autre processus :\n");
    printf("    ───────────────────────────────────\n");
    printf("    mach_port_t task;\n");
    printf("    task_for_pid(mach_task_self(), target_pid, &task);\n");
    printf("    // Permet de lire/ecrire la memoire du processus\n");
    printf("    // Necessite des privileges speciaux ou SIP desactive\n\n");
}

/*
 * Etape 5 : Enumeration des ports d'un processus
 */
static void demo_enumerate_ports(void) {
    printf("[*] Etape 5 : Enumeration des ports\n\n");

    mach_port_name_array_t names;
    mach_port_type_array_t types;
    mach_msg_type_number_t count;

    kern_return_t kr = mach_port_names(mach_task_self(),
                                       &names, &count,
                                       &types, &count);
    if (kr != KERN_SUCCESS) {
        printf("    Erreur enumeration\n\n");
        return;
    }

    printf("    Ports de notre processus (%d ports) :\n", count);
    printf("    %-10s %-10s %s\n", "Name", "Type", "Rights");
    printf("    %-10s %-10s %s\n", "──────────", "──────────", "──────────");

    int displayed = 0;
    for (mach_msg_type_number_t i = 0; i < count && displayed < 15; i++) {
        const char *rights = "?";
        if (types[i] & MACH_PORT_TYPE_SEND)
            rights = "SEND";
        if (types[i] & MACH_PORT_TYPE_RECEIVE)
            rights = "RECEIVE";
        if (types[i] & MACH_PORT_TYPE_SEND_ONCE)
            rights = "SEND_ONCE";
        if ((types[i] & MACH_PORT_TYPE_SEND) &&
            (types[i] & MACH_PORT_TYPE_RECEIVE))
            rights = "SEND+RECV";

        printf("    %-10d 0x%-8x %s\n", names[i], types[i], rights);
        displayed++;
    }
    if (count > 15)
        printf("    ... (%d de plus)\n", count - 15);

    vm_deallocate(mach_task_self(), (vm_address_t)names,
                  count * sizeof(mach_port_name_t));
    vm_deallocate(mach_task_self(), (vm_address_t)types,
                  count * sizeof(mach_port_type_t));
    printf("\n");
}

/*
 * Etape 6 : Exploitation des Mach ports
 */
static void explain_exploitation(void) {
    printf("[*] Etape 6 : Exploitation des Mach ports\n\n");

    printf("    Attaques via Mach ports :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. task_for_pid() : injection de code\n");
    printf("       -> Lire/ecrire la memoire d'un processus\n");
    printf("       -> Creer des threads distants\n\n");
    printf("    2. Port swapping : remplacer un service port\n");
    printf("       -> Man-in-the-middle sur l'IPC\n\n");
    printf("    3. Bootstrap port hijacking\n");
    printf("       -> Intercepter les connexions a launchd\n\n");
    printf("    4. Exception port stealing\n");
    printf("       -> Intercepter les crashes d'un processus\n\n");

    printf("    Protections macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - SIP protege task_for_pid sur les processus systeme\n");
    printf("    - Entitlement 'com.apple.system-task-ports' requis\n");
    printf("    - AMFI verifie les droits avant d'accorder l'acces\n");
    printf("    - Sandbox restreint les operations sur les ports\n\n");
}

int main(void) {
    printf("[*] Demo : Mach Ports - IPC macOS\n\n");

    explain_mach_ports();
    demo_create_port();
    demo_send_receive();
    explain_system_ports();
    demo_enumerate_ports();
    explain_exploitation();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
