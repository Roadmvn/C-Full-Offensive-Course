/*
 * OBJECTIF  : Comprendre l'Endpoint Security Framework macOS
 * PREREQUIS : Bases C, securite macOS, kext, system extensions
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement de l'Endpoint Security
 * Framework : types d'evenements, creation de clients, filtrage,
 * et comment il est utilise par les EDR et les malwares.
 * Demonstration pedagogique (l'API ES necessite des entitlements).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Etape 1 : Architecture de l'Endpoint Security
 */
static void explain_es_architecture(void) {
    printf("[*] Etape 1 : Architecture Endpoint Security\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  User Space                               │\n");
    printf("    │  ┌──────────┐   ┌──────────────────┐     │\n");
    printf("    │  │ Malware  │   │ EDR / Antivirus   │     │\n");
    printf("    │  │ Process  │   │ (ES Client)       │     │\n");
    printf("    │  └────┬─────┘   └────────┬─────────┘     │\n");
    printf("    │       │                   │               │\n");
    printf("    │       │ syscall           │ es_new_client │\n");
    printf("    │       v                   v               │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Kernel                                   │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │  Endpoint Security Framework      │    │\n");
    printf("    │  │  - Intercepte les evenements       │    │\n");
    printf("    │  │  - Notifie les clients ES          │    │\n");
    printf("    │  │  - AUTH events : bloquant           │    │\n");
    printf("    │  │  - NOTIFY events : informatif       │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Remplace les KEXT pour la securite (depuis macOS 10.15)\n");
    printf("    Necessite l'entitlement :\n");
    printf("    com.apple.developer.endpoint-security.client\n\n");
}

/*
 * Etape 2 : Types d'evenements
 */
static void explain_event_types(void) {
    printf("[*] Etape 2 : Types d'evenements Endpoint Security\n\n");

    printf("    AUTH events (bloquants - l'action attend la decision) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ES_EVENT_TYPE_AUTH_EXEC         : execution de binaire\n");
    printf("    ES_EVENT_TYPE_AUTH_OPEN         : ouverture de fichier\n");
    printf("    ES_EVENT_TYPE_AUTH_CREATE       : creation de fichier\n");
    printf("    ES_EVENT_TYPE_AUTH_UNLINK       : suppression\n");
    printf("    ES_EVENT_TYPE_AUTH_RENAME       : renommage\n");
    printf("    ES_EVENT_TYPE_AUTH_SIGNAL       : envoi de signal\n");
    printf("    ES_EVENT_TYPE_AUTH_MPROTECT     : changement memoire\n\n");

    printf("    NOTIFY events (informatifs - l'action continue) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ES_EVENT_TYPE_NOTIFY_EXEC       : notification exec\n");
    printf("    ES_EVENT_TYPE_NOTIFY_FORK       : fork de processus\n");
    printf("    ES_EVENT_TYPE_NOTIFY_EXIT       : fin de processus\n");
    printf("    ES_EVENT_TYPE_NOTIFY_WRITE      : ecriture fichier\n");
    printf("    ES_EVENT_TYPE_NOTIFY_CLOSE      : fermeture fichier\n");
    printf("    ES_EVENT_TYPE_NOTIFY_MMAP       : mapping memoire\n");
    printf("    ES_EVENT_TYPE_NOTIFY_KEXTLOAD   : chargement kext\n\n");

    printf("    Total : plus de 80 types d'evenements\n\n");
}

/*
 * Etape 3 : Creation d'un client ES (code reference)
 */
static void show_es_client_code(void) {
    printf("[*] Etape 3 : Creation d'un client ES (reference)\n\n");

    printf("    #include <EndpointSecurity/EndpointSecurity.h>\n\n");

    printf("    es_client_t *client = NULL;\n");
    printf("    es_new_client_result_t result = es_new_client(\n");
    printf("        &client,\n");
    printf("        ^(es_client_t *c, const es_message_t *msg) {\n");
    printf("            switch (msg->event_type) {\n\n");

    printf("            case ES_EVENT_TYPE_AUTH_EXEC: {\n");
    printf("                es_process_t *proc = msg->event.exec.target;\n");
    printf("                const char *path = proc->executable->path.data;\n");
    printf("                pid_t pid = audit_token_to_pid(proc->audit_token);\n");
    printf("                printf(\"EXEC: pid=%%d path=%%s\\n\", pid, path);\n\n");
    printf("                // Autoriser ou bloquer\n");
    printf("                es_respond_auth_result(c, msg,\n");
    printf("                    ES_AUTH_RESULT_ALLOW, false);\n");
    printf("                break;\n");
    printf("            }\n\n");

    printf("            case ES_EVENT_TYPE_NOTIFY_FORK:\n");
    printf("                printf(\"FORK: ppid=%%d\\n\",\n");
    printf("                    audit_token_to_pid(\n");
    printf("                        msg->process->audit_token));\n");
    printf("                break;\n");
    printf("            }\n");
    printf("        });\n\n");

    printf("    // S'abonner aux evenements\n");
    printf("    es_event_type_t events[] = {\n");
    printf("        ES_EVENT_TYPE_AUTH_EXEC,\n");
    printf("        ES_EVENT_TYPE_NOTIFY_FORK,\n");
    printf("    };\n");
    printf("    es_subscribe(client, events, 2);\n\n");

    printf("    // Pour arreter\n");
    printf("    es_unsubscribe_all(client);\n");
    printf("    es_delete_client(client);\n\n");
}

/*
 * Etape 4 : Produits utilisant ES
 */
static void explain_es_products(void) {
    printf("[*] Etape 4 : Produits utilisant Endpoint Security\n\n");

    printf("    Produit          | Usage\n");
    printf("    ─────────────────|──────────────────────────────\n");
    printf("    CrowdStrike      | EDR (AUTH_EXEC, NOTIFY_WRITE)\n");
    printf("    SentinelOne      | EDR, anti-ransomware\n");
    printf("    Carbon Black     | Monitoring des processus\n");
    printf("    Objective-See    | Outils gratuits (LuLu, etc.)\n");
    printf("    Santa (Google)   | Whitelist/blacklist d'execution\n");
    printf("    LuLu             | Firewall applicatif\n");
    printf("    BlockBlock        | Detection persistence\n\n");

    /* Verifier les extensions systeme installees */
    printf("    Extensions systeme installees :\n");
    FILE *fp = popen("systemextensionsctl list 2>&1 | head -15", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 5 : Evasion de l'Endpoint Security
 */
static void explain_evasion(void) {
    printf("[*] Etape 5 : Evasion de l'Endpoint Security\n\n");

    printf("    Techniques d'evasion :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Identifier les clients ES actifs\n");
    printf("       -> Chercher les system extensions\n");
    printf("       -> systemextensionsctl list\n\n");
    printf("    2. Agir avant que l'ES client ne reponde\n");
    printf("       -> Race condition sur les AUTH events\n\n");
    printf("    3. Utiliser des APIs non monitorees\n");
    printf("       -> Certaines operations n'ont pas d'event ES\n\n");
    printf("    4. Abuser des exclusions\n");
    printf("       -> Certains EDR excluent des chemins\n");
    printf("       -> Copier le payload dans un chemin exclu\n\n");
    printf("    5. Desactiver la protection\n");
    printf("       -> Desinstaller l'agent EDR (si privileges)\n");
    printf("       -> Reboot en Recovery Mode\n\n");

    printf("    Limitations de l'evasion :\n");
    printf("    - SIP protege les system extensions\n");
    printf("    - Les clients ES ont un timeout court pour AUTH\n");
    printf("    - Le kernel force la reponse en cas de timeout\n\n");
}

/*
 * Etape 6 : Detection et monitoring
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et monitoring\n\n");

    printf("    Commandes utiles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    systemextensionsctl list          # Extensions\n");
    printf("    eslogger exec fork exit            # Logger ES\n");
    printf("    log show --predicate 'subsystem == \"com.apple.es\"'\n\n");

    printf("    eslogger (macOS 13+) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Logger les executions\n");
    printf("    sudo eslogger exec\n\n");
    printf("    # Logger les ouvertures de fichiers\n");
    printf("    sudo eslogger open\n\n");
    printf("    # Logger plusieurs types\n");
    printf("    sudo eslogger exec fork exit rename\n\n");

    printf("    Bonnes pratiques pour les defenseurs :\n");
    printf("    - Deployer un EDR avec ES client\n");
    printf("    - Monitorer les desinstallations d'extensions\n");
    printf("    - Garder SIP active\n");
    printf("    - Centriser les logs ES\n");
    printf("    - Tester les capacites de l'EDR regulierement\n\n");
}

int main(void) {
    printf("[*] Demo : Endpoint Security Framework macOS\n\n");

    explain_es_architecture();
    explain_event_types();
    show_es_client_code();
    explain_es_products();
    explain_evasion();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
