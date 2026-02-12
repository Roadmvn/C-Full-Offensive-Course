/*
 * OBJECTIF  : Comprendre les services XPC sur macOS
 * PREREQUIS : Bases C, Mach ports, launchd, IPC macOS
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement des services XPC :
 * architecture, communication, enumeration des services,
 * et surface d'attaque. Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture XPC
 */
static void explain_xpc_architecture(void) {
    printf("[*] Etape 1 : Architecture XPC (Cross-Process Communication)\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Application                              │\n");
    printf("    │  ┌─────────────────┐                     │\n");
    printf("    │  │ xpc_connection  │                     │\n");
    printf("    │  │ create()        │                     │\n");
    printf("    │  └────────┬────────┘                     │\n");
    printf("    │           │ XPC message                   │\n");
    printf("    │           v                               │\n");
    printf("    │  ┌─────────────────┐                     │\n");
    printf("    │  │    launchd      │  (bootstrap server)  │\n");
    printf("    │  │  Route messages │                     │\n");
    printf("    │  └────────┬────────┘                     │\n");
    printf("    │           │                               │\n");
    printf("    │           v                               │\n");
    printf("    │  ┌─────────────────┐                     │\n");
    printf("    │  │  XPC Service    │  (processus separe)  │\n");
    printf("    │  │  (privileged?)  │                     │\n");
    printf("    │  └─────────────────┘                     │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Types de services XPC :\n");
    printf("    Type             | Privilege    | Emplacement\n");
    printf("    ─────────────────|──────────────|────────────────────\n");
    printf("    Application      | Meme user    | App.app/XPCServices/\n");
    printf("    LaunchAgent      | User         | ~/Library/LaunchAgents/\n");
    printf("    LaunchDaemon     | Root         | /Library/LaunchDaemons/\n");
    printf("    System service   | Root + SIP   | /System/Library/\n\n");
}

/*
 * Etape 2 : Communication XPC en C
 */
static void explain_xpc_api(void) {
    printf("[*] Etape 2 : API XPC en C\n\n");

    printf("    #include <xpc/xpc.h>\n\n");

    printf("    Creer une connexion :\n");
    printf("    ───────────────────────────────────\n");
    printf("    xpc_connection_t conn = xpc_connection_create_mach_service(\n");
    printf("        \"com.apple.example.service\",\n");
    printf("        NULL,\n");
    printf("        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED\n");
    printf("    );\n\n");

    printf("    xpc_connection_set_event_handler(conn,\n");
    printf("        ^(xpc_object_t event) {\n");
    printf("            // Traiter les reponses\n");
    printf("        });\n");
    printf("    xpc_connection_resume(conn);\n\n");

    printf("    Envoyer un message :\n");
    printf("    ───────────────────────────────────\n");
    printf("    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);\n");
    printf("    xpc_dictionary_set_string(msg, \"command\", \"status\");\n");
    printf("    xpc_dictionary_set_int64(msg, \"pid\", getpid());\n\n");
    printf("    xpc_connection_send_message_with_reply(conn, msg,\n");
    printf("        dispatch_get_main_queue(),\n");
    printf("        ^(xpc_object_t reply) {\n");
    printf("            const char *result = xpc_dictionary_get_string(\n");
    printf("                reply, \"result\");\n");
    printf("        });\n\n");
}

/*
 * Etape 3 : Enumeration des services
 */
static void demo_enumerate_services(void) {
    printf("[*] Etape 3 : Enumeration des services XPC\n\n");

    const char *dirs[] = {
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        NULL
    };

    for (int d = 0; dirs[d]; d++) {
        printf("    %s :\n", dirs[d]);
        DIR *dir = opendir(dirs[d]);
        if (!dir) {
            printf("      (impossible d'ouvrir)\n\n");
            continue;
        }

        struct dirent *entry;
        int count = 0;
        while ((entry = readdir(dir)) && count < 8) {
            if (strstr(entry->d_name, ".plist")) {
                printf("      %s\n", entry->d_name);
                count++;
            }
        }
        closedir(dir);
        if (count == 8) printf("      ... (tronque)\n");
        printf("\n");
    }

    /* Lister les services Mach actifs */
    printf("    Services Mach actifs (launchctl) :\n");
    FILE *fp = popen("launchctl list 2>/dev/null | head -15", "r");
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
 * Etape 4 : Structure d'un plist LaunchDaemon
 */
static void explain_plist_structure(void) {
    printf("[*] Etape 4 : Structure d'un plist LaunchDaemon\n\n");

    printf("    <?xml version=\"1.0\"?>\n");
    printf("    <!DOCTYPE plist PUBLIC ...>\n");
    printf("    <plist version=\"1.0\">\n");
    printf("    <dict>\n");
    printf("        <key>Label</key>\n");
    printf("        <string>com.example.service</string>\n\n");
    printf("        <key>Program</key>\n");
    printf("        <string>/usr/local/bin/service</string>\n\n");
    printf("        <key>MachServices</key>\n");
    printf("        <dict>\n");
    printf("            <key>com.example.service.xpc</key>\n");
    printf("            <true/>\n");
    printf("        </dict>\n\n");
    printf("        <key>RunAtLoad</key>\n");
    printf("        <true/>\n\n");
    printf("        <key>KeepAlive</key>\n");
    printf("        <true/>\n");
    printf("    </dict>\n");
    printf("    </plist>\n\n");
}

/*
 * Etape 5 : Surface d'attaque XPC
 */
static void explain_xpc_attacks(void) {
    printf("[*] Etape 5 : Surface d'attaque XPC\n\n");

    printf("    Vulnerabilites courantes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Absence de verification de l'appelant\n");
    printf("       -> Le service ne verifie pas qui envoie le message\n");
    printf("       -> N'importe quel processus peut communiquer\n\n");
    printf("    2. Injection de commandes via XPC\n");
    printf("       -> Envoyer des parametres malveillants\n");
    printf("       -> Le service execute sans valider\n\n");
    printf("    3. Race conditions\n");
    printf("       -> TOCTOU entre la verification et l'action\n\n");
    printf("    4. Privilege escalation\n");
    printf("       -> Service root qui execute des commandes user\n\n");

    printf("    Bonnes pratiques de securite :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Verifier le client (dans le service)\n");
    printf("    audit_token_t token;\n");
    printf("    xpc_connection_get_audit_token(conn, &token);\n");
    printf("    pid_t client_pid = audit_token_to_pid(token);\n");
    printf("    uid_t client_uid = audit_token_to_euid(token);\n\n");
    printf("    // Verifier la signature du client\n");
    printf("    SecCodeRef code;\n");
    printf("    SecCodeCopyGuestWithAttributes(NULL, ...);\n");
    printf("    SecCodeCheckValidity(code, kSecCSDefaultFlags, req);\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Outils d'analyse XPC :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - launchctl list     : services actifs\n");
    printf("    - xpcspy             : intercepter les messages XPC\n");
    printf("    - dtrace             : tracer les appels XPC\n");
    printf("    - Objective-See tools: monitorer les services\n\n");

    printf("    Monitorer les connexions XPC :\n");
    printf("    ───────────────────────────────────\n");
    printf("    sudo dtrace -n 'objc$target::xpc_connection*:entry'\n");
    printf("    // Ou utiliser Endpoint Security Framework\n\n");

    printf("    Protections recommandees :\n");
    printf("    - Toujours verifier l'audit_token du client\n");
    printf("    - Valider la signature du processus appelant\n");
    printf("    - Utiliser des entitlements restrictifs\n");
    printf("    - Minimiser les privileges du service\n");
    printf("    - Sanitizer toutes les entrees XPC\n\n");
}

int main(void) {
    printf("[*] Demo : XPC Services macOS\n\n");

    explain_xpc_architecture();
    explain_xpc_api();
    demo_enumerate_services();
    explain_plist_structure();
    explain_xpc_attacks();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
