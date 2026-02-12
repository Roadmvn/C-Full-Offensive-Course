/*
 * OBJECTIF  : Comprendre les services Windows (creation, enumeration, manipulation)
 * PREREQUIS : Bases du C, API Windows, notions de privileges
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib
 *
 * Les services Windows tournent en arriere-plan avec des privileges eleves.
 * Ils sont utilises pour la persistence et l'execution de code privilegiee.
 * Ce programme montre comment enumerer, interroger et comprendre les services.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/* Decoder le type de service */
const char* service_type_name(DWORD type) {
    if (type & SERVICE_KERNEL_DRIVER) return "Kernel Driver";
    if (type & SERVICE_FILE_SYSTEM_DRIVER) return "FS Driver";
    if (type & SERVICE_WIN32_OWN_PROCESS) return "Own Process";
    if (type & SERVICE_WIN32_SHARE_PROCESS) return "Shared Process";
    return "Other";
}

/* Decoder le type de demarrage */
const char* start_type_name(DWORD start) {
    switch (start) {
        case SERVICE_BOOT_START:   return "Boot";
        case SERVICE_SYSTEM_START: return "System";
        case SERVICE_AUTO_START:   return "Auto";
        case SERVICE_DEMAND_START: return "Manual";
        case SERVICE_DISABLED:     return "Disabled";
        default: return "?";
    }
}

/* Demo 1 : Enumerer les services en cours d'execution */
void demo_enumerate_services(void) {
    printf("[1] Enumeration des services actifs\n\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        printf("    [-] OpenSCManager echoue (err %lu)\n", GetLastError());
        return;
    }

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusA(scm, SERVICE_WIN32, SERVICE_ACTIVE,
                         NULL, 0, &needed, &count, &resume);

    ENUM_SERVICE_STATUSA* services = (ENUM_SERVICE_STATUSA*)malloc(needed);
    if (EnumServicesStatusA(scm, SERVICE_WIN32, SERVICE_ACTIVE,
                             services, needed, &needed, &count, &resume)) {
        printf("    %-30s  %-8s  %s\n", "Service", "PID", "Display Name");
        printf("    %-30s  %-8s  %s\n", "------------------------------", "--------", "------------");

        int display = count > 20 ? 20 : count;
        for (DWORD i = 0; i < (DWORD)display; i++) {
            printf("    %-30s  %-8lu  %s\n",
                   services[i].lpServiceName,
                   services[i].ServiceStatus.dwProcessId,
                   services[i].lpDisplayName);
        }
        if (count > 20)
            printf("    ... (%lu de plus)\n", count - 20);
        printf("\n    [+] Total services actifs : %lu\n", count);
    }

    free(services);
    CloseServiceHandle(scm);
    printf("\n");
}

/* Demo 2 : Interroger un service specifique */
void demo_query_service(const char* name) {
    printf("[2] Interrogation du service : %s\n\n", name);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);

    if (!svc) {
        printf("    [-] OpenService echoue (err %lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    /* Status */
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        const char* state;
        switch (ssp.dwCurrentState) {
            case SERVICE_RUNNING: state = "RUNNING"; break;
            case SERVICE_STOPPED: state = "STOPPED"; break;
            default: state = "OTHER"; break;
        }
        printf("    Etat    : %s\n", state);
        printf("    PID     : %lu\n", ssp.dwProcessId);
        printf("    Type    : %s\n", service_type_name(ssp.dwServiceType));
    }

    /* Configuration */
    QueryServiceConfigA(svc, NULL, 0, &needed);
    QUERY_SERVICE_CONFIGA* config = (QUERY_SERVICE_CONFIGA*)malloc(needed);
    if (QueryServiceConfigA(svc, config, needed, &needed)) {
        printf("    Start   : %s\n", start_type_name(config->dwStartType));
        printf("    Binary  : %s\n", config->lpBinaryPathName);
        printf("    Account : %s\n", config->lpServiceStartName);
    }
    free(config);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    printf("\n");
}

/* Demo 3 : Rechercher des services interessants pour le red teaming */
void demo_interesting_services(void) {
    printf("[3] Services interessants pour le red teaming\n\n");

    const char* interesting[] = {
        "Spooler",      /* Print Spooler - vecteur d'attaque PrintNightmare */
        "RemoteRegistry",/* Remote Registry - acces a distance */
        "WinRM",        /* Windows Remote Management */
        "BITS",         /* Background Intelligent Transfer Service */
        "Schedule",     /* Task Scheduler */
        "TermService",  /* Remote Desktop Services */
        "LanmanServer", /* SMB Server */
    };

    const char* why[] = {
        "PrintNightmare, privilege escalation",
        "Modification registre a distance",
        "Execution de commandes a distance (PSRemoting)",
        "Telechargement furtif de fichiers",
        "Persistence via taches planifiees",
        "Lateral movement via RDP",
        "Lateral movement via SMB",
    };

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;

    for (int i = 0; i < 7; i++) {
        SC_HANDLE svc = OpenServiceA(scm, interesting[i], SERVICE_QUERY_STATUS);
        const char* state = "[N/A]";
        if (svc) {
            SERVICE_STATUS ss;
            QueryServiceStatus(svc, &ss);
            state = ss.dwCurrentState == SERVICE_RUNNING ? "[RUNNING]" : "[STOPPED]";
            CloseServiceHandle(svc);
        }
        printf("    %-18s  %-10s  %s\n", interesting[i], state, why[i]);
    }

    CloseServiceHandle(scm);
    printf("\n");
}

/* Demo 4 : Concept de persistence via service */
void demo_persistence_concept(void) {
    printf("[4] Concept : Persistence via service\n\n");

    printf("    Un attaquant peut creer un service pour la persistence :\n\n");
    printf("    SC_HANDLE svc = CreateService(\n");
    printf("        scm,\n");
    printf("        \"UpdateService\",           // Nom discret\n");
    printf("        \"Windows Update Helper\",    // Display name innocent\n");
    printf("        SERVICE_ALL_ACCESS,\n");
    printf("        SERVICE_WIN32_OWN_PROCESS,\n");
    printf("        SERVICE_AUTO_START,          // Demarrage auto\n");
    printf("        SERVICE_ERROR_IGNORE,\n");
    printf("        \"C:\\\\temp\\\\payload.exe\",     // Chemin du malware\n");
    printf("        NULL, NULL, NULL,\n");
    printf("        \"LocalSystem\",              // Compte SYSTEM\n");
    printf("        NULL);\n\n");
    printf("    [!] Necessite des droits administrateur\n");
    printf("    [!] Detection : Sysmon Event ID 6/7, registre SERVICES\n\n");
}

int main(void) {
    printf("[*] Demo : Services Windows\n");
    printf("[*] ==========================================\n\n");

    demo_enumerate_services();
    demo_query_service("Spooler");
    demo_interesting_services();
    demo_persistence_concept();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
