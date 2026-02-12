/*
 * OBJECTIF  : Mecanismes de persistance pour un agent C2
 * PREREQUIS : Registry, Services, Scheduled Tasks
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib ole32.lib
 *
 * La persistance permet a l'agent de survivre aux redemarrages.
 * Plusieurs techniques : registry Run keys, scheduled tasks,
 * services Windows, DLL hijacking, COM hijacking.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

void demo_registry_run(void) {
    printf("[1] Persistance via Registry Run Key\n\n");

    /* Lire les cles Run existantes (sans modifier) */
    HKEY hKey;
    LONG ret = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ, &hKey);

    if (ret == ERROR_SUCCESS) {
        printf("    [+] Cle HKCU\\...\\Run ouverte\n");
        printf("    Entrees existantes :\n");

        char name[256], value[512];
        DWORD nameLen, valueLen, type;
        DWORD i = 0;

        while (1) {
            nameLen = sizeof(name);
            valueLen = sizeof(value);
            ret = RegEnumValueA(hKey, i, name, &nameLen,
                               NULL, &type, (BYTE*)value, &valueLen);
            if (ret != ERROR_SUCCESS) break;
            if (type == REG_SZ)
                printf("    [%lu] %s = %s\n", i, name, value);
            i++;
        }
        if (i == 0)
            printf("    (aucune entree)\n");
        RegCloseKey(hKey);
    }

    printf("\n    Technique d'ajout :\n");
    printf("    RegSetValueExA(HKCU\\...\\Run, \"UpdateSvc\",\n");
    printf("                   REG_SZ, \"C:\\\\Users\\\\...\\\\agent.exe\");\n\n");
    printf("    Variantes de cles :\n");
    printf("    - HKCU\\...\\Run          (user, pas admin)\n");
    printf("    - HKCU\\...\\RunOnce      (execute une seule fois)\n");
    printf("    - HKLM\\...\\Run          (tous users, admin requis)\n");
    printf("    - HKCU\\...\\Explorer\\Shell Folders (startup folder)\n\n");
}

void demo_scheduled_task(void) {
    printf("[2] Persistance via Scheduled Task\n\n");
    printf("    Commande schtasks (conceptuel) :\n\n");
    printf("    schtasks /Create /TN \"WindowsUpdate\"\n");
    printf("        /TR \"C:\\\\Users\\\\...\\\\agent.exe\"\n");
    printf("        /SC ONLOGON\n");
    printf("        /RL HIGHEST\n\n");

    printf("    Declencheurs possibles :\n");
    printf("    ONLOGON   : a chaque connexion\n");
    printf("    ONIDLE    : quand le PC est inactif\n");
    printf("    MINUTE    : toutes les N minutes\n");
    printf("    ONEVENT   : sur un evenement Windows\n\n");

    /* Lister les taches existantes (via COM serait mieux,
       ici on montre le concept) */
    printf("    API COM (ITaskService) :\n");
    printf("    CoCreateInstance(CLSID_TaskScheduler, ...)\n");
    printf("    pService->GetFolder(L\"\\\\\")\n");
    printf("    pFolder->RegisterTaskDefinition(...)\n\n");

    printf("    Detection : Sysmon Event ID 1 (Process Create)\n");
    printf("    + Event ID 4698 (Task Created)\n\n");
}

void demo_service(void) {
    printf("[3] Persistance via Service Windows\n\n");
    printf("    Necessite les privileges administrateur.\n\n");

    /* Enumerer les services (lecture seule) */
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM) {
        printf("    [+] SCM ouvert en lecture\n");

        ENUM_SERVICE_STATUS_PROCESSA* svc = NULL;
        DWORD needed = 0, count = 0, resume = 0;

        EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_ACTIVE,
            NULL, 0, &needed, &count, &resume, NULL);

        svc = (ENUM_SERVICE_STATUS_PROCESSA*)malloc(needed);
        if (svc) {
            if (EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32, SERVICE_ACTIVE,
                    (BYTE*)svc, needed, &needed, &count, &resume, NULL)) {
                printf("    Services actifs (premiers 5) :\n");
                DWORD i;
                for (i = 0; i < count && i < 5; i++) {
                    printf("    [%lu] %s (PID %lu)\n", i,
                           svc[i].lpServiceName,
                           svc[i].ServiceStatusProcess.dwProcessId);
                }
                printf("    ... (%lu services actifs total)\n", count);
            }
            free(svc);
        }
        CloseServiceHandle(hSCM);
    }

    printf("\n    Creation de service (conceptuel) :\n");
    printf("    CreateServiceA(hSCM, \"WindowsUpdateSvc\",\n");
    printf("        \"Windows Update Service\",\n");
    printf("        SERVICE_ALL_ACCESS,\n");
    printf("        SERVICE_WIN32_OWN_PROCESS,\n");
    printf("        SERVICE_AUTO_START,     <- Demarrage auto\n");
    printf("        SERVICE_ERROR_NORMAL,\n");
    printf("        \"C:\\\\...\\\\agent.exe\");\n\n");
}

void demo_other_techniques(void) {
    printf("[4] Autres techniques de persistance\n\n");

    printf("    a) Startup Folder :\n");
    printf("       C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\\n");
    printf("           Windows\\Start Menu\\Programs\\Startup\\\n");
    printf("       -> Copier un .lnk ou .exe\n\n");

    printf("    b) DLL Hijacking :\n");
    printf("       -> Placer une DLL malveillante dans le repertoire\n");
    printf("          d'un programme qui charge une DLL absente\n");
    printf("       -> L'application legitime charge notre DLL\n\n");

    printf("    c) COM Hijacking :\n");
    printf("       -> Modifier HKCU\\CLSID\\{...}\\InprocServer32\n");
    printf("       -> Pointer vers notre DLL\n");
    printf("       -> Charge quand une app utilise ce CLSID\n\n");

    printf("    d) WMI Event Subscription :\n");
    printf("       -> EventFilter + EventConsumer + Binding\n");
    printf("       -> Persistence sans fichier visible\n\n");

    printf("    Detection :\n");
    printf("    - Autoruns (Sysinternals)\n");
    printf("    - Sysmon Event ID 12/13 (Registry)\n");
    printf("    - Event ID 4697 (Service Install)\n");
    printf("    - Event ID 4698 (Task Created)\n\n");
}

int main(void) {
    printf("[*] Demo : Persistence Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_registry_run();
    demo_scheduled_task();
    demo_service();
    demo_other_techniques();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
