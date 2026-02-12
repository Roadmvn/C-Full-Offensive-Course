/*
 * OBJECTIF  : Comprendre et contourner les callbacks kernel des EDR
 * PREREQUIS : NTAPI, drivers kernel (concepts), Process Injection
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les EDR registrent des callbacks kernel pour surveiller le systeme :
 * - PsSetCreateProcessNotifyRoutine  : creation de processus
 * - PsSetCreateThreadNotifyRoutine   : creation de threads
 * - PsSetLoadImageNotifyRoutine      : chargement de DLL/images
 * - ObRegisterCallbacks              : acces aux objets (OpenProcess, etc.)
 * - CmRegisterCallbackEx             : modifications du registre
 *
 * Ces callbacks sont stockes dans des tableaux kernel que l'on peut
 * enumerer et potentiellement desactiver depuis usermode (avec des limitations)
 * ou depuis un driver vulnerable.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* Helper pour trouver un PID */
DWORD find_pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* Demo 1 : Enumerer les drivers EDR charges */
void demo_enumerate_edr_drivers(void) {
    printf("[1] Enumeration des drivers EDR potentiels\n\n");

    /* Liste des drivers EDR connus */
    typedef struct {
        const char* driver_name;
        const char* vendor;
    } EDR_DRIVER;

    EDR_DRIVER known_edrs[] = {
        {"CrowdStrike\\csagent.sys",      "CrowdStrike Falcon"},
        {"SentinelOne\\SentinelMonitor",   "SentinelOne"},
        {"WdFilter.sys",                   "Windows Defender"},
        {"MsMpEng.exe",                    "Windows Defender Engine"},
        {"CylanceSvc.exe",                "Cylance"},
        {"cb.exe",                         "Carbon Black"},
        {"CbDefense",                      "Carbon Black Defense"},
        {"Tanium",                         "Tanium"},
        {"YOURVENDORHERE",                 "Example Placeholder"},
        {NULL, NULL}
    };

    printf("    [*] Verification des processus EDR en cours d'execution :\n\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    int edr_count = 0;

    /* Processus typiques des EDR */
    const char* edr_processes[] = {
        "MsMpEng.exe", "MsSense.exe", "SenseIR.exe",
        "csfalconservice.exe", "csfalconcontainer.exe",
        "SentinelAgent.exe", "SentinelServiceHost.exe",
        "CylanceSvc.exe", "CylanceUI.exe",
        "cb.exe", "RepMgr.exe",
        "Tanium", "TaniumClient.exe",
        "bdagent.exe", "vsserv.exe",
        "savservice.exe", "SophosFS.exe",
        NULL
    };

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; edr_processes[i]; i++) {
                if (_stricmp(pe.szExeFile, edr_processes[i]) == 0) {
                    printf("    [!] EDR detecte : %s (PID %lu)\n",
                           pe.szExeFile, pe.th32ProcessID);
                    edr_count++;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (edr_count == 0)
        printf("    [+] Aucun processus EDR connu detecte\n");
    printf("\n    Total : %d processus EDR\n\n", edr_count);
}

/* Demo 2 : Expliquer les callbacks kernel */
void demo_explain_callbacks(void) {
    printf("[2] Types de callbacks kernel EDR\n\n");

    printf("    +---------------------------------------+---------------------------+\n");
    printf("    | Callback                              | Evenement surveille       |\n");
    printf("    +---------------------------------------+---------------------------+\n");
    printf("    | PsSetCreateProcessNotifyRoutine       | Creation de processus     |\n");
    printf("    | PsSetCreateProcessNotifyRoutineEx     | +info etendue (kill)      |\n");
    printf("    | PsSetCreateThreadNotifyRoutine        | Creation de threads       |\n");
    printf("    | PsSetLoadImageNotifyRoutine           | Chargement DLL/driver     |\n");
    printf("    | ObRegisterCallbacks                   | OpenProcess/OpenThread    |\n");
    printf("    | CmRegisterCallbackEx                  | Modifications registre    |\n");
    printf("    | MiniFilter (FltRegisterFilter)        | Operations fichiers       |\n");
    printf("    +---------------------------------------+---------------------------+\n\n");

    printf("    Comment fonctionne un callback kernel :\n");
    printf("    1. Le driver EDR appelle PsSetCreateProcessNotifyRoutineEx(MyCallback, FALSE)\n");
    printf("    2. Le kernel ajoute MyCallback dans le tableau PspCreateProcessNotifyRoutine\n");
    printf("    3. A chaque CreateProcess, le kernel appelle tous les callbacks enregistres\n");
    printf("    4. Le callback EDR inspecte le processus et peut le bloquer\n\n");

    printf("    Structure en memoire :\n");
    printf("    PspCreateProcessNotifyRoutine[64] = {\n");
    printf("        [0] = EDR_callback_1,\n");
    printf("        [1] = EDR_callback_2,\n");
    printf("        [2] = Sysmon_callback,\n");
    printf("        ...\n");
    printf("    }\n\n");
}

/* Demo 3 : Technique d'evasion usermode - Desactiver les callbacks indirectement */
void demo_usermode_evasion(void) {
    printf("[3] Evasion usermode des callbacks\n\n");

    printf("    Depuis le usermode, on ne peut pas directement modifier les\n");
    printf("    callbacks kernel. Mais on peut :\n\n");

    printf("    A) Exploiter un driver vulnerable (BYOVD) :\n");
    printf("       1. Charger un driver signe mais vulnerable (ex: RTCore64.sys)\n");
    printf("       2. Utiliser ses IOCTLs pour lire/ecrire la memoire kernel\n");
    printf("       3. Trouver le tableau PspCreateProcessNotifyRoutine\n");
    printf("       4. Patcher les entries pour pointer vers un RET (desactiver)\n\n");

    printf("    B) Utiliser un driver custom signe :\n");
    printf("       1. Obtenir un certificat EV pour signer un driver\n");
    printf("       2. Le driver appelle PsSetCreateProcessNotifyRoutineEx(callback, TRUE)\n");
    printf("       3. Le TRUE desinscrit le callback\n\n");

    printf("    C) Detourner le service EDR :\n");
    printf("       1. Arreter le service EDR (necessite admin/SYSTEM)\n");
    printf("       2. Le driver ne recoit plus d'instructions\n");
    printf("       3. Les callbacks restent mais ne transmettent plus\n\n");

    /* Demo : tester si on peut arreter un service EDR */
    printf("    [Demo] Verification de l'etat du service Defender :\n");
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, "WinDefend", SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(svc, &status)) {
                const char* state = "INCONNU";
                switch (status.dwCurrentState) {
                    case SERVICE_RUNNING: state = "RUNNING"; break;
                    case SERVICE_STOPPED: state = "STOPPED"; break;
                    case SERVICE_PAUSED:  state = "PAUSED"; break;
                }
                printf("    [+] WinDefend : %s\n", state);
                printf("    [*] Arreter ce service desactiverait certains callbacks\n");
            }
            CloseServiceHandle(svc);
        } else {
            printf("    [-] WinDefend non accessible (err %lu)\n", GetLastError());
        }
        CloseServiceHandle(scm);
    }
    printf("\n");
}

/* Demo 4 : ObRegisterCallbacks et protection des handles */
void demo_ob_callbacks(void) {
    printf("[4] ObRegisterCallbacks - Protection des handles\n\n");

    printf("    ObRegisterCallbacks permet aux EDR de :\n");
    printf("    - Filtrer les appels OpenProcess/OpenThread\n");
    printf("    - Retirer des droits d'acces (ex: PROCESS_VM_WRITE)\n");
    printf("    - Bloquer l'acces a des processus proteges (lsass, EDR)\n\n");

    /* Demo : essayer d'ouvrir lsass */
    DWORD lsass_pid = find_pid("lsass.exe");
    if (lsass_pid) {
        printf("    [+] lsass.exe PID : %lu\n", lsass_pid);

        /* Essayer avec PROCESS_ALL_ACCESS */
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
        if (hProc) {
            printf("    [+] OpenProcess(PROCESS_ALL_ACCESS) : SUCCES (%p)\n", hProc);
            printf("    [!] Pas de protection ObRegisterCallbacks active\n");
            CloseHandle(hProc);
        } else {
            printf("    [-] OpenProcess(PROCESS_ALL_ACCESS) : ECHOUE (err %lu)\n", GetLastError());
            printf("    [+] Protection active! L'EDR a filtre l'acces\n");
        }

        /* Essayer avec des droits reduits */
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsass_pid);
        if (hProc) {
            printf("    [+] OpenProcess(QUERY_LIMITED) : SUCCES\n");
            printf("    [*] Les droits limites sont generalement autorises\n");
            CloseHandle(hProc);
        }
    }
    printf("\n");
}

/* Demo 5 : Minifilter et evasion fichier */
void demo_minifilter_evasion(void) {
    printf("[5] MiniFilter callbacks et evasion fichier\n\n");

    printf("    Les EDR utilisent des MiniFilters pour surveiller les fichiers :\n");
    printf("    - IRP_MJ_CREATE  : ouverture de fichier\n");
    printf("    - IRP_MJ_WRITE   : ecriture dans un fichier\n");
    printf("    - IRP_MJ_READ    : lecture d'un fichier\n\n");

    printf("    Techniques d'evasion :\n");
    printf("    1. Direct I/O : NtCreateFile -> NtWriteFile (bypass MiniFilter)\n");
    printf("    2. Memory-mapped files : pas de IRP_MJ_WRITE\n");
    printf("    3. NTFS transactions (TxF) : ecriture invisible\n");
    printf("    4. ADS (Alternate Data Streams) : certains MiniFilters les ignorent\n\n");

    /* Demo : lister les minifilters charges */
    printf("    [*] Pour lister les MiniFilters : fltmc.exe (admin requis)\n");
    printf("    [*] Commande : fltmc instances\n\n");
}

/* Demo 6 : BYOVD (Bring Your Own Vulnerable Driver) */
void demo_byovd_concept(void) {
    printf("[6] BYOVD - Bring Your Own Vulnerable Driver\n\n");

    printf("    Concept : charger un driver signe mais vulnerable pour obtenir\n");
    printf("    un acces kernel et desactiver les callbacks EDR.\n\n");

    printf("    Drivers vulnerables connus :\n");
    printf("    - RTCore64.sys  (MSI Afterburner)  -> R/W memoire kernel\n");
    printf("    - dbutil_2_3.sys (Dell)            -> R/W memoire kernel\n");
    printf("    - gdrv.sys      (Gigabyte)         -> R/W ports I/O + memoire\n");
    printf("    - HW.sys        (PassMark)         -> R/W memoire kernel\n\n");

    printf("    Etapes :\n");
    printf("    1. Charger le driver vulnerable (sc create + sc start)\n");
    printf("    2. Ouvrir un handle : CreateFile(\"\\\\\\\\.\\\\RTCore64\")\n");
    printf("    3. Lire la memoire kernel pour trouver le callback array\n");
    printf("    4. Ecrire pour patcher/supprimer les callbacks EDR\n");
    printf("    5. Effectuer l'action malveillante sans surveillance\n");
    printf("    6. (Optionnel) Restaurer les callbacks\n\n");

    printf("    Detection :\n");
    printf("    - WDAC/HVCI bloque les drivers vulnerables connus\n");
    printf("    - La liste LOLDrivers (loldrivers.io) reference les drivers\n");
    printf("    - Sysmon Event ID 6 : chargement de driver\n");
    printf("    - ETW : PsSetLoadImageNotifyRoutine callback\n\n");
}

int main(void) {
    printf("[*] Demo : Callback Evasion - Contourner les callbacks EDR\n");
    printf("[*] ==========================================\n\n");

    demo_enumerate_edr_drivers();
    demo_explain_callbacks();
    demo_usermode_evasion();
    demo_ob_callbacks();
    demo_minifilter_evasion();
    demo_byovd_concept();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
