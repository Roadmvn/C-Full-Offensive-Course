/*
 * OBJECTIF  : Comprendre l'architecture interne de Windows Defender
 * PREREQUIS : Modules precedents (PE, PEB, ETW)
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib ole32.lib
 *
 * Ce programme explore les composants de Windows Defender :
 * - Etat du service MsMpEng
 * - Interface AMSI (Antimalware Scan Interface)
 * - Detection des composants Defender actifs
 * Comprendre le fonctionnement de Defender est essentiel pour l'evasion.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/* Verifier l'etat du service Windows Defender */
void check_defender_service(void) {
    printf("[1] Etat du service Windows Defender\n\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        printf("    [-] OpenSCManager echoue (err %lu)\n", GetLastError());
        return;
    }

    const char* services[] = {
        "WinDefend",     /* Service principal Defender */
        "WdNisSvc",      /* Network Inspection Service */
        "Sense",         /* Windows Defender ATP */
        "WdFilter",      /* Minifilter driver */
        "WdBoot"         /* Boot driver */
    };

    const char* descriptions[] = {
        "Windows Defender Antivirus Service",
        "Network Inspection Service",
        "Windows Defender ATP (EDR)",
        "Defender Minifilter Driver",
        "Defender Early Launch Driver"
    };

    for (int i = 0; i < 5; i++) {
        SC_HANDLE svc = OpenServiceA(scm, services[i], SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS status;
            QueryServiceStatus(svc, &status);

            const char* state;
            switch (status.dwCurrentState) {
                case SERVICE_RUNNING: state = "[RUNNING]"; break;
                case SERVICE_STOPPED: state = "[STOPPED]"; break;
                case SERVICE_START_PENDING: state = "[STARTING]"; break;
                case SERVICE_STOP_PENDING: state = "[STOPPING]"; break;
                default: state = "[UNKNOWN]"; break;
            }
            printf("    %-12s  %-10s  %s\n", services[i], state, descriptions[i]);
            CloseServiceHandle(svc);
        } else {
            printf("    %-12s  [N/A]       %s\n", services[i], descriptions[i]);
        }
    }

    CloseServiceHandle(scm);
    printf("\n");
}

/* Verifier si AMSI est disponible */
void check_amsi(void) {
    printf("[2] AMSI (Antimalware Scan Interface)\n\n");

    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (amsi) {
        printf("    [+] amsi.dll chargee a : %p\n", amsi);

        /* Lister les fonctions AMSI exportees */
        const char* amsi_funcs[] = {
            "AmsiInitialize", "AmsiOpenSession", "AmsiScanBuffer",
            "AmsiScanString", "AmsiCloseSession", "AmsiUninitialize"
        };
        for (int i = 0; i < 6; i++) {
            FARPROC func = GetProcAddress(amsi, amsi_funcs[i]);
            printf("    %-25s : %p\n", amsi_funcs[i], func);
        }

        /* Montrer les premiers octets de AmsiScanBuffer */
        BYTE* scan = (BYTE*)GetProcAddress(amsi, "AmsiScanBuffer");
        if (scan) {
            printf("\n    AmsiScanBuffer premiers octets : ");
            for (int i = 0; i < 12; i++)
                printf("%02X ", scan[i]);
            printf("\n");
            printf("    [!] Un bypass AMSI patcherait ces octets avec un RET (0xC3)\n");
        }

        FreeLibrary(amsi);
    } else {
        printf("    [-] amsi.dll non disponible\n");
    }
    printf("\n");
}

/* Verifier les processus Defender actifs */
void check_defender_processes(void) {
    printf("[3] Processus Defender actifs\n\n");

    const char* defender_procs[] = {
        "MsMpEng.exe",          /* Moteur antimalware principal */
        "MpCmdRun.exe",         /* Outil ligne de commande */
        "NisSrv.exe",           /* Network Inspection */
        "SecurityHealthService.exe", /* Health monitoring */
        "SenseIR.exe",          /* ATP Incident Response */
        "MsSense.exe"           /* ATP Sensor */
    };

    /* Enumerer les processus avec CreateToolhelp32Snapshot */
    HANDLE snap = CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("    [-] CreateToolhelp32Snapshot echoue\n");
        return;
    }

    /* PROCESSENTRY32 simplifie */
    typedef struct {
        DWORD dwSize;
        DWORD cntUsage;
        DWORD th32ProcessID;
        ULONG_PTR th32DefaultHeapID;
        DWORD th32ModuleID;
        DWORD cntThreads;
        DWORD th32ParentProcessID;
        LONG  pcPriClassBase;
        DWORD dwFlags;
        char  szExeFile[260];
    } PE32;

    PE32 pe;
    pe.dwSize = sizeof(PE32);

    typedef BOOL (WINAPI *pProcess32First)(HANDLE, PE32*);
    typedef BOOL (WINAPI *pProcess32Next)(HANDLE, PE32*);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    pProcess32First p32f = (pProcess32First)GetProcAddress(k32, "Process32First");
    pProcess32Next p32n = (pProcess32Next)GetProcAddress(k32, "Process32Next");

    if (p32f(snap, &pe)) {
        do {
            for (int i = 0; i < 6; i++) {
                if (_stricmp(pe.szExeFile, defender_procs[i]) == 0) {
                    printf("    [!] %-30s  PID: %lu\n", pe.szExeFile, pe.th32ProcessID);
                }
            }
        } while (p32n(snap, &pe));
    }

    CloseHandle(snap);
    printf("\n");
}

/* Verifier les exclusions Defender via le registre */
void check_defender_config(void) {
    printf("[4] Configuration Defender (registre)\n\n");

    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
        0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD value, size = sizeof(DWORD);

        if (RegQueryValueExA(hKey, "DisableRealtimeMonitoring", NULL, NULL,
                              (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            printf("    DisableRealtimeMonitoring : %lu %s\n",
                   value, value ? "[DESACTIVE!]" : "[ACTIF]");
        }

        if (RegQueryValueExA(hKey, "DisableBehaviorMonitoring", NULL, NULL,
                              (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            printf("    DisableBehaviorMonitoring : %lu\n", value);
        }

        if (RegQueryValueExA(hKey, "DisableIOAVProtection", NULL, NULL,
                              (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            printf("    DisableIOAVProtection     : %lu\n", value);
        }

        RegCloseKey(hKey);
    } else {
        printf("    [-] Impossible de lire la config (err %ld)\n", result);
        printf("    [*] Necessite des droits administrateur\n");
    }

    /* Verifier les exclusions de chemin */
    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD count = 0;
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &count,
                          NULL, NULL, NULL, NULL);
        printf("    Exclusions de chemin   : %lu\n", count);
        if (count > 0)
            printf("    [!] Des exclusions existent - potentiel vecteur d'evasion\n");
        RegCloseKey(hKey);
    }
    printf("\n");
}

/* Resume de l'architecture Defender */
void print_architecture(void) {
    printf("[5] Architecture de Windows Defender\n\n");
    printf("    User-mode :\n");
    printf("      MsMpEng.exe     -> Moteur antimalware (scans, heuristiques)\n");
    printf("      amsi.dll        -> Interface de scan pour scripts (PS, JS, VBS)\n");
    printf("      MpClient.dll    -> Client pour les scans on-demand\n");
    printf("      MpSvc.dll       -> Service principal\n\n");
    printf("    Kernel-mode :\n");
    printf("      WdFilter.sys    -> Minifilter driver (surveillance fichiers)\n");
    printf("      WdBoot.sys      -> Early Launch AM Driver (boot protection)\n");
    printf("      WdNisDrv.sys    -> Network Inspection driver\n\n");
    printf("    Detection :\n");
    printf("      ETW consumers   -> Evenements process/file/network\n");
    printf("      Kernel callbacks -> PsSetCreateProcessNotifyRoutine\n");
    printf("      Userland hooks  -> ntdll.dll inline hooks\n");
    printf("      AMSI providers  -> Scan de contenu dynamique\n\n");
}

int main(void) {
    printf("[*] Demo : Windows Defender Internals\n");
    printf("[*] ==========================================\n\n");

    print_architecture();
    check_defender_service();
    check_amsi();
    check_defender_processes();
    check_defender_config();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
