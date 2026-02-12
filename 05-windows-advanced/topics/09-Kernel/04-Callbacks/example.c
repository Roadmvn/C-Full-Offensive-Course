/*
 * OBJECTIF  : Comprendre les callbacks kernel (notifications)
 * PREREQUIS : Driver Basics, IOCTL
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les callbacks kernel notifient les drivers des evenements systeme :
 * creation de processus, chargement de DLL, acces aux objets.
 * Les EDR les utilisent massivement pour la detection.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

void demo_callback_types(void) {
    printf("[1] Types de callbacks kernel\n\n");
    printf("    +----------------------------------+--------------------------------+\n");
    printf("    | Callback                         | Usage                          |\n");
    printf("    +----------------------------------+--------------------------------+\n");
    printf("    | PsSetCreateProcessNotifyRoutine  | Notif creation/fin processus   |\n");
    printf("    | PsSetCreateProcessNotifyRoutineEx| + infos (image path, cmdline)  |\n");
    printf("    | PsSetCreateThreadNotifyRoutine   | Notif creation/fin thread      |\n");
    printf("    | PsSetLoadImageNotifyRoutine      | Notif chargement DLL/EXE       |\n");
    printf("    | ObRegisterCallbacks              | Pre/Post operation sur objets  |\n");
    printf("    | CmRegisterCallbackEx             | Operations sur le registre     |\n");
    printf("    | FltRegisterFilter                | Operations sur le filesystem   |\n");
    printf("    +----------------------------------+--------------------------------+\n\n");

    printf("    Les EDR s'enregistrent sur ces callbacks pour :\n");
    printf("    - Bloquer l'injection de processus\n");
    printf("    - Detecter le chargement de DLL suspectes\n");
    printf("    - Empecher l'acces a LSASS\n");
    printf("    - Surveiller les modifications de registre\n\n");
}

void demo_process_notify(void) {
    printf("[2] PsSetCreateProcessNotifyRoutineEx\n\n");
    printf("    Code driver :\n");
    printf("    void ProcessNotifyCallback(\n");
    printf("        PEPROCESS Process,\n");
    printf("        HANDLE ProcessId,\n");
    printf("        PPS_CREATE_NOTIFY_INFO CreateInfo)\n");
    printf("    {\n");
    printf("        if (CreateInfo) {  // Creation\n");
    printf("            // CreateInfo->ImageFileName\n");
    printf("            // CreateInfo->CommandLine\n");
    printf("            // CreateInfo->ParentProcessId\n");
    printf("            if (is_suspicious(CreateInfo))\n");
    printf("                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;\n");
    printf("        } else {  // Terminaison\n");
    printf("            log_process_exit(ProcessId);\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("    PsSetCreateProcessNotifyRoutineEx(\n");
    printf("        ProcessNotifyCallback, FALSE);\n\n");

    printf("    -> L'EDR peut BLOQUER la creation d'un processus!\n\n");
}

void demo_image_load(void) {
    printf("[3] PsSetLoadImageNotifyRoutine\n\n");
    printf("    Notifie quand un PE (EXE/DLL) est mappe en memoire.\n\n");
    printf("    void ImageLoadCallback(\n");
    printf("        PUNICODE_STRING FullImageName,\n");
    printf("        HANDLE ProcessId,\n");
    printf("        PIMAGE_INFO ImageInfo)\n");
    printf("    {\n");
    printf("        // ImageInfo->ImageBase\n");
    printf("        // ImageInfo->ImageSize\n");
    printf("        // ImageInfo->SystemModeImage (kernel driver?)\n");
    printf("    }\n\n");

    printf("    Utilise par les EDR pour :\n");
    printf("    - Detecter le reflective DLL loading\n");
    printf("    - Hooker ntdll.dll apres chargement\n");
    printf("    - Verifier l'integrite des DLL\n\n");

    /* Lister les modules du processus courant */
    printf("    Modules charges dans ce processus :\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me = { .dwSize = sizeof(me) };
        int count = 0;
        if (Module32First(snap, &me)) {
            do {
                printf("    [%02d] %p %s\n",
                       count, me.modBaseAddr, me.szModule);
                count++;
            } while (Module32Next(snap, &me) && count < 10);
        }
        CloseHandle(snap);
        printf("    ... (premiers %d modules)\n\n", count);
    }
}

void demo_ob_callbacks(void) {
    printf("[4] ObRegisterCallbacks\n\n");
    printf("    Intercepte les operations sur les objets kernel :\n");
    printf("    - OpenProcess / OpenThread\n");
    printf("    - DuplicateHandle\n\n");

    printf("    OB_CALLBACK_REGISTRATION reg = {\n");
    printf("        .OperationRegistration = {\n");
    printf("            .ObjectType = PsProcessType,\n");
    printf("            .Operations = OB_OPERATION_HANDLE_CREATE,\n");
    printf("            .PreOperation = PreOpenProcessCallback\n");
    printf("        }\n");
    printf("    };\n");
    printf("    ObRegisterCallbacks(&reg, &handle);\n\n");

    printf("    Dans PreOpenProcessCallback :\n");
    printf("    - Verifier si la cible est un processus protege\n");
    printf("    - Retirer les droits dangereux du handle\n");
    printf("    - Exemple : retirer PROCESS_VM_READ de LSASS\n\n");

    /* Tenter d'ouvrir lsass pour montrer la protection */
    printf("    Demo : tentative d'acces a un processus protege\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE,
                                           pe.th32ProcessID);
                    printf("    lsass.exe PID %lu : %s\n",
                           pe.th32ProcessID,
                           h ? "ACCES OK" : "ACCES REFUSE");
                    if (h) CloseHandle(h);
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    printf("\n");
}

void demo_evasion(void) {
    printf("[5] Evasion des callbacks\n\n");
    printf("    Techniques pour contourner les callbacks EDR :\n\n");
    printf("    a) Enumerer et supprimer les callbacks :\n");
    printf("       - Lire PspNotifyEnableMask\n");
    printf("       - Parcourir le tableau de callbacks\n");
    printf("       - Patch: remplacer le pointeur par NULL\n\n");
    printf("    b) Direct syscalls :\n");
    printf("       - Bypass le hook usermode de l'EDR\n");
    printf("       - Mais les callbacks kernel restent actifs!\n\n");
    printf("    c) Kernel callback removal (driver/BYOVD) :\n");
    printf("       - Charger un driver pour supprimer les callbacks\n");
    printf("       - Utiliser un driver vulnerable pour le faire\n\n");
    printf("    d) Unhooking ntdll :\n");
    printf("       - Recharger ntdll depuis le disque\n");
    printf("       - Restaurer les bytes originaux\n");
    printf("       - N'affecte PAS les callbacks kernel\n\n");
}

int main(void) {
    printf("[*] Demo : Kernel Callbacks\n");
    printf("[*] ==========================================\n\n");
    demo_callback_types();
    demo_process_notify();
    demo_image_load();
    demo_ob_callbacks();
    demo_evasion();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
