/*
 * OBJECTIF  : Direct Kernel Object Manipulation (DKOM)
 * PREREQUIS : Kernel Memory, EPROCESS, Linked Lists
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * DKOM manipule directement les structures kernel pour cacher
 * des processus, drivers ou connections reseau. Necessite un
 * acces kernel (driver ou BYOVD).
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

void demo_eprocess(void) {
    printf("[1] Structure EPROCESS\n\n");
    printf("    Chaque processus a une structure EPROCESS en kernel.\n");
    printf("    Tous les EPROCESS sont relies par une liste doublement chainee.\n\n");

    printf("    EPROCESS (offsets Windows 10 21H2 x64) :\n");
    printf("    +0x000 : Pcb (KPROCESS)\n");
    printf("    +0x440 : UniqueProcessId\n");
    printf("    +0x448 : ActiveProcessLinks (LIST_ENTRY)\n");
    printf("    +0x5A8 : ImageFileName[15]\n");
    printf("    +0x4B8 : Token\n\n");

    printf("    LIST_ENTRY :\n");
    printf("    struct LIST_ENTRY {\n");
    printf("        LIST_ENTRY* Flink;  // suivant\n");
    printf("        LIST_ENTRY* Blink;  // precedent\n");
    printf("    };\n\n");

    printf("    Les offsets varient selon la version de Windows!\n");
    printf("    -> Utiliser des heuristiques ou des symboles PDB\n\n");
}

void demo_process_hiding(void) {
    printf("[2] Technique : Process Hiding\n\n");
    printf("    La liste des processus visibles par Task Manager\n");
    printf("    et les APIs (EnumProcesses, Toolhelp) vient de la\n");
    printf("    liste chainee ActiveProcessLinks dans EPROCESS.\n\n");

    printf("    Pour cacher un processus :\n");
    printf("    PLIST_ENTRY current = &eprocess->ActiveProcessLinks;\n");
    printf("    PLIST_ENTRY prev = current->Blink;\n");
    printf("    PLIST_ENTRY next = current->Flink;\n\n");
    printf("    // Retirer de la liste\n");
    printf("    prev->Flink = next;\n");
    printf("    next->Blink = prev;\n\n");
    printf("    // Pointer vers soi-meme (eviter crash)\n");
    printf("    current->Flink = current;\n");
    printf("    current->Blink = current;\n\n");

    printf("    Resultat :\n");
    printf("    - Processus invisible dans Task Manager\n");
    printf("    - Invisible pour EnumProcesses/Toolhelp\n");
    printf("    - MAIS toujours actif et execute!\n");
    printf("    - Le scheduler utilise une autre structure (KTHREAD)\n\n");
}

void demo_token_manipulation(void) {
    printf("[3] Technique : Token Stealing via DKOM\n\n");
    printf("    Chaque EPROCESS contient un pointeur vers son Token.\n");
    printf("    On peut copier le Token de SYSTEM vers notre processus.\n\n");

    printf("    1. Trouver EPROCESS de System (PID 4)\n");
    printf("    2. Lire system_eprocess->Token\n");
    printf("    3. Trouver EPROCESS de notre processus\n");
    printf("    4. Ecrire our_eprocess->Token = system_token\n\n");

    printf("    Resultat : notre processus a les privileges SYSTEM\n\n");

    /* Afficher les infos de token du processus courant */
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD size;
        TOKEN_ELEVATION elev;
        size = sizeof(elev);
        if (GetTokenInformation(hToken, TokenElevation, &elev, size, &size))
            printf("    Token eleve : %s\n", elev.TokenIsElevated ? "OUI" : "NON");

        TOKEN_ELEVATION_TYPE type;
        size = sizeof(type);
        if (GetTokenInformation(hToken, TokenElevationType, &type, size, &size)) {
            const char* t = "Unknown";
            if (type == TokenElevationTypeDefault) t = "Default";
            else if (type == TokenElevationTypeFull) t = "Full";
            else if (type == TokenElevationTypeLimited) t = "Limited";
            printf("    Type        : %s\n", t);
        }
        CloseHandle(hToken);
    }
    printf("\n");
}

void demo_driver_hiding(void) {
    printf("[4] Technique : Driver Hiding\n\n");
    printf("    Les drivers sont aussi dans une liste chainee :\n");
    printf("    DRIVER_OBJECT->DriverSection -> LDR_DATA_TABLE_ENTRY\n");
    printf("                                     ->InLoadOrderLinks\n\n");

    printf("    Meme technique que pour les processus :\n");
    printf("    Retirer le DRIVER_OBJECT de la liste\n");
    printf("    -> Driver invisible pour EnumDeviceDrivers()\n");
    printf("    -> Invisible dans WinDbg lm\n\n");

    /* Compter les drivers actuels */
    LPVOID drivers[512];
    DWORD needed;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        int count = needed / sizeof(LPVOID);
        printf("    Drivers actuellement visibles : %d\n", count);
        printf("    Un rootkit DKOM reduirait ce nombre\n\n");
    }
}

void demo_detection(void) {
    printf("[5] Detection de DKOM\n\n");
    printf("    Le DKOM cache les processus de la liste ActiveProcessLinks\n");
    printf("    MAIS d'autres structures kernel referent au processus :\n\n");

    printf("    Methodes de detection :\n");
    printf("    - HandleTableList : liste de tous les handle tables\n");
    printf("    - PspCidTable : table PID du kernel\n");
    printf("    - KTHREAD scheduling lists\n");
    printf("    - ETW : les events sont toujours emis\n");
    printf("    - Pool scanning : chercher le tag 'Proc' en memoire\n\n");

    printf("    Cross-reference :\n");
    printf("    Si un PID existe dans PspCidTable\n");
    printf("    mais PAS dans ActiveProcessLinks\n");
    printf("    -> Processus cache par DKOM!\n\n");

    printf("    Outils de detection :\n");
    printf("    - Volatility (memory forensics)\n");
    printf("    - WinDbg !process 0 0 (liste interne)\n");
    printf("    - EDR avec kernel callbacks (pas affectes par DKOM)\n\n");
}

int main(void) {
    printf("[*] Demo : DKOM (Direct Kernel Object Manipulation)\n");
    printf("[*] ==========================================\n\n");
    demo_eprocess();
    demo_process_hiding();
    demo_token_manipulation();
    demo_driver_hiding();
    demo_detection();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
