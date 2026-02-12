/*
 * OBJECTIF  : Comprendre Event Tracing for Windows (ETW) - systeme de telemetrie
 * PREREQUIS : Bases du C, notions de processus Windows
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib
 *
 * ETW est le systeme de tracing/logging de Windows utilise par les EDR, Defender,
 * et Sysmon pour surveiller l'activite. Comprendre ETW est essentiel pour :
 * - Savoir ce que les defenses voient
 * - Comprendre comment les EDR detectent les attaques
 * - Appliquer des techniques d'evasion ETW (module 05-Evasion)
 */

#include <windows.h>
#include <evntrace.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/* Enumerer les sessions ETW actives sur le systeme */
void enumerate_etw_sessions(void) {
    printf("[1] Sessions ETW actives\n\n");

    /*
     * QueryAllTraces retourne la liste des sessions de trace actives.
     * Chaque session consomme des evenements de providers specifiques.
     */
    EVENT_TRACE_PROPERTIES* props[64];
    ULONG count = 0;

    /* Allouer les buffers pour chaque session possible */
    for (int i = 0; i < 64; i++) {
        ULONG buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        props[i] = (EVENT_TRACE_PROPERTIES*)calloc(1, buf_size);
        props[i]->Wnode.BufferSize = buf_size;
        props[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    }

    ULONG status = QueryAllTracesA((PEVENT_TRACE_PROPERTIES*)props, 64, &count);
    if (status == ERROR_SUCCESS) {
        printf("    %-4s  %-40s  %s\n", "#", "Nom de session", "Log file");
        printf("    %-4s  %-40s  %s\n", "----", "----------------------------------------", "---------");

        for (ULONG i = 0; i < count; i++) {
            char* name = (char*)props[i] + props[i]->LoggerNameOffset;
            char* logfile = props[i]->LogFileNameOffset ?
                            (char*)props[i] + props[i]->LogFileNameOffset : "(realtime)";
            printf("    [%2lu]  %-40s  %s\n", i, name, logfile);
        }
        printf("\n    [+] Total : %lu sessions ETW actives\n", count);
    } else {
        printf("    [-] QueryAllTraces echoue (err %lu)\n", status);
    }

    for (int i = 0; i < 64; i++)
        free(props[i]);
    printf("\n");
}

/* Afficher les providers ETW importants pour la securite */
void list_security_providers(void) {
    printf("[2] Providers ETW importants pour la securite\n\n");

    /* Les GUIDs des providers les plus surveilles */
    printf("    Provider                          GUID\n");
    printf("    --------------------------------  ------------------------------------\n");
    printf("    Microsoft-Windows-Kernel-Process  {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}\n");
    printf("    Microsoft-Windows-Kernel-File     {EDD08927-9CC4-4E65-B970-C2560FB5C289}\n");
    printf("    Microsoft-Windows-Kernel-Network  {7DD42A49-5329-4832-8DFD-43D979153A88}\n");
    printf("    Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}\n");
    printf("    Microsoft-Antimalware-Scan-AMSI   {2A576B87-09A7-520E-C21A-4942F0271D67}\n");
    printf("    Microsoft-Windows-PowerShell      {A0C1853B-5C40-4B15-8766-3CF1C58F985A}\n");
    printf("    Microsoft-Windows-DotNETRuntime   {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}\n");
    printf("    Microsoft-Windows-Security-Audit  {54849625-5478-4994-A5BA-3E3B0328C30D}\n\n");

    printf("    [*] Ces providers sont utilises par :\n");
    printf("        - Windows Defender (MsMpEng.exe)\n");
    printf("        - Sysmon (process creation, network, file)\n");
    printf("        - EDR commerciaux (CrowdStrike, SentinelOne, etc.)\n\n");
}

/* Demo : Creer un provider ETW simple */
void demo_etw_provider(void) {
    printf("[3] Demo : Enregistrement d'un provider ETW\n\n");

    REGHANDLE hProvider = 0;

    /* GUID unique pour notre provider de demo */
    const GUID DemoProvider = {
        0x12345678, 0xABCD, 0xEF01,
        {0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01}
    };

    ULONG status = EventRegister(&DemoProvider, NULL, NULL, &hProvider);
    if (status == ERROR_SUCCESS) {
        printf("    [+] Provider enregistre avec succes\n");
        printf("    [+] Handle : 0x%llX\n", (unsigned long long)hProvider);

        /* Ecrire un evenement simple */
        EVENT_DESCRIPTOR evtDesc = {0};
        evtDesc.Id = 1;
        evtDesc.Level = 4; /* Informational */

        status = EventWrite(hProvider, &evtDesc, 0, NULL);
        if (status == ERROR_SUCCESS)
            printf("    [+] Evenement ecrit avec succes\n");
        else
            printf("    [-] EventWrite echoue (err %lu)\n", status);

        EventUnregister(hProvider);
        printf("    [+] Provider desenregistre\n");
    } else {
        printf("    [-] EventRegister echoue (err %lu)\n", status);
    }
    printf("\n");
}

/* Expliquer le patch ETW (concept theorique) */
void explain_etw_patching(void) {
    printf("[4] Concept : ETW Patching (evasion)\n\n");

    printf("    Les malwares avances patchent ntdll!EtwEventWrite pour\n");
    printf("    empecher la generation d'evenements ETW.\n\n");

    /* Montrer l'adresse de EtwEventWrite */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* etw_write = (BYTE*)GetProcAddress(ntdll, "EtwEventWrite");

    if (etw_write) {
        printf("    EtwEventWrite @ %p\n", etw_write);
        printf("    Premiers octets : ");
        for (int i = 0; i < 8; i++)
            printf("%02X ", etw_write[i]);
        printf("\n\n");

        printf("    [!] Technique de patch (NON executee ici) :\n");
        printf("        BYTE patch[] = { 0xC3 }; // RET immediat\n");
        printf("        VirtualProtect(EtwEventWrite, 1, PAGE_READWRITE, &old);\n");
        printf("        memcpy(EtwEventWrite, patch, 1);\n");
        printf("        VirtualProtect(EtwEventWrite, 1, old, &old);\n");
        printf("        -> Plus aucun evenement ETW ne sera genere!\n");
    }
    printf("\n");
}

int main(void) {
    printf("[*] Demo : ETW Basics - Event Tracing for Windows\n");
    printf("[*] ==========================================\n\n");

    enumerate_etw_sessions();
    list_security_providers();
    demo_etw_provider();
    explain_etw_patching();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
