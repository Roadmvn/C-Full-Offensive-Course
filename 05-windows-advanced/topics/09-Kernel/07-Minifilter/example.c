/*
 * OBJECTIF  : Comprendre les Minifilters (filesystem filtering)
 * PREREQUIS : Driver Basics, IOCTL, IRP
 * COMPILE   : cl example.c /Fe:example.exe /link fltlib.lib
 *
 * Les minifilters sont le mecanisme officiel pour intercepter les
 * operations fichiers dans le kernel. Les EDR les utilisent pour
 * scanner les fichiers ecrits, detecter le ransomware, etc.
 */

#include <windows.h>
#include <stdio.h>
#include <fltuser.h>

#pragma comment(lib, "fltlib.lib")

void demo_minifilter_concept(void) {
    printf("[1] Architecture Minifilter\n\n");
    printf("    Application\n");
    printf("        |\n");
    printf("    I/O Manager (IRP)\n");
    printf("        |\n");
    printf("    Filter Manager (fltmgr.sys)\n");
    printf("        |\n");
    printf("    +-- Minifilter EDR (altitude haute) --+\n");
    printf("    +-- Minifilter AV  (altitude moyenne) --+\n");
    printf("    +-- Minifilter Backup (altitude basse) --+\n");
    printf("        |\n");
    printf("    File System (ntfs.sys)\n");
    printf("        |\n");
    printf("    Storage Driver\n\n");

    printf("    Altitude : priorite du filtre (0-430000)\n");
    printf("    Plus l'altitude est haute, plus le filtre est appele tot.\n");
    printf("    Microsoft assigne les altitudes officiellement.\n\n");
}

void demo_enumerate_filters(void) {
    printf("[2] Enumeration des minifilters installes\n\n");

    HANDLE hFinder;
    FILTER_INFORMATION_CLASS infoClass = FilterFullInformation;
    DWORD bytesReturned;

    /* Premiere iteration pour obtenir la taille */
    BYTE buf[4096];
    HRESULT hr = FilterFindFirst(FilterFullInformation,
                                 buf, sizeof(buf),
                                 &bytesReturned, &hFinder);
    if (SUCCEEDED(hr)) {
        int count = 0;
        printf("    %-30s %s\n", "FILTRE", "INSTANCES");
        printf("    %-30s %s\n", "------", "---------");

        do {
            PFILTER_FULL_INFORMATION info = (PFILTER_FULL_INFORMATION)buf;
            wchar_t name[256] = {0};
            memcpy(name, buf + info->FilterNameBufferOffset,
                   info->FilterNameLength);
            printf("    %-30ls %lu\n", name, info->NumberOfInstances);
            count++;
        } while (SUCCEEDED(FilterFindNext(hFinder, FilterFullInformation,
                           buf, sizeof(buf), &bytesReturned)));

        FilterFindClose(hFinder);
        printf("    -> %d minifilters trouves\n\n", count);
    } else {
        printf("    [-] Impossible d'enumerer les filtres (0x%08lX)\n", hr);
        printf("    (privileges administrateur requis)\n\n");
    }
}

void demo_minifilter_driver(void) {
    printf("[3] Code d'un minifilter (driver)\n\n");
    printf("    const FLT_OPERATION_REGISTRATION callbacks[] = {\n");
    printf("        { IRP_MJ_CREATE,  0, PreCreate,  PostCreate },\n");
    printf("        { IRP_MJ_WRITE,   0, PreWrite,   NULL },\n");
    printf("        { IRP_MJ_CLEANUP, 0, PreCleanup, NULL },\n");
    printf("        { IRP_MJ_OPERATION_END }\n");
    printf("    };\n\n");

    printf("    const FLT_REGISTRATION FilterRegistration = {\n");
    printf("        sizeof(FLT_REGISTRATION),\n");
    printf("        FLT_REGISTRATION_VERSION,\n");
    printf("        0,\n");
    printf("        NULL,            // ContextRegistration\n");
    printf("        callbacks,       // OperationRegistration\n");
    printf("        MiniFilterUnload,\n");
    printf("        InstanceSetup,\n");
    printf("        ...\n");
    printf("    };\n\n");

    printf("    FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);\n");
    printf("    FltStartFiltering(gFilter);\n\n");
}

void demo_pre_post_callbacks(void) {
    printf("[4] Pre/Post operation callbacks\n\n");
    printf("    PreCreate (avant ouverture d'un fichier) :\n");
    printf("    - Scanner le chemin du fichier\n");
    printf("    - Bloquer l'acces a des fichiers proteges\n");
    printf("    - Retourner FLT_PREOP_COMPLETE pour bloquer\n\n");

    printf("    PreWrite (avant ecriture) :\n");
    printf("    - Detecter le ransomware (entropie elevee)\n");
    printf("    - Detecter la modification de fichiers systeme\n");
    printf("    - Scanner le contenu ecrit\n\n");

    printf("    PostCreate (apres ouverture) :\n");
    printf("    - Logger l'evenement\n");
    printf("    - Inspecter le contenu du fichier\n\n");

    printf("    Usages EDR typiques :\n");
    printf("    - Scan AV des fichiers ecrits\n");
    printf("    - Detection ransomware (bulk rename/encrypt)\n");
    printf("    - Prevention d'acces au SAM/NTDS.dit\n");
    printf("    - Logging d'acces aux fichiers sensibles\n\n");
}

void demo_evasion(void) {
    printf("[5] Evasion des minifilters\n\n");
    printf("    Techniques :\n\n");
    printf("    a) Acceder directement au volume :\n");
    printf("       CreateFile(\"\\\\\\\\.\\\\C:\", ...) + offsets NTFS\n");
    printf("       -> Bypass le filesystem filter\n\n");

    printf("    b) Detacher le minifilter :\n");
    printf("       FltUnregisterFilter() depuis un driver\n");
    printf("       -> Necessite un acces kernel\n\n");

    printf("    c) Minifilter unloading via fltMC :\n");
    printf("       fltmc unload <FilterName>\n");
    printf("       -> Necessite admin + le filtre doit supporter unload\n\n");

    printf("    d) Direct I/O via NtFsControlFile :\n");
    printf("       -> Certaines operations ne passent pas par le filter\n\n");

    printf("    Detection des evasions :\n");
    printf("    - Surveiller les appels a FltUnregisterFilter\n");
    printf("    - ETW events pour le dechargement de filtres\n");
    printf("    - Self-protection du minifilter (refuser unload)\n\n");
}

int main(void) {
    printf("[*] Demo : Minifilter (Filesystem Filtering)\n");
    printf("[*] ==========================================\n\n");
    demo_minifilter_concept();
    demo_enumerate_filters();
    demo_minifilter_driver();
    demo_pre_post_callbacks();
    demo_evasion();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
