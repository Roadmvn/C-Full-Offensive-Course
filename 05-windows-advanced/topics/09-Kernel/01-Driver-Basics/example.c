/*
 * OBJECTIF  : Comprendre les bases du developpement de drivers Windows
 * PREREQUIS : C avance, Architecture Windows
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les drivers kernel s'executent en ring 0 avec un acces total.
 * Ce module usermode explique les concepts et interroge le systeme
 * pour comprendre l'architecture des drivers.
 */

#include <windows.h>
#include <stdio.h>

void demo_driver_architecture(void) {
    printf("[1] Architecture des drivers Windows\n\n");
    printf("    Ring 3 (Usermode)          Ring 0 (Kernel)\n");
    printf("    +-----------------+        +------------------+\n");
    printf("    | Application     |        | ntoskrnl.exe     |\n");
    printf("    |   |             |        |   (noyau)        |\n");
    printf("    | kernel32.dll    |        +------------------+\n");
    printf("    |   |             |        | HAL.dll          |\n");
    printf("    | ntdll.dll       |  --->  | (Hardware Layer)  |\n");
    printf("    |   (syscall)     |        +------------------+\n");
    printf("    +-----------------+        | Drivers (.sys)   |\n");
    printf("                               |   - WDM          |\n");
    printf("                               |   - WDF/KMDF     |\n");
    printf("                               +------------------+\n\n");

    printf("    Types de drivers :\n");
    printf("    - WDM (Windows Driver Model) : legacy, complexe\n");
    printf("    - KMDF (Kernel-Mode Driver Framework) : moderne\n");
    printf("    - UMDF (User-Mode Driver Framework) : securise\n\n");
}

void demo_driver_entry(void) {
    printf("[2] Structure d'un driver minimal\n\n");
    printf("    #include <ntddk.h>\n\n");
    printf("    void DriverUnload(PDRIVER_OBJECT DriverObject) {\n");
    printf("        DbgPrint(\"Driver unloaded\\n\");\n");
    printf("    }\n\n");
    printf("    NTSTATUS DriverEntry(\n");
    printf("        PDRIVER_OBJECT  DriverObject,\n");
    printf("        PUNICODE_STRING RegistryPath)\n");
    printf("    {\n");
    printf("        DriverObject->DriverUnload = DriverUnload;\n");
    printf("        DbgPrint(\"Driver loaded\\n\");\n");
    printf("        return STATUS_SUCCESS;\n");
    printf("    }\n\n");

    printf("    Points cles :\n");
    printf("    - DriverEntry = point d'entree (comme main())\n");
    printf("    - DriverUnload = nettoyage au dechargement\n");
    printf("    - IRQL = niveau d'interruption courant\n");
    printf("    - DbgPrint = printf() du kernel\n\n");
}

void demo_enumerate_drivers(void) {
    printf("[3] Enumeration des drivers charges\n\n");

    /* Utiliser EnumDeviceDrivers pour lister les modules kernel */
    LPVOID drivers[512];
    DWORD needed;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        int count = needed / sizeof(LPVOID);
        printf("    [+] %d modules kernel charges\n\n", count);

        printf("    %-20s %s\n", "ADRESSE", "NOM");
        printf("    %-20s %s\n", "-------", "---");
        int i;
        for (i = 0; i < count && i < 15; i++) {
            char name[256] = {0};
            GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
            printf("    0x%016llX %s\n",
                   (unsigned long long)(ULONG_PTR)drivers[i], name);
        }
        printf("    ... (%d total)\n\n", count);

        /* Trouver ntoskrnl.exe */
        for (i = 0; i < count; i++) {
            char name[256] = {0};
            GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
            if (_stricmp(name, "ntoskrnl.exe") == 0) {
                char path[512] = {0};
                GetDeviceDriverFileNameA(drivers[i], path, sizeof(path));
                printf("    [*] ntoskrnl.exe :\n");
                printf("        Base: 0x%016llX\n",
                       (unsigned long long)(ULONG_PTR)drivers[i]);
                printf("        Path: %s\n\n", path);
                break;
            }
        }
    }
}

void demo_driver_loading(void) {
    printf("[4] Chargement d'un driver\n\n");
    printf("    Methode 1 : Service Control Manager (sc.exe)\n");
    printf("    sc create MyDriver type= kernel binPath= C:\\\\driver.sys\n");
    printf("    sc start MyDriver\n");
    printf("    sc stop MyDriver\n");
    printf("    sc delete MyDriver\n\n");

    printf("    Methode 2 : API CreateService\n");
    printf("    SC_HANDLE hSvc = CreateServiceA(hSCM,\n");
    printf("        \"MyDriver\", \"My Driver\",\n");
    printf("        SERVICE_ALL_ACCESS,\n");
    printf("        SERVICE_KERNEL_DRIVER,     <- type kernel\n");
    printf("        SERVICE_DEMAND_START,\n");
    printf("        SERVICE_ERROR_NORMAL,\n");
    printf("        \"C:\\\\driver.sys\", ...);\n");
    printf("    StartService(hSvc, 0, NULL);\n\n");

    printf("    Methode 3 : NtLoadDriver (ntdll)\n");
    printf("    -> Charge un driver via son chemin registry\n");
    printf("    -> Necessite SeLoadDriverPrivilege\n\n");

    printf("    Prerequis pour charger un driver :\n");
    printf("    - Privileges administrateur\n");
    printf("    - Driver signe (DSE) ou test signing\n");
    printf("    - Pas de VBS/HVCI en mode strict\n\n");
}

void demo_compilation(void) {
    printf("[5] Compilation d'un driver\n\n");
    printf("    Outils necessaires :\n");
    printf("    - Visual Studio (Build Tools)\n");
    printf("    - Windows Driver Kit (WDK)\n");
    printf("    - SDK Windows\n\n");
    printf("    Commande :\n");
    printf("    msbuild driver.vcxproj /p:Configuration=Release\n\n");
    printf("    Ou via le Developer Command Prompt :\n");
    printf("    cl /kernel /GS- /Gz driver.c /link /DRIVER\n");
    printf("       /ENTRY:DriverEntry /SUBSYSTEM:NATIVE\n\n");
    printf("    Le resultat est un fichier .sys (PE natif)\n\n");
}

int main(void) {
    printf("[*] Demo : Driver Basics (Kernel)\n");
    printf("[*] ==========================================\n\n");
    demo_driver_architecture();
    demo_driver_entry();
    demo_enumerate_drivers();
    demo_driver_loading();
    demo_compilation();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
