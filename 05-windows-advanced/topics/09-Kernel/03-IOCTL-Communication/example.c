/*
 * OBJECTIF  : Communication usermode-kernel via IOCTL
 * PREREQUIS : Driver Basics, Device Objects
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * IOCTL (I/O Control) permet a un programme usermode de communiquer
 * avec un driver kernel via DeviceIoControl(). C'est le mecanisme
 * principal d'interaction user<->kernel.
 */

#include <windows.h>
#include <stdio.h>

/* Macro de definition d'IOCTL (comme dans le driver) */
#define CTL_CODE_CUSTOM(func) CTL_CODE(FILE_DEVICE_UNKNOWN, func, \
                              METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DEMO_PING     CTL_CODE_CUSTOM(0x800)
#define IOCTL_DEMO_READ     CTL_CODE_CUSTOM(0x801)
#define IOCTL_DEMO_WRITE    CTL_CODE_CUSTOM(0x802)

void demo_ioctl_concept(void) {
    printf("[1] Concept IOCTL\n\n");
    printf("    Usermode                    Kernel\n");
    printf("    +------------------+        +------------------+\n");
    printf("    | CreateFile(      |        | DriverEntry()    |\n");
    printf("    |  \\\\.\\MyDevice)  | -----> | IoCreateDevice() |\n");
    printf("    +------------------+        | IoCreateSymLink()|\n");
    printf("    | DeviceIoControl( |        +------------------+\n");
    printf("    |  IOCTL_CODE,     | -----> | IRP_MJ_DEVICE_   |\n");
    printf("    |  inBuf, outBuf)  |        |   CONTROL handler|\n");
    printf("    +------------------+        +------------------+\n");
    printf("    | CloseHandle()    | -----> | IRP_MJ_CLOSE     |\n");
    printf("    +------------------+        +------------------+\n\n");
}

void demo_ctl_code(void) {
    printf("[2] Structure d'un code IOCTL\n\n");
    printf("    CTL_CODE(DeviceType, Function, Method, Access)\n\n");
    printf("    Bits 31-16 : DeviceType (FILE_DEVICE_UNKNOWN=0x22)\n");
    printf("    Bits 15-14 : Access (FILE_ANY_ACCESS=0)\n");
    printf("    Bits 13-2  : Function number (custom >= 0x800)\n");
    printf("    Bits 1-0   : Method (transfert des donnees)\n\n");

    printf("    Methodes de transfert :\n");
    printf("    METHOD_BUFFERED  (0) : Copie via SystemBuffer\n");
    printf("    METHOD_IN_DIRECT (1) : MDL pour input\n");
    printf("    METHOD_OUT_DIRECT(2) : MDL pour output\n");
    printf("    METHOD_NEITHER   (3) : Raw pointers (dangereux!)\n\n");

    /* Afficher les codes IOCTL demo */
    printf("    Nos IOCTLs de demo :\n");
    printf("    IOCTL_DEMO_PING  = 0x%08lX\n", (DWORD)IOCTL_DEMO_PING);
    printf("    IOCTL_DEMO_READ  = 0x%08lX\n", (DWORD)IOCTL_DEMO_READ);
    printf("    IOCTL_DEMO_WRITE = 0x%08lX\n\n", (DWORD)IOCTL_DEMO_WRITE);
}

void demo_driver_side(void) {
    printf("[3] Code cote driver (kernel)\n\n");
    printf("    NTSTATUS DriverEntry(PDRIVER_OBJECT drv, ...) {\n");
    printf("        IoCreateDevice(drv, 0, &devName,\n");
    printf("            FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);\n");
    printf("        IoCreateSymbolicLink(&symLink, &devName);\n");
    printf("        drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoCtlHandler;\n");
    printf("    }\n\n");

    printf("    NTSTATUS IoCtlHandler(PDEVICE_OBJECT dev, PIRP Irp) {\n");
    printf("        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);\n");
    printf("        ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;\n");
    printf("        PVOID buf = Irp->AssociatedIrp.SystemBuffer;\n\n");
    printf("        switch (ioctl) {\n");
    printf("        case IOCTL_DEMO_PING:\n");
    printf("            strcpy(buf, \"PONG\");\n");
    printf("            Irp->IoStatus.Information = 5;\n");
    printf("            break;\n");
    printf("        }\n");
    printf("        Irp->IoStatus.Status = STATUS_SUCCESS;\n");
    printf("        IoCompleteRequest(Irp, IO_NO_INCREMENT);\n");
    printf("        return STATUS_SUCCESS;\n");
    printf("    }\n\n");
}

void demo_usermode_client(void) {
    printf("[4] Code cote usermode (client)\n\n");

    /* Tenter d'ouvrir un device connu */
    printf("    Tentative d'ouverture de devices :\n\n");

    const char* devices[] = {
        "\\\\.\\PhysicalDrive0",
        "\\\\.\\C:",
        "\\\\.\\NUL",
        NULL
    };

    int i;
    for (i = 0; devices[i]; i++) {
        HANDLE hDev = CreateFileA(devices[i],
            0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        printf("    [%c] %s\n", hDev != INVALID_HANDLE_VALUE ? '+' : '-',
               devices[i]);
        if (hDev != INVALID_HANDLE_VALUE)
            CloseHandle(hDev);
    }

    printf("\n    Pattern d'utilisation IOCTL :\n");
    printf("    HANDLE hDev = CreateFileA(\"\\\\\\\\.\\\\MyDevice\",\n");
    printf("        GENERIC_READ | GENERIC_WRITE, 0, NULL,\n");
    printf("        OPEN_EXISTING, 0, NULL);\n\n");
    printf("    char outBuf[256];\n");
    printf("    DWORD returned;\n");
    printf("    DeviceIoControl(hDev, IOCTL_DEMO_PING,\n");
    printf("        NULL, 0,             // input\n");
    printf("        outBuf, sizeof(outBuf),  // output\n");
    printf("        &returned, NULL);\n");
    printf("    // outBuf = \"PONG\"\n\n");
}

void demo_security(void) {
    printf("[5] Securite des IOCTLs\n\n");
    printf("    Vulnerabilites courantes :\n");
    printf("    - METHOD_NEITHER sans validation de pointeurs\n");
    printf("    - Buffer overflow dans SystemBuffer\n");
    printf("    - TOCTOU (time-of-check-time-of-use)\n");
    printf("    - Arbitrary read/write kernel via IOCTL\n\n");

    printf("    BYOVD exploite ces vulns dans des drivers signes :\n");
    printf("    1. Charger le driver vulnerable\n");
    printf("    2. Ouvrir le device (CreateFile)\n");
    printf("    3. Envoyer l'IOCTL malveillant\n");
    printf("    4. Obtenir read/write kernel arbitraire\n\n");

    printf("    Protection :\n");
    printf("    - Toujours valider les tailles de buffer\n");
    printf("    - Utiliser METHOD_BUFFERED (le plus sur)\n");
    printf("    - Verifier les privileges du caller\n");
    printf("    - HVCI bloque certains exploits kernel\n\n");
}

int main(void) {
    printf("[*] Demo : IOCTL Communication\n");
    printf("[*] ==========================================\n\n");
    demo_ioctl_concept();
    demo_ctl_code();
    demo_driver_side();
    demo_usermode_client();
    demo_security();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
