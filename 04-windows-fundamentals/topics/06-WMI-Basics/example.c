/*
 * OBJECTIF  : Comprendre WMI (Windows Management Instrumentation) via C
 * PREREQUIS : Bases du C, COM/OLE basics
 * COMPILE   : cl example.c /Fe:example.exe /link ole32.lib oleaut32.lib wbemuuid.lib
 *
 * WMI est un framework de gestion systeme Windows base sur COM.
 * Il permet d'interroger le systeme (processus, OS, hardware) et d'executer
 * des commandes a distance. Utilise pour la reconnaissance et le lateral movement.
 *
 * Note : WMI necessite COM, ce qui rend le code en C plus verbeux qu'en C++.
 * Ce programme montre les concepts avec des appels systeme simples en fallback.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ole32.lib")

/* Demo 1 : Reconnaissance systeme sans WMI (via APIs directes) */
void demo_system_info(void) {
    printf("[1] Reconnaissance systeme (APIs directes)\n\n");

    /* Informations OS */
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    typedef LONG (NTAPI *pRtlGetVersion)(OSVERSIONINFOEXA*);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
    if (RtlGetVersion) {
        RtlGetVersion(&osvi);
        printf("    OS Version : %lu.%lu.%lu\n",
               osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }

    /* Nom de la machine */
    char hostname[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    printf("    Hostname   : %s\n", hostname);

    /* Utilisateur courant */
    char username[256];
    size = sizeof(username);
    GetUserNameA(username, &size);
    printf("    Username   : %s\n", username);

    /* Informations systeme */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("    Arch       : %s\n",
           si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");
    printf("    CPUs       : %lu\n", si.dwNumberOfProcessors);

    /* Memoire */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    printf("    RAM        : %llu MB\n", ms.ullTotalPhys / (1024 * 1024));
    printf("    RAM libre  : %llu MB\n", ms.ullAvailPhys / (1024 * 1024));

    /* Uptime */
    ULONGLONG uptime = GetTickCount64() / 1000;
    printf("    Uptime     : %lluh %llum %llus\n",
           uptime / 3600, (uptime % 3600) / 60, uptime % 60);

    printf("\n");
}

/* Demo 2 : Enumeration des processus (equivalent WQL : SELECT * FROM Win32_Process) */
void demo_process_enum(void) {
    printf("[2] Enumeration des processus (equivalent WMI Win32_Process)\n\n");

    HANDLE snap = CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    typedef struct {
        DWORD dwSize; DWORD cntUsage; DWORD th32ProcessID;
        ULONG_PTR th32DefaultHeapID; DWORD th32ModuleID;
        DWORD cntThreads; DWORD th32ParentProcessID;
        LONG pcPriClassBase; DWORD dwFlags; char szExeFile[260];
    } PE32;

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    typedef BOOL (WINAPI *p32F)(HANDLE, PE32*);
    typedef BOOL (WINAPI *p32N)(HANDLE, PE32*);
    p32F pFirst = (p32F)GetProcAddress(k32, "Process32First");
    p32N pNext = (p32N)GetProcAddress(k32, "Process32Next");

    PE32 pe;
    pe.dwSize = sizeof(PE32);

    printf("    %-8s  %-8s  %-4s  %s\n", "PID", "PPID", "Thr", "Processus");
    printf("    %-8s  %-8s  %-4s  %s\n", "--------", "--------", "----", "---------");

    int count = 0;
    if (pFirst(snap, &pe)) {
        do {
            if (count < 25) {
                printf("    %-8lu  %-8lu  %-4lu  %s\n",
                       pe.th32ProcessID, pe.th32ParentProcessID,
                       pe.cntThreads, pe.szExeFile);
            }
            count++;
        } while (pNext(snap, &pe));
    }

    CloseHandle(snap);
    printf("    ... Total : %d processus\n\n", count);
}

/* Demo 3 : Informations reseau (equivalent WQL : SELECT * FROM Win32_NetworkAdapterConfiguration) */
void demo_network_info(void) {
    printf("[3] Informations reseau\n\n");

    /* Nom DNS */
    char dns[256];
    DWORD size = sizeof(dns);
    if (GetComputerNameExA(ComputerNameDnsFullyQualified, dns, &size))
        printf("    DNS Name   : %s\n", dns);

    /* Adaptateurs reseau via GetAdaptersInfo */
    typedef struct _IP_ADDR {
        struct _IP_ADDR* Next;
        char IpAddress[16];
        char IpMask[16];
        DWORD Context;
    } IP_ADDR;

    typedef struct _ADAPTER_INFO {
        struct _ADAPTER_INFO* Next;
        DWORD ComboIndex;
        char AdapterName[260];
        char Description[132];
        UINT AddressLength;
        BYTE Address[8];
        DWORD Index;
        UINT Type;
        UINT DhcpEnabled;
        IP_ADDR* CurrentIpAddress;
        IP_ADDR IpAddressList;
        IP_ADDR GatewayList;
        IP_ADDR DhcpServer;
    } ADAPTER_INFO;

    HMODULE iphlp = LoadLibraryA("iphlpapi.dll");
    if (iphlp) {
        typedef DWORD (WINAPI *pGetAdaptersInfo)(ADAPTER_INFO*, ULONG*);
        pGetAdaptersInfo GetAdaptersInfo =
            (pGetAdaptersInfo)GetProcAddress(iphlp, "GetAdaptersInfo");

        if (GetAdaptersInfo) {
            ULONG bufSize = 0;
            GetAdaptersInfo(NULL, &bufSize);
            ADAPTER_INFO* info = (ADAPTER_INFO*)malloc(bufSize);

            if (GetAdaptersInfo(info, &bufSize) == 0) {
                ADAPTER_INFO* adapter = info;
                while (adapter) {
                    printf("    Adapter    : %s\n", adapter->Description);
                    printf("    IP         : %s\n", adapter->IpAddressList.IpAddress);
                    printf("    Gateway    : %s\n", adapter->GatewayList.IpAddress);
                    printf("    MAC        : %02X:%02X:%02X:%02X:%02X:%02X\n",
                           adapter->Address[0], adapter->Address[1], adapter->Address[2],
                           adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                    printf("\n");
                    adapter = adapter->Next;
                }
            }
            free(info);
        }
        FreeLibrary(iphlp);
    }
}

/* Demo 4 : Execution WMI via ligne de commande (concept) */
void demo_wmi_exec_concept(void) {
    printf("[4] Execution a distance via WMI (concept)\n\n");

    printf("    WMI permet l'execution de commandes a distance :\n\n");
    printf("    wmic /node:TARGET process call create \"cmd.exe /c whoami\"\n\n");
    printf("    En C, via l'interface COM IWbemServices :\n");
    printf("    1. CoInitializeEx()     -> Initialiser COM\n");
    printf("    2. CoCreateInstance()   -> Creer IWbemLocator\n");
    printf("    3. ConnectServer()      -> Se connecter au namespace WMI\n");
    printf("    4. ExecMethod()         -> Executer Win32_Process::Create\n\n");
    printf("    [!] Detection : Sysmon Event ID 1 (parent: wmiprvse.exe)\n");
    printf("    [!] Lateral movement : WMI + DCOM sur port 135\n\n");
}

int main(void) {
    printf("[*] Demo : WMI Basics - Reconnaissance systeme\n");
    printf("[*] ==========================================\n\n");

    demo_system_info();
    demo_process_enum();
    demo_network_info();
    demo_wmi_exec_concept();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
