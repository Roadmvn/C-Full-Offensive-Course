/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 31 : Anti-VM & Anti-Sandbox
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#endif

// 1. CPUID Hypervisor detection
int check_cpuid_hypervisor() {
    #ifdef _WIN32
    int cpuinfo[4] = {0};
    __cpuid(cpuinfo, 1);

    // Bit 31 of ECX indique hypervisor present
    if (cpuinfo[2] & (1 << 31)) {
        printf("[-] Hypervisor detected (CPUID leaf 1)\n");

        // Get hypervisor vendor
        __cpuid(cpuinfo, 0x40000000);
        char vendor[13];
        memcpy(vendor, &cpuinfo[1], 4);
        memcpy(vendor + 4, &cpuinfo[2], 4);
        memcpy(vendor + 8, &cpuinfo[3], 4);
        vendor[12] = 0;
        printf("    Vendor: %s\n", vendor);
        return 1;
    }
    #endif
    return 0;
}

// 2. MAC Address OUI check
int check_mac_address_oui() {
    #ifdef _WIN32
    IP_ADAPTER_INFO adapters[16];
    DWORD size = sizeof(adapters);

    if (GetAdaptersInfo(adapters, &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapters;
        while (adapter) {
            if (adapter->AddressLength == 6) {
                // VMware: 00:0C:29, 00:1C:14, 00:50:56
                // VirtualBox: 08:00:27
                // QEMU: 52:54:00
                if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29) ||
                    (adapter->Address[0] == 0x08 && adapter->Address[1] == 0x00 && adapter->Address[2] == 0x27) ||
                    (adapter->Address[0] == 0x52 && adapter->Address[1] == 0x54 && adapter->Address[2] == 0x00)) {
                    printf("[-] VM MAC OUI detected: %02X:%02X:%02X\n",
                           adapter->Address[0], adapter->Address[1], adapter->Address[2]);
                    return 1;
                }
            }
            adapter = adapter->Next;
        }
    }
    #endif
    return 0;
}

// 3. VM Files/Registry artifacts
int check_vm_artifacts() {
    #ifdef _WIN32
    const char* files[] = {
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",
        "C:\\windows\\system32\\vboxdisp.dll",
        "C:\\windows\\system32\\vboxhook.dll",
        NULL
    };

    for (int i = 0; files[i]; i++) {
        if (GetFileAttributesA(files[i]) != INVALID_FILE_ATTRIBUTES) {
            printf("[-] VM file detected: %s\n", files[i]);
            return 1;
        }
    }

    // Registry keys
    HKEY hkey;
    const char* reg_keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        NULL
    };

    for (int i = 0; reg_keys[i]; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_keys[i], 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
            printf("[-] VM registry key detected: %s\n", reg_keys[i]);
            RegCloseKey(hkey);
            return 1;
        }
    }
    #endif
    return 0;
}

// 4. VM Processes
int check_vm_processes() {
    #ifdef _WIN32
    const char* processes[] = {
        "vmtoolsd.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        NULL
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32)};
        if (Process32First(snapshot, &pe32)) {
            do {
                for (int i = 0; processes[i]; i++) {
                    if (_stricmp(pe32.szExeFile, processes[i]) == 0) {
                        printf("[-] VM process detected: %s\n", pe32.szExeFile);
                        CloseHandle(snapshot);
                        return 1;
                    }
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    #endif
    return 0;
}

// 5. Sleep acceleration (sandbox skip sleep)
int check_sleep_acceleration() {
    DWORD start = GetTickCount();
    Sleep(5000);  // 5 seconds
    DWORD actual = GetTickCount() - start;

    printf("[*] Sleep 5000ms, actual: %dms\n", actual);

    // Sandbox accélère souvent (< 1000ms pour 5000ms sleep)
    if (actual < 4000) {
        printf("[-] Sleep acceleration detected (sandbox)\n");
        return 1;
    }
    return 0;
}

// 6. User interaction check
int check_user_interaction() {
    #ifdef _WIN32
    LASTINPUTINFO lii = {sizeof(LASTINPUTINFO)};
    GetLastInputInfo(&lii);
    DWORD idle_time = GetTickCount() - lii.dwTime;

    printf("[*] User idle time: %d ms\n", idle_time);

    // Sandbox généralement pas d'interaction (idle élevé)
    if (idle_time > 600000) {  // 10 minutes
        printf("[-] No user interaction (sandbox)\n");
        return 1;
    }
    #endif
    return 0;
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques anti-VM/Sandbox malware dev\n");
    printf("   Usage éducatif uniquement.\n\n");

    int vm_detected = 0;

    printf("[*] Running anti-VM/Sandbox checks...\n\n");

    vm_detected |= check_cpuid_hypervisor();
    vm_detected |= check_mac_address_oui();
    vm_detected |= check_vm_artifacts();
    vm_detected |= check_vm_processes();
    vm_detected |= check_sleep_acceleration();
    vm_detected |= check_user_interaction();

    if (vm_detected) {
        printf("\n[!] VM/SANDBOX DETECTED! Exiting...\n");
        printf("[!] Real malware would refuse execution\n");
        return 1;
    } else {
        printf("\n[+] No VM/Sandbox detected\n");
        printf("[+] Continuing execution...\n");
    }

    return 0;
}
