/*
 * Sandbox/VM Detection - Evading automated analysis
 * Patterns from APT samples, commodity malware
 */

#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>

// ============================================================================
// CPUID CHECKS
// ============================================================================

BOOL chk_hypervisor(void)
{
    int cpu[4];
    __cpuid(cpu, 1);
    return (cpu[2] >> 31) & 1;  // ECX bit 31 = hypervisor present
}

BOOL chk_vm_vendor(void)
{
    int cpu[4];
    __cpuid(cpu, 0);

    char vendor[13];
    *(int*)(vendor) = cpu[1];
    *(int*)(vendor+4) = cpu[3];
    *(int*)(vendor+8) = cpu[2];
    vendor[12] = 0;

    // VMware: "VMwareVMware"
    // VBox:   "VBoxVBoxVBox"
    // Hyper-V: "Microsoft Hv"
    // KVM:    "KVMKVMKVM"
    // Xen:    "XenVMMXenVMM"

    char* vm_vendors[] = {"VMware", "VBox", "Hv", "KVM", "Xen", 0};
    for(int i = 0; vm_vendors[i]; i++) {
        char* p = vendor;
        char* q = vm_vendors[i];
        while(*p && *q) {
            if(*p == *q) return 1;
            p++; q++;
        }
    }
    return 0;
}

// ============================================================================
// HARDWARE CHECKS
// ============================================================================

BOOL chk_ram(void)
{
    MEMORYSTATUSEX ms = {sizeof(ms)};
    GlobalMemoryStatusEx(&ms);
    return (ms.ullTotalPhys / (1024*1024*1024)) < 4;  // < 4GB
}

BOOL chk_disk(void)
{
    ULARGE_INTEGER total;
    GetDiskFreeSpaceExA("C:\\", 0, &total, 0);
    return (total.QuadPart / (1024*1024*1024)) < 80;  // < 80GB
}

BOOL chk_cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}

BOOL chk_screen(void)
{
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    return (w <= 1024 && h <= 768);  // Low resolution
}

// ============================================================================
// REGISTRY CHECKS
// ============================================================================

BOOL chk_reg_vm(void)
{
    HKEY hk;
    char* keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "SYSTEM\\CurrentControlSet\\Services\\vmci",
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        0
    };

    for(int i = 0; keys[i]; i++) {
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hk) == 0) {
            RegCloseKey(hk);
            return 1;
        }
    }
    return 0;
}

BOOL chk_reg_sandbox(void)
{
    HKEY hk;
    char* keys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie",
        "SYSTEM\\CurrentControlSet\\Services\\SbieDrv",
        "SOFTWARE\\Classes\\Folder\\shell\\sandbox",
        0
    };

    for(int i = 0; keys[i]; i++) {
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hk) == 0) {
            RegCloseKey(hk);
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// FILE CHECKS
// ============================================================================

BOOL chk_vm_files(void)
{
    char* files[] = {
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vmGuestLib.dll",
        "C:\\Windows\\System32\\vm3dgl.dll",
        0
    };

    for(int i = 0; files[i]; i++) {
        if(GetFileAttributesA(files[i]) != INVALID_FILE_ATTRIBUTES)
            return 1;
    }
    return 0;
}

// ============================================================================
// PROCESS CHECKS
// ============================================================================

BOOL chk_analysis_procs(void)
{
    char* procs[] = {
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe",
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "processhacker.exe", "procexp.exe", "procexp64.exe",
        "procmon.exe", "procmon64.exe",
        "wireshark.exe", "fiddler.exe", "tcpview.exe",
        "vmtoolsd.exe", "vmwaretray.exe", "VGAuthService.exe",
        "vboxservice.exe", "vboxtray.exe",
        "sandboxierpcss.exe", "sandboxiedcomlaunch.exe",
        "joeboxcontrol.exe", "joeboxserver.exe",
        "python.exe", "pythonw.exe",  // Often used in analysis
        0
    };

    HANDLE snap = CreateToolhelp32Snapshot(0x2, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};

    if(Process32First(snap, &pe)) {
        do {
            for(int i = 0; procs[i]; i++) {
                if(!_stricmp(pe.szExeFile, procs[i])) {
                    CloseHandle(snap);
                    return 1;
                }
            }
        } while(Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

// ============================================================================
// TIMING CHECKS
// ============================================================================

BOOL chk_sleep_acceleration(void)
{
    DWORD t1 = GetTickCount();
    Sleep(500);
    DWORD t2 = GetTickCount();

    return (t2 - t1) < 450;  // Accelerated sleep
}

BOOL chk_rdtsc_vm(void)
{
    DWORD64 t1 = __rdtsc();

    // Trigger VM exit
    int cpu[4];
    __cpuid(cpu, 0);

    DWORD64 t2 = __rdtsc();

    return (t2 - t1) > 1000;  // VM exits are slow
}

BOOL chk_gettickcount_skip(void)
{
    DWORD t1 = GetTickCount();

    for(volatile int i = 0; i < 100000000; i++);

    DWORD t2 = GetTickCount();

    // Should take some time
    return (t2 - t1) < 10;  // Too fast = hooked/skipped
}

// ============================================================================
// USER ACTIVITY CHECKS
// ============================================================================

BOOL chk_recent_files(void)
{
    WIN32_FIND_DATAA fd;
    char path[MAX_PATH];

    GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH);
    lstrcatA(path, "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*");

    HANDLE h = FindFirstFileA(path, &fd);
    if(h == INVALID_HANDLE_VALUE) return 1;

    int count = 0;
    do { count++; } while(FindNextFileA(h, &fd) && count < 20);
    FindClose(h);

    return count < 5;  // Real users have many recent files
}

BOOL chk_mouse_move(DWORD wait_ms)
{
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(wait_ms);
    GetCursorPos(&p2);

    return (p1.x == p2.x && p1.y == p2.y);  // No movement = sandbox
}

BOOL chk_click_count(void)
{
    // GetKeyboardState won't show history of clicks
    // Check for presence of UI elements instead
    return (GetForegroundWindow() == 0);
}

// ============================================================================
// NETWORK CHECKS
// ============================================================================

BOOL chk_no_internet(void)
{
    HINTERNET h = InternetOpenA("", 0, 0, 0, 0);
    if(!h) return 1;

    HINTERNET c = InternetOpenUrlA(h, "http://www.microsoft.com", 0, 0, 0, 0);
    InternetCloseHandle(h);

    return (c == 0);  // No connectivity
}

BOOL chk_mac_vendor(void)
{
    // Common VM MAC prefixes:
    // VMware: 00:0C:29, 00:50:56, 00:05:69
    // VBox:   08:00:27
    // Hyper-V: 00:15:5D
    // Parallels: 00:1C:42

    // Would need to call GetAdaptersInfo() and check
    return 0;
}

// ============================================================================
// DEVICE CHECKS
// ============================================================================

BOOL chk_devices(void)
{
    HANDLE h;

    // VMware
    h = CreateFileA("\\\\.\\HGFS", 0, 0, 0, OPEN_EXISTING, 0, 0);
    if(h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 1; }

    h = CreateFileA("\\\\.\\vmci", 0, 0, 0, OPEN_EXISTING, 0, 0);
    if(h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 1; }

    // VirtualBox
    h = CreateFileA("\\\\.\\VBoxMiniRdrDN", 0, 0, 0, OPEN_EXISTING, 0, 0);
    if(h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 1; }

    h = CreateFileA("\\\\.\\VBoxGuest", 0, 0, 0, OPEN_EXISTING, 0, 0);
    if(h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 1; }

    return 0;
}

// ============================================================================
// WMI CHECKS
// ============================================================================

BOOL chk_wmi_vm(void)
{
    // Would use COM/WMI to query:
    // Win32_ComputerSystem - Manufacturer, Model
    // Win32_BIOS - SerialNumber, Version
    // Win32_DiskDrive - Model
    // Contains "VBOX", "VMWARE", "VIRTUAL", etc.
    return 0;
}

// ============================================================================
// COMBINED SCORING
// ============================================================================

int sandbox_score(void)
{
    int score = 0;

    if(chk_hypervisor())       score += 15;
    if(chk_vm_vendor())        score += 25;
    if(chk_ram())              score += 10;
    if(chk_disk())             score += 10;
    if(chk_cpu_count())        score += 10;
    if(chk_screen())           score += 5;
    if(chk_reg_vm())           score += 20;
    if(chk_reg_sandbox())      score += 25;
    if(chk_vm_files())         score += 20;
    if(chk_analysis_procs())   score += 30;
    if(chk_sleep_acceleration()) score += 25;
    if(chk_rdtsc_vm())         score += 15;
    if(chk_devices())          score += 25;

    return score;
}

BOOL is_sandbox(void)
{
    return sandbox_score() > 50;
}

// ============================================================================
// EVASION ACTIONS
// ============================================================================

void sandbox_evade(void)
{
    // Delay execution
    Sleep(60000);  // 1 minute delay

    // Wait for mouse movement
    while(chk_mouse_move(3000));

    // Check multiple times
    for(int i = 0; i < 5; i++) {
        if(!is_sandbox()) break;
        Sleep(30000);
    }
}

void sandbox_exit(void)
{
    // Graceful exit - don't trigger alerts
    ExitProcess(0);
}

// ============================================================================
// EOF
// ============================================================================
