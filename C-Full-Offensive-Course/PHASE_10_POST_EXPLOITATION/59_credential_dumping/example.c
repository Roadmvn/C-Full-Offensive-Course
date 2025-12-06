// EDUCATIONAL ONLY - LSASS Access Detection Demo
// AVERTISSEMENT LEGAL : Code volontairement incomplet et non-fonctionnel
// Implementation complete serait illegale sans autorisation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

// Note: Ce code NE DUMP PAS credentials reellement
// Il demontre uniquement detection et protections

// Trouver PID LSASS
DWORD find_lsass_pid(void) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed\n");
        return 0;
    }

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (_stricmp(entry.szExeFile, "lsass.exe") == 0) {
            pid = entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return pid;
}

// Verifier si SeDebugPrivilege active
BOOL check_debug_privilege(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return FALSE;
    }

    PRIVILEGE_SET privileges = {0};
    privileges.PrivilegeCount = 1;
    privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privileges.Privilege[0].Luid = luid;
    privileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result;
    PrivilegeCheck(token, &privileges, &result);
    CloseHandle(token);

    return result;
}

// Tenter activer SeDebugPrivilege
BOOL enable_debug_privilege(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printf("[!] OpenProcessToken failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[!] LookupPrivilegeValue failed\n");
        CloseHandle(token);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges failed (error: %lu)\n", GetLastError());
        CloseHandle(token);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] SeDebugPrivilege not available (need admin)\n");
        CloseHandle(token);
        return FALSE;
    }

    CloseHandle(token);
    printf("[+] SeDebugPrivilege enabled\n");
    return TRUE;
}

// Detecter LSASS protection (PPL)
BOOL is_lsass_protected(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        printf("[!] Cannot open LSASS (error: %lu)\n", GetLastError());
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            printf("[!] LSASS likely protected by PPL (RunAsPPL)\n");
            return TRUE;
        }
        return FALSE;
    }

    // Tenter PROCESS_VM_READ (bloque si PPL)
    CloseHandle(process);
    process = OpenProcess(PROCESS_VM_READ, FALSE, pid);

    if (!process) {
        printf("[!] PROCESS_VM_READ denied - LSASS is PPL protected\n");
        return TRUE;
    }

    CloseHandle(process);
    printf("[+] LSASS NOT protected by PPL (dump theoriquement possible)\n");
    return FALSE;
}

// Demonstrer tentative dump LSASS (NON-FONCTIONNEL)
int attempt_lsass_dump_demo(DWORD pid) {
    printf("\n[*] Attempting LSASS memory dump (DEMO - non-functional)...\n");
    printf("[!] AVERTISSEMENT: Real implementation would be illegal\n\n");

    // Tenter ouvrir process LSASS
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  FALSE, pid);

    if (!process) {
        DWORD error = GetLastError();
        printf("[!] OpenProcess failed (error: %lu)\n", error);

        if (error == ERROR_ACCESS_DENIED) {
            printf("[!] Access denied - Possible causes:\n");
            printf("    - LSASS protected by PPL (RunAsPPL)\n");
            printf("    - Insufficient privileges\n");
            printf("    - EDR blocking access\n");
        }

        return -1;
    }

    printf("[+] LSASS process opened (handle: 0x%p)\n", process);
    printf("[!] In real attack, would call MiniDumpWriteDump here\n");
    printf("[!] EDR would detect this immediately (Sysmon Event ID 10)\n");

    // NE PAS dumper reellement - juste fermer handle
    CloseHandle(process);

    printf("\n[*] Demo complete - no actual dump performed\n");
    return 0;
}

// Lister protections actives
void enumerate_protections(void) {
    printf("\n[*] Enumerating credential protections...\n\n");

    // Check Credential Guard
    HKEY key;
    DWORD value;
    DWORD size = sizeof(value);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                     0, KEY_READ, &key) == ERROR_SUCCESS) {

        // LsaCfgFlags = 1 (Credential Guard enabled)
        if (RegQueryValueExA(key, "LsaCfgFlags", NULL, NULL,
                            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value & 0x01) {
                printf("[!] Credential Guard: ENABLED (credentials protected)\n");
            } else {
                printf("[+] Credential Guard: DISABLED (vulnerable)\n");
            }
        }

        // RunAsPPL = 1 (LSASS PPL protection)
        size = sizeof(value);
        if (RegQueryValueExA(key, "RunAsPPL", NULL, NULL,
                            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value == 1) {
                printf("[!] LSASS PPL Protection: ENABLED (dump blocked)\n");
            } else {
                printf("[+] LSASS PPL Protection: DISABLED (dumpable)\n");
            }
        }

        RegCloseKey(key);
    }

    // Check WDigest (plaintext passwords)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                     0, KEY_READ, &key) == ERROR_SUCCESS) {

        size = sizeof(value);
        if (RegQueryValueExA(key, "UseLogonCredential", NULL, NULL,
                            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            if (value == 1) {
                printf("[+] WDigest: ENABLED (plaintext passwords in memory)\n");
            } else {
                printf("[!] WDigest: DISABLED (only hashes available)\n");
            }
        } else {
            printf("[!] WDigest: DISABLED by default (Windows 8.1+)\n");
        }

        RegCloseKey(key);
    }
}

int main(void) {
    printf("========================================\n");
    printf("  LSASS Access Detection Demo\n");
    printf("========================================\n");
    printf("AVERTISSEMENT LEGAL STRICT:\n");
    printf("  Code educatif uniquement\n");
    printf("  Implementation complete serait illegale\n");
    printf("  NE JAMAIS executer sans autorisation\n");
    printf("========================================\n\n");

    // Verifier si admin
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group;

    if (AllocateAndInitializeSid(&nt_authority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    if (!is_admin) {
        printf("[!] Not running as administrator\n");
        printf("[!] SeDebugPrivilege requires admin rights\n\n");
    } else {
        printf("[+] Running as administrator\n\n");
    }

    // Enumerer protections
    enumerate_protections();

    // Trouver LSASS
    printf("\n[*] Searching for lsass.exe...\n");
    DWORD lsass_pid = find_lsass_pid();

    if (lsass_pid == 0) {
        printf("[!] Could not find lsass.exe\n");
        return 1;
    }

    printf("[+] LSASS found (PID: %lu)\n", lsass_pid);

    // Verifier privileges
    printf("\n[*] Checking SeDebugPrivilege...\n");
    if (!check_debug_privilege()) {
        printf("[~] SeDebugPrivilege not enabled, attempting to enable...\n");
        if (!enable_debug_privilege()) {
            printf("[!] Failed to enable SeDebugPrivilege\n");
            printf("[!] Cannot proceed without debug privileges\n");
            return 1;
        }
    } else {
        printf("[+] SeDebugPrivilege already enabled\n");
    }

    // Verifier protection LSASS
    printf("\n[*] Checking LSASS protection status...\n");
    is_lsass_protected(lsass_pid);

    // Demo tentative dump (non-fonctionnel)
    attempt_lsass_dump_demo(lsass_pid);

    printf("\n========================================\n");
    printf("BLUE TEAM DETECTION:\n");
    printf("  - Sysmon Event ID 10 (ProcessAccess)\n");
    printf("  - EDR alerts on LSASS access\n");
    printf("  - Behavior analytics (LSASS dump = IOC)\n");
    printf("========================================\n");

    printf("\nMITIGATIONS:\n");
    printf("  1. Enable Credential Guard\n");
    printf("  2. Enable LSASS PPL (RunAsPPL)\n");
    printf("  3. Deploy EDR with LSASS protection\n");
    printf("  4. Monitor Event ID 10 (Sysmon)\n");
    printf("  5. Implement least privilege\n");

    return 0;
}

#else
// Non-Windows platform
int main(void) {
    printf("Credential dumping concepts are Windows-specific\n");
    printf("Compile on Windows with: cl example.c\n");
    return 1;
}
#endif
