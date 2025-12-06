// EDUCATIONAL ONLY - Lateral Movement Detection Demo
// AVERTISSEMENT LEGAL : Code demonstratif uniquement - NE PAS utiliser malicieusement
// Implementation complete lateral movement serait ILLEGALE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")

// Note: Ce code NE PERFORME PAS lateral movement reel
// Il demontre uniquement concepts et detection

// Verifier connectivite SMB vers target
int check_smb_connectivity(const char* target) {
    printf("[*] Checking SMB connectivity to %s...\n", target);

    // Construire UNC path vers ADMIN$ share
    char unc_path[512];
    snprintf(unc_path, sizeof(unc_path), "\\\\%s\\ADMIN$", target);

    // Tenter connection (THEORIQUE - ne fonctionne que si credentials valides)
    NETRESOURCEA resource = {0};
    resource.dwType = RESOURCETYPE_DISK;
    resource.lpRemoteName = unc_path;

    DWORD result = WNetAddConnection2A(&resource, NULL, NULL, 0);

    if (result == NO_ERROR) {
        printf("[+] SMB connection successful to %s\n", target);
        WNetCancelConnection2A(unc_path, 0, TRUE);
        return 0;
    } else {
        printf("[!] SMB connection failed (error: %lu)\n", result);

        switch (result) {
            case ERROR_ACCESS_DENIED:
                printf("    - Access denied (invalid credentials)\n");
                break;
            case ERROR_BAD_NETPATH:
                printf("    - Network path not found (target unreachable)\n");
                break;
            case ERROR_INVALID_PASSWORD:
                printf("    - Invalid password\n");
                break;
            case ERROR_LOGON_FAILURE:
                printf("    - Logon failure\n");
                break;
        }

        return -1;
    }
}

// Enumerer shares sur target (reconnaissance)
void enumerate_shares(const char* target) {
    printf("\n[*] Enumerating shares on %s...\n", target);

    PSHARE_INFO_1 shares = NULL;
    DWORD entries_read = 0;
    DWORD total_entries = 0;

    wchar_t wtarget[256];
    MultiByteToWideChar(CP_ACP, 0, target, -1, wtarget, 256);

    NET_API_STATUS status = NetShareEnum(
        wtarget,
        1,
        (LPBYTE*)&shares,
        MAX_PREFERRED_LENGTH,
        &entries_read,
        &total_entries,
        NULL
    );

    if (status != NERR_Success) {
        printf("[!] NetShareEnum failed (error: %lu)\n", status);
        return;
    }

    printf("[+] Found %lu shares:\n", entries_read);

    for (DWORD i = 0; i < entries_read; i++) {
        wprintf(L"  - %s (%s)\n", shares[i].shi1_netname, shares[i].shi1_remark);

        // Identifier shares critiques
        if (wcscmp(shares[i].shi1_netname, L"ADMIN$") == 0 ||
            wcscmp(shares[i].shi1_netname, L"C$") == 0 ||
            wcscmp(shares[i].shi1_netname, L"IPC$") == 0) {
            wprintf(L"    ^ CRITICAL: Administrative share\n");
        }
    }

    NetApiBufferFree(shares);
}

// Enumerer sessions actives sur target
void enumerate_sessions(const char* target) {
    printf("\n[*] Enumerating active sessions on %s...\n", target);

    PSESSION_INFO_10 sessions = NULL;
    DWORD entries_read = 0;
    DWORD total_entries = 0;

    wchar_t wtarget[256];
    MultiByteToWideChar(CP_ACP, 0, target, -1, wtarget, 256);

    NET_API_STATUS status = NetSessionEnum(
        wtarget,
        NULL,
        NULL,
        10,
        (LPBYTE*)&sessions,
        MAX_PREFERRED_LENGTH,
        &entries_read,
        &total_entries,
        NULL
    );

    if (status != NERR_Success) {
        printf("[!] NetSessionEnum failed (error: %lu)\n", status);
        printf("    - Requires admin privileges on target\n");
        return;
    }

    printf("[+] Found %lu active sessions:\n", entries_read);

    for (DWORD i = 0; i < entries_read; i++) {
        wprintf(L"  - Client: %s, User: %s, Time: %lu sec\n",
               sessions[i].sesi10_cname,
               sessions[i].sesi10_username,
               sessions[i].sesi10_time);
    }

    NetApiBufferFree(sessions);
}

// Demonstrer WMI connection (THEORIQUE)
void demonstrate_wmi_connection(const char* target) {
    printf("\n[*] WMI Connection Demonstration (THEORIQUE)\n");
    printf("[!] Real WMI execution would trigger EDR alerts\n\n");

    printf("WMI Execution Flow:\n");
    printf("1. Connect to namespace: \\\\%s\\root\\cimv2\n", target);
    printf("2. Authenticate with credentials\n");
    printf("3. Execute WQL query or method\n");
    printf("4. Example: Win32_Process.Create(\"cmd.exe /c command\")\n");
    printf("5. Retrieve output via WMI event subscription\n\n");

    printf("Detection Indicators:\n");
    printf("- Network traffic to RPC ports (135/TCP)\n");
    printf("- DCOM connections (dynamic high ports)\n");
    printf("- WMI process creation (Sysmon Event ID 1)\n");
    printf("- Parent process: WmiPrvSE.exe\n");
}

// Demonstrer PsExec-like service creation (THEORIQUE)
void demonstrate_psexec_flow(const char* target) {
    printf("\n[*] PsExec-like Flow Demonstration (THEORIQUE)\n");
    printf("[!] Real service creation would be malicious\n\n");

    printf("PsExec Execution Steps:\n");
    printf("1. Connect to \\\\%s\\ADMIN$ share\n", target);
    printf("2. Copy executable to C:\\Windows\\<random>.exe\n");
    printf("3. Connect to Service Control Manager (SCM)\n");
    printf("4. Create service: sc \\\\%s create <service_name> binPath=...\n", target);
    printf("5. Start service: sc \\\\%s start <service_name>\n", target);
    printf("6. Retrieve output via named pipes (\\\\%s\\pipe\\<name>)\n", target);
    printf("7. Stop service and delete\n\n");

    printf("Detection Indicators:\n");
    printf("- SMB file copy to ADMIN$ (Sysmon Event ID 11)\n");
    printf("- Service creation (Event ID 7045)\n");
    printf("- Service with unusual binary path\n");
    printf("- Named pipe creation/access\n");
}

// Enumerer services remote (reconnaissance)
void enumerate_remote_services(const char* target) {
    printf("\n[*] Enumerating services on %s (THEORIQUE)...\n", target);
    printf("[!] Requires admin privileges and SCM access\n\n");

    printf("Services of Interest:\n");
    printf("- RemoteRegistry (remote registry access)\n");
    printf("- WinRM (Windows Remote Management)\n");
    printf("- RpcSs (RPC endpoint mapper)\n");
    printf("- WMI (Windows Management Instrumentation)\n\n");

    printf("DETECTION: Service enumeration generates Event ID 4656/4658\n");
}

// Analyser detection mechanisms
void analyze_detection_mechanisms(void) {
    printf("\n=== Lateral Movement Detection Mechanisms ===\n\n");

    printf("1. Network Detection:\n");
    printf("   - IDS/IPS signatures for SMB/RPC abuse\n");
    printf("   - Unusual traffic patterns (admin to admin)\n");
    printf("   - Port scanning detection (445, 135, 3389)\n\n");

    printf("2. Host-Based Detection:\n");
    printf("   - Event ID 4624 (Logon Type 3 - Network)\n");
    printf("   - Event ID 4648 (Explicit credential usage)\n");
    printf("   - Event ID 4672 (Special privileges assigned)\n");
    printf("   - Event ID 7045 (Service installation)\n\n");

    printf("3. Endpoint Detection:\n");
    printf("   - Sysmon Event ID 1 (Process creation from network)\n");
    printf("   - Sysmon Event ID 3 (Network connections)\n");
    printf("   - Sysmon Event ID 11 (File creation in ADMIN$)\n");
    printf("   - Sysmon Event ID 13 (Registry modifications)\n\n");

    printf("4. Behavioral Analytics:\n");
    printf("   - Credential usage anomalies\n");
    printf("   - Lateral movement graph analysis\n");
    printf("   - Time-based anomalies (off-hours access)\n");
    printf("   - Geo-location impossibilities\n");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Lateral Movement Detection Demo\n");
    printf("========================================\n");
    printf("AVERTISSEMENT LEGAL STRICT:\n");
    printf("  Code demonstratif uniquement\n");
    printf("  Lateral movement reel est ILLEGAL\n");
    printf("  NE JAMAIS executer sans autorisation\n");
    printf("========================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <target_ip_or_hostname>\n", argv[0]);
        printf("\nNote: This is a DETECTION demonstration tool\n");
        printf("      It shows what attackers do, not how to attack\n\n");
        return 1;
    }

    const char* target = argv[1];

    printf("[*] Target: %s\n", target);
    printf("[*] Purpose: Demonstrate detection mechanisms\n\n");

    // Reconnaissance (legal - passive)
    printf("=== RECONNAISSANCE PHASE ===\n");
    enumerate_shares(target);
    enumerate_sessions(target);

    // Demonstrate attack flows (THEORIQUE)
    printf("\n=== ATTACK FLOW DEMONSTRATIONS (THEORIQUE) ===\n");
    demonstrate_wmi_connection(target);
    demonstrate_psexec_flow(target);
    enumerate_remote_services(target);

    // Detection analysis
    analyze_detection_mechanisms();

    printf("\n=== BLUE TEAM RECOMMENDATIONS ===\n\n");
    printf("Prevention:\n");
    printf("1. Network segmentation (VLANs, firewalls)\n");
    printf("2. Disable SMBv1, enable SMB signing\n");
    printf("3. Limit admin accounts (PAM, LAPS)\n");
    printf("4. MFA for RDP/remote access\n");
    printf("5. Application whitelisting\n\n");

    printf("Detection:\n");
    printf("1. Deploy Sysmon with comprehensive config\n");
    printf("2. Centralize logs (SIEM)\n");
    printf("3. Monitor lateral movement patterns\n");
    printf("4. Alert on admin share access\n");
    printf("5. Baseline normal behavior\n\n");

    printf("Response:\n");
    printf("1. Isolate affected systems\n");
    printf("2. Disable compromised accounts\n");
    printf("3. Analyze attack path (BloodHound)\n");
    printf("4. Credential rotation\n");
    printf("5. Forensic analysis\n");

    return 0;
}

#else
// Non-Windows platform
int main(void) {
    printf("Lateral movement concepts are Windows-specific\n");
    printf("Compile on Windows with: cl example.c -lnetapi32\n");
    return 1;
}
#endif
