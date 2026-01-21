SOLUTIONS - Module 44 : Lateral Movement

AVERTISSEMENT LEGAL : Solutions THEORIQUES ou DEFENSE-FOCUSED uniquement.
Execution lateral movement reel est ILLEGALE sans autorisation legale formelle.

Solution 1 : Network Reconnaissance (IMPLEMENTATION LEGALE - lab)

Scanner reseau et enumeration shares dans environnement controle.

```c

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
```


```c
void scan_local_network(void) {
    // Obtenir adresses locales
```
    IP_ADAPTER_INFO adapters[16];
    DWORD size = sizeof(adapters);

    if (GetAdaptersInfo(adapters, &size) != ERROR_SUCCESS) {
        printf("[!] GetAdaptersInfo failed\n");
        return;
    }

    printf("[*] Local network interfaces:\n");

    IP_ADAPTER_INFO* adapter = adapters;
    while (adapter) {
        printf("  - %s\n", adapter->Description);
        printf("    IP: %s\n", adapter->IpAddressList.IpAddress.String);
        printf("    Subnet: %s\n", adapter->IpAddressList.IpMask.String);


```c
        // Scanner subnet (implementation simplifiee)
```
        scan_subnet(adapter->IpAddressList.IpAddress.String,
                   adapter->IpAddressList.IpMask.String);

        adapter = adapter->Next;
    }
}


```c
void scan_subnet(const char* ip, const char* mask) {
```
    printf("[*] Scanning subnet %s/%s\n", ip, mask);


```c
    // Calculer range (simplifie - assume /24)
    char base_ip[16];
```
    strncpy(base_ip, ip, sizeof(base_ip));
    char* last_octet = strrchr(base_ip, '.');
    if (!last_octet) return;

    *last_octet = '\0';


```c
    // Scanner 1-254
```
    for (int i = 1; i < 255; i++) {
        char target[32];
        snprintf(target, sizeof(target), "%s.%d", base_ip, i);


```c
        // Ping rapide (ICMP echo request)
```
        if (ping_host(target)) {
            printf("  [+] Host alive: %s\n", target);


```c
            // Enumerer shares
```
            enumerate_shares_safe(target);
        }
    }
}

BOOL ping_host(const char* target) {

```c
    // Implementation simplifiee via connect timeout
```
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;


```c
    // Timeout court (500ms)
```
    DWORD timeout = 500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(445);  // SMB port
    inet_pton(AF_INET, target, &addr.sin_addr);

    BOOL result = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    closesocket(sock);

    return result;
}
```

Solution 2 : Session Enumeration (IMPLEMENTATION LEGALE)

Enumeration sessions actives pour comprehension topologie.

```c

```c
typedef struct {
    char hostname[256];
    char username[256];
    char client[256];
```
    DWORD session_time;
    BOOL is_admin;
} SessionInfo;


```c
void enumerate_network_sessions(const char** targets, int target_count,
```
                                SessionInfo* sessions, int* session_count) {
    *session_count = 0;

    for (int i = 0; i < target_count; i++) {
        printf("[*] Enumerating sessions on %s\n", targets[i]);

        PSESSION_INFO_10 si = NULL;
        DWORD entries = 0, total = 0;

        wchar_t wtarget[256];
        MultiByteToWideChar(CP_ACP, 0, targets[i], -1, wtarget, 256);

        NET_API_STATUS status = NetSessionEnum(
            wtarget, NULL, NULL, 10,
            (LPBYTE*)&si, MAX_PREFERRED_LENGTH,
            &entries, &total, NULL
        );

        if (status == NERR_Success) {
            for (DWORD j = 0; j < entries && *session_count < 256; j++) {
                strncpy(sessions[*session_count].hostname, targets[i], 255);
                WideCharToMultiByte(CP_ACP, 0, si[j].sesi10_username, -1,
                                   sessions[*session_count].username, 255, NULL, NULL);
                WideCharToMultiByte(CP_ACP, 0, si[j].sesi10_cname, -1,
                                   sessions[*session_count].client, 255, NULL, NULL);
                sessions[*session_count].session_time = si[j].sesi10_time;


```c
                // Detecter admin accounts (simpliste)
```
                sessions[*session_count].is_admin =
                    (strstr(sessions[*session_count].username, "admin") != NULL ||
                     strstr(sessions[*session_count].username, "Administrator") != NULL);

                (*session_count)++;
            }

            NetApiBufferFree(si);
        }
    }


```c
    // Afficher sessions privilegiees
```
    printf("\n[!] Privileged sessions detected:\n");
    for (int i = 0; i < *session_count; i++) {
        if (sessions[i].is_admin) {
            printf("  - %s@%s (from %s)\n",
                   sessions[i].username,
                   sessions[i].hostname,
                   sessions[i].client);
        }
    }
}
```

Solution 3 : Service Analysis (THEORIQUE)

Documentation complete Service Control Manager sans implementation malveillante.

```
THEORIQUE - Service Control Manager (SCM) Analysis:

Architecture:
- services.exe (SCM process)
- Database: HKLM\SYSTEM\CurrentControlSet\Services
- Communication: RPC (135/TCP + dynamic ports)

API Functions:
1. OpenSCManager(target, NULL, SC_MANAGER_ALL_ACCESS)
   - Requires admin privileges
   - Opens handle to SCM database

2. CreateService(scm_handle, name, display, ...)
   - Parameters:
     * dwServiceType: SERVICE_WIN32_OWN_PROCESS
     * dwStartType: SERVICE_DEMAND_START
     * lpBinaryPathName: path to executable
   - Generates Event ID 7045 (Service installed)

3. StartService(service_handle, 0, NULL)
   - Launches service executable
   - Runs as SYSTEM by default

4. ControlService(service_handle, SERVICE_CONTROL_STOP, ...)
   - Stops service

5. DeleteService(service_handle)
   - Removes service from registry

PsExec-like Flow:
1. Connect ADMIN$ share: \\target\ADMIN$
2. Copy binary: copy payload.exe \\target\ADMIN$\temp.exe
3. OpenSCManager(target)
4. CreateService(scm, "TempService", ..., binPath="C:\Windows\temp.exe")
5. StartService(service)
6. Retrieve output via named pipes
7. ControlService(SERVICE_CONTROL_STOP)
8. DeleteService()
9. Delete file from ADMIN$

Detection Points:
- SMB file copy (Sysmon Event ID 11)
- Service creation (Event ID 7045)
- Service with unusual binary path
- Service start/stop in quick succession
- Named pipe creation (Sysmon Event ID 17)

Code Example (DEMO - non-functional):
```c

```c
// NE PAS EXECUTER - DEMO SEULEMENT
```
SC_HANDLE scm = OpenSCManager(target, NULL, SC_MANAGER_CREATE_SERVICE);
if (!scm) {
    printf("[!] OpenSCManager failed (requires admin)\n");
    return;
}

SC_HANDLE service = CreateService(
    scm,
    "DemoService",
    "Demo Service",
    SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
    "C:\\Windows\\system32\\cmd.exe",  // Benign demo
    NULL, NULL, NULL, NULL, NULL
);


```c
// Real malware would start service here
// StartService(service, 0, NULL);
```

CloseServiceHandle(service);
CloseServiceHandle(scm);
```
```

Solution 4 : WMI Execution Research (THEORIQUE)

Documentation WMI sans execution malveillante.

```
THEORIQUE - WMI Remote Execution:

COM Architecture:
- Client: IWbemLocator -> ConnectServer()
- Server: IWbemServices (namespace: \\target\root\cimv2)
- Authentication: CoSetProxyBlanket (NTLM/Kerberos)

Win32_Process.Create Method:
Method signature:
  uint32 Create(
    [in] string CommandLine,
    [in] string CurrentDirectory,
    [in] Win32_ProcessStartup ProcessStartupInformation,
    [out] uint32 ProcessId
  );

Execution Flow:
1. CoInitializeEx(NULL, COINIT_MULTITHREADED)
2. CoInitializeSecurity(...)
3. CoCreateInstance(CLSID_WbemLocator, ...)
4. IWbemLocator->ConnectServer(L"\\\\target\\root\\cimv2", ...)
5. CoSetProxyBlanket(proxy, RPC_C_AUTHN_WINNT, ...)
6. IWbemServices->ExecMethod(L"Win32_Process", L"Create", ...)
7. Process created on target with parent: WmiPrvSE.exe

Detection Indicators:
- RPC traffic to 135/TCP
- DCOM connections (ephemeral ports)
- Sysmon Event ID 1: Parent = WmiPrvSE.exe
- WMI-Activity event logs (Operational)
- Network traffic patterns (authentication + method call)

Command-Line Alternative:
wmic /node:TARGET /user:DOMAIN\user /password:pass process call create "cmd.exe"

PowerShell Alternative:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName TARGET

Mitigations:
- Firewall block RPC (135/TCP) between endpoints
- Disable WMI service where not needed
- Monitor WMI activity (Event Tracing)
- Constrained delegation Kerberos
```

Solution 5 : Pass-the-Hash Mechanics (THEORIQUE UNIQUEMENT)

Comprehension NTLM authentication sans implementation PtH.

```
THEORIQUE - NTLM Authentication Protocol:

Challenge-Response Flow:
1. Client -> Server: NEGOTIATE_MESSAGE
   - Client announces capabilities

2. Server -> Client: CHALLENGE_MESSAGE
   - Server sends 8-byte random challenge

3. Client -> Server: AUTHENTICATE_MESSAGE
   - Client responds with:
     * Response = function(NTLM_Hash, Challenge)
     * Username, Domain, Workstation

Response Calculation:
  Response = DES(NTLM_Hash, Challenge)
  Where NTLM_Hash = MD4(password)

Pass-the-Hash Vulnerability:
- NTLM hash sufficient for authentication
- No need for plaintext password
- Hash can be extracted from LSASS memory

PtH Attack Flow (THEORIQUE):
1. Attacker dumps LSASS on Workstation A
2. Extracts NTLM hash: Administrator:31d6cfe0d16ae931b73c59d7e0c089c0
3. Injects hash into current session (mimikatz: sekurlsa::pth)
4. Uses hash to authenticate to Server B
5. Server challenges, attacker responds correctly using hash
6. Authentication succeeds WITHOUT plaintext password

Tools (THEORIQUE - ne pas utiliser malicieusement):
- Mimikatz: sekurlsa::pth /user:admin /ntlm:<hash> /domain:CORP
- Impacket: psexec.py -hashes :<ntlm_hash> admin@target
- CrackMapExec: cme smb target -u admin -H <ntlm_hash>

Mitigations:
1. Disable NTLM completely (Kerberos-only)
   - GPO: Network security: Restrict NTLM
2. Enable NTLMv2 only (not v1)
3. Credential Guard (hashes inaccessible)
4. LSASS PPL protection
5. Frequent credential rotation
6. Privileged account separation

Detection:
- Event ID 4624 (Logon Type 3 with NTLM)
- Event ID 4776 (NTLM authentication)
- Unusual source IPs for admin accounts
- Concurrent logons from impossible locations
```

Solution 6 : Detection Rule Development (IMPLEMENTATION LEGALE)

Configuration complete Sysmon et SIEM rules.

```xml
<!-- sysmon_lateral_movement.xml -->
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Detect network logons -->
    <NetworkConnect onmatch="include">
      <DestinationPort>445</DestinationPort>  <!-- SMB -->
      <DestinationPort>135</DestinationPort>  <!-- RPC -->
      <DestinationPort>5985</DestinationPort> <!-- WinRM -->
      <DestinationPort>3389</DestinationPort> <!-- RDP -->
    </NetworkConnect>

    <!-- Detect service creation (PsExec-like) -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="is">C:\Windows\System32\services.exe</ParentImage>
      <Image condition="contains">\ADMIN$\</Image>
    </ProcessCreate>

    <!-- Detect WMI execution -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">WmiPrvSE.exe</ParentImage>
      <Image condition="is not">C:\Windows\System32\wbem\scrcons.exe</Image>
    </ProcessCreate>

    <!-- Detect file copy to admin shares -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\ADMIN$\</TargetFilename>
      <TargetFilename condition="contains">\C$\</TargetFilename>
    </FileCreate>

    <!-- Detect named pipe usage (PsExec) -->
    <PipeEvent onmatch="include">
      <PipeName condition="contains">\PSEXESVC</PipeName>
      <PipeName condition="contains">\PAExec</PipeName>
    </PipeEvent>
  </EventFiltering>
</Sysmon>
```

SIEM Correlation Rules:

```python

```bash
# Pseudo-code SIEM rule
```
rule LateralMovementDetection:
    events:
        - event_id: 4624  # Network logon
          logon_type: 3
        - event_id: 4672  # Special privileges
        - event_id: 7045  # Service installation
    condition:
        all events within 60 seconds AND
        source_ip == internal_network AND
        destination == different_host
    severity: HIGH
    action: alert("Lateral movement suspected")
```

Solution 7 : Network Segmentation Analysis (IMPLEMENTATION LEGALE)

Analyse et proposition architecture segmentee.

```
Network Segmentation Design:

Tier 0 (Critical):
├── Domain Controllers
├── Certificate Authorities
├── ADFS servers
└── PAWs (Privileged Access Workstations)

Tier 1 (Servers):
├── Application servers
├── Database servers
├── File servers
└── Management systems

Tier 2 (Workstations):
├── User workstations
├── Laptops
└── VDI infrastructure

Firewall Rules (example):

```bash
# Block lateral movement between workstations
```
Deny: Tier2 -> Tier2 (SMB 445, RPC 135, WinRM 5985)


```bash
# Allow management from PAWs only
```
Allow: Tier0_PAW -> Tier1_Servers (RDP 3389, WinRM 5985)
Deny: * -> Tier0 (except PAWs)


```bash
# Segment application tiers
```
Allow: Tier2 -> Tier1_AppServers (HTTPS 443 only)
Deny: Tier2 -> Tier1_DatabaseServers (no direct DB access)

Implementation (Azure NSG example):
```powershell

```bash
# Block lateral SMB between workstations
```
New-AzNetworkSecurityRuleConfig `
    -Name "DenyLateralSMB" `
    -Priority 100 `
    -Access Deny `
    -Protocol TCP `
    -Direction Inbound `
    -SourceAddressPrefix "VirtualNetwork" `
    -SourcePortRange * `
    -DestinationAddressPrefix "10.0.2.0/24" `  # Workstation subnet
    -DestinationPortRange 445
```
```

Solution 8 : Incident Response Simulation (LEGAL - tabletop exercise)

Playbook complet incident response lateral movement.

```
INCIDENT RESPONSE PLAYBOOK - Lateral Movement


### SCENARIO:
Alert: Sysmon Event ID 10 (LSASS access) on WORKSTATION-01
Follow-up: Event ID 4624 (Network logon) to multiple servers
Timeframe: Last 30 minutes

PHASE 1: DETECTION & TRIAGE (0-15 minutes)
[ ] Verify alert legitimacy
    - Check Sysmon logs for LSASS access details
    - Identify source process (mimikatz, procdump, etc.)
    - Correlate with other alerts

[ ] Determine scope
    - Query SIEM: network logons from WORKSTATION-01
    - Identify all affected systems
    - Check for data exfiltration indicators

[ ] Assess severity
    - Privileged accounts compromised?
    - Critical systems accessed?
    - Data exfiltration occurred?

PHASE 2: CONTAINMENT (15-30 minutes)
[ ] Isolate source system
    - Disable network interface (not power off!)
    - Block at firewall if remote
    - Preserve memory for forensics

[ ] Disable compromised accounts
    - Identify accounts used for lateral movement
    - Disable in Active Directory
    - Force logoff all sessions

[ ] Block attacker infrastructure
    - Identify C2 IPs/domains
    - Block at firewall/proxy
    - Update IOC lists

PHASE 3: INVESTIGATION (30 minutes - 4 hours)
[ ] Collect evidence
    - Memory dump (WORKSTATION-01)
    - Event logs (Security, Sysmon, PowerShell)
    - Network traffic (PCAP if available)
    - File system artifacts

[ ] Timeline reconstruction
    - Initial access vector
    - Credential dumping activity
    - Lateral movement path
    - Actions on objectives

[ ] Identify indicators
    - Malware hashes
    - C2 infrastructure
    - Attacker tools (mimikatz, psexec, etc.)
    - Techniques used (MITRE ATT&CK mapping)

PHASE 4: ERADICATION (4-24 hours)
[ ] Remove malware
    - Scan all affected systems
    - Remove persistence mechanisms
    - Patch vulnerabilities exploited

[ ] Credential rotation
    - Reset all potentially compromised passwords
    - Krbtgt password reset (if domain-wide)
    - Service account passwords
    - Local admin passwords (LAPS)

[ ] Validate clean state
    - Re-scan systems
    - Monitor for re-infection
    - Verify no backdoors remain

PHASE 5: RECOVERY (24-72 hours)
[ ] Restore services
    - Re-enable systems after validation
    - Monitor closely for anomalies
    - Staged rollout (not all at once)

[ ] Update detections
    - Add new IOCs to detection rules
    - Tune SIEM rules based on incident
    - Update EDR policies

[ ] Document lessons learned
    - Root cause analysis
    - Gaps identified
    - Process improvements
    - Security control updates


### COMMUNICATION PLAN:
- IT Management: Immediate notification
- Executive Leadership: Within 1 hour
- Legal/Compliance: If data breach
- External (customers): Per breach notification laws
- Law Enforcement: If criminal activity

POST-INCIDENT:
- Threat intelligence sharing (ISAC, etc.)
- Security awareness training
- Tabletop exercise based on incident
- Implement recommended mitigations
```

POINTS CLES DEFENSE

1. Segmentation = limite blast radius lateral movement
2. Detection rapide (Sysmon + SIEM) = containment efficace
3. Privileged accounts = cibles prioritaires protection
4. Incident response preparedness = reduit dwell time
5. Defense in depth = multiple layers echec acceptable

MITIGATIONS PRIORITAIRES

Immediate (Deploy today):
1. Enable Sysmon avec config lateral movement
2. Centralize logs (SIEM)
3. Deploy LAPS (local admin rotation)
4. Enable SMB signing

Short-term (1-3 months):
5. Network segmentation VLANs
6. PAWs pour admin privilegies
7. Credential Guard sur endpoints critiques
8. 24/7 SOC monitoring

Long-term (3-12 months):
9. Zero Trust architecture
10. Micro-segmentation complete
11. Privileged Access Management (PAM) solution
12. Automated incident response (SOAR)

NE JAMAIS OUBLIER : Lateral movement = activite post-compromise. Prevention
compromise initial (phishing, vulns) = premiere ligne defense.

