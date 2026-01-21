SOLUTIONS - Module 43 : Credential Dumping

AVERTISSEMENT LEGAL : Solutions THEORIQUES uniquement. Implementation complete
credential dumping est ILLEGALE sans autorisation. Contenu educatif DEFENSE uniquement.

Solution 1 : Protection Enumerator (IMPLEMENTATION LEGALE)

Enumeration complete protections credentials Windows.

```c

```c
typedef struct {
```
    BOOL credential_guard_enabled;
    BOOL lsass_ppl_enabled;
    BOOL wdigest_enabled;
    BOOL laps_deployed;
    char os_version[128];
} CredentialProtectionStatus;


```c
void enumerate_credential_protections(CredentialProtectionStatus* status) {
```
    memset(status, 0, sizeof(CredentialProtectionStatus));


```c
    // Version OS
```
    OSVERSIONINFOEX osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&osvi);
    snprintf(status->os_version, sizeof(status->os_version),
             "Windows %lu.%lu Build %lu",
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);


```c
    // Credential Guard
```
    HKEY key;
    DWORD value, size = sizeof(value);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                     0, KEY_READ, &key) == ERROR_SUCCESS) {

        if (RegQueryValueExA(key, "LsaCfgFlags", NULL, NULL,
                            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            status->credential_guard_enabled = (value & 0x01) != 0;
        }

        size = sizeof(value);
        if (RegQueryValueExA(key, "RunAsPPL", NULL, NULL,
                            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            status->lsass_ppl_enabled = (value == 1);
        }

        RegCloseKey(key);
    }


```c
    // WDigest
```
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                     0, KEY_READ, &key) == ERROR_SUCCESS) {

        size = sizeof(value);
        if (RegQueryValueExA(key, "UseLogonCredential", NULL, NULL,
                            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            status->wdigest_enabled = (value == 1);
        }

        RegCloseKey(key);
    }


```c
    // Afficher rapport
```
    printf("\n=== Credential Protection Status ===\n");
    printf("OS Version: %s\n", status->os_version);
    printf("Credential Guard: %s\n",
           status->credential_guard_enabled ? "ENABLED (Protected)" : "DISABLED (Vulnerable)");
    printf("LSASS PPL: %s\n",
           status->lsass_ppl_enabled ? "ENABLED (Protected)" : "DISABLED (Vulnerable)");
    printf("WDigest (plaintext): %s\n",
           status->wdigest_enabled ? "ENABLED (Vulnerable)" : "DISABLED (Secure)");
}
```

Solution 2 : Process Protection Detector (IMPLEMENTATION LEGALE)

Detection systematique processes proteges PPL/PP.

```c

```c
typedef struct {
```
    DWORD pid;
    char name[MAX_PATH];
    BOOL is_protected;
    DWORD denied_access;
} ProcessProtectionInfo;


```c
void enumerate_protected_processes(ProcessProtectionInfo* procs, int* count) {
```
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(PROCESSENTRY32);

    *count = 0;
    if (Process32First(snapshot, &entry)) {
        do {

```c
            // Tenter differents access rights
```
            HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                     FALSE, entry.th32ProcessID);

            procs[*count].pid = entry.th32ProcessID;
            strncpy(procs[*count].name, entry.szExeFile, MAX_PATH);

            if (!proc) {
                DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED) {
                    procs[*count].is_protected = TRUE;
                    procs[*count].denied_access = error;
                }
            } else {
                procs[*count].is_protected = FALSE;
                CloseHandle(proc);
            }

            (*count)++;
        } while (Process32Next(snapshot, &entry) && *count < 256);
    }

    CloseHandle(snapshot);


```c
    // Afficher processes proteges
```
    printf("\n=== Protected Processes Detected ===\n");
    for (int i = 0; i < *count; i++) {
        if (procs[i].is_protected) {
            printf("[PROTECTED] %s (PID: %lu)\n", procs[i].name, procs[i].pid);
        }
    }
}
```

Solution 3 : Privilege Escalation Checker (IMPLEMENTATION LEGALE)

Verification privileges sans actions malveillantes.

```c

```c
void enumerate_token_privileges(void) {
```
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return;
    }

    DWORD length;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &length);

    TOKEN_PRIVILEGES* privileges = (TOKEN_PRIVILEGES*)malloc(length);
    if (!GetTokenInformation(token, TokenPrivileges, privileges, length, &length)) {
        free(privileges);
        CloseHandle(token);
        return;
    }

    printf("\n=== Current Token Privileges ===\n");

    for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
        char name[128];
        DWORD name_len = sizeof(name);

        if (LookupPrivilegeName(NULL, &privileges->Privilege[i].Luid,
                               name, &name_len)) {
            BOOL enabled = (privileges->Privilege[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;

            printf("%-40s %s\n", name, enabled ? "[ENABLED]" : "[DISABLED]");


```c
            // Highlight privileges critiques pour attacks
```
            if (strcmp(name, SE_DEBUG_NAME) == 0 && enabled) {
                printf("  ^ CRITICAL: SeDebugPrivilege allows LSASS access\n");
            }
        }
    }

    free(privileges);
    CloseHandle(token);
}
```

Solution 4 : SAM Database Analysis (THEORIQUE UNIQUEMENT)

Documentation structure SAM - NE PAS extraire reellement.

```
THEORIQUE - Structure SAM Database:

Registry Hives:
├── SAM (HKLM\SAM)
│   └── Contains user account hashes (LM, NTLM)
├── SYSTEM (HKLM\SYSTEM)
│   └── Contains boot key (SysKey) for SAM encryption
└── SECURITY (HKLM\SECURITY)
    └── Contains LSA secrets, cached domain credentials

Hash Storage Format:
Username:RID:LM_Hash:NTLM_Hash:::

Example (benin):
Administrator:500:NO_LM_HASH:31d6cfe0d16ae931b73c59d7e0c089c0:::

NTLM Hash Algorithm:
1. Convert password to UTF-16LE
2. Calculate MD4(password)
3. Result = 128-bit NTLM hash

Extraction Methods (THEORIQUE):
1. Registry export (requires SYSTEM)
2. Shadow Copy (VSS) bypass locks
3. Offline extraction (boot alternative OS)
4. Memory dump (LSASS contains cached)

Mitigations:
- Strong passwords (>15 chars disable LM)
- Account lockout policies
- Monitor SAM/SYSTEM/SECURITY access
- Credential Guard prevents extraction
```

Solution 5 : LSASS Memory Structures (THEORIQUE)

Documentation interne LSASS - NE PAS dumper reellement.

```
THEORIQUE - LSASS Internal Structures:

Security Support Providers (SSP):
├── msv1_0.dll    → NTLM authentication
├── kerberos.dll  → Kerberos tickets
├── wdigest.dll   → Digest authentication (plaintext!)
├── tspkg.dll     → Terminal Services
└── cloudap.dll   → Azure AD authentication

Credential Storage Locations (memoire):
- LogonSessionList (linked list of logon sessions)
- Primary Credentials (username, domain, password/hashes)
- Kerberos Tickets (TGT, service tickets)
- WDigest credentials (plaintext if enabled)

Memory Patterns (detection):
- "lsasrv.dll" signature patterns
- Unicode strings (usernames, domains)
- Hash patterns (32 hex chars for NTLM)
- Kerberos ticket structures

Extraction Flow (THEORIQUE):
1. OpenProcess(LSASS) with PROCESS_VM_READ
2. Enumerate loaded modules (msv1_0.dll, etc.)
3. Search memory patterns (signatures)
4. Parse credential structures
5. Extract hashes/passwords/tickets

Protection Mechanisms:
- PPL (Protected Process Light) blocks OpenProcess
- Credential Guard isolates credentials in VTL1
- LSA Protection prevents memory reading
- EDR monitors LSASS access attempts
```

Solution 6 : Detection Research (IMPLEMENTATION LEGALE - BLUE TEAM)

Configuration Sysmon detection LSASS access.

```xml
<!-- sysmon_lsass_protection.xml -->
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Detect LSASS process access -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
      <!-- Common access rights used for dumping -->
      <GrantedAccess>0x1010</GrantedAccess>
      <GrantedAccess>0x1410</GrantedAccess>
      <GrantedAccess>0x1438</GrantedAccess>
    </ProcessAccess>

    <!-- Detect LSASS dump files -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">lsass</TargetFilename>
      <TargetFilename condition="end with">.dmp</TargetFilename>
    </FileCreate>

    <!-- Detect credential dumping tools -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz</Image>
      <Image condition="contains">procdump</Image>
      <CommandLine condition="contains">sekurlsa</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

Analyse logs apres detection:

```c

```c
void analyze_sysmon_lsass_events(void) {
```
    printf("=== Sysmon Event ID 10 Analysis ===\n\n");
    printf("Key Fields:\n");
    printf("- SourceImage: Process accessing LSASS\n");
    printf("- TargetImage: C:\\Windows\\system32\\lsass.exe\n");
    printf("- GrantedAccess: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)\n");
    printf("- CallTrace: Stack trace showing API calls\n\n");

    printf("Suspicious Indicators:\n");
    printf("1. GrantedAccess 0x1410 or 0x1438\n");
    printf("2. SourceImage from non-system locations\n");
    printf("3. Unusual CallTrace (not expected Windows components)\n");
    printf("4. Correlation with other IOCs (network connections, etc.)\n\n");

    printf("Response Actions:\n");
    printf("1. Isolate affected system\n");
    printf("2. Investigate SourceImage executable\n");
    printf("3. Check for credential usage (lateral movement)\n");
    printf("4. Force password resets for exposed accounts\n");
}
```

Solution 7 : Mimikatz Behavior Analysis (LEGAL - SANDBOX ISOLE)

Analyse comportementale Mimikatz dans environnement controle.

```
COMPORTEMENT MIMIKATZ (OBSERVÉ EN SANDBOX):

API Calls (Process Monitor):
1. OpenProcess(lsass.exe) → PROCESS_VM_READ
2. CreateFileMapping(lsass.exe memory)
3. MapViewOfFile(mapped LSASS)
4. ReadProcessMemory(credential structures)

Registry Access:
- HKLM\SAM\SAM (dump SAM hashes)
- HKLM\SECURITY\Policy\Secrets (LSA secrets)
- HKLM\SYSTEM (boot key extraction)

File System Artifacts:
- Execution from temp directories
- Creation .kirbi files (Kerberos tickets)
- Dump files (lsass.dmp, etc.)

Network Indicators (si module C2):
- DNS queries (update checks)
- HTTP/HTTPS connections (exfiltration)
- SMB connections (lateral movement modules)

Memory Indicators:
- Strings: "sekurlsa", "kerberos", "lsadump"
- Import table: DbgHelp.dll (MiniDumpWriteDump)
- Unusual privileges (SeDebugPrivilege)

Detection Evasion Techniques:
- Process name spoofing
- In-memory execution (no disk artifacts)
- API unhooking (bypass EDR)
- Direct syscalls (bypass ntdll hooks)
```

Solution 8 : Credential Guard Testing (IMPLEMENTATION LEGALE)

Activation et test Credential Guard dans VM test.

```powershell

```bash
# Activer Credential Guard (PowerShell Admin)
# Requires Windows 10 Enterprise/Education, Hyper-V
```


```bash
# Methode 1: Group Policy
```
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1


```bash
# Methode 2: Device Guard/Credential Guard enablement
```
Enable-WindowsOptionalFeature -Online -FeatureName IsolatedUserMode -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorEnforcedCodeIntegrity -NoRestart


```bash
# Redemarrer
```
Restart-Computer


```bash
# Verifier status apres reboot
```
Get-ComputerInfo | Select-Object DeviceGuardSecurityServicesConfigured
```

Test impact:

```c

```c
void test_credential_guard_impact(void) {
```
    printf("=== Testing with Credential Guard Enabled ===\n\n");


```c
    // Tenter dump LSASS (devrait echouer)
```
    DWORD lsass_pid = find_lsass_pid();
    HANDLE proc = OpenProcess(PROCESS_VM_READ, FALSE, lsass_pid);

    if (!proc) {
        printf("[EXPECTED] LSASS access DENIED\n");
        printf("Credential Guard successfully blocking credential extraction\n");
    } else {
        printf("[UNEXPECTED] LSASS access granted!\n");
        printf("Credential Guard may not be properly configured\n");
        CloseHandle(proc);
    }


```c
    // Verifier presence LsaIso.exe (Credential Guard process)
```
    if (find_process_by_name("LsaIso.exe")) {
        printf("[+] LsaIso.exe running (Credential Guard active)\n");
    } else {
        printf("[!] LsaIso.exe NOT found (Credential Guard inactive)\n");
    }
}
```

POINTS CLES DEFENSE

1. Credential Guard = protection ultime (VTL1 isolation)
2. LSASS PPL bloque dumps basiques
3. WDigest desactive = pas plaintext passwords
4. Sysmon Event ID 10 = detection LSASS access
5. Multiple layers defense necessaires

DETECTION COMPLETE STACK

```
Detection Layer 1: Prevention
- Credential Guard (VTL1 isolation)
- LSASS PPL (RunAsPPL)
- Least privilege (minimize SeDebugPrivilege)

Detection Layer 2: Real-time Monitoring
- EDR (LSASS access alerts)
- Sysmon Event ID 10 (ProcessAccess)
- Behavioral analytics (abnormal privileges)

Detection Layer 3: Forensics
- Memory dumps analysis (Volatility)
- Event log correlation (Windows Security)
- File system artifacts (dump files)

Detection Layer 4: Network
- Lateral movement detection
- Credential usage anomalies
- C2 communication patterns
```

INCIDENT RESPONSE CREDENTIAL DUMP

```
Si credential dump detecte:

IMMEDIATE (Minutes):
1. Isoler systeme compromis (network)
2. Identifier comptes exposes
3. Desactiver comptes compromis
4. Alerter SOC/CERT

SHORT-TERM (Hours):
5. Force password reset comptes exposes
6. Audit lateral movement tentatives
7. Analyze malware/tools utilises
8. Containment lateral spread

LONG-TERM (Days):
9. Root cause analysis
10. Improve detection rules
11. Deploy additional mitigations
12. Security awareness training
```

NE JAMAIS OUBLIER : Credential dumping = crime. Education defense uniquement.

