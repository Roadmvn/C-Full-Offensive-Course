# Module 44 - Lateral Movement

AVERTISSEMENT LEGAL STRICT : Lateral movement est technique attaque reseau illegale sans autorisation. Contenu strictement educatif pour comprehension blue team defense. NE JAMAIS executer sur reseaux non autorises.

## Concepts

Lateral movement consiste a se deplacer d'un systeme compromis vers d'autres systemes du reseau en exploitant credentials volees et services Windows.

### Techniques Principales

**PsExec**: Execution remote via SMB + Service Control Manager
**WMI/WMIC**: Windows Management Instrumentation execution
**Pass-the-Hash**: Authentification avec hash NTLM (sans plaintext password)
**RDP Hijacking**: Session hijacking Terminal Services
**DCOM**: Distributed COM execution

### PsExec Mechanism

```
Attacker Machine
    |
    v
1. Connect to ADMIN$ share (SMB)
2. Upload executable to C:\Windows
3. Create service via SCM (Service Control Manager)
4. Start service remotely
5. Retrieve output via named pipes
```

### Pass-the-Hash Attack

Permet authentification Windows avec hash NTLM sans connaitre password plaintext. Exploite NTLM authentication protocol.

### WMI Execution

Windows Management Instrumentation permet execution commandes remote via DCOM protocol.

```powershell
wmic /node:TARGET process call create "cmd.exe /c command"
```

### Real-World Campaigns

**APT29 (Cozy Bear)**: WMI persistence et lateral movement
**FIN7**: PsExec-like tools pour propagation ransomware
**NotPetya**: SMB exploitation lateral spread
**Ryuk Ransomware**: Credential dumping + PsExec deployment

### Network Protocols

**SMB (445/TCP)**: File sharing, ADMIN$ share, IPC$
**RPC (135/TCP)**: Remote Procedure Calls, WMI
**WinRM (5985/5986)**: Windows Remote Management
**RDP (3389/TCP)**: Remote Desktop Protocol

## Detection & Mitigation

**Network Segmentation**: Limiter lateral movement paths
**Privileged Access Management**: Limiter admin credentials
**Event Monitoring**: Event ID 4624 (Logon Type 3), 4648 (Explicit credentials)
**SMB Signing**: Prevent SMB relay attacks

## Compilation

```bash
# AVERTISSEMENT : Exemple demonstratif uniquement
# Implementation complete serait illegale

# Windows
cl lateral_demo.c /Fe:lateral_demo.exe -lnetapi32

# Test detection
# Monitorer avec Sysmon, Wireshark
```

## Network Indicators

```
Lateral Movement IOCs:
- Multiple failed logon attempts (Event ID 4625)
- Logon Type 3 (Network) from unusual sources
- Admin shares access (ADMIN$, C$, IPC$)
- Service creation remote (Event ID 7045)
- WMI process creation (Sysmon Event ID 1)
- RDP logons from internal IPs
```

## Limitations

- Requires administrative credentials
- Highly detectable (network traffic, event logs)
- Firewall rules can block protocols
- EDR detects suspicious lateral movement patterns

## References

- MITRE ATT&CK: T1021 (Remote Services)
- Tool: PsExec (Sysinternals)
- Research: "Pass-the-Hash" (SANS Institute)
- Detection: Windows Event Log Analysis
