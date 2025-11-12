# Module 43 - Credential Dumping

AVERTISSEMENT LEGAL STRICT : Ce module couvre techniques illegales si utilisees sans autorisation. Credential dumping est crime federal dans la plupart pays. Contenu strictement educatif pour comprehension blue team defense. NE JAMAIS EXECUTER sur systemes non autorises.

## Concepts

Credential dumping consiste a extraire credentials (passwords, hashes, tokens) stockes en memoire ou disque par systeme d'exploitation.

### Targets Principaux

**LSASS (Local Security Authority Subsystem Service)**: Process stockant credentials en memoire
**SAM (Security Account Manager)**: Base donnees locale passwords Windows
**NTDS.dit**: Active Directory database (Domain Controllers)
**LSA Secrets**: Credentials caches dans registry

### LSASS Memory Dump

LSASS.exe stocke credentials en clair ou hashes (NTLM, Kerberos tickets) en memoire. Dumping LSASS permet extraction offline.

### Techniques Extraction

**Process Memory Dump**: MiniDumpWriteDump API
**Direct Memory Reading**: ReadProcessMemory sur LSASS
**Kernel Driver**: Acces direct memoire kernel-mode
**Shadow Copies**: VSS pour copier fichiers verrouilles

### Mimikatz Concepts

Mimikatz est outil reference credential dumping. Fonctionnalites:

- sekurlsa::logonpasswords (dump LSASS)
- lsadump::sam (dump SAM database)
- sekurlsa::tickets (extract Kerberos tickets)
- vault::cred (Windows Vault credentials)

### Protection Mechanisms

**Credential Guard**: Virtualisation credentials (Windows 10+)
**LSA Protection**: PPL (Protected Process Light) pour LSASS
**WDigest Disabled**: Windows 8.1+ passwords pas en clair
**LAPS**: Local Administrator Password Solution

### Real-World Attackers

**APT29 (Cozy Bear)**: Credential dumping systematique
**FIN7**: LSASS dump pour lateral movement
**Ryuk Ransomware**: Domain Admin credential theft
**Lazarus Group**: Advanced credential harvesting

## Detection & Mitigation

**EDR Monitoring**: Alertes acces memoire LSASS
**Event Logging**: Event ID 10 (Sysmon ProcessAccess)
**LSASS Protection**: RunAsPPL registry key
**Credential Guard**: Enable sur tous endpoints

## Compilation

```bash
# AVERTISSEMENT : Exemple non-fonctionnel volontairement
# Implementation complete serait illegal

# Windows
cl credential_demo.c /Fe:credential_demo.exe

# Tester detection
sysmon  # Event ID 10 = LSASS access detected
```

## Protected Targets

```
LSASS.exe
- Protected by PPL (si active)
- Requires SeDebugPrivilege
- Monitored by EDR/AV

SAM/SYSTEM/SECURITY registry hives
- Locked by kernel
- Requires SYSTEM privileges
- Shadow copies bypass
```

## Limitations Techniques

- Credential Guard = credentials inaccessibles
- PPL LSASS = dump bloque sans exploit kernel
- EDR detection immediate tentatives acces
- Event logging expose attacker activity

## References

- Tool: Mimikatz (Benjamin Delpy)
- Research: "Credential Dumping" (MITRE ATT&CK T1003)
- Defense: Microsoft Credential Guard Documentation
- Detection: Sysmon Configuration (SwiftOnSecurity)
