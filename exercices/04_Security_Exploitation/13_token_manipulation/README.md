# Windows Token Manipulation - Privilege Escalation

OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser - techniques pour voler tokens, élever privilèges, impersonater users. Utilisé par APT pour lateral movement et escalade SYSTEM.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Token stealing (SYSTEM)
HANDLE hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);
DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                 TokenPrimary, &hNewToken);
CreateProcessWithTokenW(hNewToken, 0, L"cmd.exe", ...);

// Enable SeDebugPrivilege
TOKEN_PRIVILEGES tp;
tp.Privileges[0].Luid = SeDebugPrivilege;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
AdjustTokenPrivileges(hToken, FALSE, &tp, ...);
```

## Compilation

```bash
gcc example.c -o token_manip.exe -ladvapi32
```

## Concepts clés

- **Access Token** : Objet kernel contenant SID user, groupes, privilèges
- **OpenProcessToken** : Ouvrir token d'un processus existant
- **DuplicateTokenEx** : Dupliquer token pour impersonation/primary
- **ImpersonateLoggedOnUser** : Impersonater user sans CreateProcess
- **SeDebugPrivilege** : Nécessaire pour ouvrir processus SYSTEM
- **SeImpersonatePrivilege** : Nécessaire pour CreateProcessWithToken
- **Token Types** : Primary (CreateProcess), Impersonation (threads)
- **Integrity Levels** : Low, Medium, High, SYSTEM

## Techniques utilisées par

- **Mimikatz** : Token stealing pour SYSTEM/domain admin
- **Cobalt Strike** : steal_token, make_token commands
- **APT29 (Cozy Bear)** : Token manipulation pour lateral movement
- **Empire/PowerSploit** : Invoke-TokenManipulation module
- **Meterpreter** : incognito module (token stealing)

## Détection et Mitigation

**Indicateurs** :
- SeDebugPrivilege enabled sur processus non-admin
- Processus créés avec tokens volés (parent PID mismatch)
- OpenProcessToken sur lsass.exe, winlogon.exe
- Sysmon Event ID 10 (ProcessAccess) sur processus SYSTEM
- AdjustTokenPrivileges calls anormaux

**Mitigations** :
- Protected Process Light (PPL) pour lsass
- Credential Guard (virtualize lsass)
- Restreindre SeDebugPrivilege aux admins
- Sysmon monitoring (ProcessAccess, CreateRemoteThread)
- Token Elevation Type vérification (UAC)
