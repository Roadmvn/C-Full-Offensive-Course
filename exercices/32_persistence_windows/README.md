# Windows Persistence - Survivre aux Redémarrages

Registry Run keys, Scheduled Tasks, Windows Services, WMI Event Subscriptions, DLL Hijacking - techniques pour maintenir accès après redémarrage système. Utilisé par APT et ransomwares pour persistance long-terme.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Registry Run key persistence
HKEY hkey;
RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              0, KEY_SET_VALUE, &hkey);
RegSetValueExA(hkey, "MyApp", 0, REG_SZ, (BYTE*)path, strlen(path));
RegCloseKey(hkey);

// Scheduled Task (schtasks)
system("schtasks /create /tn MyTask /tr C:\\malware.exe /sc onlogon /ru SYSTEM");
```

## Compilation

```bash
gcc example.c -o persistence.exe -ladvapi32
```

## Concepts clés

- **Registry Run Keys** : HKCU/HKLM\\...\\Run, RunOnce (démarrage user/system)
- **Scheduled Tasks** : schtasks.exe ou Task Scheduler COM API
- **Windows Services** : CreateService pour exécution SYSTEM
- **WMI Event Subscriptions** : Permanent event consumer (furtif)
- **Startup Folder** : shell:startup, shell:common startup
- **DLL Hijacking** : Remplacer DLL légitime chargée par app
- **COM Hijacking** : Détourner CLSID pour auto-launch

## Techniques utilisées par

- **Emotot** : Registry Run keys + Scheduled Tasks
- **TrickBot** : WMI Event Subscriptions (très furtif)
- **APT29 (Cozy Bear)** : Windows Services + DLL hijacking
- **Ryuk Ransomware** : Scheduled Tasks SYSTEM level
- **Cobalt Strike** : Multiple persistence methods (autoruns)

## Détection et Mitigation

**Indicateurs** :
- Nouvelles entrées Registry Run keys (Autoruns tool)
- Scheduled Tasks suspects (Task Scheduler, schtasks /query)
- Services non-Microsoft (services.msc, sc query)
- WMI subscriptions anormales (Get-WmiObject)
- DLLs non-signées dans System32

**Mitigations** :
- Autoruns (Sysinternals) scan régulier
- AppLocker/WDAC pour whitelist binaires
- Scheduled Tasks monitoring (Sysmon Event ID 4698)
- Service creation alerts (Event ID 7045)
- DLL signature verification
