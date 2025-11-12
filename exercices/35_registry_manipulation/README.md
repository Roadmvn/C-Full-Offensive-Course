# Windows Registry Manipulation - Data Hiding & Persistence

RegOpenKeyEx, RegSetValueEx, RegQueryValueEx - techniques pour hiding data dans registry, persistence, forensics evasion. Utilisé par malwares pour stocker configuration et persistence.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Hide data in registry
HKEY hkey;
RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows", 0, KEY_SET_VALUE, &hkey);
BYTE data[] = {0x41, 0x42, 0x43};  // Hidden payload
RegSetValueExA(hkey, "HiddenData", 0, REG_BINARY, data, sizeof(data));
RegCloseKey(hkey);

// Read hidden data
DWORD type, size = 256;
BYTE buffer[256];
RegQueryValueExA(hkey, "HiddenData", NULL, &type, buffer, &size);
```

## Compilation

```bash
gcc example.c -o reg_manip.exe -ladvapi32
```

## Concepts clés

- **HKEY_CURRENT_USER** : User-level storage (pas admin requis)
- **HKEY_LOCAL_MACHINE** : System-level (nécessite admin)
- **REG_BINARY** : Stocker données binaires (payloads chiffrés)
- **REG_SZ** : Strings (URLs C2, paths)
- **Persistence Run keys** : Auto-start applications
- **Null-byte injection** : Cacher valeurs dans names
- **Alternate locations** : Clés peu visitées (obscure)

## Techniques utilisées par

- **Emotot** : Registry Run keys persistence + config
- **TrickBot** : REG_BINARY pour modules chiffrés
- **APT28 (Fancy Bear)** : Registry pour configuration C2
- **Carberp** : Hiding binary blobs dans registry
- **ZeroAccess** : Rootkit config dans registry

## Détection et Mitigation

**Indicateurs** :
- Nouvelles Run keys (Autoruns scan)
- REG_BINARY suspectes dans locations anormales
- Valeurs avec noms longs/aléatoires
- Modifications fréquentes registry keys
- Process Monitor registry writes anormaux

**Mitigations** :
- Autoruns (Sysinternals) scan régulier
- RegShot comparaison avant/après
- Process Monitor monitoring registry ops
- Sysmon Event ID 12, 13, 14 (Registry)
- Backup registry régulier (reg export)
