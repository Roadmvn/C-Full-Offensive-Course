⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 35 : REGISTRY MANIPULATION

[ ] 1. HIDE ENCRYPTED PAYLOAD
Stocker payload chiffré dans registry :
- XOR encrypt shellcode
- REG_BINARY dans HKCU\Software\Microsoft\Windows\CurrentVersion
- Nom valeur aléatoire (GUID-like)
- Read + decrypt à l'exécution
- Delete après usage

Référence : Emotet config storage

[ ] 2. PERSISTENCE MULTI-KEYS
Multiples Run keys persistence :
- HKCU\...\Run
- HKCU\...\RunOnce
- HKLM\...\Run (si admin)
- Startup folder registry pointer
- Vérifier si déjà présent avant set

Référence : TrickBot persistence techniques

[ ] 3. REGISTRY DATA EXFILTRATION
Lire données sensibles registry :
- HKLM\SAM (SAM database hashes)
- HKCU\Software\Microsoft\Terminal Server Client\Servers (RDP history)
- Run keys (installed malware)
- Uninstall registry (software installed)
- Export to file

Référence : Post-exploitation enumeration

[ ] 4. STEALTH REGISTRY MODIFICATION
Techniques discrétion :
- Timestamp manipulation (SetFileTime sur registry file)
- Hidden registry keys (null byte tricks)
- Alternate Data Streams registry
- RegNotifyChangeKeyValue eviter
- Minimal writes (batch operations)

Référence : APT registry stealth

[ ] 5. REGISTRY ROOTKIT HIDING
Cacher présence dans registry :
- Hook RegQueryValueEx
- Filter results (remove malicious entries)
- NtQueryKey hooking (kernel-level)
- Return STATUS_OBJECT_NAME_NOT_FOUND pour nos keys
- Bypass Autoruns/RegShot

Référence : ZeroAccess rootkit

[ ] 6. C2 CONFIG IN REGISTRY
Configuration C2 dans registry :
- IP/domain REG_SZ encodé (base64)
- Port REG_DWORD
- Sleep interval REG_DWORD
- Encryption key REG_BINARY
- Update config sans recompile

Référence : Carberp C2 config

[ ] 7. REGISTRY FORENSICS EVASION
Éviter détection forensics :
- RegDeleteKey (vraiment supprimé ?)
- Overwrite avant delete (wipe)
- USN Journal manipulation
- Transaction Registry (TxR) pour atomicity
- Vérifier registry slack space

Référence : Registry forensics anti-analysis

[ ] 8. CROSS-PROCESS REGISTRY IPC
Communication inter-process via registry :
- Process A write REG_BINARY message
- Process B RegNotifyChangeKeyValue
- Callback read message
- Mutex synchronization
- Delete message après read

Référence : Stuxnet registry IPC


### NOTES :
- Admin requis pour HKLM modifications
- Sysmon Event 12/13/14 détecte registry ops
- Autoruns détecte persistence keys
- RegShot compare registry snapshots
- Process Monitor trace registry activity

