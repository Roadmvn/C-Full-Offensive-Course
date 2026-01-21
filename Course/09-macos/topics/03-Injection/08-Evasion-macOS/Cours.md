# Module 45 : macOS Evasion

## Objectifs
- Bypass TCC (Transparency Consent and Control)
- Exploiter entitlements
- Techniques SIP evasion
- Evader detection EDR

## Théorie

### TCC (Transparency, Consent, Control)

**Protections TCC:**
- Camera/Microphone
- Files and Folders
- Screen Recording
- Accessibility
- Full Disk Access

**Database:**
```
~/Library/Application Support/com.apple.TCC/TCC.db
/Library/Application Support/com.apple.TCC/TCC.db
```

### SIP (System Integrity Protection)

**Protected:**
```
/System
/usr (except /usr/local)
/bin
/sbin
```

**Bypass (technique):**
- Signed binaries avec entitlements
- Injection dans processus autorisé
- Exploitation de bugs SIP

### Entitlements

```xml
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
```

## Pertinence Red Team

### TCC Bypass
- Injection dans app autorisée
- Synthetic clicks (Accessibility)
- Extraction TCC.db

### SIP Evasion
- Exploiter binaires signés Apple
- Dylib hijacking sur apps whitelisted
- Kernel exploits (extrême)

### EDR Evasion
- Obfuscation
- Process hollowing
- Syscalls directs

## Ressources
- TCC Research Papers
- macOS Security Guide
- SIP Bypass Techniques
