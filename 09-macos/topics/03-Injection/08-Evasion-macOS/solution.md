# MODULE 45 : macOS EVASION - SOLUTIONS

## Check TCC database
```bash
# User TCC
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access"

# System TCC (root)
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access"
```

## Check SIP
```bash
csrutil status
# System Integrity Protection status: enabled

# Lister protections
ls -lO /System
ls -lO /bin
# Devrait montrer "restricted" flag
```

## Examiner entitlements
```bash
# Safari entitlements
codesign -d --entitlements :- /Applications/Safari.app

# App système
codesign -d --entitlements :- /bin/ls

# Entitlements dangereux:
# - com.apple.security.cs.disable-library-validation
# - com.apple.security.cs.allow-unsigned-executable-memory
# - com.apple.security.cs.allow-dyld-environment-variables
```

## TCC Bypass (théorique)
```c
// Technique 1: Synthetic events
// Nécessite com.apple.private.tcc.allow.prompting

// Technique 2: Injection dans app autorisée
// DYLD_INSERT_LIBRARIES dans Zoom.app (si autorisé)

// Technique 3: Exploiter TOCTOU
// Race entre check et use
```

## Evasion EDR
```c
// Syscalls directs (module 42)
// Evite hooks libc

// Obfuscation strings
char cmd[] = {0x6f, 0x70, 0x65, 0x6e, 0x00};  // "open"

// Process hollowing
// Lancer processus légitime, remplacer code
```

## Detection
```bash
# Lister processus suspects
ps aux | grep -v grep

# Lister network connections
lsof -i

# Lister dylibs chargées
vmmap <pid>

# Vérifier signing
codesign -v /path/to/app
```
