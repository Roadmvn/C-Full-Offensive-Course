# Setup Debugging Environment - Multi-Platform

## Vue d'ensemble

Configuration complète GDB, LLDB, x64dbg pour debugging multi-plateforme.

## GDB (Linux)

### Installation
```bash
# Debian/Ubuntu
sudo apt install gdb gdb-multiarch

# Arch
sudo pacman -S gdb

# Build from source (latest)
wget https://ftp.gnu.org/gnu/gdb/gdb-13.2.tar.gz
tar xf gdb-13.2.tar.gz && cd gdb-13.2
./configure --with-python=/usr/bin/python3
make -j$(nproc)
sudo make install
```

### Extensions essentielles

#### pwndbg (recommandé)
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Usage
gdb ./binary
pwndbg> context
pwndbg> vmmap
pwndbg> checksec
```

#### GEF (alternative)
```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Usage
gdb ./binary
gef> heap chunks
gef> rop
```

#### peda (legacy mais utile)
```bash
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

### Configuration ~/.gdbinit

```bash
cat << 'EOF' > ~/.gdbinit
# Load pwndbg
source ~/pwndbg/gdbinit.py

# Syntaxe Intel
set disassembly-flavor intel

# Pas de pagination
set pagination off

# Historique
set history save on
set history filename ~/.gdb_history
set history size 10000

# Pretty printing
set print pretty on
set print array on
set print array-indexes on

# Suivre child process après fork
set follow-fork-mode child

# Disable ASLR dans GDB (pour debugging)
set disable-randomization on

# Auto-load .gdbinit local (securité)
set auto-load safe-path /

# Custom commands
define hook-stop
    info registers
    x/5i $rip
end

# Aliases
alias -a disas = disassemble
alias -a cc = continue
alias -a si = stepi
alias -a ni = nexti
EOF
```

### Remote debugging

```bash
# Sur target (gdbserver)
gdbserver :1234 ./binary

# Sur attacker
gdb ./binary
(gdb) target remote 192.168.1.100:1234
(gdb) continue
```

## LLDB (macOS/Linux)

### Installation

```bash
# macOS (inclus avec Xcode)
xcode-select --install

# Linux
sudo apt install lldb

# Build from source
git clone https://github.com/llvm/llvm-project.git
cd llvm-project
cmake -S llvm -B build -G Ninja -DLLVM_ENABLE_PROJECTS="clang;lldb"
ninja -C build
```

### Configuration ~/.lldbinit

```bash
cat << 'EOF' > ~/.lldbinit
# Syntaxe Intel
settings set target.x86-disassembly-flavor intel

# Pas de confirmation pour quit
settings set target.process.stop-on-exec false

# Hook auto pour afficher contexte
target stop-hook add
    register read
    disassemble --pc --count 5
    DONE

# Aliases
command alias si thread step-inst
command alias ni thread step-inst-over
command alias cc process continue
command alias regs register read

# Custom command pour vmmap
command script import lldb.macosx.heap
EOF
```

### Extensions Voltron (UI)

```bash
# Installer Voltron
pip3 install voltron

# Lancer Voltron server
voltron init

# Dans terminaux séparés
voltron view register
voltron view disasm
voltron view stack
voltron view backtrace

# Dans LLDB
lldb ./binary
(lldb) run
```

### Remote debugging

```bash
# Sur target
lldb-server platform --listen 0.0.0.0:1234

# Sur attacker
lldb
(lldb) platform select remote-macosx  # ou remote-linux
(lldb) platform connect connect://192.168.1.100:1234
(lldb) process attach --pid 1234
```

## x64dbg (Windows)

### Installation

1. Télécharger: https://x64dbg.com/
2. Extraire dans `C:\Tools\x64dbg`
3. Lancer `x64dbg.exe`

### Plugins essentiels

#### ScyllaHide (anti-anti-debug)
```
Télécharger: https://github.com/x64dbg/ScyllaHide/releases
Extraire dans: C:\Tools\x64dbg\plugins\

Configuration:
  - Plugins → ScyllaHide → Options
  - Activer toutes protections
```

#### xAnalyzer
```
Télécharger: https://github.com/ThunderCls/xAnalyzer/releases
Extraire dans: C:\Tools\x64dbg\plugins\
```

#### OllyDumpEx
```
Pour dumper process depuis mémoire
https://low-priority.appspot.com/ollydumpex/
```

### Configuration x64dbg

```
Options → Preferences:

Events:
  ☑ System Breakpoint
  ☑ Entry Breakpoint
  ☐ DLL Load/Unload
  ☑ Thread Start/End

Engine:
  ☑ Save Database
  ☑ Enable Debug Privilege
  ☑ Break on TLS Callbacks

Disassembler:
  ☑ Uppercase
  ☑ Show Jump Lines
  ☑ Tabs

GUI:
  Theme: Dark (optionnel)
```

### Scripts x64dbg

Créer `C:\Tools\x64dbg\scripts\monitor_api.txt`:
```
// Monitor CreateRemoteThread
bp CreateRemoteThread
log "CreateRemoteThread called"
log "hProcess: {arg.1}"
log "lpStartAddress: {arg.3}"
run

// Monitor VirtualAllocEx
bp VirtualAllocEx
log "VirtualAllocEx: size={arg.2}, protect={arg.4}"
run
```

Exécuter: `File → Run Script`

## WinDbg (Windows)

### Installation

```
Microsoft Store → WinDbg Preview
Ou: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
```

### Configuration

Créer `C:\Users\<user>\.windbgrc`:
```
.sympath SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
.symfix
.reload

* Syntaxe Intel
.asm no_code_bytes
.asm intel_syntax

* Auto commands
sxe ld:ntdll
sxe ld:kernel32
```

### Extensions

```
# PYKD (Python scripting)
.load pykd

# MEX (Memory Explorer)
https://www.microsoft.com/en-us/download/details.aspx?id=53304
.load mex
!mex.grep
```

## Configuration multi-debugger

### Terminal multiplexer (tmux)

```bash
# ~/.tmux.conf pour debugging
cat << 'EOF' > ~/.tmux-debug.conf
# Split automatique
split-window -h
split-window -v
select-pane -t 0

# Commandes auto
send-keys -t 0 'gdb ./binary' C-m
send-keys -t 1 'tail -f /tmp/debug.log' C-m
send-keys -t 2 'htop' C-m
EOF

# Usage
tmux -f ~/.tmux-debug.conf
```

## Debugging Docker containers

```bash
# Lancer container avec capabilities
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it ubuntu

# GDB remote via container
docker run -p 1234:1234 ubuntu gdbserver :1234 ./binary

# Depuis host
gdb ./binary
(gdb) target remote localhost:1234
```

## Core dumps

### Linux
```bash
# Activer core dumps
ulimit -c unlimited
echo "core.%e.%p" | sudo tee /proc/sys/kernel/core_pattern

# Analyser
gdb ./binary core.binary.1234
(gdb) bt
(gdb) info registers
```

### macOS
```bash
# Core dumps location
~/Library/Logs/DiagnosticReports/

# Analyser avec LLDB
lldb -c core_file
(lldb) bt
```

### Windows
```
# Activer crash dumps
Panneau → Système → Avancé → Démarrage et récupération

# Analyser avec WinDbg
windbg -z C:\Windows\MEMORY.DMP
```

## Debugging multi-process

### GDB (follow fork)
```bash
gdb ./binary
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) run

# Lister inferiors
(gdb) info inferiors

# Switch
(gdb) inferior 2
```

### LLDB
```bash
(lldb) settings set target.process.follow-fork-mode child
(lldb) run
```

## Anti-debugging bypasses

### Linux/GDB
```bash
# Bypass ptrace check
(gdb) catch syscall ptrace
(gdb) commands
  > set $rax = 0
  > continue
  > end

# Bypass RDTSC
(gdb) catch syscall rdtsc
# Ou patch binary
```

### Windows/x64dbg
```
# Bypass IsDebuggerPresent
bp IsDebuggerPresent
Set RAX=0 à return

# Bypass PEB check
Dump PEB, modifier BeingDebugged à 0
```

## Cheatsheet commandes

### GDB
```
run                    # Lancer
break *0x401234        # BP à adresse
continue               # Continuer
stepi / nexti          # Step instruction
info registers         # Registres
x/20xg $rsp           # Dump stack
disassemble            # Désassembler
```

### LLDB
```
run                    # Lancer
br s -a 0x401234      # BP
continue               # Continuer
stepi / nexti          # Step
register read          # Registres
memory read $rsp       # Dump
disassemble            # Désassembler
```

### x64dbg
```
F9                     # Run
F2                     # Toggle BP
F7 / F8                # Step into/over
Ctrl+G                 # Go to address
Ctrl+F                 # Find pattern
```

## Ressources

- [GDB Cheatsheet](https://darkdust.net/files/GDB%20Cheatsheet.pdf)
- [LLDB Tutorial](https://lldb.llvm.org/use/tutorial.html)
- [x64dbg Documentation](https://help.x64dbg.com/)
