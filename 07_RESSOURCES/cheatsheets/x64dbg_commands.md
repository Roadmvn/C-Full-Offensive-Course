# Cheatsheet x64dbg - Red Team Edition

## Interface et navigation

### Fenêtres principales
```
CPU Panel:
- Désassemblage (instructions)
- Registres
- Dump (mémoire hexadécimale)
- Stack

Autres fenêtres:
- Memory Map (View → Memory Map)
- Call Stack (View → Call Stack)
- Handles (View → Handles)
- Threads (View → Threads)
- Symbols (View → Symbols)
```

### Raccourcis essentiels
```
F2              - Toggle breakpoint
F7              - Step into
F8              - Step over
F9              - Run
Ctrl+F9         - Run until return
Ctrl+F2         - Restart
Alt+F9          - Execute until user code
Ctrl+G          - Go to address/expression
Ctrl+F          - Find pattern
Ctrl+B          - Binary search
Ctrl+E          - Edit value
Space           - Assemble instruction
```

## Breakpoints

### Types de breakpoints
```
F2                          - Software breakpoint (INT3)
Hardware breakpoint:
  Right-click → Breakpoint → Hardware, Execute
  Right-click → Breakpoint → Hardware, Write
  Right-click → Breakpoint → Hardware, Read

Memory breakpoint:
  Memory Map → Right-click section → Set Memory Breakpoint
```

### Commandes breakpoint (Command Bar)
```
bp address                  - Set breakpoint
bp module.function          - BP sur fonction
bp kernel32.CreateProcessA
bc address                  - Clear breakpoint
bd address                  - Disable breakpoint
be address                  - Enable breakpoint
bpl                         - List breakpoints

# Conditional breakpoints
bp address, condition
bp 0x401234, rax == 0x1337
bp kernel32.VirtualAlloc, arg.1 > 1000  # Si size > 1000

# Hardware breakpoints (4 max)
bph address, r              - Read
bph address, w              - Write
bph address, x              - Execute
```

## Inspection mémoire

### Memory Dump
```
# Dans fenêtre Dump
Ctrl+G                      - Go to address
Right-click → Follow in Dump → Selection
Right-click → Follow in Dump → Address
Right-click → Binary → Edit
Right-click → Binary → Fill
Right-click → Binary → Copy
```

### Commandes dump
```
dump address                - Afficher mémoire à adresse
d rax                       - Dump à adresse dans RAX
db address                  - Dump bytes
dw address                  - Dump words
dd address                  - Dump dwords
dq address                  - Dump qwords
```

### Recherche en mémoire
```
Ctrl+B                      - Binary search
Ctrl+F                      - Find pattern

# Dans Command Bar
find pattern, address       - Chercher pattern
findall pattern             - Chercher partout
findallmem pattern          - Chercher dans toute la mémoire

# Exemples
findall #90909090#          - 4x NOP
findall "password"          - String
findallmem &48 8B EC&       - Opcodes (mov rbp, rsp)
```

## Registres

### Modification registres
```
# Dans panneau Registers
Double-click sur valeur     - Modifier
Right-click → Increment     - Incrémenter
Right-click → Decrement     - Décrémenter
Right-click → Zero          - Mettre à 0
Right-click → Follow in Dump

# Commandes
r                           - Show registers
r rax=0x1337               - Set RAX
r rip=0x401234             - Changer EIP/RIP
```

### Flags (EFLAGS/RFLAGS)
```
Double-click sur flag       - Toggle
Flags:
  ZF (Zero Flag)
  CF (Carry Flag)
  SF (Sign Flag)
  OF (Overflow Flag)
  TF (Trap Flag)            - Single-step mode
```

## Désassemblage

### Navigation
```
Ctrl+G                      - Go to address
Enter sur CALL              - Follow call
Backspace                   - Retour arrière
-                           - Go back
+                           - Go forward

Right-click → Follow:
  - Follow in Disassembler
  - Follow in Dump
  - Follow CALL/JMP
```

### Analyse
```
Right-click → Analysis:
  - Analyse module
  - Analyse function
  - Remove analysis

Right-click → Labels:
  - Label current address
  - Comment
  - Bookmark
```

### Assembly inline
```
Space                       - Assemble at cursor
a rax, 0x1337              - Assemble: mov rax, 0x1337
a nop                       - Insert NOP

# Patch multiple instructions
Right-click → Binary → Edit
Right-click → Binary → Fill with NOPs
```

## Stack

### Navigation stack
```
Right-click → Follow in Disassembler
Right-click → Follow in Dump
Right-click → Modify
Double-click valeur         - Follow address

# Commandes
dps rsp                     - Dump stack pointers
```

## Memory Map

### Sections importantes
```
View → Memory Map

Colonnes:
- Address: Adresse de base
- Size: Taille
- Protection: RWX permissions
- Type: Private/Mapped/Image
- Module: DLL/EXE associé

# Trouver sections
Chercher sections RWX (shellcode injection)
Chercher sections RW (data)
.text section (code)
```

### Dump sections
```
Right-click → Dump Memory to File
Right-click → Set Memory Breakpoint
Right-click → Find Pattern
```

## Commandes utiles

### Execution control
```
run / r                     - Run
pause                       - Pause
stop                        - Stop
sti / StepInto              - Step into (F7)
sto / StepOver              - Step over (F8)
rtr / RunToReturn           - Run until return
rtu / RunToUser             - Run until user code
```

### Information
```
dis address                 - Disassemble
dis rip                     - Disassemble à RIP
mod                         - List modules
asm instruction             - Assemble instruction
cmt address, "comment"      - Add comment
lbl address, "label"        - Add label
```

### Call Stack
```
View → Call Stack
Double-click pour naviguer
Identifie la chaîne d'appels
```

## Scripts et automation

### Script commands (.txt)
```
# Créer script.txt:
bp kernel32.VirtualAlloc
run
log "VirtualAlloc called: {arg.1}"
bc kernel32.VirtualAlloc
run

# Exécuter
File → Run Script → script.txt
```

### Commandes de logging
```
log "Message"
log "RAX = {rax}"
log "Arg1 = {arg.1}"
logfile "C:\output.txt"
```

## API Monitoring

### Breakpoints sur API Windows critiques
```
# Process injection
bp kernel32.CreateRemoteThread
bp kernel32.WriteProcessMemory
bp ntdll.NtCreateThreadEx
bp kernel32.VirtualAllocEx

# Memory operations
bp kernel32.VirtualAlloc
bp kernel32.VirtualProtect
bp ntdll.NtAllocateVirtualMemory
bp ntdll.NtProtectVirtualMemory

# Code injection
bp kernel32.LoadLibraryA
bp kernel32.LoadLibraryW
bp ntdll.LdrLoadDll

# Registry
bp advapi32.RegOpenKeyExA
bp advapi32.RegSetValueExA

# Network
bp ws2_32.connect
bp ws2_32.send
bp ws2_32.recv

# File operations
bp kernel32.CreateFileA
bp kernel32.WriteFile
bp kernel32.ReadFile
```

### Conditional API monitoring
```
# Break seulement si allocation > 1MB
bp kernel32.VirtualAlloc, arg.2 > 0x100000

# Break si lpAddress spécifique
bp kernel32.WriteProcessMemory, arg.2 == 0x400000

# Log arguments
bp kernel32.CreateFileA
log "CreateFileA: {arg.1}"
```

## Plugins essentiels

### ScyllaHide (Anti-Anti-Debug)
```
Plugins → ScyllaHide → Options
- Hide PEB fields
- NtQueryInformationProcess
- OutputDebugString
- Timing checks
```

### xAnalyzer (Analysis)
```
Plugins → xAnalyzer
- Automatic API call analysis
- Argument names
- Return types
```

### OllyDumpEx (Dumping)
```
Plugins → OllyDumpEx
- Dump process
- Fix IAT
- Unpack
```

## Patching

### Modifier instructions
```
Space                       - Assemble
Right-click → Binary → Edit
Right-click → Binary → Fill with NOPs
Right-click → Patches → Patch File
```

### Sauvegarder patches
```
File → Patch File
Sélectionner modifications
Apply patches
```

## Anti-Analysis Bypass

### Détection de debugger
```
# IsDebuggerPresent bypass
bp kernel32.IsDebuggerPresent
sto  # Step over
r rax=0  # Force return FALSE

# NtQueryInformationProcess bypass
bp ntdll.NtQueryInformationProcess
# Modifier résultat après execution

# Timing checks bypass
# Modifier TSC (Time Stamp Counter)
bp rdtsc
# Ajuster RAX:RDX après
```

### PEB Flags
```
# PEB.BeingDebugged à 0
dump fs:[30h]              # 32-bit
dump gs:[60h]              # 64-bit
# Modifier offset +0x2 à 0x00

# NtGlobalFlag
# Offset +0x68 dans PEB (32-bit)
# Offset +0xBC dans PEB (64-bit)
# Set to 0x00
```

## Expressions et conditions

### Opérateurs
```
==  !=  <  >  <=  >=       - Comparaison
&&  ||  !                   - Logique
+  -  *  /  %              - Arithmétique
&  |  ^  ~                 - Bitwise
```

### Variables spéciales
```
rax, rbx, rcx, ...         - Registres
arg.1, arg.2, ...          - Arguments (calling convention)
ret                         - Return value
cip                         - Current instruction pointer
csp                         - Current stack pointer
```

### Exemples conditions
```
bp address, rax > 0 && rbx < 0x1000
bp address, arg.1 != 0
bp address, [rsp] == 0x401234  # Top of stack
```

## Shellcode Analysis

### Identifier shellcode
```
# Chercher patterns shellcode
findallmem #EBFE#          - jmp short (infinite loop)
findallmem #FFE4#          - jmp rsp
findallmem #C3#            - ret

# Encoder patterns (XOR, etc.)
findallmem #31C0#          - xor eax, eax
findallmem #99#            - cdq

# Syscalls
findallmem #0F05#          - syscall (x64)
findallmem #CD80#          - int 0x80 (x86)
```

### Dump shellcode
```
# Dans Memory Map
Chercher RWX pages
Right-click → Dump Memory to File
Analyser avec scdbg/speakeasy
```

## Import/Export Table

### IAT Hooking detection
```
# View IAT
Symbols → Imports
Chercher addresses suspectes (hors module)

# Comparer avec version légitime
bp sur imports suspects
Vérifier si redirected
```

## Tips Red Team

### 1. Skip fonctions anti-debug
```
# Mettre RIP après le check
Ctrl+G → address après check
Right-click → New Origin Here
```

### 2. Dump processus unpacké
```
# Attendre OEP (Original Entry Point)
View → Memory Map
Right-click .text → Dump Memory to File
Utiliser PE reconstruction tools
```

### 3. Extract strings
```
Right-click → Search for → String references
Chercher IP, URLs, registry keys
```

### 4. Monitor API calls
```
Debug → Call Log
Active API call logging
Filter par module (kernel32, ntdll, etc.)
```

### 5. Trace execution
```
Debug → Run Trace
Enregistre toutes instructions exécutées
Analyse control flow
```

### 6. Hardware breakpoint sur write
```
# Détecter self-modifying code
Memory Map → Find RWX section
Right-click address → Hardware, Write
Trigger quand code se modifie
```

### 7. Conditional logging
```
bp VirtualAlloc
log "Alloc size: {arg.2}, protect: {arg.3}"
```

### 8. Breakpoint sur exceptions
```
Options → Preferences → Exceptions
Break on specific exceptions:
- Access Violation (C0000005)
- Guard Page (80000001)
```

## Configuration recommandée

### Options → Preferences
```
Events:
  ☑ System Breakpoint
  ☑ Entry Breakpoint
  ☐ DLL Load/Unload (bruyant)

Engine:
  ☑ Save Database
  ☑ Enable debug privilege
  ☑ Break on TLS callbacks

Disasm:
  ☑ Uppercase
  ☑ Show jump lines
  ☑ Show registers
```

## Commandes avancées

### Recherche de gadgets ROP
```
# Dans Command Bar
ropfind "pop rax # ret"
ropfind "pop rdi # ret"
ropfind "syscall"

# Via plugin
Plugins → Rp++ → Search gadgets
```

### Memory allocation tracking
```
# Script pour tracer allocations
bp VirtualAlloc
log "VirtualAlloc: addr={rax}, size={arg.2}"
run

bp VirtualAllocEx
log "VirtualAllocEx: remote_addr={rax}, size={arg.4}"
run
```

### Detect code caves
```
Memory Map
Chercher sections avec 0x00 patterns
Right-click → Find Pattern → 00 00 00 00
Identifier caves >= 200 bytes (pour shellcode)
```
