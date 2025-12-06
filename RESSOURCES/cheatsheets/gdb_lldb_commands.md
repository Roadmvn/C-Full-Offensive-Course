# Cheatsheet GDB/LLDB - Red Team Edition

## Démarrage et attachement

### GDB
```bash
gdb ./binary                    # Charger binaire
gdb -q ./binary                 # Quiet mode
gdb --args ./binary arg1 arg2   # Avec arguments
gdb -p 1234                     # Attach au PID 1234

# Pendant execution
(gdb) attach 1234               # Attach à process
(gdb) detach                    # Détach sans kill
```

### LLDB (macOS/Linux)
```bash
lldb ./binary                   # Charger binaire
lldb -- ./binary arg1 arg2      # Avec arguments
lldb -p 1234                    # Attach au PID 1234

# Pendant execution
(lldb) process attach --pid 1234
(lldb) process detach
```

## Exécution et contrôle

### GDB
```gdb
run [args]              # Démarrer (ou 'r')
start                   # Break au main() puis run
continue                # Continuer (ou 'c')
step                    # Step into (ou 's')
next                    # Step over (ou 'n')
stepi                   # Step instruction (ou 'si')
nexti                   # Next instruction (ou 'ni')
finish                  # Finir fonction courante
kill                    # Tuer process
quit                    # Quitter (ou 'q')
```

### LLDB
```lldb
run [args]              # Ou 'r'
process launch --stop-at-entry
continue                # Ou 'c'
step                    # Ou 's'
next                    # Ou 'n'
stepi                   # Ou 'si'
nexti                   # Ou 'ni'
finish                  # Ou 'f'
kill
quit                    # Ou 'q'
```

## Breakpoints

### GDB
```gdb
# Par nom de fonction
break main                      # Ou 'b main'
break *0x401000                 # Par adresse
break file.c:42                 # Par ligne
break syscall                   # Sur syscalls

# Conditionnels (utile pour loops)
break main if argc > 2
break *0x401234 if $rax == 0

# Hardware breakpoints (4 max)
hbreak *0x401000
watch *0x7fff00000000           # Break sur write
rwatch *0x7fff00000000          # Break sur read
awatch *0x7fff00000000          # Break sur access

# Gestion
info breakpoints                # Liste (ou 'i b')
delete 1                        # Supprimer BP 1
disable 1                       # Désactiver BP 1
enable 1                        # Activer BP 1
clear main                      # Supprimer BP sur main
```

### LLDB
```lldb
# Par nom
breakpoint set --name main      # Ou 'b main'
breakpoint set --address 0x401000
breakpoint set --file file.c --line 42
breakpoint set --name syscall

# Conditionnels
breakpoint set --name main --condition "argc > 2"

# Watchpoints
watchpoint set expression -- 0x7fff00000000
watchpoint set variable global_var

# Gestion
breakpoint list                 # Ou 'br l'
breakpoint delete 1             # Ou 'br del 1'
breakpoint disable 1
breakpoint enable 1
```

## Inspection mémoire

### GDB
```gdb
# Examiner mémoire (x/[count][format][size] address)
x/10i $rip                      # 10 instructions
x/20xb 0x401000                 # 20 bytes en hex
x/4xg $rsp                      # 4 qwords (64-bit)
x/s 0x404000                    # String
x/10wx $rsp                     # 10 words (32-bit)

# Formats: x(hex) d(decimal) u(unsigned) o(octal) t(binary) a(address) c(char) s(string)
# Sizes:   b(byte) h(halfword/2) w(word/4) g(giant/8)

# Dump mémoire vers fichier
dump binary memory dump.bin 0x400000 0x401000
dump memory shellcode.bin 0x7fff00000000 0x7fff00000100

# Restaurer
restore dump.bin binary 0x400000
```

### LLDB
```lldb
# Examiner mémoire
x/10i $rip                      # 10 instructions
x/20xb 0x401000                 # 20 bytes hex
memory read --size 1 --count 20 --format x 0x401000
memory read --format s 0x404000  # String

# Dump
memory write --infile payload.bin 0x400000
memory read --outfile dump.bin --count 4096 0x400000
```

## Registres

### GDB
```gdb
info registers                  # Tous les registres (ou 'i r')
info registers rax rbx          # Registres spécifiques
print $rax                      # Afficher RAX (ou 'p $rax')
print/x $rax                    # En hexadécimal
set $rax = 0x1337               # Modifier RAX
set $eflags = $eflags | 0x100   # Activer Trap Flag (single-step)

# Registres x64
info registers rax rbx rcx rdx rsi rdi rbp rsp rip
info registers r8 r9 r10 r11 r12 r13 r14 r15
```

### LLDB
```lldb
register read                   # Tous
register read rax rbx           # Spécifiques
register write rax 0x1337       # Modifier
```

## Désassemblage

### GDB
```gdb
disassemble main                # Fonction complète (ou 'disas main')
disassemble 0x401000            # Par adresse
disassemble $rip                # Autour de RIP
disassemble /r main             # Avec opcodes raw
set disassembly-flavor intel    # Syntaxe Intel (sinon AT&T)

# Layout TUI (interface)
layout asm                      # Vue assembly
layout regs                     # Vue registres
layout split                    # Code + assembly
Ctrl+X Ctrl+A                   # Toggle TUI mode
```

### LLDB
```lldb
disassemble --name main         # Ou 'di -n main'
disassemble --pc                # Autour de PC
disassemble --address 0x401000
disassemble --bytes --count 20  # 20 instructions avec bytes
settings set target.x86-disassembly-flavor intel
```

## Stack et backtrace

### GDB
```gdb
backtrace                       # Call stack (ou 'bt')
backtrace full                  # Avec variables locales
frame 0                         # Sélectionner frame (ou 'f 0')
up                              # Frame parent
down                            # Frame enfant
info frame                      # Info frame courant
info locals                     # Variables locales
info args                       # Arguments fonction
```

### LLDB
```lldb
thread backtrace                # Ou 'bt'
thread backtrace all            # Tous les threads
frame select 0                  # Ou 'f 0'
up
down
frame info
frame variable                  # Variables locales
```

## Variables et expressions

### GDB
```gdb
print variable                  # Afficher (ou 'p')
print/x pointer                 # En hexa
print *pointer                  # Déréférence
print array[5]
print struct.member
print sizeof(variable)

# Casting
print (char *)0x404000
print *(long *)$rsp

# Tableau
print *array@10                 # 10 éléments

# Pretty printing structures
set print pretty on
```

### LLDB
```lldb
print variable                  # Ou 'p'
expression variable             # Ou 'expr'
print/x pointer
print *pointer
po object                       # Print object (Objective-C)
```

## Informations binaire

### GDB
```gdb
info functions                  # Liste toutes fonctions
info variables                  # Variables globales
info files                      # Fichiers/sections
info proc mappings              # Memory maps (Linux)
maintenance info sections       # Sections détaillées
info shared                     # Bibliothèques chargées

# Symboles
info address main
info symbol 0x401000
```

### LLDB
```lldb
image list                      # Binaires chargés
image dump sections             # Sections
image lookup --name main        # Info sur symbole
image lookup --address 0x401000
```

## Hooks et scripting

### GDB (Python)
```gdb
# Hook sur breakpoint
commands 1
  print $rax
  continue
end

# Python inline
python print("Hello from GDB")
python gdb.execute("info registers")

# Script Python
source script.py
```

Script GDB Python (`script.py`):
```python
import gdb

class MyBreakpoint(gdb.Breakpoint):
    def stop(self):
        rax = gdb.parse_and_eval("$rax")
        print(f"RAX = {rax}")
        return True  # Stop execution

MyBreakpoint("*0x401234")
```

### LLDB (Python)
```lldb
# Script Python inline
script print("Hello from LLDB")

# Breakpoint avec commandes
breakpoint command add 1
  register read rax
  continue
  DONE

# Charger script
command script import script.py
```

Script LLDB Python (`script.py`):
```python
import lldb

def custom_command(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    rax = frame.FindRegister("rax").GetValueAsUnsigned()
    print(f"RAX = {hex(rax)}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f script.custom_command mycmd')
```

## Threads

### GDB
```gdb
info threads                    # Liste threads
thread 2                        # Switch vers thread 2
thread apply all bt             # Backtrace tous threads
```

### LLDB
```lldb
thread list
thread select 2
thread backtrace all
```

## Patterns et recherche

### GDB
```gdb
# Chercher pattern en mémoire
find 0x400000, 0x500000, 0x90, 0x90, 0x90  # 3x NOP
find /b 0x400000, +0x100000, 0x48, 0x89, 0xe5  # Prologue fonction

# Pattern cyclic (pwntools style)
# Générer: python3 -c "import pwn; print(pwn.cyclic(100))"
```

### LLDB
```lldb
memory find --string "password" --count 1 0x400000 0x500000
```

## Process injection monitoring

### GDB
```gdb
# Catch syscalls spécifiques
catch syscall mmap
catch syscall mprotect
catch syscall execve

# Catch tous syscalls
catch syscall

# Catch signals
catch signal SIGSEGV

# Catch library load
catch load libcrypto.so
```

### LLDB
```lldb
# Breakpoint sur syscalls (indirect)
breakpoint set --name mmap
breakpoint set --name mprotect
```

## Configuration .gdbinit / .lldbinit

### GDB (~/.gdbinit)
```gdb
set disassembly-flavor intel
set pagination off
set print pretty on
set history save on
set history filename ~/.gdb_history

# Auto-load ASLR info
define hook-run
  info proc mappings
end

# Afficher context après chaque step
define hook-stop
  x/5i $rip
  info registers rax rbx rcx rdx rsi rdi
end
```

### LLDB (~/.lldbinit)
```lldb
settings set target.x86-disassembly-flavor intel
settings set target.process.stop-on-exec false

# Afficher désassemblage automatiquement
target stop-hook add
  disassemble --pc
  register read rax rbx rcx rdx rsi rdi
  DONE
```

## Plugins Red Team essentiels

### GDB - pwndbg
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
```

Commandes pwndbg:
```gdb
context                 # Affiche registres/stack/code
vmmap                   # Memory mappings
cyclic 100              # Générer pattern
cyclic -l 0x61616161    # Trouver offset
rop                     # Chercher ROP gadgets
```

### GDB - GEF
```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

### LLDB - Voltron
```bash
pip install voltron
```

## Anti-debugging detection

### GDB
```gdb
# Masquer présence de debugger
set environment LD_PRELOAD=./fake_ptrace.so

# Modifier comportement
catch syscall ptrace
commands
  set $rax = 0
  continue
end
```

## Core dumps

### GDB
```gdb
# Analyser core dump
gdb ./binary core

# Générer core dump
generate-core-file core.manual

# Configuration système
# echo "core" > /proc/sys/kernel/core_pattern
# ulimit -c unlimited
```

### LLDB
```lldb
# Charger core dump
lldb --core core ./binary
```

## Remote debugging

### GDB
```bash
# Sur target (gdbserver)
gdbserver :1234 ./binary

# Sur attacker
gdb ./binary
(gdb) target remote 192.168.1.100:1234
```

### LLDB
```bash
# Debug remote iOS/macOS
lldb
(lldb) platform select remote-ios
(lldb) process connect connect://192.168.1.100:1234
```

## Tips Red Team

```gdb
# 1. Skip ASLR dans tests
set disable-randomization on

# 2. Follow forks (multi-process)
set follow-fork-mode child

# 3. Détection anti-debug bypass
catch syscall ptrace
commands
  set $rax = 0  # Fake success
  continue
end

# 4. Dump shellcode en C array
dump binary memory sc.bin 0x7fff00000000 0x7fff00000100
xxd -i sc.bin

# 5. Chercher ROP gadgets
x/1000i 0x400000 | grep "pop.*ret"

# 6. Monitoring CreateRemoteThread (Windows via Wine + GDB)
break CreateRemoteThread
commands
  print $rdi  # hProcess
  print $rsi  # lpStartAddress
  continue
end
```
