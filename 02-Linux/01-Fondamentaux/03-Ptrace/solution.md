# MODULE 18 : DEBUGGING GDB/LLDB - SOLUTIONS

## Exercice 1 : Breakpoints de base

```bash
# Compilation
gcc -g -O0 example.c -o example

# GDB
gdb ./example
(gdb) break main
Breakpoint 1 at 0x401234: file example.c, line 95.
(gdb) break factorial
Breakpoint 2 at 0x401156: file example.c, line 17.
(gdb) run
Starting program: ./example
Breakpoint 1, main () at example.c:95

(gdb) continue
Continuing.
Breakpoint 2, factorial (n=5) at example.c:17

(gdb) info breakpoints
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401234 in main at example.c:95
2       breakpoint     keep y   0x0000000000401156 in factorial at example.c:17

# LLDB
lldb ./example
(lldb) breakpoint set -n main
Breakpoint 1: where = example`main, address = 0x0000000100003e20
(lldb) breakpoint set -n factorial
Breakpoint 2: where = example`factorial, address = 0x0000000100003d40
(lldb) run
(lldb) continue
(lldb) breakpoint list
```

## Exercice 2 : Step et navigation

```gdb
# GDB
(gdb) break main
(gdb) run
(gdb) next          # Avance ligne par ligne (step over)
(gdb) next
(gdb) step          # Entre dans factorial (step into)
(gdb) next          # Dans factorial
(gdb) finish        # Sort de factorial
(gdb) until 105     # Va jusqu'à ligne 105

# LLDB
(lldb) breakpoint set -n main
(lldb) run
(lldb) thread step-over  # ou 'n'
(lldb) thread step-into  # ou 's'
(lldb) thread step-out
```

## Exercice 3 : Examination de variables

```gdb
# GDB
(gdb) break factorial
(gdb) run
(gdb) print n
$1 = 5
(gdb) print/x n
$2 = 0x5
(gdb) print/t n
$3 = 101
(gdb) info locals
n = 5
(gdb) info args
n = 5
(gdb) set var n=10
(gdb) print n
$4 = 10
(gdb) continue

# LLDB
(lldb) breakpoint set -n factorial
(lldb) run
(lldb) print n
(int) $0 = 5
(lldb) frame variable
(int) n = 5
(lldb) expr n = 10
(int) $1 = 10
```

## Exercice 4 : Backtrace et frames

```gdb
# GDB
(gdb) break factorial if n==1
(gdb) run
(gdb) backtrace
#0  factorial (n=1) at example.c:17
#1  0x0000000000401178 in factorial (n=2) at example.c:20
#2  0x0000000000401178 in factorial (n=3) at example.c:20
#3  0x0000000000401178 in factorial (n=4) at example.c:20
#4  0x0000000000401178 in factorial (n=5) at example.c:20
#5  0x0000000000401256 in main () at example.c:99

(gdb) backtrace full
# Affiche aussi les variables locales

(gdb) frame 0
#0  factorial (n=1) at example.c:17
(gdb) info locals
n = 1

(gdb) frame 5
#5  0x0000000000401256 in main () at example.c:99
(gdb) info locals
fact = 0

# LLDB
(lldb) thread backtrace
(lldb) bt
(lldb) frame select 2
(lldb) frame variable
```

## Exercice 5 : Watchpoints

```gdb
# GDB
(gdb) break modify_variable
(gdb) run
(gdb) watch watch_me
Hardware watchpoint 3: watch_me
(gdb) continue
Continuing.

Hardware watchpoint 3: watch_me
Old value = 100
New value = 42
modify_variable (ptr=0x7fffffffe3ec) at example.c:27

# Read watchpoint
(gdb) rwatch variable
# Access watchpoint (read ou write)
(gdb) awatch variable

# Supprimer
(gdb) delete 3

# LLDB
(lldb) breakpoint set -n modify_variable
(lldb) run
(lldb) watchpoint set variable watch_me
Watchpoint created: Watchpoint 1: addr = 0x7ffeefbff4ec size = 4
(lldb) continue
Watchpoint 1 hit:
old value: 100
new value: 42

(lldb) watchpoint delete 1
```

## Exercice 6 : Examination mémoire

```gdb
# GDB
(gdb) break memory_operations
(gdb) run
(gdb) next 3
# À la ligne avec stack_var et heap_var

(gdb) print stack_var
$1 = "Stack variable"
(gdb) print &stack_var
$2 = (char (*)[15]) 0x7fffffffe3d0

(gdb) x/s stack_var
0x7fffffffe3d0: "Stack variable"

(gdb) print heap_var
$3 = 0x555555756260 "Heap variable"

(gdb) x/s heap_var
0x555555756260: "Heap variable"

# Examiner 20 bytes en hex
(gdb) x/20x 0x7fffffffe3d0
0x7fffffffe3d0: 0x63617453  0x6176206b  0x62616972  0x0000656c
...

# Différence adresses
# Stack: 0x7fffffffe3d0 (haute mémoire)
# Heap:  0x555555756260 (basse mémoire)

# Dumper région mémoire
(gdb) dump binary memory stack.bin 0x7fffffffe3d0 0x7fffffffe400
(gdb) dump binary memory heap.bin heap_var heap_var+32

# LLDB
(lldb) memory read stack_var
(lldb) memory read -c 20 stack_var
(lldb) x/20x stack_var
(lldb) memory read -f s heap_var
```

## Exercice 7 : Registres et assembleur

```gdb
# GDB
(gdb) break main
(gdb) run

# Tous les registres
(gdb) info registers
rax            0x401234            4199988
rbx            0x0                 0
rcx            0x7ffff7dd1718      140737351865112
rdx            0x7fffffffe508      140737488348424
rsi            0x7fffffffe4f8      140737488348408
rdi            0x1                 1
rbp            0x7fffffffe410      0x7fffffffe410
rsp            0x7fffffffe3f0      0x7fffffffe3f0
rip            0x401234            0x401234 <main+4>
...

# Registre spécifique
(gdb) print $rax
$1 = 4199988
(gdb) print/x $rip
$2 = 0x401234

# Désassembler
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000401230 <+0>:     push   %rbp
   0x0000000000401231 <+1>:     mov    %rsp,%rbp
=> 0x0000000000401234 <+4>:     sub    $0x20,%rsp
   ...

(gdb) disassemble factorial
Dump of assembler code for function factorial:
   0x0000000000401156 <+0>:     push   %rbp
   0x0000000000401157 <+1>:     mov    %rsp,%rbp
   ...

# Breakpoint sur adresse
(gdb) break *0x401234
Breakpoint 2 at 0x401234: file example.c, line 95.

# Code autour de RIP
(gdb) x/10i $rip
=> 0x401234 <main+4>:   sub    $0x20,%rsp
   0x401238 <main+8>:   mov    %edi,-0x14(%rbp)
   ...

# LLDB
(lldb) register read
(lldb) register read rax
(lldb) disassemble -n main
(lldb) disassemble -a $rip
```

## Exercice 8 : Debugging de crash

```c
// vuln.c
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[32];
    strcpy(buffer, input);  // Pas de vérification!
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable(argv[1]);
    }
    return 0;
}
```

```bash
# Compiler sans protections
gcc -g -fno-stack-protector -z execstack vuln.c -o vuln

# GDB avec input malveillant
gdb ./vuln
(gdb) run $(python3 -c 'print("A"*100)')
Starting program: ./vuln AAAAAAAAAA...

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()

# Examiner registres
(gdb) info registers
rax            0x7fffffffe3b0      ...
rsp            0x7fffffffe418      ...
rip            0x414141414141      0x414141414141
                                   ^^^^ Écrasé par 'AAAA'!

# Examiner stack
(gdb) x/40x $rsp
0x7fffffffe418: 0x41414141  0x41414141  0x41414141  0x41414141
0x7fffffffe428: 0x41414141  0x41414141  0x41414141  0x41414141
...

# Identifier où commence le buffer
(gdb) backtrace
Cannot access memory at address 0x414141414141

# Trouver offset exact
(gdb) run $(python3 -c 'print("A"*40 + "BBBB")')
# Si RIP = 0x42424242, offset = 40
```

## BONUS : Configuration et automation

```bash
# ~/.gdbinit
set disassembly-flavor intel
set pagination off
set confirm off

define hook-stop
    info registers
    x/5i $rip
end

alias -a xx = x/10x
alias -a ii = x/10i $rip

# Script GDB
# script.gdb
break main
run
print "Starting analysis..."
backtrace
info registers
continue

# Utilisation
gdb -x script.gdb ./program

# Installer pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Lancer avec pwndbg
gdb ./program
pwndbg> context  # Affichage complet
pwndbg> cyclic 100  # Générer pattern
```

## Script Python pour GDB

```python
# exploit_helper.py
import gdb

class FindROPGadget(gdb.Command):
    """Find ROP gadgets in binary"""
    
    def __init__(self):
        super(FindROPGadget, self).__init__("rop-find", 
                                             gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        # Obtenir le binaire
        inferior = gdb.selected_inferior()
        
        # Rechercher gadget
        # (Implémentation simplifiée)
        print(f"Searching for: {arg}")

FindROPGadget()

# Utilisation dans GDB:
# (gdb) source exploit_helper.py
# (gdb) rop-find "pop rdi"
```

NOTES:
- Toujours compiler avec -g pour symboles complets
- -O0 empêche les optimisations qui compliquent le debug
- TUI mode: Ctrl+X puis A (ou gdb -tui)
- Dans LLDB, gui lance interface graphique
- Pour Windows: utiliser WinDbg ou x64dbg
