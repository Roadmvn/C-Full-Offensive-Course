# MODULE 19 : DEBUGGING WINDOWS - SOLUTIONS

## x64dbg
```
bp main
F9 (run)
F8 (step over)
bp CreateFileA
Follow parameters in dump
```

## Bypass anti-debug
```
bp IsDebuggerPresent
F9
r eax=0  (set register)
F9
```

## WinDbg
```
lm              # List modules
r               # Registers
bp main
g               # Go
k               # Stack trace
db rsp          # Dump bytes
u main          # Unassemble
```

## API Monitor
- Filter: File Management, Registry
- Monitor New Process
- Observe CreateFileA, WriteFile calls
- Export log for analysis
