# SOLUTION : CODE SIGNING & PAC


```bash
# Vérifier signature Safari
```
codesign -dv /Applications/Safari.app


```bash
# Voir entitlements
```
codesign -d --entitlements - /Applications/Safari.app


```bash
# Code ARM64 avec PAC (fichier .s)
```
.global _main
_main:
    PACIASP                    // Sign LR
    stp x29, x30, [sp, #-16]!
    
    mov x0, #42
    
    ldp x29, x30, [sp], #16
    AUTIASP                    // Authenticate LR
    ret


```bash
# Compilation
```
clang -o prog prog.s
./prog


