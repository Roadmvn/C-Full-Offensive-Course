# ROP Chains - Return-Oriented Programming

ROP (Return-Oriented Programming), gadgets, stack pivoting - technique exploitation avancée pour bypass DEP/NX en réutilisant code existant. Permet exécution arbitraire sans injecter shellcode.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Vulnerable program
void vuln() {
    char buf[64];
    gets(buf);  // Buffer overflow - ROP exploit
}

// ROP chain example (x64)
payload = b'A' * 72              // Overflow to RIP
payload += p64(pop_rdi_ret)       // Gadget: pop rdi ; ret
payload += p64(binsh_addr)        // "/bin/sh" address
payload += p64(system_addr)       // Call system("/bin/sh")
```

## Compilation

```bash
# Disable protections for learning
gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space  # Disable ASLR
```

## Concepts clés

- **ROP (Return-Oriented Programming)** : Exploit via code reuse
- **Gadgets** : Instruction sequences ending with `ret`
- **ROP Chain** : Sequence of gadgets to achieve goal
- **DEP/NX Bypass** : Execute existing code (not data)
- **ret2libc** : Call libc functions (system, execve)
- **Stack Pivoting** : Redirect RSP to controlled memory
- **ASLR Bypass** : Information leak + calculation

## Techniques utilisées par

- **Advanced exploits** : Modern vulnerability exploitation
- **CTF challenges** : ROP is standard technique
- **APT malware** : Sophisticated exploits use ROP
- **Zero-day exploits** : Bypass modern mitigations
- **Browser exploits** : JIT-ROP, information disclosure

## Détection et Mitigation

**Indicateurs** :
- Abnormal stack patterns
- Frequent small code snippets execution
- Indirect calls to unusual addresses
- Excessive `ret` instructions execution

**Mitigations** :
- CFI (Control Flow Integrity)
- Shadow Stack (Intel CET)
- ASLR + PIE (high entropy)
- Stack Canaries
- FORTIFY_SOURCE
- Return address encryption
