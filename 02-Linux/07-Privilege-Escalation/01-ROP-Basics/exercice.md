⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 38 : ROP CHAINS

[ ] 1. GADGET FINDER
Trouver gadgets dans binaire :
- Use ROPgadget --binary ./vuln
- Find pop rdi ; ret
- Find pop rsi ; ret
- Find pop rdx ; ret
- Find syscall ; ret
- Save addresses for ROP chain

Référence : ROPgadget, ropper tools

[ ] 2. BASIC RET2WIN
Simple ROP : overflow to win() function :
- Calculate offset to saved RIP
- Overflow buffer with padding
- Overwrite RIP with win_function address
- No gadgets needed (direct call)
- Verify execution reaches win()

Référence : ROP Emporium ret2win

[ ] 3. RET2LIBC EXPLOITATION
Call system("/bin/sh") via libc :
- Find system() address in libc
- Find "/bin/sh" string in libc
- Build payload: pop_rdi + binsh + system
- Send payload via buffer overflow
- Get shell

Référence : Classic ret2libc attack

[ ] 4. FULL ROP CHAIN (EXECVE)
Build complete ROP chain for execve syscall :
- pop rdi ; ret  -> "/bin/sh"
- pop rsi ; ret  -> NULL
- pop rdx ; ret  -> NULL
- pop rax ; ret  -> 59 (execve)
- syscall ; ret
- Test exploitation

Référence : x64 syscall conventions

[ ] 5. ASLR BYPASS (INFO LEAK)
Bypass ASLR via information disclosure :
- Exploit format string or read() to leak libc address
- Calculate libc base from leak
- Find system/binsh offsets from base
- Build ROP chain with calculated addresses
- Exploit with ASLR enabled

Référence : ASLR bypass techniques

[ ] 6. STACK PIVOTING
Redirect RSP to controlled memory :
- Find xchg rsp, rax ; ret gadget
- Control RAX with ROP
- Pivot stack to heap/bss
- Execute ROP chain from new stack
- Useful when stack space limited

Référence : Stack pivoting exploitation

[ ] 7. SIGROP (SIGRETURN ROP)
Use sigreturn for arbitrary register control :
- Setup rt_sigreturn frame on stack
- Call sigreturn syscall (rax=15)
- Control all registers (rdi, rsi, rdx, rip)
- Execute execve with full control
- One gadget technique

Référence : SROP exploitation (pwntools)

[ ] 8. JIT-ROP (ADVANCED)
Dynamic ROP in presence of randomization :
- Read executable memory to find gadgets
- Build ROP chain at runtime
- Adapt to ASLR addresses
- Chain read + execute primitives
- Advanced browser exploit technique

Référence : JIT-ROP paper, browser exploits


### NOTES :
- Disable ASLR: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
- Compile vulnerable: gcc -fno-stack-protector -z execstack -no-pie vuln.c
- Use pwntools for exploitation
- GDB + pwndbg for debugging
- CFI/CET defeats ROP (modern protection)

