# Module 05 : Windows Advanced

```
+-------------------------------------------------------------------+
|                                                                     |
|   "C'est ici que ca devient serieux.                               |
|    Shellcode, injection, evasion, C2, kernel."                     |
|                                                                     |
|   Le module le plus dense du cours. Tu vas apprendre a            |
|   construire des outils offensifs complets sur Windows.            |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Ecrire et encoder du shellcode (position-independent, null-free, chiffre)
- Injecter du code dans des processus distants (DLL injection, process hollowing, hooking)
- Evader les defenses (AMSI, ETW, sandbox, anti-debug, sleep obfuscation)
- Developper un C2 complet (HTTP/HTTPS/DNS/SMB, beacon, commandes)
- Comprendre les bases du kernel Windows (drivers, DKOM, rootkits)

## Prerequis

- Module 04 (Windows Fundamentals) valide
- Module 03 (Assembly x64) valide
- Bonne maitrise du C, des pointeurs et de la memoire
- VM Windows avec les outils de dev installes

## Contenu du module

Ce module est organise en **6 sections** dans `topics/`.

---

### Section 1 : Shellcoding (`topics/03-Shellcoding/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Shellcode-Basics | Fondamentaux du shellcode, execution en memoire |
| 02 | Position-Independent-Code | Ecrire du code qui fonctionne a n'importe quelle adresse |
| 03 | Null-Free-Shellcode | Supprimer les null bytes du shellcode |
| 04 | API-Hashing-Resolution | Resoudre les API par hash (djb2, ror13) |
| 05 | Encoders-XOR-RC4 | Encoder le shellcode (XOR, RC4) |
| 06 | Crypters-AES | Chiffrer le shellcode avec AES |
| 07 | Staged-vs-Stageless | Comprendre les deux architectures |

### Section 2 : Process Injection (`topics/04-Process-Injection/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | DLL-Injection-Basics | Injection DLL classique (CreateRemoteThread) |
| 02 | DLL-Injection-Advanced | Techniques avancees d'injection DLL |
| 03 | Process-Hollowing | Remplacer le code d'un processus legitime |
| 04 | Process-Doppelganging | Technique via transactions NTFS |
| 05 | Module-Stomping | Ecraser un module DLL charge |
| 06 | Shellcode-Injection | Injection de shellcode directe |
| 07 | IAT-Hooking | Hooking via l'Import Address Table |
| 08 | Inline-Hooking | Hooking par modification des premiers bytes |
| 09 | Unhooking | Detecter et supprimer les hooks (ntdll) |
| 10 | Reflective-DLL | DLL qui se charge elle-meme en memoire |

### Section 3 : Evasion (`topics/05-Evasion/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | String-Obfuscation | Cacher les strings sensibles |
| 02 | API-Hashing | Appeler des API sans les nommer |
| 03 | Direct-Syscalls | Appels systeme directs (bypass ntdll hooks) |
| 04 | AMSI-Bypass | Contourner l'Anti-Malware Scan Interface |
| 05 | ETW-Patching | Desactiver Event Tracing for Windows |
| 06 | Sleep-Obfuscation | Chiffrer la memoire pendant le sleep |
| 07 | Memory-Evasion | Techniques d'evasion memoire |
| 08 | Sandbox-Detection | Detecter les environnements sandbox |
| 09 | Anti-Debug | Techniques anti-debugging |
| 10 | PPID-Spoofing | Falsifier le parent process ID |
| 11 | Callback-Evasion | Evasion via callbacks Windows |
| 12 | PE-Packer | Ecrire un packer de PE |

### Section 4 : Credential Access & Lateral Movement (`topics/07-Credential-Access/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Token-Impersonation | Voler et utiliser des tokens |
| 02 | Credential-Access | Extraire des credentials |
| 03 | Pass-The-Hash | Authentification avec des hashes NTLM |
| 04 | WMI-Lateral | Mouvement lateral via WMI |
| 05 | PSExec-Technique | Implementer PSExec from scratch |
| 06 | DCOM-Lateral | Mouvement lateral via DCOM |

### Section 5 : C2 Development (`topics/08-C2-Development/`)

| # | Topic | Description |
|---|-------|-------------|
| 00 | Reverse-Shell | Shell inverse complet (client + serveur) |
| 01 | HTTP-Client-WinHTTP | Client HTTP avec WinHTTP |
| 02 | HTTPS-Communication | Communication chiffree HTTPS |
| 03 | WinInet-Client | Client HTTP avec WinInet |
| 04 | JSON-Parsing | Parser du JSON en C pur |
| 05 | DNS-Communication | Communication C2 via DNS |
| 06 | Domain-Fronting | Cacher le vrai serveur C2 |
| 07 | Proxy-Awareness | Gerer les proxys d'entreprise |
| 08 | SMB-Communication | Communication via named pipes SMB |
| 09 | Beacon-Architecture | Architecture d'un beacon |
| 10 | Session-Management | Gestion des sessions |
| 11 | Jitter-Sleep | Sleep avec variation aleatoire |
| 12 | Staged-vs-Stageless | Loader staged vs agent complet |
| 13 | Command-Dispatcher | Dispatcher de commandes |
| 14 | Output-Capture | Capturer la sortie des commandes |
| 15 | File-Operations | Upload/download de fichiers |
| 16 | Process-Operations | Gestion de processus distants |
| 17 | Screenshot | Capture d'ecran |
| 18 | Keylogger | Enregistrement des frappes clavier |
| 19 | Persistence-Agent | Mecanismes de persistence |
| 20 | Kill-Switch | Auto-destruction de l'agent |

### Section 6 : Kernel (`topics/09-Kernel/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Driver-Basics | Ecrire un driver Windows minimal |
| 02 | Kernel-Memory | Manipulation memoire en kernel mode |
| 03 | IOCTL-Communication | Communication userland <-> kernel |
| 04 | Callbacks | Process/Thread callbacks |
| 05 | DKOM | Direct Kernel Object Manipulation |
| 06 | SSDT-Hooking | Hooking de la System Service Descriptor Table |
| 07 | Minifilter | Filesystem minifilter driver |
| 08 | BYOVD | Bring Your Own Vulnerable Driver |
| 09 | DSE-Bypass | Contourner Driver Signature Enforcement |
| 10 | Kernel-Rootkit-Basics | Fondamentaux d'un rootkit kernel |
| 11 | Hypervisor-Awareness | Detecter les hyperviseurs |
| 12 | PatchGuard-Basics | Comprendre Kernel Patch Protection |

## Comment travailler

```
1. Suis les sections dans l'ordre (Shellcoding -> Injection -> Evasion -> ...)
2. Dans chaque topic, lis d'abord example.c
3. Si un raw_maldev.c existe, c'est la version offensive
4. Fais le solution.c toi-meme avant de regarder
5. Teste dans ta VM Windows (PAS sur ta machine principale)
```

## Compilation

```batch
REM Compilation standard
cl example.c /link kernel32.lib user32.lib

REM Pour les topics C2 (reseau)
cl example.c /link winhttp.lib ws2_32.lib

REM Pour les drivers kernel
Utilise le WDK (Windows Driver Kit)
```

## Checklist

- [ ] Shellcoding : j'ai ecrit et encode du shellcode
- [ ] Injection : j'ai injecte du code dans un processus distant
- [ ] Evasion : j'ai bypass AMSI et/ou ETW
- [ ] C2 : j'ai un beacon qui communique en HTTP/HTTPS
- [ ] Kernel : j'ai compile et charge un driver basique

---

Temps estime : **40-60 heures** (le plus gros module du cours)

Prochain module : [06 - Network](../06-network/)
