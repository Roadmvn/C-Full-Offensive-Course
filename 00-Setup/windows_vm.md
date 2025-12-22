# Setup VM Windows pour Lab Malware Dev

## Vue d'ensemble

VM Windows isolée pour développement et test de malware de manière sécurisée.

## Configuration recommandée

### Specs minimales
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disque**: 60 GB
- **Réseau**: Host-only ou NAT isolé

### OS recommandés
- Windows 10 (21H2 ou plus récent)
- Windows 11 (pour tests modernes)
- Windows 7 (legacy testing)

## Installation

### 1. Télécharger Windows

#### ISO officielle (gratuit pour lab)
```
Windows 10/11 Evaluation:
https://www.microsoft.com/en-us/evalcenter/

Windows 10 Development Environment (pré-configuré):
https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/
```

### 2. Créer VM (VirtualBox)

```bash
# Créer VM
VBoxManage createvm --name "Windows10-Lab" --ostype Windows10_64 --register

# Configurer RAM et CPU
VBoxManage modifyvm "Windows10-Lab" --memory 4096 --cpus 2

# Créer disque
VBoxManage createhd --filename ~/VMs/Windows10-Lab.vdi --size 60000

# Attacher disque
VBoxManage storagectl "Windows10-Lab" --name "SATA" --add sata
VBoxManage storageattach "Windows10-Lab" --storagectl "SATA" --port 0 --device 0 --type hdd --medium ~/VMs/Windows10-Lab.vdi

# Attacher ISO
VBoxManage storageattach "Windows10-Lab" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium ~/Downloads/Win10.iso

# Réseau (Host-only pour isolation)
VBoxManage modifyvm "Windows10-Lab" --nic1 hostonly --hostonlyadapter1 vboxnet0

# Boot
VBoxManage startvm "Windows10-Lab"
```

### 3. Installer Windows

1. Booter sur ISO
2. Suivre installation standard
3. **NE PAS** activer mises à jour automatiques
4. Créer user `lab` (mot de passe simple pour lab)

## Configuration Post-Installation

### Désactiver Windows Defender (ESSENTIEL)

#### Via GUI
```
Settings → Update & Security → Windows Security → Virus & threat protection
→ Manage settings → Désactiver tout
```

#### Via PowerShell (Admin)
```powershell
# Désactiver Real-time protection
Set-MpPreference -DisableRealtimeMonitoring $true

# Désactiver Cloud protection
Set-MpPreference -MAPSReporting 0

# Désactiver Sample submission
Set-MpPreference -SubmitSamplesConsent 2

# Exclusions (dossier lab)
Add-MpPreference -ExclusionPath "C:\Lab"
Add-MpPreference -ExclusionExtension ".exe"
Add-MpPreference -ExclusionExtension ".dll"

# Désactiver Tamper Protection (via Registry)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0
```

#### Via Group Policy
```
gpedit.msc
→ Computer Configuration
→ Administrative Templates
→ Windows Components
→ Microsoft Defender Antivirus
→ Turn off Microsoft Defender Antivirus: Enabled
```

### Désactiver autres protections

#### SmartScreen
```powershell
# SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
```

#### UAC (User Account Control)
```powershell
# Désactiver UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# Reboot requis
Restart-Computer
```

#### Firewall
```powershell
# Désactiver Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

### Désactiver mises à jour automatiques

```powershell
# Stop Windows Update service
Stop-Service wuauserv
Set-Service wuauserv -StartupType Disabled

# Via Group Policy
gpedit.msc
→ Computer Configuration
→ Administrative Templates
→ Windows Components
→ Windows Update
→ Configure Automatic Updates: Disabled
```

## Installation Outils de Dev

### 1. Compilateurs

#### MinGW-w64 (GCC pour Windows)
```
Télécharger: https://github.com/niXman/mingw-builds-binaries/releases
Installer dans: C:\mingw64

Ajouter au PATH:
  C:\mingw64\bin
```

#### Visual Studio Build Tools
```
https://visualstudio.microsoft.com/downloads/
→ Build Tools for Visual Studio 2022
→ Installer "C++ build tools"
```

### 2. Debuggers

#### x64dbg
```
https://x64dbg.com/
Extraire dans: C:\Tools\x64dbg

Plugins recommandés:
  - ScyllaHide (anti-anti-debug)
  - xAnalyzer
```

#### WinDbg Preview
```
Microsoft Store → WinDbg Preview
Ou: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
```

### 3. Outils d'analyse

#### Process Hacker 2
```
https://processhacker.sourceforge.io/
Installer dans: C:\Tools\ProcessHacker
```

#### Process Monitor (Sysinternals)
```powershell
# Télécharger Sysinternals Suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\Tools\Sysinternals.zip"
Expand-Archive -Path "C:\Tools\Sysinternals.zip" -DestinationPath "C:\Tools\Sysinternals"

# Ajouter au PATH
$env:PATH += ";C:\Tools\Sysinternals"
```

#### PE-bear (PE parser)
```
https://github.com/hasherezade/pe-bear-releases
```

### 4. Networking

#### Wireshark
```
https://www.wireshark.org/download.html
```

#### Netcat
```powershell
# Télécharger ncat (Nmap version)
Invoke-WebRequest -Uri "https://nmap.org/dist/nmap-7.94-setup.exe" -OutFile "C:\Tools\nmap-setup.exe"
# Installer, nc.exe sera dans C:\Program Files (x86)\Nmap\
```

### 5. Python (pour scripts)

```powershell
# Python 3
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe" -OutFile "C:\Tools\python-installer.exe"
C:\Tools\python-installer.exe /quiet InstallAllUsers=1 PrependPath=1

# Packages utiles
pip install pefile capstone keystone-engine unicorn
```

## Structure dossiers lab

```powershell
# Créer structure
New-Item -ItemType Directory -Path "C:\Lab"
New-Item -ItemType Directory -Path "C:\Lab\Source"      # Code source
New-Item -ItemType Directory -Path "C:\Lab\Build"       # Binaires compilés
New-Item -ItemType Directory -Path "C:\Lab\Payloads"    # Shellcode, DLLs
New-Item -ItemType Directory -Path "C:\Lab\Targets"     # Apps victimes
New-Item -ItemType Directory -Path "C:\Lab\Logs"        # Logs d'analyse

# Permissions totales (pour éviter erreurs d'accès)
icacls "C:\Lab" /grant Everyone:F /T
```

## Configuration réseau

### Host-Only (isolation complète)

```
VirtualBox:
  - Network Adapter 1: Host-only Adapter (vboxnet0)
  - IP: 192.168.56.10 (configuré via DHCP ou statique)

Host (attacker machine):
  - IP sur vboxnet0: 192.168.56.1

Test connexion:
  - Depuis VM: ping 192.168.56.1
  - Depuis Host: ping 192.168.56.10
```

### NAT avec isolation

```
VirtualBox:
  - Network Adapter 1: NAT
  - Port Forwarding pour reverse shells:
    Host 0.0.0.0:4444 → Guest 10.0.2.15:4444
```

## Snapshots essentiels

```bash
# Snapshot après installation complète
VBoxManage snapshot "Windows10-Lab" take "Fresh-Install" --description "Windows 10 clean install with tools"

# Snapshot avant chaque test
VBoxManage snapshot "Windows10-Lab" take "Before-Test-$(date +%Y%m%d)"

# Restaurer snapshot
VBoxManage snapshot "Windows10-Lab" restore "Fresh-Install"
```

## Scripts utiles

### Disable Defender (permanent)
Créer `C:\Lab\disable_defender.ps1`:
```powershell
# Exécuter en Admin
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableScriptScanning $true
Add-MpPreference -ExclusionPath "C:\Lab"
Write-Host "[+] Defender disabled"
```

### Auto-start listener
Créer `C:\Lab\listener.bat`:
```batch
@echo off
echo Starting listener on port 4444...
C:\Tools\nmap\ncat.exe -lvp 4444
```

## Checklist avant tests

- [ ] Snapshot créé
- [ ] Windows Defender désactivé
- [ ] UAC désactivé
- [ ] Firewall désactivé
- [ ] Réseau isolé (Host-only)
- [ ] Process Monitor lancé (optionnel)
- [ ] x64dbg prêt

## Restauration rapide

```batch
REM restore.bat
VBoxManage controlvm "Windows10-Lab" poweroff
timeout /t 2
VBoxManage snapshot "Windows10-Lab" restore "Fresh-Install"
VBoxManage startvm "Windows10-Lab"
```

## Sécurité

**IMPORTANT**:
- Ne JAMAIS connecter cette VM à Internet non filtré
- Ne JAMAIS partager de dossiers avec host contenant données sensibles
- Isoler réseau via Host-only
- Détruire VM si compromise
- Ne pas stocker données personnelles dans VM

## Ressources

- [Flare VM](https://github.com/mandiant/flare-vm): VM pré-configurée pour malware analysis
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/): Documentation Microsoft
- [x64dbg Documentation](https://help.x64dbg.com/)
