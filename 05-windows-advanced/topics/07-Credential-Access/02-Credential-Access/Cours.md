# Cours : Credential Dumping - Extraction de Mots de Passe

## 1. Introduction

**Credential Dumping** = Extraire les mots de passe et hashes du système.

## 2. Cibles Windows

### 2.1 LSASS (Local Security Authority Subsystem)

```ascii
lsass.exe :
┌──────────────────────────┐
│ Mémoire de lsass.exe     │
├──────────────────────────┤
│ Credentials en clair :   │
│ ├─ Passwords             │
│ ├─ NTLM hashes           │
│ ├─ Kerberos tickets      │
│ └─ ...                   │
└──────────────────────────┘
```

**Mimikatz** :
```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### 2.2 SAM Database

```ascii
C:\Windows\System32\config\SAM
├─ Contient les hashes NTLM
└─ Chiffré, mais peut être extrait

Registry :
HKLM\SAM\SAM\Domains\Account\Users
```

## 3. Techniques

- Dump mémoire de lsass.exe
- Parse structures LSASS
- Extraire et décrypter

## Ressources

- [Mimikatz](https://github.com/gentilkiwi)
- [Credential Dumping](https://attack.mitre.org/techniques/T1003/)

