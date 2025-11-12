# Module 34 : Token Manipulation

## Vue d'ensemble

Ce module explore la manipulation des **Windows Access Tokens**, mécanisme fondamental de sécurité Windows qui détermine les privilèges et permissions d'un processus ou thread. La compréhension de cette technique est essentielle pour le développement sécurisé et l'analyse de sécurité.

## Concepts clés

### Windows Access Tokens

Un Access Token est un objet noyau Windows contenant :
- **SID (Security Identifier)** : Identité unique de l'utilisateur
- **Groupes** : Liste des groupes auxquels l'utilisateur appartient
- **Privilèges** : Droits spéciaux (SeDebugPrivilege, SeShutdownPrivilege, etc.)
- **Niveau d'intégrité** : Low, Medium, High, System
- **Session ID** : Identifiant de session utilisateur

### Token Stealing et Duplication

**Token Stealing** :
```
Processus cible (SYSTEM) → Dupliquer token → Appliquer au processus actuel
```

**Token Duplication** :
- **Primary Token** : Utilisé pour créer de nouveaux processus
- **Impersonation Token** : Utilisé pour impersonnification temporaire

### Privilege Escalation

Techniques d'élévation de privilèges via tokens :

1. **Token Duplication** : Copier un token privilégié
2. **Token Impersonation** : Se faire passer pour un utilisateur privilégié
3. **Privilege Enabling** : Activer des privilèges dormants
4. **Parent PID Spoofing** : Hériter du token parent

### SeDebugPrivilege

Privilège critique permettant :
- **Accès mémoire** : Lecture/écriture dans n'importe quel processus
- **Handle manipulation** : Ouverture de processus protégés
- **Kernel debugging** : Attachement debugger au noyau

Par défaut assigné uniquement aux administrateurs.

### Impersonation

Mécanisme Windows permettant à un thread d'exécuter du code dans le contexte de sécurité d'un autre utilisateur :

```
Thread original → ImpersonateLoggedOnUser → Thread impersonifié
```

Niveaux d'impersonification :
- **SecurityAnonymous** : Serveur ne peut pas identifier le client
- **SecurityIdentification** : Serveur peut identifier le client
- **SecurityImpersonation** : Serveur peut impersonnifier le client
- **SecurityDelegation** : Impersonification avec délégation réseau

## ⚠️ AVERTISSEMENT LÉGAL STRICT ⚠️

### ATTENTION CRITIQUE

La manipulation de tokens Windows est une technique **EXTRÊMEMENT SENSIBLE** utilisée dans :

**Utilisations légitimes** :
- Développement d'outils d'administration système
- Services Windows nécessitant impersonification
- Solutions de sécurité et monitoring
- Recherche académique en sécurité informatique

**Utilisations ILLÉGALES** :
- Élévation de privilèges non autorisée
- Contournement de sécurité système
- Accès non autorisé à des ressources
- Malware et outils d'attaque

### Cadre légal

**INTERDICTIONS STRICTES** :
- ❌ Utiliser ces techniques sur des systèmes sans autorisation écrite
- ❌ Développer des outils d'attaque ou malware
- ❌ Contourner des mécanismes de sécurité en production
- ❌ Accéder à des données sans autorisation

**AUTORISATIONS REQUISES** :
- ✅ Environnement de test isolé et contrôlé
- ✅ Autorisation écrite du propriétaire du système
- ✅ Cadre professionnel (pentesting contractuel)
- ✅ Recherche académique éthique

### Conséquences légales

Violation des lois :
- **Computer Fraud and Abuse Act (CFAA)** - USA
- **Directive NIS2** - Union Européenne
- **Loi Godfrain** - France
- **Computer Misuse Act** - Royaume-Uni

Sanctions possibles :
- Amendes pouvant atteindre plusieurs millions d'euros
- Peines de prison (jusqu'à 20 ans selon juridiction)
- Interdiction d'exercer dans l'informatique
- Poursuites civiles pour dommages

### Responsabilité

**VOUS ÊTES PERSONNELLEMENT RESPONSABLE** :
- De l'utilisation de ces techniques
- Des conséquences de vos actions
- Du respect des lois locales et internationales
- De l'obtention des autorisations nécessaires

**L'auteur de ce module décline toute responsabilité** pour tout usage illégal ou non autorisé de ces informations.

## Utilisation éthique et légale

### Environnement de test recommandé

```
VM Windows isolée
├── Aucune connexion réseau production
├── Snapshots réguliers
├── Logs détaillés
└── Destruction après tests
```

### Checklist avant utilisation

- [ ] Autorisation écrite du propriétaire système
- [ ] Environnement de test isolé
- [ ] Documentation des objectifs légitimes
- [ ] Connaissance des lois applicables
- [ ] Backup complet du système de test
- [ ] Plan de remédiation en cas de problème

## APIs Windows essentielles

### OpenProcessToken
```c
BOOL OpenProcessToken(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
);
```

### DuplicateTokenEx
```c
BOOL DuplicateTokenEx(
    HANDLE hExistingToken,
    DWORD dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpTokenAttributes,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE TokenType,
    PHANDLE phNewToken
);
```

### AdjustTokenPrivileges
```c
BOOL AdjustTokenPrivileges(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
);
```

### ImpersonateLoggedOnUser
```c
BOOL ImpersonateLoggedOnUser(
    HANDLE hToken
);
```

## Objectifs pédagogiques

À la fin de ce module, vous devriez comprendre :
- Architecture des Access Tokens Windows
- Mécanismes de sécurité basés sur tokens
- Techniques d'impersonification sécurisées
- Risques liés à la manipulation de tokens
- Détection et prévention des abus

## Prérequis

- Connaissance de l'architecture Windows
- Compréhension des privilèges et permissions
- Expérience avec les APIs Windows
- Notions de sécurité système

## Références

- Microsoft Documentation : Security and Access Rights
- Windows Internals (Russinovich, Solomon, Ionescu)
- MITRE ATT&CK : T1134 (Access Token Manipulation)
- Windows Security Best Practices

---

**RAPPEL FINAL** : Ce module est strictement éducatif. Utilisez ces connaissances de manière éthique et légale uniquement.
