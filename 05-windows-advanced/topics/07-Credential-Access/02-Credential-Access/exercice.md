
### EXERCICES - Module 43 : Credential Dumping

AVERTISSEMENT LEGAL MAXIMAL : Credential dumping est CRIME FEDERAL. Ne JAMAIS
executer sur systemes non autorises. Exercices THEORIQUES uniquement pour
comprehension DEFENSE. Implementation complete interdite sans autorisation legale.

Difficulte : ★★★★★ (Avance - ILLEGAL sans autorisation)

IMPORTANT : Exercices ci-dessous sont THEORIQUES. NE PAS IMPLEMENTER completement.

Exercice 1 : Protection Enumerator (LEGAL)
[ ] Enumerer toutes protections credentials actives
[ ] Verifier Credential Guard status (registry)
[ ] Verifier LSASS PPL protection (RunAsPPL)
[ ] Verifier WDigest status (plaintext passwords)
[ ] Creer rapport complet posture securite credentials

Exercice 2 : Process Protection Detector (LEGAL)
[ ] Identifier tous processes proteges (PPL/PP)
[ ] Tenter OpenProcess avec differents access rights
[ ] Logger erreurs acces (ERROR_ACCESS_DENIED)
[ ] Identifier quels processes dumpables vs proteges
[ ] Creer matrice protection par process critique

Exercice 3 : Privilege Escalation Checker (LEGAL)
[ ] Enumerer tous privileges token courant
[ ] Identifier privileges manquants pour dump LSASS
[ ] Verifier SeDebugPrivilege status
[ ] Tester AdjustTokenPrivileges (sans action malveillante)
[ ] Documenter privileges requis par attaque type

Exercice 4 : SAM Database Analysis (THEORIQUE SEULEMENT)
[ ] THEORIQUE: Comprendre structure SAM database
[ ] THEORIQUE: Identifier emplacements registry (SAM/SYSTEM/SECURITY)
[ ] THEORIQUE: Documenter algorithmes hashing (LM, NTLM, NTLMv2)
[ ] THEORIQUE: Analyser format dumps SAM publics (examples online)
[ ] NE PAS extraire SAM de systeme reel

Exercice 5 : LSASS Memory Structures (THEORIQUE)
[ ] THEORIQUE: Rechercher structures internes LSASS (lsasrv.dll)
[ ] THEORIQUE: Identifier ou credentials stockes (msv1_0.dll, etc.)
[ ] THEORIQUE: Comprendre SSP (Security Support Providers)
[ ] THEORIQUE: Documenter Kerberos ticket storage
[ ] NE PAS dumper memoire LSASS reelle

Exercice 6 : Detection Research (LEGAL - BLUE TEAM)
[ ] Configurer Sysmon pour detecter LSASS access
[ ] Tester generation Event ID 10 (ProcessAccess)
[ ] Analyser logs Sysmon apres tentative acces
[ ] Identifier patterns detection (GrantedAccess, etc.)
[ ] Creer regles SIEM pour alerting

Exercice 7 : Mimikatz Behavior Analysis (LEGAL - SANDBOX)
[ ] Executer Mimikatz dans VM sandbox isolee
[ ] Monitorer API calls (Process Monitor)
[ ] Capturer network traffic (si C2 communication)
[ ] Analyser artifacts filesystem/registry
[ ] Documenter IOCs (Indicators of Compromise)

Exercice 8 : Credential Guard Testing (LEGAL)
[ ] Activer Credential Guard dans VM test
[ ] Tester impact sur logon mechanisms
[ ] Verifier inaccessibilite credentials avec outils dump
[ ] Mesurer overhead performance Credential Guard
[ ] Documenter limitations et compatibilite

BONUS CHALLENGES (THEORIQUES - RECHERCHE UNIQUEMENT)

Challenge 9 : PPL Bypass Research (THEORIQUE)
[ ] THEORIQUE: Rechercher vulnerabilites PPL bypass connues (CVEs)
[ ] THEORIQUE: Comprendre exploitation kernel drivers (BYOVD)
[ ] THEORIQUE: Analyser patches Microsoft pour PPL bypass
[ ] THEORIQUE: Documenter mitigations PPL bypass
[ ] NE JAMAIS tenter bypass PPL en pratique

Challenge 10 : Active Directory Attack Paths (THEORIQUE)
[ ] THEORIQUE: Comprendre NTDS.dit extraction (Domain Controllers)
[ ] THEORIQUE: Analyser DCSync attack (Mimikatz)
[ ] THEORIQUE: Documenter Kerberoasting attack flow
[ ] THEORIQUE: Identifier chemins compromise Domain Admin
[ ] NE PAS executer contre AD reel

Challenge 11 : Memory Forensics (LEGAL - DEFENSE)
[ ] Creer memory dump benin (process non-sensible)
[ ] Utiliser Volatility framework pour analyse
[ ] Identifier patterns credentials en memoire
[ ] Pratiquer extraction artifacts memoire
[ ] Documenter techniques forensics defense


**OUTILS RECHERCHE (USAGE LEGAL UNIQUEMENT)**
- Mimikatz : Comprendre concepts (NE PAS executer en production)
- Volatility : Memory forensics (usage defensif legal)
- Sysmon : Detection credential access attempts
- BloodHound : AD attack path analysis (pentesting autorise)
- Process Hacker : Process inspection (usage benin legal)

CRITERES VALIDATION (THEORIQUES)
- Comprehension profonde protections Windows
- Identification correcte detection mechanisms
- Documentation precise attack flow
- Propositions mitigations appropriees
- AUCUNE implementation malveillante reelle

INDICATEURS DETECTION (BLUE TEAM)
1. Sysmon Event ID 10 (LSASS ProcessAccess)
2. Event ID 4656 (Handle to Object requested) - LSASS
3. MiniDumpWriteDump API calls vers LSASS
4. Fichiers .dmp suspects (LSASS dumps)
5. Execution Mimikatz (signatures, behavior)
6. SeDebugPrivilege usage anormal
7. Registry access SAM/SYSTEM/SECURITY hives


**SYSMON CONFIGURATION EXEMPLE**
<ProcessAccess onmatch="include">
  <TargetImage>C:\Windows\system32\lsass.exe</TargetImage>
  <GrantedAccess>0x1010</GrantedAccess>
  <GrantedAccess>0x1410</GrantedAccess>
</ProcessAccess>

MITIGATIONS CRITIQUES
1. Activer Credential Guard (Windows 10 Enterprise+)
2. Activer LSASS PPL (RunAsPPL registry key)
3. Desactiver WDigest (UseLogonCredential = 0)
4. Deploy LAPS (Local Admin Password Solution)
5. Privileged Access Workstations (PAWs)
6. EDR avec LSASS protection active
7. Network segmentation (limiter lateral movement)
8. Monitor Sysmon Event ID 10 systematiquement

AVERTISSEMENT LEGAL FINAL
Credential dumping sans autorisation ecrite explicite est ILLEGAL dans tous
pays developpes (USA: CFAA violation, UE: GDPR + cybercrime laws, etc.).

Consequences legales incluent:
- Poursuites penales (felony charges)
- Prison (jusqu'a 10+ ans selon juridiction)
- Amendes massives ($100,000+)
- Interdiction professionnelle IT/security
- Casier judiciaire permanent


### CES TECHNIQUES SONT ENSEIGNEES UNIQUEMENT POUR:
1. Comprehension blue team defense
2. Penetration testing AVEC CONTRAT SIGNE
3. Recherche academique ethique
4. Security awareness training

NE JAMAIS executer credential dumping sans autorisation legale formelle.

