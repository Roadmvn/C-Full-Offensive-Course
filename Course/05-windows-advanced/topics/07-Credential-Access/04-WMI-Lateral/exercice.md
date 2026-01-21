
### EXERCICES - Module 44 : Lateral Movement

AVERTISSEMENT LEGAL MAXIMAL : Lateral movement sans autorisation est CRIME FEDERAL.
Ne JAMAIS executer sur reseaux non autorises. Exercices THEORIQUES uniquement pour
comprehension DEFENSE. Implementation complete interdite sans autorisation legale.

Difficulte : ★★★★★ (Avance - ILLEGAL sans autorisation)

IMPORTANT : Exercices ci-dessous sont THEORIQUES ou DEFENSE-FOCUSED uniquement.

Exercice 1 : Network Reconnaissance (LEGAL dans lab isole)
[ ] Scanner reseau local pour identifier hosts actifs
[ ] Enumerer shares SMB sur hosts identifies (NetShareEnum)
[ ] Lister services accessibles (135, 445, 3389, 5985)
[ ] Identifier domain controllers (LDAP 389)
[ ] Creer carte reseau complete (hosts, services, shares)

Exercice 2 : Session Enumeration (LEGAL - reconnaissance)
[ ] Enumerer sessions actives sur machines accessibles
[ ] Identifier comptes privilegies connectes (Domain Admins)
[ ] Logger users par machine (qui est ou)
[ ] Detecter RDP sessions actives (qwinsta)
[ ] Creer graphe connectivite users/machines

Exercice 3 : Service Analysis (THEORIQUE)
[ ] THEORIQUE: Comprendre Service Control Manager (SCM)
[ ] THEORIQUE: Analyser OpenSCManager remote API
[ ] THEORIQUE: Documenter service creation flow (CreateService)
[ ] THEORIQUE: Identifier permissions requises (WRITE_DAC, etc.)
[ ] NE PAS creer services sur machines reelles

Exercice 4 : WMI Execution Research (THEORIQUE)
[ ] THEORIQUE: Etudier WMI COM interfaces (IWbemServices)
[ ] THEORIQUE: Analyser Win32_Process.Create method
[ ] THEORIQUE: Comprendre WMI authentication (RPC)
[ ] THEORIQUE: Documenter WMI event subscriptions
[ ] NE PAS executer commandes WMI remote

Exercice 5 : Pass-the-Hash Mechanics (THEORIQUE UNIQUEMENT)
[ ] THEORIQUE: Comprendre NTLM authentication protocol
[ ] THEORIQUE: Analyser challenge-response mechanism
[ ] THEORIQUE: Documenter ou hashes NTLM sont utilises
[ ] THEORIQUE: Identifier mitigations (Kerberos, NTLMv2)
[ ] NE JAMAIS implementer PtH reel

Exercice 6 : Detection Rule Development (LEGAL - BLUE TEAM)
[ ] Creer regles Sysmon detection lateral movement
[ ] Configurer Event Log monitoring (4624, 4648, 7045)
[ ] Implementer alertes SIEM pour admin shares access
[ ] Tester regles avec simulations benignes
[ ] Documenter faux positifs et tuning

Exercice 7 : Network Segmentation Analysis (LEGAL)
[ ] Analyser topologie reseau existante
[ ] Identifier chemins lateral movement possibles
[ ] Proposer segmentation VLANs/firewalls
[ ] Documenter ACLs necessaires inter-segments
[ ] Tester isolation avec outils scanning

Exercice 8 : Incident Response Simulation (LEGAL - tabletop)
[ ] Simuler scenario lateral movement detecte
[ ] Definir procedures containment (isolation)
[ ] Creer playbook investigation (logs, forensics)
[ ] Documenter escalation procedures
[ ] Tester communication stakeholders

BONUS CHALLENGES (THEORIQUES - RECHERCHE UNIQUEMENT)

Challenge 9 : BloodHound Analysis (LEGAL - lab AD)
[ ] Deployer BloodHound dans lab Active Directory
[ ] Collecter donnees avec SharpHound
[ ] Analyser chemins vers Domain Admins
[ ] Identifier chemins lateral movement critiques
[ ] Proposer mitigations chemins identifies

Challenge 10 : Kerberos Delegation Research (THEORIQUE)
[ ] THEORIQUE: Comprendre unconstrained delegation
[ ] THEORIQUE: Analyser constrained delegation
[ ] THEORIQUE: Documenter resource-based constrained delegation
[ ] THEORIQUE: Identifier abus delegation (lateral movement)
[ ] NE PAS exploiter delegations reelles

Challenge 11 : RDP Hijacking Analysis (THEORIQUE)
[ ] THEORIQUE: Comprendre session IDs Terminal Services
[ ] THEORIQUE: Analyser tscon.exe functionality
[ ] THEORIQUE: Documenter privileges requis (SYSTEM)
[ ] THEORIQUE: Identifier detection RDP hijacking
[ ] NE JAMAIS hijacker sessions RDP reelles


**OUTILS RECHERCHE (USAGE LEGAL UNIQUEMENT)**
- PsExec (Sysinternals) : Comprendre legitimate usage
- BloodHound : AD attack path analysis (pentesting autorise)
- Sysmon : Detection lateral movement
- Wireshark : Analyse traffic reseau (lab uniquement)
- CrackMapExec : Pentesting tool (autorisation requise)

CRITERES VALIDATION (THEORIQUES)
- Comprehension complete protocols (SMB, RPC, WMI)
- Identification correcte detection mechanisms
- Documentation precise attack flows
- Propositions mitigations appropriees
- AUCUNE execution lateral movement reel

INDICATEURS DETECTION (BLUE TEAM FOCUS)

Windows Event Logs:
1. Event ID 4624 - Logon Type 3 (Network logon)
2. Event ID 4625 - Failed logon (brute force detection)
3. Event ID 4648 - Explicit credential usage (runas, etc.)
4. Event ID 4672 - Special privileges assigned
5. Event ID 7045 - Service installation
6. Event ID 5140 - Network share access (ADMIN$, C$)
7. Event ID 5145 - Shared object access check

Sysmon Events:
1. Event ID 1 - Process creation (unusual parent processes)
2. Event ID 3 - Network connection (SMB, RPC ports)
3. Event ID 11 - File creation (ADMIN$ write)
4. Event ID 13 - Registry modification (remote)
5. Event ID 17/18 - Named pipe creation/connection
6. Event ID 19/20/21 - WMI event filters/consumers

Network Indicators:
1. SMB traffic (445/TCP) between endpoints
2. RPC traffic (135/TCP) + dynamic high ports
3. WinRM traffic (5985/5986)
4. RDP traffic (3389/TCP) internal
5. Admin share access patterns
6. NTLM authentication traffic

MITIGATIONS CRITIQUES

Technical Controls:
1. Network segmentation (VLANs, micro-segmentation)
2. SMB signing enforcement (prevent relay)
3. Disable SMBv1 globally
4. LAPS (Local Administrator Password Solution)
5. PAM (Privileged Access Management)
6. Kerberos-only authentication (disable NTLM)
7. Application whitelisting (prevent unauthorized tools)

Administrative Controls:
8. Least privilege principle enforcement
9. Separate admin accounts (no domain admin workstation logon)
10. Privileged Access Workstations (PAWs)
11. Regular credential rotation
12. MFA for remote access (RDP, WinRM)
13. Tiered administration model

Monitoring:
14. Centralized logging (SIEM)
15. Lateral movement detection (UBA/UEBA)
16. Baseline normal behavior
17. Alert fatigue reduction (tuning)
18. 24/7 SOC monitoring

ATTACK PATH EXAMPLES (THEORIQUES)

Scenario 1: PsExec Lateral Movement
1. Attacker compromises Workstation A
2. Dumps LSASS, obtains Domain Admin hash
3. Pass-the-Hash to Server B (ADMIN$ access)
4. PsExec deploys payload on Server B
5. Payload executes with SYSTEM privileges
DETECTION: Event 4624 (Type 3), 7045 (service), 5140 (share access)

Scenario 2: WMI Lateral Movement
1. Attacker has credentials for Administrator
2. WMI connection to multiple servers
3. Win32_Process.Create executes malware
4. Malware establishes persistence
DETECTION: Sysmon Event 1 (parent: WmiPrvSE.exe), RPC traffic

Scenario 3: RDP Hijacking
1. Attacker escalates to SYSTEM on Server
2. Enumerates active RDP sessions (query session)
3. Hijacks Domain Admin session (tscon)
4. Performs actions as Domain Admin
DETECTION: Event 4778/4779 (session reconnect), unusual logon patterns

INCIDENT RESPONSE PROCEDURES

Phase 1: Detection & Triage
- Alert received (lateral movement suspected)
- Verify alert legitimacy (false positive check)
- Identify source and destination systems
- Determine scope (how many systems affected)

Phase 2: Containment
- Isolate affected systems (network segmentation)
- Disable compromised accounts
- Block attacker IPs at firewall
- Prevent further spread

Phase 3: Investigation
- Collect logs (Windows, Sysmon, network)
- Timeline reconstruction
- Identify initial access vector
- Map lateral movement path
- Determine data exfiltration (if any)

Phase 4: Remediation
- Remove malware/persistence
- Patch vulnerabilities exploited
- Reset compromised credentials
- Restore from clean backups if necessary

Phase 5: Recovery
- Re-enable systems after validation
- Monitor closely for re-infection
- Update detection rules based on IOCs
- Conduct lessons learned

AVERTISSEMENT LEGAL FINAL

Lateral movement sans autorisation ecrite explicite est ILLEGAL dans tous pays
(USA: CFAA, Computer Fraud and Abuse Act; UE: Cybercrime Directive; etc.).

Consequences legales:
- Charges criminelles (felony)
- Prison (5-20 ans selon severite)
- Amendes massives ($250,000+)
- Poursuites civiles (dommages entreprise)
- Interdiction professionnelle permanente


### CES TECHNIQUES SONT ENSEIGNEES UNIQUEMENT POUR:
1. Comprehension blue team defense et detection
2. Penetration testing AVEC CONTRAT LEGAL SIGNE
3. Recherche academique ethique approuvee
4. Security operations center (SOC) training

NE JAMAIS executer lateral movement sans autorisation legale formelle ecrite.

