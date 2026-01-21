⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 34 : WINDOWS TOKEN MANIPULATION

[ ] 1. SEDEBUGPRIVILEGE ENABLER
Activer tous privilèges disponibles :
- LookupPrivilegeValue pour chaque privilège
- SeDebugPrivilege, SeImpersonatePrivilege
- SeLoadDriverPrivilege, SeTcbPrivilege
- AdjustTokenPrivileges pour activer
- Lister privilèges avant/après

Référence : MSDN AdjustTokenPrivileges

[ ] 2. TOKEN STEALING COMPLET
Voler token SYSTEM depuis processus :
- Trouver winlogon.exe ou lsass.exe (PID)
- OpenProcessToken avec TOKEN_DUPLICATE
- DuplicateTokenEx en TokenPrimary
- Vérifier integrity level (SYSTEM = 0x3000)
- Display SID et groupes

Référence : Token theft techniques

[ ] 3. CREATEPROCESS WITH STOLEN TOKEN
Spawn cmd.exe SYSTEM :
- Voler token SYSTEM (exercice 2)
- CreateProcessWithTokenW nécessite SeImpersonatePrivilege
- Lancer cmd.exe avec token volé
- Vérifier whoami dans nouveau cmd (SYSTEM)
- Parent PID spoofing détectable

Référence : CreateProcessWithTokenW MSDN

[ ] 4. THREAD IMPERSONATION
Impersonater user sans CreateProcess :
- DuplicateTokenEx en TokenImpersonation
- ImpersonateLoggedOnUser sur thread actuel
- GetUserName vérifier user impersonaté
- Accès fichiers avec permissions impersonatées
- RevertToSelf pour revenir

Référence : Impersonation levels

[ ] 5. TOKEN INFORMATION ENUMERATION
Extraire toutes infos token :
- TokenUser (SID utilisateur)
- TokenGroups (liste groupes)
- TokenPrivileges (liste privilèges avec état)
- TokenIntegrityLevel (Low/Medium/High/SYSTEM)
- TokenSessionId, TokenElevationType

Référence : GetTokenInformation TOKEN_INFORMATION_CLASS

[ ] 6. PARENT PID SPOOFING
Créer processus avec parent spoofé :
- UpdateProcThreadAttribute avec PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
- Choisir parent légitime (explorer.exe)
- Token hérité du parent
- STARTUPINFOEX avec attribute list
- Bypass parent-child heuristics

Référence : Parent PID spoofing technique

[ ] 7. NAMED PIPE IMPERSONATION
Token stealing via named pipe :
- CreateNamedPipe avec PIPE_ACCESS_DUPLEX
- ImpersonateNamedPipeClient après connexion
- Client se connecte (local user ou admin)
- Voler token client impersonaté
- Escalade privilège si admin

Référence : Named pipe impersonation (hot potato)

[ ] 8. TOKEN MANIPULATION MULTI-STAGE
Chaîne complète privilege escalation :
- Démarrer en Medium integrity
- Enable SeDebugPrivilege
- Trouver processus SYSTEM
- Voler token SYSTEM
- Spawn SYSTEM shell
- Logging toutes étapes
- Cleanup propre

Référence : APT token manipulation chains


### NOTES :
- SeDebugPrivilege = admin required
- OpenProcessToken = ProcessAccess Sysmon event
- Token Primary vs Impersonation = CreateProcess vs thread
- Integrity levels = Low < Medium < High < SYSTEM
- PPL (Protected Process Light) = bloque OpenProcessToken
- Credential Guard = virtualize lsass (token stealing fail)
- Parent PID spoofing = bypass behavioral detection
- Named pipes = alternative token theft (no SeDebug)

