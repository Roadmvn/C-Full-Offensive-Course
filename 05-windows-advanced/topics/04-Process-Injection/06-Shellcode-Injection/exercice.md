
### EXERCICES - Module 39 : Code Caves & PE Backdooring

AVERTISSEMENT : Exercices strictement educatifs. Ne jamais pratiquer sur systemes non autorises.

Difficulte : ★★★★★ (Avance - Malware Development)

Exercice 1 : PE Header Parser
[ ] Implementer parser complet PE (DOS header, NT headers, sections)
[ ] Afficher toutes informations headers (machine type, timestamp, entry point)
[ ] Calculer et afficher checksums
[ ] Identifier sections executables (.text) vs data (.data, .rdata)
[ ] Valider integrite structure PE

Exercice 2 : Code Cave Detector Avance
[ ] Etendre detection caves avec criteres avances
[ ] Filtrer par permissions section (executable/writable)
[ ] Calculer entropie pour chaque cave trouvee
[ ] Identifier caves "safe" (entre sections, padding alignment)
[ ] Exporter rapport JSON avec toutes caves

Exercice 3 : Shellcode Injector
[ ] Creer fonction injection shellcode dans cave selectionnee
[ ] Calculer offset correct dans fichier PE
[ ] Ecrire shellcode a l'offset cave
[ ] Verifier taille shellcode <= taille cave
[ ] Creer backup fichier avant modification

Exercice 4 : Entry Point Redirection
[ ] Sauvegarder entry point original (OEP - Original Entry Point)
[ ] Modifier entry point vers RVA code cave
[ ] Injecter stub qui execute payload puis jump vers OEP
[ ] Tester avec simple MessageBox shellcode
[ ] Restaurer entry point original (feature "unpatch")

Exercice 5 : Import Address Table (IAT) Hooking
[ ] Parser Import Address Table du PE
[ ] Identifier fonction cible (ex: MessageBoxA)
[ ] Remplacer adresse fonction par RVA code cave
[ ] Creer hook qui log appels puis call fonction originale
[ ] Tester hooking sans crasher application

Exercice 6 : TLS Callback Injection
[ ] Parser TLS Directory dans PE
[ ] Ajouter nouvelle entree TLS callback pointant vers cave
[ ] Injecter code execute AVANT entry point
[ ] Implementer anti-debug check dans callback
[ ] Tester execution callback au lancement

Exercice 7 : Polymorphic Code Cave
[ ] Generer shellcode polymorphique (XOR encoder simple)
[ ] Injecter decoder stub + payload encode dans cave
[ ] Implementer multiple schemas encoding (XOR, ADD, ROL)
[ ] Randomiser cle encoding a chaque injection
[ ] Verifier execution correcte payload decode

Exercice 8 : Stealth Backdoor Framework
[ ] Combiner techniques: code cave + IAT hook + TLS callback
[ ] Implementer persistence via modification binaire systeme
[ ] Ajouter obfuscation (junk code, dead code insertion)
[ ] Calculer et mettre a jour PE checksum apres patch
[ ] Creer outil "cleaner" pour retirer tous patches

BONUS CHALLENGES

Challenge 9 : Multi-Cave Payload Splitter
[ ] Decouper payload volumineux en fragments
[ ] Distribuer fragments dans multiples caves
[ ] Creer trampoline code reliant fragments
[ ] Implementer reassembly runtime en memoire

Challenge 10 : Code Signing Bypass Research
[ ] Analyser comment code signing valide PE
[ ] Identifier sections non-signees (overlay, resources)
[ ] Injecter payload dans zones non-verifiees
[ ] Documenter techniques preservation signature

Challenge 11 : Anti-Forensics
[ ] Implementer wiping metadata PE (timestamp, debug info)
[ ] Normaliser entropy caves injectees (mimick legitimate code)
[ ] Supprimer artifacts compilation (PDB paths, etc.)
[ ] Creer profil "clean" indistinguishable de binaire legitime

OUTILS RECOMMANDES
- PE-bear : Editeur PE graphique
- CFF Explorer : Advanced PE editor
- HxD / 010 Editor : Hex editors avec templates PE
- x64dbg : Debugger pour tester patches
- VirusTotal : Tester detection (JAMAIS uploader malware reel)

CRITERES VALIDATION
- Code cave detection 100% precise (pas faux positifs)
- Injection preserve fonctionnalite binaire original
- Aucun crash apres patching
- Shellcode execute correctement
- Modifications stealth (pas detection triviale)

AVERTISSEMENT LEGAL
La modification de binaires sans autorisation est illegale. Ces techniques
sont enseignees pour comprehension defense/detection malware uniquement.

