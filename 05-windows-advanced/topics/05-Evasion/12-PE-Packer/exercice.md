
### EXERCICES - Module 40 : Packing & Unpacking

AVERTISSEMENT : Exercices strictement educatifs. Ne jamais packer malware reel.

Difficulte : ★★★★★ (Avance - Malware Evasion)

Exercice 1 : Entropy Analyzer
[ ] Implementer calculateur entropie Shannon complet
[ ] Analyser entropie par section PE (pas fichier entier)
[ ] Detecter sections anormalement haute entropie (>7.0)
[ ] Creer rapport avec score suspicion packing
[ ] Tester sur binaires packes UPX vs non-packes

Exercice 2 : Multi-Layer XOR Packer
[ ] Implementer packing multi-couches (XOR, ADD, ROL)
[ ] Generer cles aleatoires differentes par couche
[ ] Sauvegarder metadata couches dans header
[ ] Creer stub unpacker iteratif (N passes)
[ ] Verifier checksum a chaque etape unpacking

Exercice 3 : Compression Packer (zlib)
[ ] Integrer compression zlib/deflate dans packer
[ ] Combiner compression + encryption (compress puis XOR)
[ ] Mesurer ratio compression (original vs packed)
[ ] Implementer decompression runtime dans stub
[ ] Comparer taille vs UPX sur memes binaires

Exercice 4 : Stub Unpacker Executable
[ ] Creer stub unpacker autonome (prepend au payload)
[ ] Stub alloue memoire RWX pour payload original
[ ] Stub decompress/decrypt payload en memoire
[ ] Stub transfert execution vers OEP du payload
[ ] Tester avec simple executable (MessageBox, etc.)

Exercice 5 : Import Table Reconstruction
[ ] Parser import table du payload original
[ ] Sauvegarder imports dans section metadata
[ ] Stub unpacker reconstruit IAT en memoire
[ ] Resoudre dynamiquement adresses fonctions (GetProcAddress)
[ ] Verifier execution correcte avec imports resolus

Exercice 6 : Anti-Unpacking Techniques
[ ] Implementer anti-debugging checks dans stub
[ ] Ajouter anti-VM detection (CPUID, timing checks)
[ ] Obfusquer code stub (junk instructions, faux jumps)
[ ] Implementer self-integrity check (CRC stub)
[ ] Terminer execution si tampering detecte

Exercice 7 : Dynamic Unpacking & Dump
[ ] Creer script debugger automation (x64dbg/gdb)
[ ] Poser breakpoint sur allocations memoire executables
[ ] Detecter write dans regions executables (unpacking)
[ ] Identifier OEP (changement brutal entropy)
[ ] Dumper memoire process a l'OEP

Exercice 8 : Polymorphic Packer
[ ] Generer stub unpacker different a chaque execution
[ ] Randomiser ordres operations unpacking
[ ] Varier registres utilises (EAX vs EBX, etc.)
[ ] Inserer junk code aleatoire entre instructions
[ ] Verifier hash fichiers packes toujours differents

BONUS CHALLENGES

Challenge 9 : Section Encryption
[ ] Packer qui chiffre uniquement section .text (pas tout fichier)
[ ] Preserver headers et autres sections intactes
[ ] Modifier entry point vers stub dans nouvelle section
[ ] Stub dechiffre .text puis restaure entry point
[ ] Maintenir PE structure valide

Challenge 10 : UPX-Compatible Packer
[ ] Implementer packer compatible format UPX
[ ] Creer sections .UPX0, .UPX1 comme UPX
[ ] Utiliser meme algorithme compression (LZMA/UCL)
[ ] Tester decompression avec upx -d
[ ] Documenter format UPX reverse-engineere

Challenge 11 : Automated Unpacking Service
[ ] Creer service automatise unpacking (a la UnpacMe)
[ ] Detecter type packer (signatures, heuristiques)
[ ] Executer dans sandbox avec hooks API
[ ] Dumper memoire a l'OEP automatiquement
[ ] Reconstruire PE executable depuis dump

OUTILS RECOMMANDES
- UPX : Packer open source reference
- Detect It Easy : Detection packers
- PE-bear : Analyse sections PE
- x64dbg : Debugging pour unpacking manuel
- Scylla : Import reconstruction
- UnpacMe : Service unpacking online

CRITERES VALIDATION
- Packing preserve fonctionnalite binaire 100%
- Unpacking produit binaire identique original (hash)
- Entropy sections packees >= 7.0
- Stub unpacker < 5KB (compact)
- Pas crash durant execution packed binary

INDICATEURS DETECTION PACKING
1. Entropie elevee (>7.0)
2. Sections noms suspects (.UPX, .ASPack, etc.)
3. Peu imports (seulement stub)
4. Sections RWX (Read-Write-Execute)
5. Entry point dans section non-.text
6. Taille section virtuelle >> taille raw
7. Anomalies PE structure

AVERTISSEMENT LEGAL
Le packing est technique legale utilisee legitimement (protection IP).
MAIS son usage pour evasion AV avec malware est illegal. Educational only.

