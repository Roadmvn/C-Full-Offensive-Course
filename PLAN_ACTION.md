# Plan d'Action : Arbre d'Apprentissage "Système & Offensif"

Ce plan structure la refonte de la documentation et l'ajout de contenu pédagogique visuel.

## 1. Mise à jour de la Feuille de Route Globale (`README.md`)
*   **Objectif** : Remplacer la documentation actuelle par l'Arbre d'Apprentissage complet (Niveaux 1 à 10).
*   **Contenu** :
    *   Niveaux Fondamentaux (1-6).
    *   **Nouveau** : Malware Dev & Windows Internals (Niveau 7).
    *   **Nouveau** : macOS ARM & Apple Silicon (Niveau 8).
    *   **Nouveau** : Evasion & Post-Exploitation (Niveaux 9-10).

## 2. Création des Supports Théoriques (`Cours.md`)
*   **Objectif** : Pour chaque section, créer un fichier `Cours.md` dédié à la théorie pure, séparé de l'exercice.
*   **Structure type d'un `Cours.md`** :
    1.  **Concept** : Explication simple "from scratch".
    2.  **Visualisation** : Schémas ASCII (Memory Layout, Pointers, Stack Frames).
    3.  **Sous le capot** : Ce qui se passe en mémoire/assembleur.
    4.  **Sécurité** : Risques associés (Buffer Overflow, Race Condition) si applicable.
*   **Action** : Générer ces fichiers pour les modules existants et futurs.

## 3. Suivi de Progression (`PROGRESSION.md`)
*   Mettre à jour la liste des compétences pour inclure les nouveaux modules offensifs et macOS.

## Détail des Nouveaux Modules Techniques

### Windows Offensif
*   PE Headers, IAT/EAT, Process Injection, Win32 API.

### macOS ARM Offensif
*   Registres ARM64, Mach-O, PAC, Codesigning, Shellcode ARM.

### Evasion
*   Obfuscation, Direct Syscalls, Anti-Analysis.

