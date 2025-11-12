# 🎯 Apprentissage du C pour le Red Teaming

## 🚀 Ce projet commence depuis ZÉRO

**Important** : Ce programme d'apprentissage débute au niveau débutant absolu. Même si tu as terminé des cours comme Bro Code ou d'autres tutoriels, **fais TOUS les exercices dans l'ordre**. Chaque exercice construit les fondations pour les suivants.

## 📚 Pourquoi ce projet ?

Le C est le langage fondamental pour comprendre :
- Comment fonctionne la mémoire
- Comment les programmes interagissent avec le système
- Comment identifier et exploiter les vulnérabilités
- Comment développer des exploits et des outils de sécurité

## 🎓 Prérequis

**AUCUN** - Ce projet est conçu pour les débutants absolus en C.

Tu dois seulement savoir :
- Utiliser un terminal/ligne de commande
- Naviguer dans les dossiers (cd, ls)
- Avoir de la curiosité et de la persévérance

## 🛠️ Installation

```bash
# Cloner ou télécharger ce repository
cd learning-c

# Rendre le script d'installation exécutable
chmod +x setup.sh

# Installer les outils nécessaires (gcc, make, gdb)
./setup.sh
```

## 📂 Structure du projet

```
learning-c/
├── README.md              ← Tu es ici
├── PROGRESSION.md         ← Calendrier et progression détaillée
├── setup.sh               ← Script d'installation
├── .gitignore
└── exercices/
    ├── 01_hello_world/
    ├── 02_variables_types/
    ├── 03_printf_scanf/
    └── ... (20 exercices au total)
```

## 🎯 Progression

### Phase 1 : Bases Absolues (Exercices 01-09) - 1 à 2 semaines
Tu vas apprendre :
- Écrire et compiler ton premier programme
- Variables et types de données
- Afficher et lire des données
- Conditions et boucles
- Arrays et strings
- Fonctions

### Phase 2 : Niveau Intermédiaire (Exercices 10-14) - 1 semaine
Tu vas comprendre :
- Les pointeurs (concept crucial)
- La gestion dynamique de la mémoire
- Les structures de données
- La manipulation de fichiers

### Phase 3 : Exploitation et Sécurité (Exercices 15-20) - 1 à 2 semaines
Tu vas explorer :
- Les concepts de buffers et overflow
- Stack overflow
- Shellcode et exécution de code
- Format string vulnerabilities
- Heap exploitation
- Reverse shells

## 📋 Règles d'apprentissage

### ✅ À FAIRE
1. **Respecter l'ordre strict** : 01 → 02 → 03 → ... → 20
2. **Ne pas skipper d'exercices** : Chacun construit sur le précédent
3. **Lire tous les commentaires** : Le code est sur-commenté pour une raison
4. **Faire les défis** : Essaye de modifier le code avant de voir les solutions
5. **Prendre des notes** : Garde un carnet de ce que tu apprends
6. **Pratiquer** : Réécris le code sans regarder pour mémoriser

### ❌ À ÉVITER
1. Ne pas copier-coller sans comprendre
2. Ne pas sauter directement aux exercices avancés
3. Ne pas ignorer les warnings du compilateur
4. Ne pas abandonner si ça semble difficile (c'est normal !)

## 🚀 Comment utiliser ce projet

### Pour chaque exercice :

1. **Lire le README.md de l'exercice**
```bash
cd exercices/01_hello_world/
cat README.md
```

2. **Étudier le code main.c**
```bash
cat main.c
# Lis TOUS les commentaires !
```

3. **Compiler et exécuter**
```bash
make
./program
```

4. **Essayer les défis (exercice.txt)**
```bash
cat exercice.txt
# Modifie main.c et re-compile
```

5. **Vérifier les solutions si bloqué**
```bash
cat solution.txt
```

6. **Nettoyer**
```bash
make clean
```

## ⏱️ Temps estimé par exercice

- **Exercices 01-05** : 30-60 minutes chacun
- **Exercices 06-09** : 1-2 heures chacun
- **Exercices 10-14** : 2-3 heures chacun
- **Exercices 15-20** : 3-4 heures chacun

**Temps total estimé** : 40-60 heures de travail

## 📖 Ressources additionnelles

- [GCC Documentation](https://gcc.gnu.org/onlinedocs/)
- [GDB Tutorial](https://www.gdbtutorial.com/)
- [C Reference](https://en.cppreference.com/w/c)

## 🎓 Après avoir terminé

Une fois les 20 exercices complétés, tu auras :
- ✅ Une solide compréhension du langage C
- ✅ La capacité de lire et écrire du code C
- ✅ Les bases de l'exploitation de vulnérabilités
- ✅ Les fondations pour continuer vers des CTFs et bug bounty

## 🤝 Contribution

Si tu trouves des erreurs ou as des suggestions :
1. Note-les dans un fichier
2. Propose des améliorations
3. Partage avec la communauté

## ⚠️ Avertissement légal

**IMPORTANT** : Les techniques d'exploitation enseignées dans ce projet sont à des fins éducatives uniquement.

**N'utilise ces connaissances que sur :**
- Tes propres systèmes
- Des environnements de test autorisés
- Des plateformes CTF légales
- Des programmes de bug bounty avec autorisation

**Toute utilisation malveillante est ILLÉGALE et CONTRAIRE À L'ÉTHIQUE.**

## 🚀 Prêt à commencer ?

```bash
cd exercices/01_hello_world/
cat README.md
```

**Bonne chance dans ton apprentissage ! 🔥**

---

*"La maîtrise du C est la clé pour comprendre comment les systèmes fonctionnent réellement."*
