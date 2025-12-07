# Exercices - IOCTL Communication

## Objectifs des exercices

Pratiquer la communication user-mode/kernel-mode via IOCTL

---

## Exercice 1 : Premier IOCTL (Tres facile)

**Objectif** : Creer un IOCTL basique

**Instructions** :
1. Definir un code IOCTL_PING avec CTL_CODE()
2. Implementer un handler qui retourne "PONG"
3. Creer une app user-mode qui envoie l'IOCTL
4. Afficher la reponse

---

## Exercice 2 : IOCTL avec Parametres (Facile)

**Objectif** : Passer des structures entre user/kernel

**Instructions** :
1. Definir IOCTL_ADD_NUMBERS
2. Creer structure avec 2 entiers input, 1 entier output
3. Le driver additionne les 2 nombres
4. L'app affiche le resultat

---

## Exercice 3 : Driver Calculator (Moyen)

**Objectif** : Plusieurs IOCTL pour differentes operations

**Instructions** :
1. IOCTL_ADD, IOCTL_SUB, IOCTL_MUL, IOCTL_DIV
2. Handler qui switche sur l'operation
3. Gestion erreurs (division par zero)
4. App interactive user-mode

---

## Exercice 4 : Process Lister via IOCTL (Difficile)

**Objectif** : Lister les processus depuis kernel

**Instructions** :
1. IOCTL_ENUM_PROCESSES
2. Parcourir ActiveProcessLinks
3. Remplir tableau de PIDs/noms
4. Retourner au user-mode
5. Afficher la liste

---

## Exercice 5 : Rootkit C2 (Challenge Red Team)

**Objectif** : Interface IOCTL complete pour rootkit

**Instructions** :
1. IOCTL_HIDE_PROCESS
2. IOCTL_PROTECT_PROCESS
3. IOCTL_INJECT_DLL
4. IOCTL_KILL_PROCESS
5. App C2 user-mode
6. Menu interactif

**Bonus** : Implementer authentification (secret key dans IOCTL)
