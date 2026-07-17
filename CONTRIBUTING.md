# Contribuer · Contributing

[Français](fr/README.md) · [English](en/README.md) · [Code de conduite · Code of Conduct](CODE_OF_CONDUCT.md)

## Français

### Contributions bienvenues

Les corrections de cours, améliorations de configuration, tests, clarifications de documentation et propositions de laboratoires sûrs sont bienvenues. Avant un changement important, ouvrez une proposition de contenu afin de confirmer le périmètre.

### Limite de sécurité

Toute contribution doit servir l'apprentissage ou la recherche autorisée dans un laboratoire isolé. N'ajoutez pas de cibles réelles, d'identifiants, de secrets, de données personnelles, ni d'instructions destinées à un usage opérationnel non autorisé. Expliquez l'autorisation, l'isolation, les conditions d'arrêt et le nettoyage lorsque le contenu touche à la sécurité.

### Règles du dépôt

- Livrez ensemble les versions française et anglaise de tout nouveau contenu destiné aux apprenants, avec le même sens et les mêmes commandes.
- Gardez le code C partagé dans les dossiers historiques. Ne copiez pas de source ou d'artefact C sous `fr/` ou `en/`.
- Conservez les chemins historiques et évitez toute suppression de fichier suivi sans décision explicite du mainteneur.
- Décrivez honnêtement la maturité : `Ready`, `Draft` ou `Reference`. Ne présentez pas un brouillon comme terminé et ne promettez pas un résultat non vérifié.
- Limitez chaque commit à un sujet cohérent et indiquez précisément les chemins modifiés.

### Vérifications locales et pull request

Exécutez les tests et contrôles depuis la racine du dépôt :

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --all
```

La pull request doit expliquer le périmètre, lister les chemins modifiés, indiquer les tests exécutés et confirmer la parité linguistique, le partage du code, le statut de maturité, la revue de sécurité et l'absence de nouveau lien local cassé. Utilisez des commits ciblés et répondez aux retours dans la pull request.

## English

### Welcome contributions

Course corrections, setup improvements, tests, documentation clarifications, and safe lab proposals are welcome. Open a content proposal before a substantial change so the scope can be agreed first.

### Safe-content boundary

Every contribution must support learning or authorized research in an isolated lab. Do not add real targets, credentials, secrets, personal data, or instructions intended for unauthorized operational use. Explain authorization, isolation, stop conditions, and cleanup whenever security-sensitive material is involved.

### Repository rules

- Keep **FR/EN parity**: deliver French and English versions of new learner-facing content together, with equivalent meaning and identical commands.
- Keep all **shared C code** in the historical course directories. Never copy C source or artifacts into `fr/` or `en/`.
- Preserve historical paths and do not delete a tracked file without an explicit maintainer decision.
- Report the real **maturity status** as `Ready`, `Draft`, or `Reference`; never present unfinished material as complete or promise an unverified outcome.
- Use a **focused commit** for each coherent change and identify the exact paths changed.

### Local checks and pull request expectations

Run the tests and repository checks from the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --all
```

In the pull request, explain the scope, list the paths changed, record the tests run, complete a **safety review**, confirm language and shared-code rules, and state the maturity status. Run the link check so the change introduces **no new broken links**. Keep commits focused and address review feedback in the pull request.
