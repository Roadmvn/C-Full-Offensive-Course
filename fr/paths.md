**Français** · [English](../en/paths.md)

# Choisir un parcours d'apprentissage

Commencez par le parcours qui correspond à vos acquis et à votre système d'exploitation. Les durées sont des fourchettes de planification, pas des garanties de réussite. La disponibilité et la maturité des unités viennent des champs `status` de [`content/curriculum.json`](../content/curriculum.json) ; consultez cet inventaire avant de vous appuyer sur une unité avancée.

Tous les travaux pratiques de sécurité sont également soumis aux [règles de sécurité du labo](safety/lab-safety.md).

## 1. Tronc commun débutant en 12 semaines

Suivez les sections partagées dans cet ordre : `00-prerequisites`, `01-c-fundamentals`, `02-memory-pointers`, `03-asm-x64`, `04-windows-fundamentals`, `05-windows-advanced`, `06-network`, puis `07-beacon-dev`. La section `03-asm-x64` précède les internes Windows afin d'introduire d'abord les registres, les conventions d'appel et le comportement de la mémoire.

`03-asm-x64` nécessite un environnement `x86-64` pour ses exercices d'assembleur. Sur un hôte d'une autre architecture, préparez une VM x86-64 avant de commencer ce module.

- **Prérequis :** aucun ; faites les lectures et les exercices écrits de `00-prerequisites` si le modèle de la machine est nouveau pour vous.
- **Durée estimée :** 12 semaines pour le tronc commun proposé, avec du temps supplémentaire pour toute unité `Draft` ou toute notion à retravailler.
- **Plateformes :** Windows, Linux ou macOS pour les sections `00` à `02` ; un environnement x86-64 pour `03` ; une VM Windows jetable pour les travaux propres à Windows dans les sections suivantes du tronc commun.
- **Résultat visé :** des bases opérationnelles en C, mémoire, assembleur x64, concepts Windows, réseau et structure d'un projet intégré. C'est un objectif d'apprentissage, pas la garantie d'un niveau professionnel.
- **Source du statut :** utilisez [`content/curriculum.json`](../content/curriculum.json) pour distinguer les unités prêtes du contenu `Draft`.

## 2. Approfondissement Windows

Étudiez `04-windows-fundamentals`, puis `05-windows-advanced`, et consultez certaines références Windows de `10-advanced` uniquement lorsqu'une unité du tronc commun les indique ou que votre objectif les exige.

- **Prérequis :** terminez ou maîtrisez les connaissances de `01`, `02` et `03` ; validez les règles de sécurité du labo avant les exercices pratiques de sécurité.
- **Durée estimée :** 4 à 8 semaines supplémentaires ou plus, selon votre expérience de Windows et du débogage ainsi que le statut audité des unités choisies.
- **Plateformes :** une VM Windows 10 ou Windows 11 jetable, avec un instantané restaurable et un réseau host-only ou loopback.
- **Résultat visé :** comprendre et examiner les API Windows, les processus, les threads, la mémoire et certaines références avancées dans un labo autorisé.
- **Source du statut :** vérifiez chaque unité choisie de `04`, `05` ou `10` dans [`content/curriculum.json`](../content/curriculum.json) ; visible ne signifie pas nécessairement prête.

## 3. Spécialisation Linux ou macOS

Après `02-memory-pointers` et `03-asm-x64`, choisissez `08-linux` ou `09-macos`. Il n'est pas nécessaire de suivre les deux spécialisations en même temps.

- **Prérequis :** fondamentaux C, puis sections `02` et `03` ; validez les règles de sécurité du labo avant les exercices pratiques de sécurité.
- **Durée estimée :** 4 à 8 semaines supplémentaires ou plus pour une plateforme, selon l'état de ses unités et votre expérience des systèmes.
- **Plateformes :** une VM Linux jetable pour `08-linux`, ou un environnement de test macOS dédié/jetable pour `09-macos` ; gardez son réseau isolé.
- **Résultat visé :** relier le C, la mémoire, les formats exécutables, les interfaces système et les protections de la plateforme sur le système choisi.
- **Source du statut :** consultez les entrées `08` ou `09` choisies dans [`content/curriculum.json`](../content/curriculum.json) et traitez les unités `Draft` comme des références incomplètes.

## 4. Références avancées

Utilisez `10-advanced` comme une référence organisée par sujet. Cette section se trouve explicitement hors de la promesse des 12 semaines et ne constitue pas la prochaine étape automatique de chaque apprenant.

- **Prérequis :** bases solides en C, mémoire, assembleur, systèmes d'exploitation et débogage, ainsi que tout module antérieur indiqué par la référence choisie.
- **Durée estimée :** ouverte ; choisissez un sujet audité à la fois au lieu de traiter `10` comme un cours de durée fixe.
- **Plateformes :** variables selon le sujet, toujours dans un labo possédé, autorisé et isolé.
- **Résultat visé :** trouver et évaluer le contenu avancé sans confondre la couverture de l'inventaire avec des cours terminés.
- **Source du statut :** le champ `status` de l'entrée choisie dans [`content/curriculum.json`](../content/curriculum.json) fait foi ; une entrée `Draft` se trouve hors du cursus prêt.

## Commencer

Si vous n'avez pas encore vérifié de compilateur, suivez [Bien démarrer](start-here.md). Notez ensuite le parcours choisi et la prochaine unité prête que vous allez terminer.
