**Français** · [English](../../en/safety/lab-safety.md)

# Règles de sécurité du labo

Cette validation est obligatoire avant chaque exercice pratique de sécurité. Ne commencez pas tant qu'une case reste décochée. Recommencez la vérification si la cible, le réseau, l'instantané, l'exercice ou l'autorisation change.

## Conditions requises avant toute exécution

- [ ] **Autorisation écrite :** je possède un périmètre écrit qui nomme le propriétaire, la cible permise, l'exercice permis, les dates et le contact à prévenir en cas d'arrêt.
- [ ] **Cible possédée :** chaque cible est un système de labo que je possède et contrôle ; aucun système tiers, public, professionnel ou personnel n'est inclus.
- [ ] **VM jetable :** l'exercice s'exécute dans une machine virtuelle jetable ou un système de test dédié tout aussi jetable, jamais sur une machine utilisée au quotidien.
- [ ] **Instantané :** j'ai créé et vérifié un instantané restaurable avant l'exercice.
- [ ] **Réseau isolé :** le labo utilise un réseau host-only ou loopback. Le mode bridge, l'exposition publique, la redirection entrante de ports et les routes vers des réseaux sans rapport sont désactivés.
- [ ] **Aucun secret réel :** le labo contient uniquement des identifiants, jetons, certificats et clés de test synthétiques, jamais de vrais secrets.
- [ ] **Aucune donnée professionnelle ou personnelle :** la VM, les entrées, les sorties et les dossiers montés ne contiennent aucune donnée de production, d'employeur, de client ou personnelle.
- [ ] **Privilèges documentés :** j'ai noté les comptes du labo, les privilèges attribués, les actions élevées nécessaires et la personne qui les a approuvés. J'utiliserai le moindre privilège nécessaire à l'exercice.
- [ ] **Conditions d'arrêt :** j'arrêterai immédiatement si du trafic atteint une adresse inattendue, si l'isolation change, si la cible sort du périmètre, si la supervision est perdue, si l'hôte devient instable ou si j'ai un doute sur l'autorisation.
- [ ] **Plan de nettoyage :** je connais les processus, fichiers, comptes, journaux et changements réseau que l'exercice peut générer, et je sais comment les arrêter ou les retirer avant de restaurer ou supprimer la VM.
- [ ] **Réponse à incident :** je sais isoler la VM, préserver les éléments utiles, noter les heures et les actions, prévenir le propriétaire ou l'encadrant du cours et attendre son accord avant de reprendre.

## Limite du périmètre

L'exposition publique, la persistance, la collecte d'identifiants et toute exécution hors du labo isolé sont hors périmètre. Une leçon impossible à réaliser dans ces limites doit être reportée, pas adaptée à une cible réelle.

Une autorisation visant une cible ou une date n'en autorise pas une autre. Pouvoir atteindre un système ne constitue pas une permission de le tester.

## Si une condition d'arrêt survient

1. Arrêtez l'exercice et ne lancez aucune nouvelle commande depuis celui-ci.
2. Déconnectez ou mettez en pause le réseau du labo sans interagir avec un système inattendu.
3. Préservez l'état de la VM, les journaux utiles, l'heure et la dernière action connue ; n'effacez pas les éléments de preuve.
4. Prévenez le propriétaire ou l'encadrant nommé par le canal d'incident convenu.
5. Ne reprenez qu'après confirmation de l'isolation et renouvellement ou clarification de l'autorisation écrite.

## Nettoyage normal

Si aucun incident n'a eu lieu, arrêtez les processus générés, retirez les identifiants synthétiques et les artefacts produits, annulez les changements réseau propres au labo, puis restaurez l'instantané ou supprimez la VM jetable. Confirmez qu'aucun dossier partagé, périphérique monté, règle de redirection ou compte de labo ne reste actif.

Si un incident a pu se produire, suivez plutôt les étapes de réponse à incident afin de préserver les éléments de preuve.

[Bien démarrer](../start-here.md) · [Choisir un parcours](../paths.md) · [Accueil du cours](../README.md)
