# Module 12 : Unions et Enums - Exercices

## Exercice 1 : Union de base (Facile)

**Objectif** : Comprendre le partage mémoire.

Créer une union `Value` avec int, float, char[16]. Afficher sizeof et tester que les membres partagent la mémoire.

---

## Exercice 2 : Type Punning (Facile)

**Objectif** : Voir la représentation binaire.

Créer une union pour voir les bytes d'un `float`. Afficher 3.14 en hex et bytes.

---

## Exercice 3 : Enum de base (Facile)

**Objectif** : Définir des constantes nommées.

Créer un enum `LogLevel` (DEBUG=0, INFO, WARNING, ERROR, CRITICAL). Fonction `log_message(level, msg)` qui affiche avec le niveau.

---

## Exercice 4 : Enum flags (Moyen)

**Objectif** : Utiliser les flags bitwise.

Créer un enum `FileMode` (NONE=0, READ=1, WRITE=2, EXECUTE=4, HIDDEN=8). Fonctions pour tester, ajouter et retirer des flags.

---

## Exercice 5 : Tagged Union (Moyen)

**Objectif** : Combiner enum et union.

Créer un type `ConfigValue` qui peut être int, string ou bool. Utiliser un enum comme tag et une union pour la valeur.

---

## Exercice 6 : Parsing IP (Moyen)

**Objectif** : Manipuler des adresses IP.

Union `IPv4` pour accéder à une IP comme uint32_t ou octets[4]. Fonctions `ip_from_string("192.168.1.1")` et `ip_to_string(ip)`.

---

## Exercice 7 : État d'implant (Moyen)

**Objectif** : Machine à états avec enum.

Enum `ImplantState` avec 6 états. Structure `Implant` avec état, transitions valides, et fonction `transition(imp, new_state)`.

---

## Exercice 8 : Message protocol (Difficile)

**Objectif** : Parser des messages binaires.

Structures pour header (magic, type, length) et payload. Union pour différents types de payload. Parser et builder.

---

## Exercice 9 : Commandes C2 (Difficile)

**Objectif** : Système de commandes avec union.

Enum `CmdType` (SHELL, DOWNLOAD, UPLOAD, SLEEP, EXIT). Structure `Command` avec type et union d'arguments. Dispatcher.

---

## Exercice 10 : Registre CPU (Difficile)

**Objectif** : Simuler un registre avec union.

Union `Register64` accessible comme uint64, uint32[2], uint16[4], uint8[8]. Fonctions pour lire/écrire chaque partie.

---

## Exercice 11 : Variant JSON (Challenge)

**Objectif** : Type variant complet.

Enum des types (NULL, BOOL, INT, FLOAT, STRING, ARRAY, OBJECT). Tagged union pour les valeurs. Fonction `print_json_value()`.

---

## Exercice 12 : Packet parser (Challenge)

**Objectif** : Parser de protocoles réseau.

Structures packed pour IP et TCP/UDP/ICMP. Union pour les couches transport. Fonction `parse_ip_packet(data, len)`.

---

## Barème

| Exercice | Difficulté | Concepts |
|----------|------------|----------|
| 1-3 | Facile | Bases union/enum |
| 4-7 | Moyen | Flags, tagged union, états |
| 8-10 | Difficile | Protocoles, variant types |
| 11-12 | Challenge | Parsers complexes |

Bonne chance !
