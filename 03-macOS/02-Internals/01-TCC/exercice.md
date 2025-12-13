# EXERCICE : CODE SIGNING & PAC

1. Vérifier la signature d'un binaire système

2. Créer un programme et le signer avec différentes options

3. Extraire les entitlements d'une application

4. Écrire du code ARM64 avec PAC (PACIASP/AUTIASP)

5. Détecter si la machine supporte PAC


### COMMANDES :
codesign -dv /Applications/Safari.app
codesign -s - --options=runtime mybinary


