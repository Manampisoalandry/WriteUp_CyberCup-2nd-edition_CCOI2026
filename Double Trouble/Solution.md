# iNode Never Forgets — Write-up

**Category:** Web 
**Difficulty:** Medium  

---

## Contexte

Sur ce challenge, le but c'est de changer la cracké la coockie de l'user par la coockie de l'admin qui fait le bypass de la 2fa qui est verify2fa.php

## 1) Outils utilisés

- `hashcat`(pour cracké la cookie de l'user avec jwt)
- `python`(pour le scripting)
---

## 2) Méthode / Étapes suivies

- Creer un compte avec le bouton 'Register'
- Connection avec l'username, mdp, resolution des enigme de calcul, et l'otp

Rediriger sur cette interface

![alt text](<Screenshot From 2026-02-21 21-10-41.png>)

T'inquites, dès ma premiere reflexion, j'ai douté de la faire le brute force de cette 2fa de 6 chiffres 🫢 avec un script python en recuperant l'auth_token car le sujet disait que le token a eu une validité d'une heure.
Mais à la derniere reflexion, j'avais une idéé pour de n'est pas cracké le token de l'user par le token de l'admin. J'ai utilisé hascat pour le cracké. Le but c'est de n'est pas seulement cracké mais de bypassé la signature

![alt text](<Screenshot From 2026-02-24 07-35-51.png>)

- hashcat: util de cracking de mots de passe par force brute / dictionnaire.a
- -a 0 : mode d'attaque dictionnaire (wordlist attack) : teste chaque mot de la liste un par un.
- -m 1650 : type de hash cible : JWT (JSON Web Token). Hashcat va tenter de trouver le secret utilisé pour signer le token.
- token2.txt : fichier contenant le JWT à cracker, le token de l'user
- /usr/share/wordlists/rockyou.txt :la wordlist 

et uppp, on a cracké le token 

![alt text](<Screenshot From 2026-02-24 07-43-01-1.png>)

On a obtenu le token cracké avec l'user tareq.
Pour la prochaine etape, j'ai créé un script python meme fonctionnalité de jwt.io qui permet de changer la signature de la token de l'user par l'admin par le secret tareq

![alt text](<Screenshot From 2026-02-24 07-55-08.png>)

Il suffit juste de copie, cette token dans l'auth_token et on actualise.

Booom, on accès au admin panel et on obtenu la flag

A cause de la pression, j'ai pas pu arriver à capturer l'admin panel mais il rassemble à celle ci

![alt text](<Screenshot From 2026-02-21 01-30-51.png>)









