# Who is this guy — Write-up

**Category:** OSINT  
**Difficulty:** Medium 

---

## Contexte

Sur ce challenge, je n’avais pas **Sherlock** installé sur mon système (Debian).  
Pour garder la même approche qu’avec l’outil en local, j’ai donc cherché une alternative **en ligne** offrant les mêmes fonctionnalités.

Au début, j’ai aussi identifié le vrai nom associé au pseudo **d3dpanda** : **Clément Lagier**.  
J’ai ensuite exploré ses réseaux sociaux (dont GitHub), parcouru ses repositories et vérifié ses derniers commits, mais **je n’ai rien trouvé de concluant**.

Après avoir demandé un indice aux admins, ils m’ont répondu : **“Sherlock est ton ami !”**  
J’ai donc décidé d’utiliser Sherlock via un service web.

---

## 1) Outils utilisés

- **Google** (recherche d’un Sherlock en ligne)
- **Apify — Sherlock Online** :  
  `https://apify.com/misceres/sherlock`

---

## 2) Méthode / Étapes suivies

### 2.1 Trouver un Sherlock en ligne

J’ai recherché sur Google :

> `sherlock tool online`

![alt text](<Screenshot From 2026-02-23 21-23-04.png>)

En parcourant les résultats, je suis tombé sur une solution Apify très pratique :

![alt text](<Screenshot From 2026-02-23 21-26-54.png>)

### 2.2 Lancer la recherche Sherlock

Sur Apify, j’ai cliqué sur **Run** et j’ai lancé la recherche sur le pseudo `d3dpanda` :

![alt text](<Screenshot From 2026-02-23 21-27-58.png>)

Sherlock a retourné environ **35 résultats** (liens vers des profils / pages associées au pseudo) :

![alt text](<Screenshot From 2026-02-23 21-36-50.png>)

### 2.3 Analyse des résultats

J’ai parcouru les liens un par un.  
Au **23ᵉ résultat**, un lien m’a semblé plus “suspect” que les autres :

- `https://replit.com/@d3dpanda`

![alt text](<Screenshot From 2026-02-23 21-41-13.png>)

### 2.4 Découverte du flag

En cliquant sur ce profil Replit, j’ai été **redirigé vers une chaîne YouTube**.  
Et là : le **titre de la vidéo** contenait directement le flag.

![alt text](<Screenshot From 2026-02-23 21-43-32.png>)

---

## Flag

**Flag : CCOI2026{th47_w45_4_l0n6_j0urn3y}**

---

## Remarques / Fausses pistes

- Recherche manuelle sur GitHub (repos, commits, profils) : rien de concluant.
- L’indice des admins (“Sherlock”) a été déterminant pour passer d’une approche manuelle à une recherche large et systématique.