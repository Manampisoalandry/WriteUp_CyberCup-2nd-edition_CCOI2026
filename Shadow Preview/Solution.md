# Shadow Preview — Write-up

**Category:** Web  
**Difficulty:** Medium  

---

## 1) Outils utilisés

- `git` (récupération / inspection du dépôt)
- `curl` (tests HTTP et exploitation)

---

## 2) Étapes suivies

### 2.1 Reconnaissance et analyse du code : structure et services

Le dépôt contient plusieurs composants :

- `web/index.js` : serveur **Express** + endpoint de preview (`/api/preview`)
- `internal/app.py` : service **Flask** “admin interne” qui sert le **flag**
- `nginx/nginx.conf` : **forward proxy** local sur `127.0.0.1:8888`
- `docker-compose.yml` + `entrypoint.sh` : orchestration des services

#### Point important côté infra

Le fichier `docker-compose.yml` définit deux services (`web` + `internal`) et un réseau `backend` marqué `internal: true` (donc **non exposé vers l’extérieur**).  
👉 Le flag est donc forcément côté **internal**.

---

### 2.2 Analyse du backend “internal” : où est le flag ?

Dans `internal/app.py` :

![alt text](<Screenshot From 2026-02-23 20-31-02.png>)

✅ Conclusion :

- Le flag est servi à `GET /flag`
- Il n’est retourné **que si** `request.remote_addr` est **privé** ou **loopback**
- Donc un accès direct depuis une IP publique renverra `403`

🎯 Objectif : **forcer le serveur web (preview bot) à appeler `/flag` depuis l’intérieur.**

---

### 2.3 Analyse de la feature “URL Preview” : SSRF

Dans `web/index.js`, l’endpoint principal est :

![alt text](<Screenshot From 2026-02-23 20-36-11.png>)

#### 2.3.1 Filtrage SSRF trop faible (blocklist)

Le code interdit seulement quelques hosts :

![alt text](<Screenshot From 2026-02-23 20-38-06.png>)

👉 On ne peut pas passer directement `internal`, `localhost`, `127.0.0.1` en paramètre initial.

#### 2.3.2 Redirects suivis sans re-validation

Dans `fetchWithRedirects()` : les redirections sont suivies, mais le host **n’est pas re-filtré** à chaque hop.

![alt text](<Screenshot From 2026-02-23 20-41-15.png>)

✅ Conclusion : on peut fournir une URL **autorisée** au départ, qui redirige vers une URL **interdite** (`127.0.0.1` / `internal`) et elle sera quand même fetch.

#### 2.3.3 Open redirect prêt à l’emploi

Toujours dans `web/index.js` :

![alt text](<Screenshot From 2026-02-23 20-43-59.png>)

✅ Endpoint “bounce” parfait :  
`/auth/continue?next=<url>`

---

### 2.4 Le “twist” : le proxy HTTP local (explication du 502)

Dans `fetchWithRedirects()` :

- Si l’URL est en `http://` → axios utilise un proxy local `127.0.0.1:8888`
- Si l’URL est en `https://` → pas de proxy

![alt text](<Screenshot From 2026-02-23 20-46-05.png>)

Et dans `nginx/nginx.conf` (forward proxy) :

- si `Host = web` → proxifie vers `127.0.0.1:8080`
- si `Host = internal` → proxifie vers `127.0.0.1:9000`

![alt text](<Screenshot From 2026-02-23 20-48-13.png>)

➡️ **Pourquoi on obtient parfois `502` ?**  
Si on utilise l’IP publique comme URL de départ (`http://87.x.x.x:8080/...`), le bot (dans le conteneur) peut ne pas réussir à “reboucler” vers l’extérieur (hairpin NAT / route / restrictions). Le proxy nginx n’arrive pas à joindre l’upstream → `502 Bad Gateway`.

✅ Solution : passer par le hostname interne **`web`**, résolu localement.

---

## 3) Exploit final : SSRF via redirect + host `web`

### Idée de l’exploit

1. Donner une URL autorisée : hostname = `web` (pas bloqué)
2. Appeler `/auth/continue` qui redirige vers `http://127.0.0.1:9000/flag`
3. La redirection est suivie **sans re-vérification**
4. La requête vers `127.0.0.1:9000` est interne → `internal/app.py` renvoie le flag

### Commande d’exploitation

```bash
curl -s -X POST 'http://87.106.89.40:8080/api/preview' \
  -H 'Content-Type: application/json' \
  --data '{"url":"http://web:8080/auth/continue?next=http%3A%2F%2F127.0.0.1%3A9000%2Fflag"}'
```

 ![alt text](<Screenshot From 2026-02-23 20-04-15-1.png>)

  Et yeupp, la flag 

## FLAG

Youupiii, la flag est là:

**Flag : CCOI26{f0rc3_url_pr3v13w_t0_f0ll0w_0p3n_r3d1r3ct_t0_1nt3rn4l_4dm1n_4nd_l34k_fl4g_1n_sn1pp3t}**
