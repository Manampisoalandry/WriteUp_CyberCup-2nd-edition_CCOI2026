# HashCrumb — Write-up

**Category:** Crypto  
**Difficulty:** Easy  

---

## Contexte

On nous fournit deux fichiers :

- `hashcrumb.py`
- `hashes.txt`

Le but est de retrouver la **flag** au format `CCOI26{...}`.

---

## 1) Outils utilisés

- `cat` / `head` (inspecter les fichiers)
- `python3` + `hashlib` (reconstruction / reverse)

---

## 2) Méthode / Étapes suivies

### 2.1 Comprendre ce que fait `hashcrumb.py`

Dans `hashcrumb.py`, on voit que le programme :

- parcourt la flag caractère par caractère
- calcule `md5(ch)` pour **chaque caractère**
- écrit chaque hash sur une ligne dans `hashes.txt`

Donc `hashes.txt` contient :

\[
hashes[i] = MD5(flag[i])
\]

---

### 2.2 Inverser des MD5 “1 caractère” (très simple)

MD5 est irréversible en général, mais ici chaque hash correspond à **un seul caractère**.
On peut donc :

1. Pré-calculer un dictionnaire `{ md5(char) -> char }` sur les caractères imprimables (ASCII 32..126)
2. Lire chaque ligne de `hashes.txt`
3. Remplacer chaque hash par le caractère correspondant
4. Concaténer → flag

---

## 3) Résolution (script)

### 3.1 Script `solve.py`

```python
import hashlib

# Charger les hashes
hashes = open("hashes.txt", "r", encoding="utf-8").read().splitlines()

# Construire un mapping md5(char) -> char sur ASCII imprimable
chars = [chr(i) for i in range(32, 127)]
md5_map = {hashlib.md5(c.encode()).hexdigest(): c for c in chars}

# Reconstituer le plaintext
out = []
for h in hashes:
    out.append(md5_map.get(h, "?"))  # "?" si non trouvé

flag = "".join(out)
print(flag)

```
Execution du script

![alt text](<Screenshot From 2026-02-24 14-05-42.png>)

## Flag

**Flag : CCOI26{_h4sh_crum83_easy_TO_cR4ck_}**