# GhostKey — Write-up

**Category:** Crypto  
**Difficulty:** Difficile (400 pts)

---

## Contexte

On nous fournit un fichier :

- `bedef964-a8bc-415a-8b25-4296a98e6af9.json`

L’énoncé indique :

> “La signature des jeux de PS3 était vraiment impressionnante mais pas assez pour moi.  
> Du coup j'ai décidé de l'améliorer. D'ailleurs, j'ai réutilisé le secret de la signature (une fois digéré) comme clé pour chiffrer mon super flag :)”

On comprend qu’il y a :
- **ECDSA** (avec une faiblesse “PS3-like” : nonce `k` prévisible / corrélé),
- puis un chiffrement **AES-256-CBC** dont la clé est dérivée (“digérée”) depuis le secret de signature.

Objectif : retrouver la flag au format `CCOI26{...}`.

---

## 1) Outils utilisés

- `jq` / `cat` : lecture du JSON
- `python3` : résolution ECDSA + déchiffrement AES
- `pycryptodome` : AES-CBC + padding
- `hashlib` : SHA-256

---

## 2) Méthode / Étapes suivies

### 2.1 Comprendre la faille ECDSA (nonce type PS3)

ECDSA (modulo `n`) :

\[
s \equiv k^{-1}(z + r\cdot d)\ \ (\text{mod } n)
\]

- `d` : clé privée (inconnue)
- `k` : nonce (doit être aléatoire ; sinon ECDSA se casse)
- `z` : hash du message (ici SHA-256)

L’indice “PS3” fait penser à un nonce **prévisible**.  
Le JSON fournit deux signatures sur deux messages différents avec un champ `seq_id` (consécutif), ce qui suggère une relation du style :

\[
k_i \equiv k_0 + seq_i\ (\text{mod } n)
\]

En remplaçant dans la formule :

\[
s_i (k_0 + seq_i) \equiv z_i + r_i\cdot d\ (\text{mod } n)
\]

Avec deux signatures `(r1,s1)` et `(r2,s2)`, on obtient **2 équations** et **2 inconnues** (`k0` et `d`) → solvable modulo `n`.

---

### 2.2 Extraire les champs utiles depuis le JSON

Dans `captured_traffic[0]` et `captured_traffic[1]`, on récupère :
- `seq_id`
- `data` (message)
- `signature.r`
- `signature.s`

Et pour la partie AES :
- `encrypted_secret.iv`
- `encrypted_secret.ciphertext`

---

### 2.3 Calculer les hashes `z1` et `z2`

\[
z_i = SHA256(m_i) \mod n
\]

---

### 2.4 Résoudre le système modulaire pour retrouver `d`

On résout :

\[
s_i (k_0 + seq_i) = z_i + r_i d\ (\text{mod } n)
\]

Ce calcul donne la **clé privée ECDSA `d`**.

---

### 2.5 Dériver la clé AES (“digéré”)

L’énoncé dit que le secret est “digéré”, donc on applique un hash :

```text
AES_key = SHA256(d_bytes)
d_bytes = d.to_bytes(32, "big") (secp256k1 → 32 octets)

SHA256 → 32 octets → AES-256

### 2.6 Déchiffrer AES-256-CBC et récupérer la flag

On utilise :

- IV depuis le JSON
- ciphertext depuis le JSON
- AES-CBC + unpadding PKCS#7

Le plaintext contient directement la flag.

---

## 3) Résolution (script)

### 3.1 Installation

```bash
pip install pycryptodome

```
### 3.2 Script `solve.py`

```python
import json, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Ordre du groupe secp256k1
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def inv(a, m):
    return pow(a, -1, m)

data = json.load(open("bedef964-a8bc-415a-8b25-4296a98e6af9.json", "r", encoding="utf-8"))

t1, t2 = data["captured_traffic"][0], data["captured_traffic"][1]

q1, m1 = int(t1["seq_id"]), t1["data"].encode()
q2, m2 = int(t2["seq_id"]), t2["data"].encode()

r1 = int(t1["signature"]["r"], 16)
s1 = int(t1["signature"]["s"], 16)
r2 = int(t2["signature"]["r"], 16)
s2 = int(t2["signature"]["s"], 16)

z1 = int.from_bytes(hashlib.sha256(m1).digest(), "big") % n
z2 = int.from_bytes(hashlib.sha256(m2).digest(), "big") % n

# Système : s_i*(k0 + q_i) = z_i + r_i*d (mod n)
b1 = (z1 - (s1 * q1) % n) % n
b2 = (z2 - (s2 * q2) % n) % n

det = (s2 * r1 - s1 * r2) % n
deti = inv(det, n)

k0 = ((-r2 * b1 + r1 * b2) * deti) % n
d  = ((-s2 * b1 + s1 * b2) * deti) % n  # clé privée

# AES-256 key = SHA256(d)
key = hashlib.sha256(d.to_bytes(32, "big")).digest()

iv = bytes.fromhex(data["encrypted_secret"]["iv"])
ct = bytes.fromhex(data["encrypted_secret"]["ciphertext"])

pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode())

```
Execution du script

![alt text](<Screenshot From 2026-02-24 13-22-19.png>)

## FLAG

Youupiii, la flag est là:

**Flag : CCOI26{Ps3_N0nc3_R38s3_1s_SW33t}**