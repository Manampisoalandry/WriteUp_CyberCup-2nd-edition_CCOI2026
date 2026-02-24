# Mirage — Write-up

**Category:** Crypto  
**Difficulty:** Medium  

---

## Contexte

On nous fournit un fichier chiffré :

- `cipher.bin`

Le flag a le format habituel des challenges : **`CCOI26{...}`**.  
On suspecte donc que le plaintext commence par `CCOI26{`.

Le chiffrement ressemble à un **stream cipher XOR** basé sur un PRNG **xorshift32** (état 32 bits), qui génère un keystream ensuite XOR avec le message.

---

## 1) Outils utilisés

- `xxd` / `hexdump` (visualiser `cipher.bin`)
- `python3` (script de déchiffrement)
- (optionnel) `strings` pour repérer des motifs

---

## 2) Méthode / Étapes suivies

### 2.1 Principe : XOR + keystream

Si le chiffrement est :

\[
C = P \oplus KS
\]

Alors :

\[
KS = C \oplus P
\]

Comme on connaît le début de `P` (`CCOI26{`), on peut reconstruire les **premiers octets du keystream** en faisant `ct XOR known`.

---

### 2.2 Récupérer la 1ère sortie du PRNG

Le keystream est produit à partir de blocs 32-bit packés en **little-endian** (`<I`).

On récupère donc les **4 premiers octets** du keystream → ça correspond à la **première valeur 32-bit** sortie par xorshift32.

---

### 2.3 Inverser xorshift32 pour retrouver le seed

xorshift32 applique des opérations réversibles :

- `x ^= x << 13`
- `x ^= x >> 17`
- `x ^= x << 5`

On inverse ces opérations (bit par bit / par “couches”) pour retrouver l’état précédent :

- inversion de `x ^= x << k`
- inversion de `x ^= x >> k`

Ainsi, avec la **première sortie** `s1`, on remonte au **seed initial**.

---

### 2.4 Générer tout le keystream et déchiffrer

Une fois le seed récupéré :

- on regénère `KS` sur la longueur de `cipher.bin`
- on calcule `PT = CT XOR KS`
- on affiche le plaintext → flag

---

## 3) Résolution (script)

### 3.1 Script `solve.py`

```python
import struct

MASK = 0xFFFFFFFF

def xorshift32(x):
    x &= MASK
    x ^= (x << 13) & MASK
    x ^= (x >> 17) & MASK
    x ^= (x << 5) & MASK
    return x & MASK

def keystream(seed, n):
    s = seed & MASK
    out = bytearray()
    while len(out) < n:
        s = xorshift32(s)
        out += struct.pack("<I", s)
    return out[:n]

# Inversion exacte de x ^= x<<k / x ^= x>>k
def unxorshift_left(y, k):
    x = y & MASK
    s = k
    while s < 32:
        x ^= (x << s) & MASK
        s *= 2
    return x & MASK

def unxorshift_right(y, k):
    x = y & MASK
    s = k
    while s < 32:
        x ^= (x >> s)
        s *= 2
    return x & MASK

def invert_xorshift32(y):
    x = y & MASK
    x = unxorshift_left(x, 5)
    x = unxorshift_right(x, 17)
    x = unxorshift_left(x, 13)
    return x & MASK

ct = open("cipher.bin", "rb").read()
known = b"CCOI26{"

# Keystream prefix = ct XOR known plaintext prefix
ks_prefix = bytes(c ^ p for c, p in zip(ct, known))

# 1ère sortie 32-bit du PRNG (little-endian)
s1 = int.from_bytes(ks_prefix[:4], "little")

# seed avant le 1er xorshift
seed = invert_xorshift32(s1)

# Déchiffrement complet
ks = keystream(seed, len(ct))
pt = bytes(c ^ k for c, k in zip(ct, ks))

print(pt.decode())

```
Execution du script:

![alt text](<Screenshot From 2026-02-24 13-42-05.png>)

## FLAG

Youupiii, la flag est là:

**Flag : CCOI26{t1m3_s33d3d_x0r_v4u17}**
