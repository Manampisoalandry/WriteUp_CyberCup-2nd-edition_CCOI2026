# Masked Multiply — Write-up

**Category:** Reverse (RE)  
**Difficulty:** Medium  

---

## Contexte

On nous fournit un binaire :

- `masked_multiply`

Le programme affiche le format attendu du flag : **`CCOI26{...}`**, puis demande une entrée.

L’objectif est de comprendre la vérification et de reconstruire le flag.

---

## 1) Outils utilisés

- `strings` (repérer les messages / indices)
- `objdump` / `readelf` (désassemblage + repérage `.rodata`)
- `python3` (script de reconstruction)

---

## 2) Méthode / Étapes suivies

### 2.1 Trouver la longueur attendue

En testant une entrée courte, le binaire répond :

- `[-] Nope. (wrong length)`

La vérification passe la longueur uniquement si elle vaut **26** caractères.

---

### 2.2 Comprendre la transformation (dans la boucle)

Dans la boucle principale, pour chaque caractère `c[i]` :

1. Le caractère est lu comme un octet.
2. Il est multiplié par **1337** (`0x539` en hex).
3. Le résultat est XOR avec un octet “mask” pris dans une table de **7 octets** en `.rodata`,
   indexée par `i % 7`.

On peut résumer la formule :

\[
v[i] = (1337 \times c[i]) \oplus T[i \bmod 7]
\]

avec :

- `T = [0x5a, 0xc3, 0x1f, 0x88, 0xe1, 0x07, 0xb4]`

Le binaire compare ensuite `v[i]` à un tableau de **26 constantes 32-bit** stockées en `.rodata`.

---

### 2.3 Inversion de la vérification

Le XOR est réversible, donc :

\[
1337 \times c[i] = v[i] \oplus T[i \bmod 7]
\]

et donc :

\[
c[i] = \frac{(v[i] \oplus T[i \bmod 7])}{1337}
\]

Dans le binaire, `v[i]` correspond aux constantes attendues (le tableau en `.rodata`).

---

### 2.4 Reconstruction complète du flag

On extrait :

- `expected[0..25]` : les 26 constantes 32-bit
- `T[0..6]` : la table de 7 octets

Puis on applique l’inversion sur chaque index `i` pour reconstruire les 26 caractères.

---

## 3) Résolution (script)

### 3.1 Script `solve.py`

```python
import struct
from pathlib import Path

BIN = Path("masked_multiply").read_bytes()

# Offsets vus via readelf/objdump (PIE, mais .rodata est à VA 0x2000, offset fichier 0x2000)
EXPECTED_OFF = 0x2100      # 26 x uint32 little-endian
MASK_OFF     = 0x2168      # 7 bytes

expected = [struct.unpack_from("<I", BIN, EXPECTED_OFF + 4*i)[0] for i in range(26)]
T = list(BIN[MASK_OFF:MASK_OFF + 7])

flag_bytes = bytearray()

for i, e in enumerate(expected):
    prod = e ^ T[i % 7]              # undo XOR
    assert prod % 1337 == 0          # must divide cleanly
    c = prod // 1337
    assert 0 <= c <= 0xFF
    flag_bytes.append(c)

print(flag_bytes.decode())
```

### 3.2 Exécution

![alt text](<Screenshot From 2026-02-24 21-10-30.png>)

## FLAG

**Flag : `CCOI26{m4sk3d_mul7i_cH3ck}`**