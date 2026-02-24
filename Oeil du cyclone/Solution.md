# EYE OF THE STORM — Write-up

**Category:** Forensic  
**Difficulty:** Medium

---

## Contexte

Le cyclone a fragmenté le **code d’évacuation** en **9 fragments** distribués à des stations météo.

- **5 stations** (hauts plateaux) : données **complètes**
- **4 stations** (côtes) : données **partielles** — les **20 bits de poids faible** de chaque fragment ont été perdus

On doit reconstruire le code avec **au moins 6 fragments**.

---

## Paramètres

- Champ fini : \(\mathbb{F}_p\) avec  
  \(p = 2^{521} - 1\) (Mersenne prime M521)
- Seuil : **6 fragments sur 9** \(\Rightarrow\) polynôme de degré **5**
- Stations inondées : **20 bits** perdus (LSB)
- Contrainte : `SHA256(flag)[:16] = f687cb74fdcefefc`
- Format : `CCOI26{...}`

---

## 1) Analyse crypto

C’est un schéma type **Shamir Secret Sharing** :

- Chaque station fournit un point \((x, y)\) sur un polynôme \(f(x)\) de degré 5 dans \(\mathbb{F}_p\).
- Le secret (code) est typiquement :
  \[
  \text{secret} = f(0)
  \]
- Pour une station inondée, on ne connait que les bits hauts :
  \[
  y = y_{\text{partial}} + u,\quad u \in [0, 2^{20}-1]
  \]
  (les 20 bits bas \(u\) sont inconnus)

---

## 2) Outils utilisés

- **Python 3**
- Module standard `hashlib` (SHA256)

---

## 3) Méthode / Étapes

### 3.1 Utiliser les 5 points complets

On dispose de 5 points exacts \((x=1..5)\).  
Il manque **un seul point** pour atteindre le seuil 6.

### 3.2 Brute-force d’une seule station inondée (20 bits)

On choisit une station inondée (ex: \(x=6\)) comme 6e point et on brute-force :

- \(y_6 = y_{6,\text{partial}} + u\) pour tous les \(u \in [0,2^{20}-1]\)

### 3.3 Filtrer via les 3 autres stations inondées

Pour chaque candidat \(u\) :

1. Interpoler (via **Lagrange**) avec les 6 points \((1..5) + (6)\)
2. Calculer \(f(7), f(8), f(9)\)
3. Vérifier que leurs **bits hauts** correspondent exactement aux valeurs `y_partial` :
   \[
   (f(x) \ \&\ \sim(2^{20}-1)) = y_{x,\text{partial}}
   \]

➡️ Ça élimine quasiment tout.

### 3.4 Extraire le secret et valider

Si le filtre passe :

- secret = \(f(0)\)
- convertir en bytes → doit commencer par `CCOI26{`
- valider la contrainte SHA256 :
  `SHA256(flag)[:16] == f687cb74fdcefefc`

---

## 4) Script de résolution (solve.py)

```python
#!/usr/bin/env python3
import hashlib

p = 2**521 - 1
MASK = (1 << 20) - 1
TARGET = "f687cb74fdcefefc"

full = {
    1:int("d0393fd5aa76c02f53757a5883d97a0f0ade112cffc590c8378f2b5a6696a284dcc1ef10c29f7275958952bca3c40922f75258f47e808d587aca867f48f0d798f5",16),
    2:int("a0deb8650c459c78e99ca5ae29c1399c8221723e6c966a4a4494ec69bcb20399336bba13c10998b4b0b554cffdaec9b8b536e6fa9ea4eefa7321782797b84672e4",16),
    3:int("9dc6d639cbda2c6893efafe086027e1f9126a9e27f2d342e45e8090675c2eca7e4ae330b163f8f059fa665a20ea4be41a4de9fe882ac3b08387ba8649622293745",16),
    4:int("ff3a80c762b7a71ee3793ed87a7951f819960a86b067cefbe94cac78b9f556291ebf42ae21395da1a5e9d3d426624b6cf5bebb4487d9311737417749e401c0cb57",16),
    5:int("748755843bdf0733e28882bb8f096fdd4c4ae2142cba5fb2ea4ba7e65a7b007a75f34a4f7a94b4b8e5b9d425d415b5750066cb52e451f11933b086614b816d4ecb",16),
}

partial = {
    6:int("18e91e304d2372e99ce65481f4a15284c423aa9ac47a25b639109b2c0c5d60cb6ba133679b80d2d34cfdc2c2968c5b83977eaa1b6e5ad7ed0368e3d0a9639300000",16),
    7:int("2a67e416cef50a7fd1040a3c88f446f6955c3564ef1992c7311eab32fc23958dcbb2918c2ff4897a9380dcf879b81f599b4c34142f81454279da4cdb6245300000",16),
    8:int("dbd27adc2803b734baba0522d86af830f98ee4051f093dd8a86cd68f8366481c71859657bcaaf62d8e20cde862d85e4e66e580aff9ee9a2e558135fef75c500000",16),
    9:int("57e86be63e6ca409bbf147ebcd20ae61d581cec154bd076cddf821be5bd0fcc42db742bb80174af1bb5c773ec91e2884c5d273125030417e2c0ecb961be6800000",16),
}

def lagrange_weights(xpoints, x):
    weights = []
    for i, xi in enumerate(xpoints):
        num = 1
        den = 1
        for j, xj in enumerate(xpoints):
            if j == i:
                continue
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        weights.append((num * pow(den, -1, p)) % p)
    return weights

def solve_with_base(fx):
    xpoints = [1,2,3,4,5,fx]
    yfixed = [full[i] for i in [1,2,3,4,5]]

    # Poids Lagrange pour f(0) et f(autres stations inondées)
    w0 = lagrange_weights(xpoints, 0)
    check_xs = [x for x in [6,7,8,9] if x != fx]
    wchecks = {xc: lagrange_weights(xpoints, xc) for xc in check_xs}

    # On sépare partie fixe (y1..y5) / partie variable (y_fx)
    var_idx = 5

    w0_fix = w0[:var_idx]
    w0_var = w0[var_idx]
    w0_fix_dot = sum((a*b) % p for a,b in zip(w0_fix, yfixed)) % p

    wcheck_fix_dot = {}
    wcheck_var = {}
    for xc in check_xs:
        w = wchecks[xc]
        wcheck_fix_dot[xc] = sum((a*b) % p for a,b in zip(w[:var_idx], yfixed)) % p
        wcheck_var[xc] = w[var_idx]

    base = partial[fx]

    for u in range(1 << 20):
        y = base + u

        # Filtre bits hauts sur les 3 autres stations inondées
        ok = True
        for xc in check_xs:
            ye = (wcheck_fix_dot[xc] + (wcheck_var[xc] * y) % p) % p
            if (ye & ~MASK) != partial[xc]:
                ok = False
                break
        if not ok:
            continue

        # secret = f(0)
        secret = (w0_fix_dot + (w0_var * y) % p) % p

        # Décodage en flag
        blen = (secret.bit_length() + 7) // 8
        b = secret.to_bytes(blen, "big")
        if not b.startswith(b"CCOI26{"):
            continue
        try:
            flag = b.decode("utf-8")
        except UnicodeDecodeError:
            continue

        if hashlib.sha256(flag.encode()).hexdigest()[:16] == TARGET:
            return flag, u

    return None, None

def main():
    for fx in [6,7,8,9]:
        flag, u = solve_with_base(fx)
        if flag:
            print("FLAG:", flag)
            print(f"Recovered low20 for x={fx}: {u} (0x{u:05x})")
            return
    print("No solution found.")

if __name__ == "__main__":
    main()

```

# Exectution de solve.py

![alt text](<Screenshot From 2026-02-23 23-59-33.png>)

Eh boom, la flag est là:

## Flag

**Flag : CCOI26{CycL0n3_B3l4l_R3uN10n_974}**

