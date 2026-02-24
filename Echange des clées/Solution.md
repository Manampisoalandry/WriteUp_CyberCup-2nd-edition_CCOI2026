# Twisted DLog — Write-up

**Category:** Crypto  
**Difficulty:** Hard  

---

## Contexte

On nous donne des paramètres de courbe elliptique sur un corps premier `p`, ainsi que :

- une abscisse de générateur `x_gen`
- une abscisse publique `x_pub`

Particularité : les `x` fournis **ne sont pas forcément des points sur la courbe “normale”**, mais deviennent des points valides sur **une courbe tordue (quadratic twist)**.

Objectif : retrouver un secret `k` tel que :

\[
Q = k \cdot P
\]

et ensuite **décoder `k` en texte** (le script cherche un texte qui ressemble à `CCOI26{...}`).

---

## 1) Outils utilisés

- `python3`
- Modules Python standards : `math`, `random`, `struct` (ici `struct` n’est pas utilisé), etc.
- Aucun module externe requis

---

## 2) Méthode / Étapes suivies

### 2.1 Vérifier / reconstruire les points à partir des x

La courbe “twist” utilisée ici s’écrit :

\[
B_{tw} \cdot y^2 = x^3 + A x^2 + x \pmod p
\]

On choisit un `d` **non carré** (ici `d = 2`) et on définit :

\[
B_{tw} = B \cdot d^{-1} \pmod p
\]

Ensuite, pour chaque `x` donné, on calcule :

\[
y^2 = \frac{x^3 + Ax^2 + x}{B_{tw}} \pmod p
\]

et on retrouve `y` avec **Tonelli–Shanks** (racine carrée mod `p`).

---

### 2.2 Implémenter les opérations EC sur la twist

On implémente :

- `add(P, Q)` : addition de points (cas doublement + cas général)
- `mul(k, P)` : multiplication scalaire (double-and-add)

---

### 2.3 Résoudre le DLP avec Pohlig–Hellman

On connaît (ou on déduit via le challenge) l’ordre :

- `ORD = order(P)`

et sa factorisation :

\[
ORD = \prod p_i^{e_i}
\]

Pohlig–Hellman permet de résoudre :

\[
k \bmod p_i^{e_i}
\]

en travaillant dans des sous-groupes plus petits :

- si le sous-groupe est petit → brute force
- si le sous-groupe est premier et grand → **Pollard Rho** (memoryless)

---

### 2.4 Recomposer avec CRT

Une fois tous les `k mod p_i^{e_i}` trouvés, on reconstruit :

\[
k \bmod ORD
\]

avec le **CRT** (Chinese Remainder Theorem).

---

### 2.5 “Lift” et décodage du secret

Le challenge encode le secret réel comme :

\[
k = k_0 + n \cdot ORD
\]

On teste plusieurs `n` (ici jusqu’à 70000) et on convertit `k` en bytes puis en string.
Dès qu’on obtient un texte qui commence par `CCOI26{` et finit par `}`, c’est la flag.

---

## 3) Résolution (script)

### 3.1 Script `solve.py`

Copie ce code dans `solve.py` :

```python
import math
import random

# --- Params (challenge) ---
p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
A = 0x76D05E5CBC14DE510A438591395C79571FAD112B6B69ABDE209D7FDEE0D2AE39
B = 0x3A22A31949886AFC815DBFC44E26780F4A38DCEDDE05AFC0368523A6272F0F7A

x_gen = 0x357D0CC97C51172CEDDD5B0E3398EEA57E989ECA09C5E8AEC025B968E31353E9
x_pub = 42505452888139451234160619061600404445586246682494761185988888720489385844860

MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED - 1

# --- Number theory helpers ---
def inv(a: int) -> int:
    return pow(a, -1, p)

def legendre(a: int) -> int:
    return pow(a % p, (p - 1) // 2, p)

def tonelli(n: int):
    """Tonelli-Shanks: solve r^2 = n mod p (p prime). Return r or None if no sqrt."""
    n %= p
    if n == 0:
        return 0
    if legendre(n) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 2
    while legendre(z) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 1
        t2 = pow(t, 2, p)
        while t2 != 1:
            t2 = pow(t2, 2, p)
            i += 1

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

    return r

# --- Twist setup (choose nonsquare d) ---
d = 2
B_tw = (B * inv(d)) % p

def rhs(x: int) -> int:
    return (pow(x, 3, p) + A * pow(x, 2, p) + x) % p

# point recovery on twist: B_tw*y^2 = rhs(x)
def y_from_x(x: int):
    y2 = rhs(x) * inv(B_tw) % p
    return tonelli(y2)

P = (x_gen, y_from_x(x_gen))
Q = (x_pub, y_from_x(x_pub))

# --- Elliptic curve ops on twist: B_tw*y^2 = x^3 + A x^2 + x ---
def add(Pt, Qt):
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt

    x1, y1 = Pt
    x2, y2 = Qt

    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        num = (3 * x1 * x1 + 2 * A * x1 + 1) % p
        den = (2 * B_tw * y1) % p
        lam = num * inv(den) % p
    else:
        lam = (y2 - y1) * inv(x2 - x1) % p

    x3 = (B_tw * lam * lam - A - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def mul(k: int, Pt):
    if k == 0 or Pt is None:
        return None
    if k < 0:
        x, y = Pt
        return mul(-k, (x, (-y) % p))

    R = None
    Qq = Pt
    while k:
        if k & 1:
            R = add(R, Qq)
        Qq = add(Qq, Qq)
        k >>= 1
    return R

# --- order of P (given/derived from challenge structure) ---
ORD = 627894464622987704824320113040397677942220845750
factors = [
    (2, 1), (3, 1), (5, 3),
    (570373, 1), (544627, 1), (45451957, 1),
    (5388392096723, 1), (11004124281581, 1),
]

# brute dlog for very small groups
def brute_dlog(G, H, n):
    R = None
    for k in range(n):
        if R == H:
            return k
        R = add(R, G)
    return None

# Pollard rho for prime order subgroup (memoryless)
def pollard_rho(G, H, r, tries=20):
    def step(X, a, b):
        s = 0 if X is None else (X[0] % 3)
        if s == 0:
            return add(X, G), (a + 1) % r, b
        elif s == 1:
            return add(X, X), (2 * a) % r, (2 * b) % r
        else:
            return add(X, H), a, (b + 1) % r

    for _ in range(tries):
        a = random.randrange(r)
        b = random.randrange(r)
        X = add(mul(a, G), mul(b, H))
        a2, b2, X2 = a, b, X

        for _ in range(4 * int(math.isqrt(r)) + 5000):
            X, a, b = step(X, a, b)
            X2, a2, b2 = step(*step(X2, a2, b2))
            if X == X2:
                den = (b2 - b) % r
                num = (a - a2) % r
                if den == 0:
                    break
                k = num * pow(den, -1, r) % r
                if mul(k, G) == H:
                    return k
                break
    return None

# Pohlig-Hellman + CRT
def crt(pairs):
    x, M = 0, 1
    for r_i, m_i in pairs:
        g = math.gcd(M, m_i)
        t = ((r_i - x) // g) * pow(M // g, -1, m_i // g) % (m_i // g)
        x = x + M * t
        M = M * (m_i // g)
        x %= M
    return x

pairs = []
for prime, exp in factors:
    pe = prime ** exp
    m = ORD // pe
    G = mul(m, P)
    H = mul(m, Q)

    if pe <= 1_000_000:
        k = brute_dlog(G, H, pe)
    elif exp == 1:
        k = pollard_rho(G, H, prime)
    else:
        k = brute_dlog(G, H, pe)

    print("solved mod", pe, "=", k)
    pairs.append((k, pe))

k0 = crt(pairs)
print("[+] k mod ORD =", k0)

# lift to real secret and decode
for ntry in range(0, 70000):
    k = k0 + ntry * ORD
    try:
        s = k.to_bytes((k.bit_length() + 7) // 8, "big").decode()
        if s.startswith("CCOI26{") and s.endswith("}"):
            print("[+] FLAG =", s)
            break
    except Exception:
        pass

```

Execution du script

![alt text](<Screenshot From 2026-02-24 14-19-22.png>)

## Flag

**Flag : CCOI26{c3sT_l4_t0rDu3}**