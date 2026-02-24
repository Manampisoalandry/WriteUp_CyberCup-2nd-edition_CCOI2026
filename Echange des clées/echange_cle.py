import math
import random

# --- Params (challenge) ---
p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
A = 0x76D05E5CBC14DE510A438591395C79571FAD112B6B69ABDE209D7FDEE0D2AE39
B = 0x3A22A31949886AFC815DBFC44E26780F4A38DCEDDE05AFC0368523A6272F0F7A

x_gen = 0x357D0CC97C51172CEDDD5B0E3398EEA57E989ECA09C5E8AEC025B968E31353E9
x_pub = 42505452888139451234160619061600404445586246682494761185988888720489385844860

MASK = p - 1

# --- Number theory helpers ---
def inv(a: int) -> int:
    return pow(a, -1, p)

def legendre(a: int) -> int:
    return pow(a % p, (p - 1) // 2, p)

def tonelli(n: int) -> int | None:
    """Tonelli-Shanks: solve r^2 = n mod p (p prime). Return r or None if no sqrt."""
    n %= p
    if n == 0:
        return 0
    if legendre(n) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Factor p-1 = q * 2^s with q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Find a quadratic non-residue z
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
d = 2  # nonsquare in this field (as assumed in original script)
B_tw = (B * inv(d)) % p

def rhs(x: int) -> int:
    return (pow(x, 3, p) + A * pow(x, 2, p) + x) % p

# point recovery on twist: B_tw*y^2 = rhs(x)
def y_from_x(x: int) -> int | None:
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
        # tangent
        num = (3 * x1 * x1 + 2 * A * x1 + 1) % p
        den = (2 * B_tw * y1) % p
        lam = num * inv(den) % p
    else:
        # chord
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

# --- Group order of P (given/derived from challenge structure) ---
ORD = 627894464622987704824320113040397677942220845750
factors = [
    (2, 1), (3, 1), (5, 3),
    (570373, 1), (544627, 1), (45451957, 1),
    (5388392096723, 1), (11004124281581, 1),
]

# --- Discrete log helpers ---
def brute_dlog(G, H, n: int):
    R = None
    for k in range(n):
        if R == H:
            return k
        R = add(R, G)
    return None

def pollard_rho(G, H, r: int, tries: int = 20):
    """Memoryless Pollard-rho in subgroup of prime order r."""
    def step(X, a, b):
        s = 0 if X is None else (X[0] % 3)
        if s == 0:
            return add(X, G), (a + 1) % r, b
        if s == 1:
            return add(X, X), (2 * a) % r, (2 * b) % r
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

# --- CRT + Pohlig-Hellman ---
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

# --- Lift to real secret and decode flag from integer -> bytes -> text ---
for ntry in range(0, 70000):
    k = k0 + ntry * ORD
    try:
        s = k.to_bytes((k.bit_length() + 7) // 8, "big").decode()
        if s.startswith("CCOI26{") and s.endswith("}"):
            print("[+] FLAG =", s)
            break
    except Exception:
        pass