#!/usr/bin/env python3
import hashlib

p = 2**521 - 1
MASK = (1 << 20) - 1

# les données complets dans l'énoncé
full = {
    1:int("d0393fd5aa76c02f53757a5883d97a0f0ade112cffc590c8378f2b5a6696a284dcc1ef10c29f7275958952bca3c40922f75258f47e808d587aca867f48f0d798f5",16),
    2:int("a0deb8650c459c78e99ca5ae29c1399c8221723e6c966a4a4494ec69bcb20399336bba13c10998b4b0b554cffdaec9b8b536e6fa9ea4eefa7321782797b84672e4",16),
    3:int("9dc6d639cbda2c6893efafe086027e1f9126a9e27f2d342e45e8090675c2eca7e4ae330b163f8f059fa665a20ea4be41a4de9fe882ac3b08387ba8649622293745",16),
    4:int("ff3a80c762b7a71ee3793ed87a7951f819960a86b067cefbe94cac78b9f556291ebf42ae21395da1a5e9d3d426624b6cf5bebb4487d9311737417749e401c0cb57",16),
    5:int("748755843bdf0733e28882bb8f096fdd4c4ae2142cba5fb2ea4ba7e65a7b007a75f34a4f7a94b4b8e5b9d425d415b5750066cb52e451f11933b086614b816d4ecb",16),
}

# les données partiels dans l'énoncé
partial = {
    6:int("18e91e304d2372e99ce65481f4a15284c423aa9ac47a25b639109b2c0c5d60cb6ba133679b80d2d34cfdc2c2968c5b83977eaa1b6e5ad7ed0368e3d0a9639300000",16),
    7:int("2a67e416cef50a7fd1040a3c88f446f6955c3564ef1992c7311eab32fc23958dcbb2918c2ff4897a9380dcf879b81f599b4c34142f81454279da4cdb6245300000",16),
    8:int("dbd27adc2803b734baba0522d86af830f98ee4051f093dd8a86cd68f8366481c71859657bcaaf62d8e20cde862d85e4e66e580aff9ee9a2e558135fef75c500000",16),
    9:int("57e86be63e6ca409bbf147ebcd20ae61d581cec154bd076cddf821be5bd0fcc42db742bb80174af1bb5c773ec91e2884c5d273125030417e2c0ecb961be6800000",16),
}

TARGET = "f687cb74fdcefefc"

def lagrange_coeffs(xpoints, x):
    """Retourne [L_i(x)] pour la base de Lagrange sur xpoints."""
    coeffs = []
    for i, xi in enumerate(xpoints):
        num = 1
        den = 1
        for j, xj in enumerate(xpoints):
            if j == i:
                continue
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        coeffs.append((num * pow(den, -1, p)) % p)
    return coeffs

def eval_from_coeffs(coeffs, ypoints):
    s = 0
    for c, y in zip(coeffs, ypoints):
        s = (s + c*y) % p
    return s

def try_one_base(flood_x):
    x_full = [1,2,3,4,5]
    y_full = [full[x] for x in x_full]

    xpoints = x_full + [flood_x]
    coeff0 = lagrange_coeffs(xpoints, 0)

    check_xs = [x for x in partial if x != flood_x]
    coeff_checks = {xc: lagrange_coeffs(xpoints, xc) for xc in check_xs}

    base = partial[flood_x]

    for u in range(1 << 20):
        y_flood = base + u
        ypoints = y_full + [y_flood]

        # Vérif bits hauts sur les autres stations inondées
        ok = True
        for xc in check_xs:
            ye = eval_from_coeffs(coeff_checks[xc], ypoints)
            if (ye & ~MASK) != partial[xc]:
                ok = False
                break
        if not ok:
            continue

        # Secret = f(0)
        secret = eval_from_coeffs(coeff0, ypoints)

        # Décodage -> flag ASCII
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
        flag, u = try_one_base(fx)
        if flag:
            print("FLAG:", flag)
            print(f"Recovered low20 for station x={fx}: {u} (0x{u:05x})")
            return
    print("No solution found.")

if __name__ == "__main__":
    main()