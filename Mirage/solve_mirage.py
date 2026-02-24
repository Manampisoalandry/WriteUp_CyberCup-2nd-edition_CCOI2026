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

ks_prefix = bytes(c ^ p for c, p in zip(ct, known))
s1 = int.from_bytes(ks_prefix[:4], "little")  # 1ère sortie du PRNG

seed = invert_xorshift32(s1)  # seed avant le 1er xorshift

ks = keystream(seed, len(ct))
pt = bytes(c ^ k for c, k in zip(ct, ks))

print(pt.decode())
