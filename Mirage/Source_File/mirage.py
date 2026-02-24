import struct
import zlib

CHALLENGE = b"Mirage"
FLAG = b"CCOI26{fakeFlag}"

def xorshift32(x):
    x &= 0xFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF

def keystream(seed, n):
    s = seed & 0xFFFFFFFF
    out = bytearray()
    while len(out) < n:
        s = xorshift32(s)
        out += struct.pack("<I", s)
    return out[:n]

def encrypt(data):
    seed = zlib.crc32(CHALLENGE) ^ 0xA5C3F1E7
    seed = xorshift32(seed ^ 0x1F123BB5)
    ks = keystream(seed, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))

def main():
    ct = encrypt(FLAG)
    with open("cipher.bin", "wb") as f:
        f.write(ct)

if __name__ == "__main__":
    main()
