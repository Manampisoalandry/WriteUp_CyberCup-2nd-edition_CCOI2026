import json, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Ordre secp256k1
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