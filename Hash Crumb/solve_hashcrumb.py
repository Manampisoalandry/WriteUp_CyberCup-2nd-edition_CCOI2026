import hashlib
import string
hashes = [line.strip() for line in open("hashes.txt", "r", encoding="utf-8") if line.strip()]
charset = [chr(i) for i in range(32, 127)]
table = {hashlib.md5(ch.encode()).hexdigest(): ch for ch in charset}
flag = "".join(table[h] for h in hashes)
print(flag)
