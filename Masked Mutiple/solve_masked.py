import struct
from pathlib import Path

b = Path("masked_multiply").read_bytes()

# .rodata est à l’offset 0x2000, et les constantes commencent à 0x2100
expected = [struct.unpack_from("<I", b, 0x2100 + 4*i)[0] for i in range(24)]
expected += [struct.unpack_from("<I", b, 0x2160)[0], struct.unpack_from("<I", b, 0x2164)[0]]

T = list(b[0x2168:0x2168+7])

flag = []
for i, e in enumerate(expected):
    v = e ^ T[i % 7]
    assert v % 1337 == 0
    flag.append(v // 1337)

print(bytes(flag).decode())