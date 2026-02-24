import hashlib

FLAG = "CCOI26{fake_fl4g}"

def main():
    out = []
    for ch in FLAG:
        out.append(hashlib.md5(ch.encode()).hexdigest())
    with open("hashes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(out))

if __name__ == "__main__":
    main()
