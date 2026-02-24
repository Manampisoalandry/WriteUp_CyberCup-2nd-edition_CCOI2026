# Suspicious Traffic — Write-up

**Category:** Forensics / Network  
**Difficulty:** Hard

---

## Contexte

On nous fournit deux fichiers :

- `suspicious_traffic.pcap` : une capture réseau (trafic chiffré en TLS)
- `sslkeylog.txt` : un fichier **TLS key log** (lignes `CLIENT_RANDOM ...`)

L’objectif est de **déchiffrer le trafic TLS**, retrouver les requêtes HTTP cachées derrière, puis extraire une **flag** au format `CCOI{...}`.

---

## 1) Outils utilisés

- **Wireshark** (décryptage TLS via keylog + Follow HTTP Stream)
- (Optionnel) `tshark` (filtrage en CLI)
- `python3` (décodage automatique / script complet)
- `base64`, `xxd` / `hexdump` (validation des données)
- (Optionnel) `jq` (lecture de JSON propre)

---

## 2) Méthode / Étapes suivies

L’idée principale : **le PCAP contient du TLS**, et le fichier `sslkeylog.txt` donne les secrets nécessaires pour **déchiffrer** ce TLS dans Wireshark (ou via un script).

---

### 2.1 Déchiffrer TLS dans Wireshark (avec sslkeylog)

1. Ouvrir `suspicious_traffic.pcap` dans **Wireshark**
2. Aller dans :  
   **Edit → Preferences → Protocols → TLS**
3. Renseigner :  
   **(Pre)-Master-Secret log filename** → sélectionner `sslkeylog.txt`
4. Valider

### 2.2 Identifier les requêtes importantes (playlists)

Une fois le TLS déchiffré, on voit apparaître du **HTTP** en clair.  
On observe plusieurs requêtes **`POST`** vers une API de playlists (ex : `POST /v1/users/.../playlists`).

On distingue **2 familles** de playlists qui sont essentielles pour reconstruire la flag.

---

#### A) Playlist “Mon tresor …” (le **mapping**)

Une des requêtes `POST` crée une playlist dont le champ `name` ressemble à :

- `Mon tresor a qui saura le prendre` (ou très proche)

Son champ `description` est une **longue chaîne hexadécimale** (souvent ça commence par `7b22...`, ce qui est typique d’un JSON encodé en hex).

🔎 En convertissant cette chaîne hex en texte, on obtient un **JSON de correspondance** :

- **clés** : caractères Base64 (`A-Z a-z 0-9 + / =`)
- **valeurs** : coordonnées / couples (`a1`, `b2`, `i0`, etc.)

👉 Ce JSON sert de **table de décodage** : il permet de convertir les coordonnées (ex : `e2`) en un caractère Base64.

---

#### B) Playlists `inpayloadwetrust*` (les **payloads**)

On trouve ensuite plusieurs playlists du style :

- `inpayloadwetrust0`
- `inpayloadwetrust300`
- `inpayloadwetrust600`
- `inpayloadwetrust900`

Ici, le champ `description` **n’est pas du texte lisible** : c’est une **suite de coordonnées** (ex : `e2i2h6e5...`).

➡️ Le décodage attendu est :

1. **Découper** la chaîne en paires : `e2`, `i2`, `h6`, ...
2. Pour chaque paire, utiliser le **mapping** (coord → caractère Base64)
3. Reconstruire une **chaîne Base64**
4. Faire un **Base64 decode** → obtenir le contenu en clair (config / token / etc.)

---

### 2.3 Récupération de la flag

En décodant notamment `inpayloadwetrust600`, on récupère un token interne :

---

## 3) Script de résolution (solve.py)

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import struct
import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------------------------
# PCAP + TCP parsing
# -------------------------

@dataclass(frozen=True)
class FlowKey:
    a_ip: bytes
    a_port: int
    b_ip: bytes
    b_port: int

def ip_str(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))

def parse_pcap(buf: bytes) -> Tuple[List[Tuple[Tuple[int,int], bytes]], int, str]:
    if len(buf) < 24:
        raise ValueError("PCAP too short")

    magic = buf[:4]
    if magic == b"\xd4\xc3\xb2\xa1":  # little endian
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":  # big endian
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":  # ns little
        endian = "<"
    elif magic == b"\xa1\xb2\x3c\x4d":  # ns big
        endian = ">"
    else:
        raise ValueError(f"Unknown PCAP magic: {magic.hex()}")

    _magic, _vmaj, _vmin, _tz, _sigfigs, _snaplen, network = struct.unpack(endian + "IHHIIII", buf[:24])

    off = 24
    packets: List[Tuple[Tuple[int,int], bytes]] = []
    while off + 16 <= len(buf):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", buf[off:off+16])
        off += 16
        pkt = buf[off:off+incl_len]
        off += incl_len
        packets.append(((ts_sec, ts_usec), pkt))
    return packets, network, endian

def parse_ethernet(pkt: bytes) -> Optional[Tuple[int, bytes]]:
    if len(pkt) < 14:
        return None
    etype = struct.unpack("!H", pkt[12:14])[0]
    return etype, pkt[14:]

def parse_ipv4(pkt: bytes) -> Optional[Tuple[int, bytes, bytes, bytes]]:
    if len(pkt) < 20:
        return None
    v_ihl = pkt[0]
    version = v_ihl >> 4
    ihl = (v_ihl & 0xF) * 4
    if version != 4 or len(pkt) < ihl:
        return None
    total_len = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]
    src = pkt[12:16]
    dst = pkt[16:20]
    payload = pkt[ihl:total_len]
    return proto, src, dst, payload

def parse_tcp(pkt: bytes) -> Optional[Tuple[int,int,int,int,int,bytes]]:
    if len(pkt) < 20:
        return None
    sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", pkt[:14])
    data_offset = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    if len(pkt) < data_offset:
        return None
    payload = pkt[data_offset:]
    return sport, dport, seq, ack, flags, payload

def canon_flow(src_ip: bytes, sport: int, dst_ip: bytes, dport: int) -> Tuple[FlowKey, int]:
    a = (src_ip, sport)
    b = (dst_ip, dport)
    if a <= b:
        return FlowKey(src_ip, sport, dst_ip, dport), 0
    return FlowKey(dst_ip, dport, src_ip, sport), 1

def reassemble_tcp(segments: List[Tuple[int, bytes]]) -> bytes:
    """
    Simple TCP reassembly:
      - sort by seq
      - overlay bytes into a single buffer starting at min seq
    Works fine for small PCAPs without heavy retransmissions.
    """
    if not segments:
        return b""
    segments = sorted(segments, key=lambda x: x[0])
    base = segments[0][0]
    out = bytearray()
    for seq, payload in segments:
        if seq < base:
            continue
        off = seq - base
        need = off + len(payload)
        if need > len(out):
            out.extend(b"\x00" * (need - len(out)))
        out[off:off+len(payload)] = payload
    return bytes(out)

# -------------------------
# TLS parsing + decryption
# -------------------------

def parse_tls_records(stream: bytes) -> List[Tuple[int, bytes, bytes]]:
    """
    Returns list of (content_type, version(2), fragment).
    """
    records = []
    i = 0
    while i + 5 <= len(stream):
        ctype = stream[i]
        ver = stream[i+1:i+3]
        ln = struct.unpack("!H", stream[i+3:i+5])[0]
        i += 5
        if i + ln > len(stream):
            break
        frag = stream[i:i+ln]
        i += ln
        records.append((ctype, ver, frag))
    return records

def parse_handshakes(records: List[Tuple[int, bytes, bytes]]) -> List[Tuple[int, bytes]]:
    """
    Concatenate all handshake fragments (record content_type==22) then parse
    handshake messages: (hs_type, hs_body).
    """
    buf = b"".join(frag for ctype, _ver, frag in records if ctype == 22)
    out = []
    i = 0
    while i + 4 <= len(buf):
        hs_type = buf[i]
        hs_len = int.from_bytes(buf[i+1:i+4], "big")
        i += 4
        if i + hs_len > len(buf):
            break
        out.append((hs_type, buf[i:i+hs_len]))
        i += hs_len
    return out

def parse_client_hello(body: bytes) -> Optional[bytes]:
    if len(body) < 34:
        return None
    return body[2:34]  # version(2) + random(32)

def parse_server_hello(body: bytes) -> Tuple[Optional[bytes], Optional[int]]:
    if len(body) < 38:
        return None, None
    server_random = body[2:34]
    sid_len = body[34]
    p = 35 + sid_len
    if p + 2 > len(body):
        return server_random, None
    cipher_suite = struct.unpack("!H", body[p:p+2])[0]
    return server_random, cipher_suite

def read_keylog(path: str) -> Dict[bytes, bytes]:
    secrets: Dict[bytes, bytes] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("CLIENT_RANDOM"):
                parts = line.split()
                if len(parts) >= 3:
                    cr = bytes.fromhex(parts[1])
                    ms = bytes.fromhex(parts[2])
                    secrets[cr] = ms
    return secrets

def tls12_prf(secret: bytes, label: bytes, seed: bytes, out_len: int, hash_name: str) -> bytes:
    hash_name = hash_name.lower()
    if hash_name == "sha384":
        hashmod = hashlib.sha384
    elif hash_name == "sha256":
        hashmod = hashlib.sha256
    else:
        raise ValueError(f"Unsupported PRF hash: {hash_name}")

    def hmac_hash(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashmod).digest()

    A = hmac_hash(secret, label + seed)
    out = b""
    while len(out) < out_len:
        out += hmac_hash(secret, A + label + seed)
        A = hmac_hash(secret, A)
    return out[:out_len]

def derive_keys_tls12_aes_gcm(master_secret: bytes, client_random: bytes, server_random: bytes,
                             key_len: int, fixed_iv_len: int, prf_hash: str) -> Tuple[bytes, bytes, bytes, bytes]:
    label = b"key expansion"
    seed = server_random + client_random
    key_block_len = 2*key_len + 2*fixed_iv_len
    key_block = tls12_prf(master_secret, label, seed, key_block_len, prf_hash)

    p = 0
    client_write_key = key_block[p:p+key_len]; p += key_len
    server_write_key = key_block[p:p+key_len]; p += key_len
    client_write_iv  = key_block[p:p+fixed_iv_len]; p += fixed_iv_len
    server_write_iv  = key_block[p:p+fixed_iv_len]; p += fixed_iv_len
    return client_write_key, server_write_key, client_write_iv, server_write_iv

def decrypt_tls12_aes_gcm(records: List[Tuple[int, bytes, bytes]], write_key: bytes, write_iv: bytes) -> bytes:
    """
    Decrypt TLS1.2 AES-GCM records after ChangeCipherSpec.
    Returns ONLY plaintext from ApplicationData records (content_type 23).
    """
    aes = AESGCM(write_key)
    seq = 0
    after_ccs = False
    app_plain = []

    for ctype, ver, frag in records:
        if ctype == 20:  # ChangeCipherSpec (not encrypted)
            after_ccs = True
            continue
        if not after_ccs:
            continue

        if ctype not in (21, 22, 23):  # alert, handshake, appdata
            continue
        if len(frag) < 8 + 16:
            seq += 1
            continue

        explicit = frag[:8]
        ciphertext_and_tag = frag[8:]
        ciphertext_len = len(ciphertext_and_tag) - 16  # tag is 16 bytes
        if ciphertext_len < 0:
            seq += 1
            continue

        aad = struct.pack("!Q", seq) + bytes([ctype]) + ver + struct.pack("!H", ciphertext_len)
        nonce = write_iv + explicit

        try:
            pt = aes.decrypt(nonce, ciphertext_and_tag, aad)
            if ctype == 23 and pt:
                app_plain.append(pt)
        except Exception:
            pass

        seq += 1

    return b"".join(app_plain)

# -------------------------
# HTTP extraction + decoding
# -------------------------

def parse_http_messages(stream: bytes) -> List[Dict]:
    patterns = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HTTP/1.1"]
    msgs = []
    i = 0

    while True:
        next_pos = None
        for pat in patterns:
            p = stream.find(pat, i)
            if p != -1 and (next_pos is None or p < next_pos):
                next_pos = p
        if next_pos is None:
            break

        i = next_pos
        header_end = stream.find(b"\r\n\r\n", i)
        if header_end == -1:
            break

        header_blob = stream[i:header_end].decode(errors="replace")
        lines = header_blob.split("\r\n")
        start_line = lines[0]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body_len = int(headers.get("content-length", "0") or "0")
        body_start = header_end + 4
        body = stream[body_start:body_start + body_len]

        msgs.append({"start_line": start_line, "headers": headers, "body": body})
        i = body_start + body_len

    return msgs

def b64decode_loose(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.b64decode(s + ("=" * pad))

def decode_coords(mapping: Dict[str, str], coords: str) -> bytes:
    inv = {v: k for k, v in mapping.items()}
    if len(coords) % 2 != 0:
        raise ValueError("coords length is not even")

    b64_chars = []
    for i in range(0, len(coords), 2):
        pair = coords[i:i+2]
        if pair not in inv:
            raise KeyError(f"Unknown coord pair: {pair}")
        b64_chars.append(inv[pair])

    b64_str = "".join(b64_chars)
    return b64decode_loose(b64_str)

# -------------------------
# Main solve flow
# -------------------------

CIPHER_SUITE = 0xC030  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

def solve(pcap_path: str, keylog_path: str, verbose: bool = False) -> str:
    secrets = read_keylog(keylog_path)
    if not secrets:
        raise RuntimeError("No CLIENT_RANDOM secrets found in keylog")

    with open(pcap_path, "rb") as f:
        packets, network, _endian = parse_pcap(f.read())

    if network != 1:
        raise RuntimeError(f"Unsupported linktype/network={network} (expected Ethernet=1)")

    flows: Dict[FlowKey, Dict[int, List[Tuple[int, bytes]]]] = {}
    for (_ts_sec, _ts_usec), pkt in packets:
        eth = parse_ethernet(pkt)
        if not eth:
            continue
        etype, eth_payload = eth
        if etype != 0x0800:
            continue

        ip = parse_ipv4(eth_payload)
        if not ip:
            continue
        proto, src_ip, dst_ip, ip_payload = ip
        if proto != 6:
            continue

        tcp = parse_tcp(ip_payload)
        if not tcp:
            continue
        sport, dport, seq, _ack, _flags, tcp_payload = tcp
        if not tcp_payload:
            continue

        fk, direction = canon_flow(src_ip, sport, dst_ip, dport)
        flows.setdefault(fk, {0: [], 1: []})[direction].append((seq, tcp_payload))

    playlist_posts = []

    for fk, dirs in flows.items():
        cli_stream = reassemble_tcp(dirs[1])  # client->server in this trace
        srv_stream = reassemble_tcp(dirs[0])

        rec_cli = parse_tls_records(cli_stream)
        rec_srv = parse_tls_records(srv_stream)
        if not rec_cli or not rec_srv:
            continue

        client_random = None
        for hs_type, body in parse_handshakes(rec_cli):
            if hs_type == 1:
                client_random = parse_client_hello(body)
                break
        if not client_random or client_random not in secrets:
            continue

        server_random, cipher_suite = None, None
        for hs_type, body in parse_handshakes(rec_srv):
            if hs_type == 2:
                server_random, cipher_suite = parse_server_hello(body)
                break
        if not server_random or cipher_suite is None:
            continue

        if cipher_suite != CIPHER_SUITE:
            continue

        master_secret = secrets[client_random]
        cwk, swk, civ, siv = derive_keys_tls12_aes_gcm(
            master_secret=master_secret,
            client_random=client_random,
            server_random=server_random,
            key_len=32,
            fixed_iv_len=4,
            prf_hash="sha384",
        )

        cli_http_bytes = decrypt_tls12_aes_gcm(rec_cli, cwk, civ)
        if not cli_http_bytes:
            continue

        msgs = parse_http_messages(cli_http_bytes)
        for msg in msgs:
            sl = msg["start_line"]
            if sl.startswith("POST /v1/users/") and "/playlists" in sl:
                try:
                    js = json.loads(msg["body"].decode())
                except Exception:
                    continue
                playlist_posts.append(js)
                if verbose:
                    print(f"[+] Playlist POST: {js.get('name')} (desc_len={len(js.get('description',''))}) from {ip_str(fk.b_ip)}:{fk.b_port}")

    if not playlist_posts:
        raise RuntimeError("No playlist POSTs found after TLS decryption")

    mapping_hex = None
    for js in playlist_posts:
        desc = js.get("description","") or ""
        if js.get("name","").lower().startswith("mon tresor") and re.fullmatch(r"[0-9a-fA-F]+", desc):
            mapping_hex = desc
            break
    if not mapping_hex:
        raise RuntimeError("Mapping playlist not found")

    mapping = json.loads(bytes.fromhex(mapping_hex).decode())

    decoded_payloads: Dict[str, str] = {}
    for js in playlist_posts:
        name = js.get("name","")
        if name.startswith("inpayloadwetrust"):
            raw = decode_coords(mapping, js.get("description",""))
            decoded_payloads[name] = raw.decode(errors="replace")

    if not decoded_payloads:
        raise RuntimeError("No inpayloadwetrust payloads decoded")

    flag_re = re.compile(r"CCOI\{[^}]+\}")
    for name, text in decoded_payloads.items():
        m = flag_re.search(text)
        if m:
            if verbose:
                print("\n--- Decoded payloads ---")
                for n, t in sorted(decoded_payloads.items()):
                    print(f"\n[{n}]\n{t}")
            return m.group(0)

    raise RuntimeError("Flag not found in decoded payloads")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?", default="suspicious_traffic.pcap", help="PCAP file")
    ap.add_argument("keylog", nargs="?", default="sslkeylog.txt", help="TLS key log file")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print debug + decoded payloads")
    args = ap.parse_args()

    flag = solve(args.pcap, args.keylog, verbose=args.verbose)
    print(flag)

if __name__ == "__main__":
    main()

``` 
Execution du script python avec des parametre le fichier suspicious_traffic.pcap et sslkeylog.txt

![alt text](<Screenshot From 2026-02-24 08-06-04.png>)


Et upppp, la flag:

```text
FLAG = CCOI26{m0n_tr3s0r_a_qu1_s4ur4_l3_pr3ndr3_!!}

