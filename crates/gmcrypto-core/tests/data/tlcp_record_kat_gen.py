#!/usr/bin/env python3
# v1.7 — generator for the TLCP record-protection KAT vectors pinned in
# tests/tlcp_record_kat.rs. The "OpenSSL + GmSSL cross-check" oracle
# (maintainer-chosen W3; docs/v1.7-kat-sourcing.md): each record byte is
# produced by an INDEPENDENT tool, never by gmcrypto-core itself.
#   - CBC: OpenSSL 3.x EVP SM4-CBC (-nopad) for the cipher + GmSSL sm3hmac
#          for the record MAC, framed MAC-then-encrypt with TLS padding.
#   - GCM: GmSSL `sm4 -gcm -aad_hex` (full AEAD) over the RFC 5288 nonce
#          (salt||seq) and AAD (seq||type||version||length).
# Requires: openssl 3.x, gmssl 3.1.1 on PATH. Re-pin the test if you change
# any fixed input.
import subprocess, struct


def run(cmd, inp):
    r = subprocess.run(cmd, input=inp, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"FAIL {cmd}: {r.stderr.decode()}")
    return r.stdout


# ---------- CBC ----------
mac_key = bytes(range(1, 33))          # 0x01..0x20  (32 B, client_MAC)
enc_key = bytes(range(0x10, 0x20))     # 0x10..0x1f  (16 B, client_key)
seq = 0x0001020304050607
version = bytes([0x01, 0x01])
pt = b"TLCP record protection KAT"     # 26 B
iv = bytes(range(0x20, 0x30))          # 0x20..0x2f  (deterministic test IV)

hdr = struct.pack(">Q", seq) + bytes([0x17]) + version + struct.pack(">H", len(pt))
mac = bytes.fromhex(run(["gmssl", "sm3hmac", "-key", mac_key.hex()], hdr + pt).decode().strip())
buf = pt + mac
padlen = 15 - (len(buf) % 16)
buf += bytes([padlen]) * (padlen + 1)
ct = run(["openssl", "enc", "-sm4-cbc", "-nopad", "-K", enc_key.hex(), "-iv", iv.hex()], buf)
print("CBC_RECORD", (iv + ct).hex())

# ---------- GCM ----------
genc = bytes(range(0x30, 0x40))        # 16 B (client_key)
salt = bytes([0xa0, 0xa1, 0xa2, 0xa3]) # client_salt
gseq = 0x0001020304050607
gpt = b"TLCP GCM record KAT"           # 19 B
explicit = struct.pack(">Q", gseq)
nonce = salt + explicit                # 12 B
ghdr = struct.pack(">Q", gseq) + bytes([0x17]) + version + struct.pack(">H", len(gpt))
ctag = run(["gmssl", "sm4", "-gcm", "-encrypt", "-key", genc.hex(), "-iv", nonce.hex(),
            "-aad_hex", ghdr.hex()], gpt)
print("GCM_RECORD", (explicit + ctag).hex())
