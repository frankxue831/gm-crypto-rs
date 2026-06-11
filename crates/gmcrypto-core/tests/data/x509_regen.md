# x509_*.der fixture regeneration recipe (v1.3 Task 1)

Generated 2026-06-11 with **GmSSL 3.1.1** (`/opt/homebrew/bin/gmssl`). The
fixtures are a self-signed SM2 CA + a CA-issued leaf, GM/T 0015 profile
(v3, `sm2sign-with-sm3` inner+outer, `ecPublicKey`+`sm2p256v1` SPKI),
chain-verified by gmssl itself before commit. All four parties use the
default SM2 ID `1234567812345678` (no `-sm2_id` flag passed — confirmed
default in `gmssl certgen -help`).

```bash
cd "$(mktemp -d)"
gmssl sm2keygen -pass P@ss -out ca.pem -pubout capub.pem
gmssl certgen -C CN -ST Beijing -L Beijing -O gmtest -OU ca -CN "GMTEST CA" \
  -serial_len 12 -days 3650 -key ca.pem -pass P@ss \
  -ca -path_len_constraint 0 -key_usage keyCertSign -key_usage cRLSign \
  -out cacert.pem
gmssl sm2keygen -pass P@ss -out leaf.pem -pubout leafpub.pem
gmssl reqgen -C CN -ST Beijing -L Beijing -O gmtest -OU leaf -CN "gmtest leaf" \
  -key leaf.pem -pass P@ss -out leaf.req
gmssl reqsign -in leaf.req -serial_len 12 -days 365 \
  -key_usage digitalSignature -cacert cacert.pem -key ca.pem -pass P@ss \
  -out leafcert.pem
gmssl certverify -in leafcert.pem -cacert cacert.pem   # MUST print "Verification success"
gmssl certparse  -in cacert.pem                        # v3 + sm2sign-with-sm3
# PEM -> DER (certs + the two SPKI public keys):
python3 - <<'PY'
import base64, re
for src, dst, label in [
    ("cacert.pem",   "x509_ca.der",       "CERTIFICATE"),
    ("leafcert.pem", "x509_leaf.der",     "CERTIFICATE"),
    ("capub.pem",    "x509_ca_pub.der",   "PUBLIC KEY"),
    ("leafpub.pem",  "x509_leaf_pub.der", "PUBLIC KEY"),
]:
    b64 = re.search(r"-----BEGIN %s-----(.*?)-----END %s-----" % (label, label),
                    open(src).read(), re.S).group(1)
    open(dst, "wb").write(base64.b64decode("".join(b64.split())))
PY
```

Notes:
- `-serial_len` is listed as required in gmssl 3.1.1's certgen/reqsign usage
  strings but actually DEFAULTS to 12 when omitted; we pass it explicitly
  (12-byte serials — comfortably under the parser's 20-byte ceiling).
- The private keys (`ca.pem`, `leaf.pem`) are throwaway test keys and are NOT
  committed; regeneration produces a fresh CA/leaf pair, so the KAT asserts
  structural and verification properties, never specific key bytes.
- `x509_*_pub.der` are the SPKI (RFC 5280 SubjectPublicKeyInfo) DER of each
  party's public key — decoded in tests via `spki::decode` to obtain the
  expected `Sm2PublicKey` values.
