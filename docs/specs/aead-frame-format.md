# MillWorks AEAD frame format (v1)

This specifies the byte layout produced by `IAeadCipher` / `AesGcmCipher` so a non-.NET service can
encrypt or decrypt interoperably. It is the binary analogue of the RFC 8785 canonicalizer's
cross-language guarantee.

## Frame

```
+---------+-----------+---------+------------------+
| version |   nonce   |   tag   |    ciphertext    |
| 1 byte  | 12 bytes  | 16 bytes|     N bytes      |
+---------+-----------+---------+------------------+
```

| Field | Size | Value |
| --- | --- | --- |
| `version` | 1 | `0x01`. Readers MUST reject any other value. |
| `nonce` | 12 | 96-bit GCM nonce, drawn fresh at random for every encryption. |
| `tag` | 16 | 128-bit AES-GCM authentication tag. |
| `ciphertext` | N ≥ 0 | AES-256-GCM ciphertext. May be empty (GCM permits empty plaintext). |

- **Cipher:** AES-256-GCM. The key is exactly **32 bytes** and is supplied out of band (never in the frame).
- **Minimum frame length:** 29 bytes (version + nonce + tag, empty ciphertext).
- **Associated data (AAD):** authenticated but **not** stored in the frame. The decryptor must supply the
  byte-identical AAD that was used to encrypt, out of band.

## Encrypt

1. Validate `len(key) == 32`.
2. Draw a fresh random 12-byte `nonce`.
3. `ciphertext, tag = AES-256-GCM-Encrypt(key, nonce, plaintext, aad)` (16-byte tag).
4. Emit `0x01 || nonce || tag || ciphertext`.

## Decrypt

1. Validate `len(key) == 32` and `len(frame) >= 29`.
2. Reject unless `frame[0] == 0x01`.
3. Split `nonce = frame[1..13]`, `tag = frame[13..29]`, `ciphertext = frame[29..]`.
4. `plaintext = AES-256-GCM-Decrypt(key, nonce, ciphertext, tag, aad)`; on tag mismatch, fail (return no
   plaintext). The reference rejects with a single error type carrying no plaintext or key material.

## Operational notes

- **Nonce limit:** because nonces are random and unsynchronized, rotate the key well before ~2³²
  encryptions (NIST SP 800-38D).
- **Not key-committing:** a frame can authenticate under more than one key; do not rely on the tag to
  bind a unique key (relevant only for password-derived or multi-key use). A future committing variant
  would use `version = 0x02`.

## Worked example (verifiable)

Using the GCM-spec AES-256-GCM test vector (all-zero 256-bit key, all-zero nonce, one zero block):

```
key        = 0000000000000000000000000000000000000000000000000000000000000000
nonce      = 000000000000000000000000
plaintext  = 00000000000000000000000000000000
aad        = (empty)
ciphertext = cea7403d4d606b6e074ec5d3baf39d18
tag        = d0d1c8a799996bf0265b98b5d48ab919

frame (hex):
01 000000000000000000000000 d0d1c8a799996bf0265b98b5d48ab919 cea7403d4d606b6e074ec5d3baf39d18
= 01000000000000000000000000d0d1c8a799996bf0265b98b5d48ab919cea7403d4d606b6e074ec5d3baf39d18
```

A conforming implementation in any language must produce exactly this 45-byte frame for these inputs.
