# NovaCrypt

## Overview
NovaCrypt is an educational hybrid encryption tool that combines password-based key derivation with optional post-quantum key encapsulation (Kyber768 via liboqs) plus modern authenticated encryption. It replaces earlier custom ciphers with well-vetted primitives (ChaCha20-Poly1305, AES-GCM, Argon2id/Scrypt, Ed25519). Use it for learning and experimentation, not for production security.

## Current Architecture (Version 3 Envelope)
1. A per-message 32-byte data key is generated (DK).
2. Payload (message or file bytes) is encrypted with ChaCha20-Poly1305 (AEAD) using DK.
3. A password-derived key (PWK) is produced via Argon2id (if installed) else Scrypt with a 16‑byte random salt.
4. (Optional) If liboqs is available, a persistent Kyber768 keypair is maintained; the public key is used to encapsulate a shared secret (PQK).
5. A hybrid KEK = HKDF(PWK || PQK) is derived (HKDF-SHA256, info="NovaCrypt-Hybrid").
6. DK is wrapped (encrypted + authenticated) with AES-GCM under the KEK.
7. An envelope (JSON) records: version, mode (password-only or hybrid-pq), KDF metadata, PQ ciphertext (if any), wrapped key, payload ciphertext.
8. Optionally the envelope body is canonically serialized and Ed25519-signed; signature + public key are included.
9. The entire envelope JSON is base64-encoded for output.

On decryption the process is reversed; if PQ mode is present the stored Kyber secret key decrypts the PQ ciphertext to recover PQK and reproduce the KEK.

## Features
- Password-based KDF: Argon2id (preferred) or Scrypt fallback.
- Optional Kyber768 hybrid component (if `oqs` installed and supported platform).
- ChaCha20-Poly1305 for payload AEAD (confidentiality + integrity).
- AES-GCM for key wrapping (separates payload and key protection contexts).
- Ed25519 signature over canonical envelope body (detect tampering, optional).
- File and message modes via CLI.
- Deterministic persistent storage of: Ed25519 keypair, Kyber keypair (secret key wrapped with password-derived KEK) in `~/.novacrypt/`.

## Envelope Format (v3)
Unsigned example:
```
{
  "v":3,
  "mode":"password-only" | "hybrid-pq",
  "kdf": { "alg":"argon2id"|"scrypt", ... , "salt":"base64" },
  "pq": { "alg":"Kyber768", "ciphertext":"base64" } | null,
  "wrap": { "alg":"AESGCM", "nonce":"base64", "ct":"base64" },
  "data": { "alg":"ChaCha20Poly1305", "nonce":"base64", "ct":"base64" }
}
```
Signed variant wraps the above (as `body`) with:
```
{
  "sig_alg":"ed25519",
  "sig_pub":"base64(32 bytes)",
  "sig":"base64(signature)",
  "body": { ...envelope fields... }
}
```

## Installation
Create a virtual environment (recommended) and install dependencies:
```bash
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install cryptography
pip install argon2-cffi          # optional (better KDF)
pip install oqs                  # optional (Kyber PQ support; may require system liboqs)
```
If `oqs` installation fails, NovaCrypt will still function in password-only mode.

## Usage
Run the CLI:
```bash
python main.py
```
Follow prompts:
- Select encrypt (e) or decrypt (d)
- Choose message (m) or file (f)
- If encrypting and PQ support detected, optionally enable the Kyber hybrid component

Output for encryption is a Base64 string (envelope). For files a `.enc` file is written.

## Example (Message Encryption)
```
Encrypt or Decrypt? (e/d): e
(m)essage or (f)ile? m
Enter message: Hello hybrid world
Encrypted (Base64 envelope):
<base64 blob>
```
Store the blob securely; to decrypt, supply the same password (and if using PQ mode, the same local key storage directory must be present).

## Security Notes and Limitations
- Educational prototype: no formal audit, no hardening against side-channel attacks.
- Kyber integration depends on local storage of secret key encrypted by password; compromise of password compromises both layers.
- Argon2id parameters (t=3, m=64MiB, p=1) are moderate; adjust upward for higher security on capable systems.
- HKDF salt is currently None; adding a random per-envelope HKDF salt could provide extra domain separation (future enhancement).
- Ed25519 signature provides integrity of the envelope structure; AEAD already covers ciphertext integrity—signature mainly adds provenance / identity binding.
- If `oqs` is unavailable, mode falls back to password-only—communicate this to users so they do not assume PQ properties.
- Do not treat this as production-grade or claim certified post-quantum security.

## Roadmap Ideas
- Add HKDF salt field.
- Support multi-recipient envelopes (multiple wrapped DK entries).
- Integrate XChaCha20-Poly1305 for extended nonces.
- Provide test vectors and automated correctness tests.
- Add key rotation and explicit version negotiation.

## Cleaning Up Old Artifacts
If you ran older versions (pre-v3) you may have unsigned envelopes. The current code attempts to read legacy unsigned format transparently. To force re-encryption, decrypt then re-encrypt with the current version.

## License
MIT

## Disclaimer
Use at your own risk. Provided for learning and experimentation only.
