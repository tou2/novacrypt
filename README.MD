# NovaCrypt

## Overview
NovaCrypt is an educational hybrid encryption tool that combines password-based key derivation with optional post-quantum key encapsulation (Kyber768 via liboqs) plus modern authenticated encryption. It replaces earlier custom ciphers with well-vetted primitives (ChaCha20-Poly1305, AES-GCM, Argon2id/Scrypt, Ed25519). Use it for learning and experimentation, not for production security.

## Beginner Guide: What Problem Does This Solve?
If you are new to encryption, start here.

### 1. The Core Problem
You have data (a message or file) and you want to store or send it so that:
- Others cannot read it (confidentiality)
- Nobody can silently change it (integrity)
- You can tell it really came from the expected author (authenticity / origin)
- An attacker cannot easily guess the key or password (resistance to brute force)
- Future advances (like quantum computers) should not instantly break past exchanges (forward-looking security)

### 2. Plaintext vs Ciphertext
- Plaintext: the original readable bytes (e.g., "Hello").
- Ciphertext: scrambled output that looks meaningless without the right key.
Encryption turns plaintext into ciphertext; decryption reverses it with the correct secret.

### 3. Keys and Passwords Are Different
- A password is something a human chooses (often weak or reused).
- A cryptographic key should be long, random, and unguessable.
Because people remember passwords (not random 32-byte keys), we transform the password into a strong key using a Key Derivation Function (KDF). That process is intentionally slow to make large-scale guessing expensive.

### 4. Threats This Tries to Mitigate
| Threat | Risk | Mitigation in NovaCrypt |
|--------|------|--------------------------|
| Passive eavesdropping | Attacker reads your data | ChaCha20-Poly1305 encrypts payload |
| Tampering | Attacker alters data silently | AEAD tags + optional Ed25519 signature |
| Password brute force | Attacker guesses quickly | Argon2id (or Scrypt) slows guesses |
| Key reuse | One leak breaks everything | Fresh random data key per message |
| Future quantum attacks on key exchange | Classical-only exchange might be broken later | Optional Kyber KEM adds a post-quantum component (if installed) |
| Forged origin | Attacker pretends to be you | Ed25519 signature (if enabled) |

(Important: This is educational software; real-world deployments need audits and additional hardening.)

### 5. Why Two Layers (Data Key + Wrapped Key)?
Instead of encrypting your data directly with the password-derived key, NovaCrypt:
1. Generates a strong random data key (DK) for the payload.
2. Encrypts the payload with DK (ChaCha20-Poly1305).
3. Protects (wraps) DK itself using a Key Encryption Key (KEK) derived from your password (and optionally the Kyber shared secret).

Advantages:
- Compromise of one payload’s DK does not expose others.
- Enables future features like multiple recipients (store several wrapped DK entries).
- Separates performance-sensitive payload encryption from slower password stretching.

### 6. How the Password Becomes a Key
Argon2id (or Scrypt if Argon2id is unavailable) takes:
- Your password
- A random salt (so the same password yields different keys each time)
- Cost parameters (time, memory)
It outputs a strong fixed-length key that is harder to brute force rapidly.

### 7. Optional Post-Quantum (PQ) Layer
If the `oqs` library (liboqs) is present, the program uses Kyber768:
- Kyber encapsulation generates a shared secret (PQK) plus a ciphertext.
- Only the holder of the Kyber private key can recover PQK from that ciphertext.
- NovaCrypt mixes PQK with the password-derived key via HKDF to form the KEK.
Goal: Even if in the future large quantum computers weaken password-based secrecy, the PQ part could still protect the data key (assuming parameters and implementation remain secure).

### 8. Integrity vs Authenticity
- AEAD (ChaCha20-Poly1305 / AES-GCM) already prevents undetected random tampering with ciphertext.
- Ed25519 signing adds explicit origin authentication (you can verify the message came from the holder of the private signing key) and protects the structured JSON envelope.

### 9. High-Level Analogy
Think of sending a locked box (payload ciphertext) inside a sealed envelope:
- The box lock uses a one-time internal key (data key).
- The envelope contains that internal key but itself is sealed with a combination derived from your password (and optionally a PQ secret). AES-GCM does this wrapping.
- A wax seal (Ed25519 signature) shows if the envelope was tampered with and who sealed it.

### 10. What This Does NOT Solve
- It does not hide metadata (file size leaks approximately through ciphertext length).
- It does not provide deniable encryption.
- It does not protect against keylogging, malware, or a compromised system.
- It does not guarantee future PQ security (parameters, libraries, and assumptions may change).

### 11. Minimal Mental Model
Plaintext --(ChaCha20-Poly1305 under Data Key)--> Payload Ciphertext
Data Key --(AES-GCM under KEK)--> Wrapped Key
KEK = HKDF( Password-Derived Key || (optional Kyber Shared Secret) )
Signature (optional) covers the JSON body containing both ciphertext structures.

### 12. When Something Fails
- Wrong password: Unwrap step fails (AES-GCM tag mismatch) or payload decryption fails.
- Corrupted ciphertext: AEAD or signature verification error.
- Missing PQ library: Falls back to password-only mode (still works, just no hybrid KEK).

### 13. Safe Use Tips
- Use a long, unique password (consider a passphrase with multiple random words).
- Keep your `~/.novacrypt/` directory private (contains your private keys, albeit encrypted).
- Re-encrypt older data after parameter upgrades if security matters.

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
