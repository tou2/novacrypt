import os
import json
import base64
import secrets
from typing import Optional, Tuple, Dict, Any

# External (optional) dependencies:
# - cryptography (required) for AEAD and KDFs
# - argon2-cffi (optional) for Argon2id KDF
# - oqs (optional) for Kyber (post-quantum KEM)
# Hardening additions: Ed25519 signing for envelope integrity & identity.

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError as e:
    raise SystemExit("Missing required dependency 'cryptography'. Install with: pip install cryptography")

try:
    import argon2.low_level as argon2_ll
    HAVE_ARGON2 = True
except ImportError:
    HAVE_ARGON2 = False

try:
    import oqs  # python-oqs wrapper for liboqs (Kyber, etc.)
    HAVE_OQS = True
except ImportError:
    HAVE_OQS = False

KEY_DIR = os.path.join(os.path.expanduser('~'), '.novacrypt')
ED25519_PRIV_PATH = os.path.join(KEY_DIR, 'ed25519_private.pem')
ED25519_PUB_PATH = os.path.join(KEY_DIR, 'ed25519_public.pem')

# Kyber key storage
KYBER_PUB_PATH = os.path.join(KEY_DIR, 'kyber768_public.bin')
KYBER_SK_PATH  = os.path.join(KEY_DIR, 'kyber768_secret.enc')

KYBER_KEM_NAME = 'Kyber768'
KYBER_SK_WRAP_INFO = b'kyber-sk-wrap-v1'

# --------------------------- Utility Helpers --------------------------- #

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode('utf-8'))

# --------------------------- Key Derivation --------------------------- #

def derive_password_key(password: str, salt: bytes, length: int = 32) -> Tuple[bytes, Dict[str, Any]]:
    """Derive a key from a password using Argon2id (if available) else Scrypt.
    Returns (key, kdf_metadata)."""
    password_bytes = password.encode('utf-8')
    if HAVE_ARGON2:
        # Parameters chosen for interactive use; adjust (memory cost) upward if needed.
        t_cost = 3
        m_cost_kib = 64 * 1024  # 64 MiB
        parallelism = 1
        key = argon2_ll.hash_secret_raw(password_bytes, salt, t_cost, m_cost_kib, parallelism, length, argon2_ll.Type.ID)
        meta = {
            'alg': 'argon2id',
            't_cost': t_cost,
            'm_cost_kib': m_cost_kib,
            'parallelism': parallelism,
            'salt': b64e(salt)
        }
        return key, meta
    # Fallback: Scrypt (still strong; increase N for higher security)
    kdf = Scrypt(salt=salt, length=length, n=2**15, r=8, p=1)
    key = kdf.derive(password_bytes)
    meta = {
        'alg': 'scrypt',
        'n': 2**15,
        'r': 8,
        'p': 1,
        'salt': b64e(salt)
    }
    return key, meta

# --------------------------- Post-Quantum (Optional) --------------------------- #

def _load_or_create_kyber_keys(password: str) -> Optional[Tuple[bytes, bytes]]:
    """Create (if needed) and load a persistent Kyber768 keypair.
    Secret key stored AES-GCM encrypted with a key derived from password + static context.
    Returns (public_key, secret_key) or None if oqs unavailable.
    """
    if not HAVE_OQS:
        return None
    ensure_key_dir()
    # Derive KEK for wrapping the secret key (independent of per-message salt)
    kek_salt = b'NC-KYBER-KEYWRAP'
    # Re-use Scrypt fallback/Argon2 via derive_password_key but we need deterministic KEK
    kek, _ = derive_password_key(password, kek_salt[:16], length=32)

    if os.path.isfile(KYBER_PUB_PATH) and os.path.isfile(KYBER_SK_PATH):
        # Load public key
        with open(KYBER_PUB_PATH, 'rb') as f:
            pub = f.read()
        # Unwrap secret key
        with open(KYBER_SK_PATH, 'rb') as f:
            blob = f.read()
        try:
            nonce = blob[:12]
            ct = blob[12:]
            sk = AESGCM(kek).decrypt(nonce, ct, KYBER_SK_WRAP_INFO)
            return pub, sk
        except Exception:
            # Corrupted or wrong password
            raise ValueError("Failed to decrypt stored Kyber secret key (wrong password or corruption).")
    # Need to create
    import oqs
    with oqs.KeyEncapsulation(KYBER_KEM_NAME) as kem:
        pub = kem.generate_keypair()
        sk = kem.export_secret_key()
    with open(KYBER_PUB_PATH, 'wb') as f:
        f.write(pub)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(kek).encrypt(nonce, sk, KYBER_SK_WRAP_INFO)
    with open(KYBER_SK_PATH, 'wb') as f:
        f.write(nonce + ct)
    return pub, sk

def pq_encapsulate(public_key: bytes) -> Tuple[Dict[str, str], bytes]:
    """Encapsulate shared secret to given Kyber public key."""
    import oqs
    with oqs.KeyEncapsulation(KYBER_KEM_NAME, public_key=public_key) as kem:
        ct, shared = kem.encap_secret()
    return {
        'alg': KYBER_KEM_NAME,
        'ciphertext': b64e(ct)
    }, shared

def pq_decapsulate(ciphertext_b64: str, secret_key: bytes) -> bytes:
    """Decapsulate shared secret using stored Kyber secret key."""
    import oqs
    ct = b64d(ciphertext_b64)
    with oqs.KeyEncapsulation(KYBER_KEM_NAME, secret_key=secret_key) as kem:
        shared = kem.decap_secret(ct)
    return shared

# --------------------------- Hybrid Key Assembly --------------------------- #

def combine_keys(*parts: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b'NovaCrypt-Hybrid')
    return hkdf.derive(b''.join(parts))

# --------------------------- Ed25519 Key Management --------------------------- #

def ensure_key_dir():
    if not os.path.isdir(KEY_DIR):
        os.makedirs(KEY_DIR, exist_ok=True)

def load_or_create_ed25519(password: str) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Load (or create) a persistent Ed25519 key pair. Private key is password-encrypted on disk."""
    ensure_key_dir()
    if os.path.isfile(ED25519_PRIV_PATH):
        with open(ED25519_PRIV_PATH, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=password.encode('utf-8'))
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )
        with open(ED25519_PRIV_PATH, 'wb') as f:
            f.write(pem)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(ED25519_PUB_PATH, 'wb') as f:
            f.write(pub_pem)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub_bytes

# --------------------------- Core Class --------------------------- #
class NovaCrypt:
    """Hybrid (optionally post-quantum assisted) authenticated encryption wrapper with optional envelope signing.

    Design: 
      1. Generate random 32-byte data key (DK) per encryption.
      2. Encrypt payload with ChaCha20-Poly1305 (AEAD) using DK.
      3. Derive KEK from password (Argon2id or Scrypt) + salt.
      4. Optionally include Kyber768 shared secret (if oqs installed) -> hybrid secret.
      5. Wrap DK with AES-GCM under derived hybrid KEK.
      6. (Optional) Sign canonical envelope body with Ed25519.
      7. Output structured JSON then base64.
    """

    VERSION = 3  # bumped: signature envelope format

    def __init__(self, password: str, sign: bool = True):
        self.password = password
        self.sign = sign
        self._signing_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._signing_pub: Optional[bytes] = None
        if self.sign:
            try:
                self._signing_key, self._signing_pub = load_or_create_ed25519(password)
            except Exception:
                # Fallback: disable signing if key load fails
                self.sign = False

    def _canonical_json(self, obj: Dict[str, Any]) -> bytes:
        return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode('utf-8')

    # -------------------- Encryption -------------------- #
    def encrypt_bytes(self, data: bytes, use_pq: bool = True) -> str:
        salt = secrets.token_bytes(16)
        pw_key, kdf_meta = derive_password_key(self.password, salt)

        pq_meta = None
        pq_secret = b''
        if use_pq and HAVE_OQS:
            try:
                kyber_keys = _load_or_create_kyber_keys(self.password)
                if kyber_keys:
                    pub, _ = kyber_keys
                    pq_meta, pq_secret = pq_encapsulate(pub)
                else:
                    use_pq = False
            except Exception:
                use_pq = False  # fallback silently to password-only
        hybrid_kek_material = combine_keys(pw_key, pq_secret)

        # Data key (random per message)
        data_key = secrets.token_bytes(32)

        # Encrypt payload with ChaCha20-Poly1305
        payload_nonce = secrets.token_bytes(12)
        aead_payload = ChaCha20Poly1305(data_key)
        ciphertext = aead_payload.encrypt(payload_nonce, data, b'payload')

        # Wrap data key with AES-GCM
        wrap_nonce = secrets.token_bytes(12)
        wrapper = AESGCM(hybrid_kek_material)
        wrapped_key = wrapper.encrypt(wrap_nonce, data_key, b'datakey')

        # BEGIN REPLACED ENVELOPE LOGIC
        body = {
            'v': self.VERSION,
            'mode': 'hybrid-pq' if (use_pq and pq_meta) else 'password-only',
            'kdf': kdf_meta,
            'pq': pq_meta,  # contains ciphertext only
            'wrap': {
                'alg': 'AESGCM',
                'nonce': b64e(wrap_nonce),
                'ct': b64e(wrapped_key)
            },
            'data': {
                'alg': 'ChaCha20Poly1305',
                'nonce': b64e(payload_nonce),
                'ct': b64e(ciphertext)
            }
        }
        if self.sign and self._signing_key is not None and self._signing_pub is not None:
            sig = self._signing_key.sign(self._canonical_json(body))
            envelope = {
                'sig_alg': 'ed25519',
                'sig_pub': b64e(self._signing_pub),
                'sig': b64e(sig),
                'body': body
            }
        else:
            envelope = body  # unsigned legacy-compatible
        json_bytes = json.dumps(envelope, separators=(',', ':')).encode('utf-8')
        return b64e(json_bytes)
        # END REPLACED ENVELOPE LOGIC

    def encrypt(self, message: str, use_pq: bool = True) -> str:
        return self.encrypt_bytes(message.encode('utf-8'), use_pq=use_pq)

    # -------------------- Decryption -------------------- #
    def decrypt_bytes(self, blob: str) -> bytes:
        raw = b64d(blob)
        try:
            top = json.loads(raw.decode('utf-8'))
        except Exception as e:
            raise ValueError(f'Malformed envelope: {e}')

        if 'body' in top and 'sig' in top:
            body = top.get('body')
            if body.get('v') != self.VERSION:
                raise ValueError('Unsupported version')
            if self.sign:
                try:
                    sig_pub = b64d(top['sig_pub'])
                    signature = b64d(top['sig'])
                    ed25519.Ed25519PublicKey.from_public_bytes(sig_pub).verify(signature, self._canonical_json(body))
                except Exception as e:
                    raise ValueError(f'Signature verification failed: {e}')
            envelope = body
        else:
            envelope = top
            if envelope.get('v') != self.VERSION:
                raise ValueError('Unsupported version')

        kdf_meta = envelope['kdf']
        salt = b64d(kdf_meta['salt'])
        pw_key, _ = derive_password_key(self.password, salt)

        pq_secret = b''
        pq_meta = envelope.get('pq')
        if pq_meta and pq_meta.get('ciphertext') and envelope.get('mode') == 'hybrid-pq':
            if not HAVE_OQS:
                raise ValueError('PQ ciphertext present but oqs not installed')
            try:
                _, sk = _load_or_create_kyber_keys(self.password)
                pq_secret = pq_decapsulate(pq_meta['ciphertext'], sk)
            except Exception as e:
                raise ValueError(f'PQ decapsulation failed: {e}')

        hybrid_kek_material = combine_keys(pw_key, pq_secret)

        wrap = envelope['wrap']
        data_section = envelope['data']
        wrap_nonce = b64d(wrap['nonce'])
        wrapped_key = b64d(wrap['ct'])
        try:
            data_key = AESGCM(hybrid_kek_material).decrypt(wrap_nonce, wrapped_key, b'datakey')
        except Exception:
            raise ValueError('Key unwrap failed (password/PQ mismatch or corruption)')
        payload_nonce = b64d(data_section['nonce'])
        ciphertext = b64d(data_section['ct'])
        try:
            plaintext = ChaCha20Poly1305(data_key).decrypt(payload_nonce, ciphertext, b'payload')
        except Exception:
            raise ValueError('Payload authentication failed (corrupted or tampered)')
        return plaintext
        # END UPDATED PARSING

# --------------------------- CLI Interface --------------------------- #

def prompt_bool(msg: str, default: bool = True) -> bool:
    dv = 'Y/n' if default else 'y/N'
    ans = input(f"{msg} ({dv}): ").strip().lower()
    if not ans:
        return default
    return ans.startswith('y')

def run_cli():
    print('NovaCrypt Hybrid Encryption (Educational Prototype)')
    print('PQ support:', 'enabled' if HAVE_OQS else 'not available')
    choice = input('Encrypt or Decrypt? (e/d): ').strip().lower()
    if choice not in {'e','d'}:
        print('Invalid choice.')
        return
    password = input('Enter password: ')
    nc = NovaCrypt(password)
    use_pq = False
    if choice == 'e' and HAVE_OQS:
        use_pq = prompt_bool('Attempt to include Kyber768 hybrid component?', default=True)

    mode = input('(m)essage or (f)ile? ').strip().lower()
    if mode == 'm':
        if choice == 'e':
            message = input('Enter message: ')
            blob = nc.encrypt(message, use_pq=use_pq)
            print('\nEncrypted (Base64 envelope):')
            print(blob)
            with open('encrypted_message.txt','w') as f:
                f.write(blob)
            print("Saved to encrypted_message.txt")
        else:
            src = input('Paste encrypted Base64 (or press Enter to read encrypted_message.txt): ').strip()
            if not src:
                try:
                    with open('encrypted_message.txt','r') as f:
                        src = f.read().strip()
                except FileNotFoundError:
                    print('encrypted_message.txt not found.')
                    return
            try:
                plaintext = nc.decrypt(src)
                print('\nDecrypted message:')
                print(plaintext)
            except Exception as e:
                print('Decryption failed:', e)
    elif mode == 'f':
        if choice == 'e':
            in_path = input('Input file path: ').strip()
            if not os.path.isfile(in_path):
                print('File not found.')
                return
            out_path = input(f'Output (default {in_path}.enc): ').strip() or f'{in_path}.enc'
            with open(in_path,'rb') as f:
                data = f.read()
            blob = nc.encrypt_bytes(data, use_pq=use_pq)
            with open(out_path,'w') as f:
                f.write(blob)
            print(f'Encrypted -> {out_path}')
        else:
            in_path = input('Encrypted file path: ').strip()
            if not os.path.isfile(in_path):
                print('File not found.')
                return
            out_path = input('Decrypted output file path: ').strip() or 'decrypted.out'
            with open(in_path,'r') as f:
                blob = f.read()
            try:
                data = nc.decrypt_bytes(blob)
            except Exception as e:
                print('Decryption failed:', e)
                return
            with open(out_path,'wb') as f:
                f.write(data)
            print(f'Decrypted -> {out_path}')
    else:
        print('Invalid mode.')

if __name__ == '__main__':
    run_cli()