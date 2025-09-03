# Novel Encryption Tool

## Overview
This repository contains a **Python** implementation of a novel encryption algorithm that combines multiple cryptographic primitives (substitution cipher, key-stream XOR, permutation, and non-linear mixing) to provide a highly resistant encryption scheme. It is intentionally designed to be *hard to break* with standard cryptanalysis techniques, though it is not formally proven secure.

## Features
- **Dynamic substitution cipher** generated from the encryption key
- **Hash-based key stream** (SHA-256 with counter) for XOR masking
- **Permutation layer** derived from a random IV and key hash
- **Non-linear mixing** with the key hash to thwart linear attacks
- Easy-to-use API with clear `encrypt()` and `decrypt()` methods
- Works with arbitrary-length UTF-8 text

## Installation
This project only relies on Python's standard library. No external dependencies are required.

```bash
# Clone the repository
git clone https://github.com/your-username/novel-encryption.git
cd novel-encryption

# (Optional) Create a virtual environment
python -m venv .venv
source .venv/bin/activate      # On Windows: .\.venv\Scripts\activate
```

## Usage
```python
from novel_encryption import NovelEncryption

# Create an instance with a secret key
key = "my_secret_key_12345"
crypto = NovelEncryption(key)

# Encrypt a message
message = "Hello, world!"
encrypted, iv = crypto.encrypt(message)
print("Encrypted:", encrypted)
print("IV:", iv)

# Decrypt the message
original = crypto.decrypt(encrypted, iv)
print("Original:", original)
```

## API Reference
### `NovelEncryption(key: str | None = None)`
- **key**: Encryption key. If omitted, a random 32-byte key is generated.

### `encrypt(message: str) -> Tuple[str, str]`
- **message**: Plain-text string to encrypt
- **Returns**: A tuple `(ciphertext_hex, iv_hex)`

### `decrypt(ciphertext_hex: str, iv_hex: str) -> str`
- **ciphertext_hex**: Hex string produced by `encrypt`
- **iv_hex**: IV hex string produced by `encrypt`
- **Returns**: The original plain-text string

## Security Considerations
- The algorithm is *experimental* and not formally vetted
- Key management is critical: use a secure, random key and keep it confidential
- The IV is random for each encryption; it should be stored/transmitted alongside the ciphertext
- Do **not** reuse keys or IVs for multiple messages

## License
This project is released under the MIT License.

---

For more details or to contribute, feel free to open issues or pull requests!
```
