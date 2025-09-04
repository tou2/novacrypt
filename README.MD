# NovaCrypt: A Hybrid Post-Quantum Encryption Tool

## Overview
NovaCrypt is a command-line encryption tool written in Python. It implements a hybrid encryption scheme designed to be resistant to attacks from both classical and future quantum computers. It combines a lattice-based Key Encapsulation Mechanism (KEM) with a robust, multi-round symmetric cipher.

This tool is designed for educational purposes to demonstrate the principles of building a post-quantum, password-based encryption system.

## Features
- **Hybrid Post-Quantum & Symmetric Encryption:** Uses a hybrid model to ensure security against multiple threat vectors.
- **Lattice-Based KEM:** The key exchange is based on the **Learning with Errors (LWE)** problem, which is believed to be resistant to quantum computer attacks.
- **Robust Symmetric Cipher:** A custom 16-round cipher using key-dependent S-boxes and round-specific keys for strong symmetric encryption.
- **Strong Key Derivation:** Uses PBKDF2 with **600,000 iterations** to derive cryptographic keys from a user's password, making it highly resistant to brute-force attacks.
- **File and Message Support:** Can encrypt and decrypt both simple text messages and entire files of any type.

## Dependencies
- Python 3.x
- NumPy

## Installation
1.  Clone the repository:
    ```bash
    git clone https://github.com/tou2/novacrypt.git
    cd novacrypt
    ```

2.  Install the required dependency:
    ```bash
    pip install numpy
    ```

## How to Use
The tool runs from the command line.

```bash
python main.py
```

You will be prompted to choose whether to **Encrypt** or **Decrypt**, and whether you are working with a **message** or a **file**.

### Example: Encrypting a File
1.  Run `python main.py`.
2.  Choose `e` for Encrypt.
3.  Choose `f` for File.
4.  Enter the path to your file (e.g., `my_document.pdf`).
5.  Enter a strong password.
6.  The tool will create an encrypted file (e.g., `my_document.pdf.nc`).

### Example: Decrypting a File
1.  Run `python main.py`.
2.  Choose `d` for Decrypt.
3.  Choose `f` for File.
4.  Enter the path to the encrypted file (e.g., `my_document.pdf.nc`).
5.  Enter the same password you used to encrypt.
6.  The tool will decrypt the file and suggest saving it as the original filename (e.g., `my_document.pdf`).

## How It Works
NovaCrypt uses a sophisticated, multi-stage process to protect your data.

### Encryption
1.  **PQC Key Generation:** A unique salt is generated. This salt and your password are put through PBKDF2 to deterministically generate a quantum-resistant public/private key pair for the LWE scheme.
2.  **Key Encapsulation:** A new, single-use 256-bit symmetric key is generated. This key is then "encapsulated" (encrypted) using the PQC public key.
3.  **Symmetric Encryption:** The actual message or file data is encrypted using the 16-round symmetric cipher, which is keyed by the encapsulated symmetric key.
4.  **Packaging:** The salt, the encapsulated symmetric key, and the encrypted data are all Base64-encoded and combined into a single output string for storage.

### Decryption
1.  **Unpacking:** The encrypted string is split into its components (salt, encapsulated key, and encrypted data).
2.  **PQC Key Re-generation:** The salt and your password are used to re-generate the exact same PQC private key.
3.  **Key Decapsulation:** The PQC private key is used to "decapsulate" (decrypt) the symmetric key.
4.  **Symmetric Decryption:** The symmetric key is then used to decrypt the main payload, restoring the original message or file.

## Security Considerations
- This is an **experimental and educational** implementation. It has not undergone a formal security audit.
- The security of the entire system relies on the strength of your password and the presumed hardness of the Learning with Errors (LWE) problem.
- Always use a strong, unique password for encryption.

## License
This project is released under the MIT License.

---

For more details or to contribute, feel free to open issues or pull requests!
