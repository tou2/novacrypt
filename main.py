import hashlib
import secrets
import base64
import numpy as np
from typing import Tuple

class NovaCrypt:
    """
    A class for a hybrid post-quantum encryption scheme.
    It combines a lattice-based key encapsulation mechanism (LWE-KEM)
    with a multi-round symmetric cipher. The PQC keypair is derived
    deterministically from the user's password.
    """
    N = 256
    Q = 7681
    STD_DEV = 2.25
    ROUNDS = 16
    ITERATIONS = 600000

    def __init__(self, password: str):
        self.password = password.encode('utf-8')

    def _generate_deterministic_lwe_keypair(self, salt: bytes) -> Tuple[Tuple[np.ndarray, np.ndarray], np.ndarray]:
        """Deterministically generates a PQC keypair from the password and a salt."""
        # Use PBKDF2 to generate a large seed for all our random numbers
        seed_material = hashlib.pbkdf2_hmac('sha256', self.password, salt, self.ITERATIONS, dklen=128)
        
        # Seed the numpy random generator
        rng = np.random.RandomState(int.from_bytes(seed_material[:4], 'little'))
        
        # Generate components from the seed
        A = rng.randint(0, self.Q, size=(self.N, self.N))
        s = rng.randint(0, self.Q, size=self.N)
        e = np.round(rng.normal(0, self.STD_DEV, size=self.N)).astype(int)
        b = (A @ s + e) % self.Q
        
        return (A, b), s

    def _encapsulate_secret(self, public_key: Tuple[np.ndarray, np.ndarray]) -> Tuple[Tuple[np.ndarray, int], bytes]:
        """Uses the public key to encapsulate a shared secret."""
        A, b = public_key
        r = np.random.randint(0, self.Q, size=self.N)
        e1 = np.round(np.random.normal(0, self.STD_DEV, size=self.N)).astype(int)
        e2 = np.round(np.random.normal(0, self.STD_DEV))

        u = (A @ r + e1) % self.Q # Corrected: Removed transpose from A
        v = (b @ r + e2 + (self.Q // 2)) % self.Q

        # The shared secret k is derived from v
        k_binary = (v > self.Q // 4) & (v < 3 * self.Q // 4)
        k = hashlib.sha256(k_binary.tobytes()).digest()
        return (u, v), k

    def _decapsulate_secret(self, private_key: np.ndarray, ciphertext: Tuple[np.ndarray, int]) -> bytes:
        """Uses the private key to decapsulate the shared secret."""
        u, v = ciphertext
        s = private_key
        recovered_v = (v - u @ s) % self.Q # Corrected: Changed matrix multiplication order
        
        k_binary = (recovered_v > self.Q // 4) & (recovered_v < 3 * self.Q // 4)
        k = hashlib.sha256(k_binary.tobytes()).digest()
        return k

    def _get_round_key(self, main_key: bytes, round_number: int) -> bytes:
        return hashlib.sha256(main_key + bytes([round_number])).digest()

    def _generate_s_boxes(self, key: bytes) -> Tuple[list, list]:
        s_box = list(range(256))
        seed_material = hashlib.sha256(key).digest()
        # Use a different random stream for S-box generation, seeded with the first 4 bytes of the hash
        rng = np.random.RandomState(int.from_bytes(seed_material[:4], 'little'))
        rng.shuffle(s_box)
        
        inv_s_box = [0] * 256
        for i, val in enumerate(s_box):
            inv_s_box[val] = i
        return s_box, inv_s_box

    def _substitute(self, data: bytes, s_box: list) -> bytes:
        return bytes([s_box[b] for b in data])

    def _xor_with_key(self, data: bytes, key: bytes) -> bytes:
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def _symmetric_cipher(self, data: bytes, key: bytes, s_box: list, decrypt=False) -> bytes:
        """Unified symmetric cipher function."""
        rounds = reversed(range(self.ROUNDS)) if decrypt else range(self.ROUNDS)
        # The s_box argument is the inverse s_box when decrypting
        for i in rounds:
            round_key = self._get_round_key(key, i)
            if decrypt:
                # Reverse the operations in the opposite order
                data = self._substitute(data, s_box) # 1. Inverse substitute
                data = self._xor_with_key(data, round_key) # 2. XOR
            else:
                # Encrypt
                data = self._xor_with_key(data, round_key) # 1. XOR
                data = self._substitute(data, s_box) # 2. Substitute
        return data

    def encrypt_bytes(self, data: bytes) -> str:
        """
        Encrypts raw bytes using the hybrid post-quantum scheme.

        Args:
            data (bytes): The raw bytes to encrypt.

        Returns:
            str: A string containing the complete encrypted data, ready for storage.
        """
        # 1. Generate a salt to ensure the PQC keypair is unique for each encryption.
        pqc_salt = secrets.token_bytes(16)
        
        # 2. Deterministically generate the PQC keypair from the password and salt.
        public_key, _ = self._generate_deterministic_lwe_keypair(pqc_salt)
        
        # 3. Encapsulate a new, random secret (the symmetric key).
        lwe_ciphertext, symmetric_key = self._encapsulate_secret(public_key)
        
        # 4. Generate S-boxes for the symmetric cipher.
        s_box, _ = self._generate_s_boxes(symmetric_key)
        
        # 5. Encrypt the message using the symmetric cipher.
        encrypted_payload = self._symmetric_cipher(data, symmetric_key, s_box)
        
        # 6. Package everything for output.
        pqc_salt_b64 = base64.b64encode(pqc_salt).decode('utf-8')
        lwe_u_b64 = base64.b64encode(lwe_ciphertext[0].tobytes()).decode('utf-8')
        lwe_v_b64 = base64.b64encode(np.array([lwe_ciphertext[1]]).tobytes()).decode('utf-8')
        payload_b64 = base64.b64encode(encrypted_payload).decode('utf-8')
        
        return f"{pqc_salt_b64}:{lwe_u_b64}:{lwe_v_b64}:{payload_b64}"

    def encrypt(self, message: str) -> str:
        """Encrypts a message string using the hybrid post-quantum scheme."""
        return self.encrypt_bytes(message.encode('utf-8'))

    def decrypt_bytes(self, encrypted_message: str) -> bytes:
        """
        Decrypts a full encrypted message string into raw bytes.

        Args:
            encrypted_message (str): The complete encrypted data string.

        Returns:
            bytes: The original raw bytes.
        """
        # 1. Unpack the encrypted message.
        parts = encrypted_message.split(':')
        if len(parts) != 4:
            raise ValueError("Invalid encrypted message format.")
        pqc_salt_b64, lwe_u_b64, lwe_v_b64, payload_b64 = parts
        
        pqc_salt = base64.b64decode(pqc_salt_b64)
        lwe_u = np.frombuffer(base64.b64decode(lwe_u_b64), dtype=int)
        lwe_v = np.frombuffer(base64.b64decode(lwe_v_b64), dtype=int)[0]
        lwe_ciphertext = (lwe_u, lwe_v)
        encrypted_payload = base64.b64decode(payload_b64)
        
        # 2. Re-generate the same PQC private key using the password and salt.
        _, private_key = self._generate_deterministic_lwe_keypair(pqc_salt)
        
        # 3. Decapsulate the secret (the symmetric key) using the private key.
        symmetric_key = self._decapsulate_secret(private_key, lwe_ciphertext)
        
        # 4. Re-generate the same S-boxes.
        _, inv_s_box = self._generate_s_boxes(symmetric_key)
        
        # 5. Decrypt the payload.
        decrypted_bytes = self._symmetric_cipher(encrypted_payload, symmetric_key, inv_s_box, decrypt=True)
        
        return decrypted_bytes

    def decrypt(self, encrypted_message: str) -> str:
        """Decrypts a message by reversing the hybrid post-quantum scheme."""
        decrypted_bytes = self.decrypt_bytes(encrypted_message)
        return decrypted_bytes.decode('utf-8')

def main():
    """Main function to run the encryption/decryption tool."""
    # Ensure numpy is installed
    try:
        import numpy
    except ImportError:
        print("Error: NumPy is required for this script.")
        print("Please install it by running: pip install numpy")
        return

    choice = input("Encrypt or Decrypt? (e/d): ").strip().lower()

    if choice == 'e':
        mode = input("Encrypt a (m)essage or a (f)ile? ").strip().lower()
        password = input("Enter a password: ")
        encryptor = NovaCrypt(password)

        if mode == 'm':
            message = input("Enter the message to encrypt: ")
            encrypted_msg = encryptor.encrypt(message)
            
            print("\n--- Encryption Successful ---")
            print(f"Encrypted Output (save this securely):\n{encrypted_msg}")
            
            with open('encrypted_message.txt', 'w') as f:
                f.write(encrypted_msg)
            print("\nOutput saved to 'encrypted_message.txt'")
        
        elif mode == 'f':
            try:
                input_file = input("Enter the path to the file to encrypt: ")
                output_file = input(f"Enter the output path for the encrypted file (default: {input_file}.nc): ")
                if not output_file:
                    output_file = f"{input_file}.nc"

                print(f"Reading file: {input_file}...")
                with open(input_file, 'rb') as f:
                    file_bytes = f.read()
                
                print("Encrypting file...")
                encrypted_data = encryptor.encrypt_bytes(file_bytes)

                with open(output_file, 'w') as f:
                    f.write(encrypted_data)
                
                print("\n--- File Encryption Successful ---")
                print(f"File encrypted and saved to: {output_file}")

            except FileNotFoundError:
                print(f"\nError: Input file not found at '{input_file}'")
            except Exception as e:
                print(f"\nAn unexpected error occurred during file encryption: {e}")
        
        else:
            print("Invalid mode. Please choose 'm' or 'f'.")

    elif choice == 'd':
        mode = input("Decrypt a (m)essage or a (f)ile? ").strip().lower()
        password = input("Enter the password to decrypt: ")
        decryptor = NovaCrypt(password)

        if mode == 'm':
            try:
                encrypted_input = input("Enter the encrypted message (or press Enter to read from file): ").strip()
                if not encrypted_input:
                    with open('encrypted_message.txt', 'r') as f:
                        encrypted_input = f.read().strip()
                    print("Read encrypted message from 'encrypted_message.txt'")
                
                decrypted_msg = decryptor.decrypt(encrypted_input)
                
                print("\n--- Decryption Successful ---")
                print("Decrypted message:", decrypted_msg)

            except FileNotFoundError:
                print("\nError: 'encrypted_message.txt' not found and no input provided.")
            except (ValueError, IndexError, base64.binascii.Error) as e:
                print(f"\nAn error occurred during decryption: Invalid data. ({e})")
                print("This could be due to an incorrect password or corrupted message.")
            except Exception as e:
                print(f"\nAn unexpected error occurred: {e}")

        elif mode == 'f':
            try:
                input_file = input("Enter the path to the encrypted file (e.g., 'myfile.txt.nc'): ")
                # Suggest an output file by removing the .nc extension if it exists
                default_output = input_file[:-3] if input_file.endswith('.nc') else ""
                output_file = input(f"Enter the output path for the decrypted file (default: {default_output}): ")
                if not output_file:
                    if default_output:
                        output_file = default_output
                    else:
                        # If no default could be determined, ask again.
                        print("Output path cannot be empty.")
                        output_file = input("Enter the output path for the decrypted file: ")


                print(f"Reading encrypted file: {input_file}...")
                with open(input_file, 'r') as f:
                    encrypted_data = f.read()
                
                print("Decrypting file...")
                decrypted_bytes = decryptor.decrypt_bytes(encrypted_data)

                with open(output_file, 'wb') as f:
                    f.write(decrypted_bytes)
                
                print("\n--- File Decryption Successful ---")
                print(f"File decrypted and saved to: {output_file}")

            except FileNotFoundError:
                print(f"\nError: Input file not found at '{input_file}'")
            except (ValueError, IndexError, base64.binascii.Error) as e:
                print(f"\nAn error occurred during decryption: Invalid data. ({e})")
                print("This could be due to an incorrect password or corrupted message.")
            except Exception as e:
                print(f"\nAn unexpected error occurred during file decryption: {e}")
        
        else:
            print("Invalid mode. Please choose 'm' or 'f'.")
    
    else:
        print("Invalid choice. Please enter 'e' for encrypt or 'd' for decrypt.")

if __name__ == "__main__":
    main()