import hashlib
import secrets
import base64
import random
from typing import Tuple

class NovaCrypt:
    """
    A class for a novel multi-layered encryption scheme.
    """
    ROUNDS = 16  # Number of encryption rounds
    ITERATIONS = 600000  # Number of PBKDF2 iterations

    def __init__(self, password: str, salt: bytes):
        """
        Initializes the NovaCrypt instance.

        Args:
            password (str): The user's password.
            salt (bytes): A random salt.
        """
        self.password = password
        self.salt = salt
        self.key = self._derive_key()
        self.s_box, self.inv_s_box = self._generate_s_boxes()

    def _derive_key(self) -> bytes:
        """Derives a 32-byte key from the password and salt using PBKDF2."""
        return hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), self.salt, self.ITERATIONS, dklen=32)

    def _get_round_key(self, round_number: int) -> bytes:
        """Generates a unique key for a specific encryption round."""
        return hashlib.sha256(self.key + bytes([round_number])).digest()

    def _generate_s_boxes(self) -> Tuple[list, list]:
        """Generates a key-dependent substitution box (S-box) and its inverse."""
        s_box = list(range(256))
        # Use the key to seed the random number generator for a deterministic shuffle
        random.seed(self.key)
        random.shuffle(s_box)
        
        # Create the inverse S-box for decryption
        inv_s_box = [0] * 256
        for i, val in enumerate(s_box):
            inv_s_box[val] = i
            
        return s_box, inv_s_box

    def _substitute(self, data: bytes, s_box: list) -> bytes:
        """Substitutes bytes using the S-box."""
        return bytes([s_box[b] for b in data])

    def _xor_with_key(self, data: bytes, key: bytes) -> bytes:
        """Performs a repeating-key XOR operation on the data."""
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def encrypt(self, message: str) -> str:
        """
        Encrypts a message using a multi-layered, multi-round approach.
        """
        message_bytes = message.encode('utf-8')
        
        # Apply multiple rounds of encryption
        data = message_bytes
        for i in range(self.ROUNDS):
            round_key = self._get_round_key(i)
            # Layer 1: XOR with round-specific key
            data = self._xor_with_key(data, round_key)
            # Layer 2: Substitution with the main S-box
            data = self._substitute(data, self.s_box)
            
        return base64.b64encode(data).decode('utf-8')

    def decrypt(self, encrypted_message: str) -> str:
        """
        Decrypts a message by reversing the multi-round encryption process.
        """
        encrypted_data = base64.b64decode(encrypted_message)
        
        # Apply multiple rounds of decryption in reverse order
        data = encrypted_data
        for i in reversed(range(self.ROUNDS)):
            round_key = self._get_round_key(i)
            # Reverse Layer 2: Substitution
            data = self._substitute(data, self.inv_s_box)
            # Reverse Layer 1: XOR with round-specific key
            data = self._xor_with_key(data, round_key)
            
        return data.decode('utf-8')

def main():
    """Main function to run the encryption/decryption tool."""
    choice = input("Encrypt or Decrypt? (e/d): ").strip().lower()

    if choice == 'e':
        message = input("Enter the message to encrypt: ")
        password = input("Enter a password: ")
        
        salt = secrets.token_bytes(16)
        encryptor = NovaCrypt(password, salt)
        
        encrypted_msg = encryptor.encrypt(message)
        
        # Combine salt and encrypted message for storage
        # The format is salt(base64) + ":" + encrypted_message(base64)
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        output_message = f"{salt_b64}:{encrypted_msg}"
        
        print("\n--- Encryption Successful ---")
        print(f"Encrypted Output (save this securely):\n{output_message}")
        
        with open('encrypted_message.txt', 'w') as f:
            f.write(output_message)
        print("\nOutput saved to 'encrypted_message.txt'")

    elif choice == 'd':
        try:
            encrypted_input = input("Enter the encrypted message (or press Enter to read from file): ").strip()
            if not encrypted_input:
                with open('encrypted_message.txt', 'r') as f:
                    encrypted_input = f.read().strip()
                print("Read encrypted message from 'encrypted_message.txt'")

            password = input("Enter the password to decrypt: ")
            
            # Split the input to get the salt and the encrypted message
            parts = encrypted_input.split(':')
            if len(parts) != 2:
                raise ValueError("Invalid encrypted message format.")
                
            salt_b64, encrypted_msg = parts
            salt = base64.b64decode(salt_b64)
            
            decryptor = NovaCrypt(password, salt)
            decrypted_msg = decryptor.decrypt(encrypted_msg)
            
            print("\n--- Decryption Successful ---")
            print("Decrypted message:", decrypted_msg)

        except FileNotFoundError:
            print("\nError: 'encrypted_message.txt' not found and no input provided.")
        except (ValueError, IndexError, base64.binascii.Error) as e:
            print(f"\nAn error occurred during decryption: Invalid data. ({e})")
            print("This could be due to an incorrect password or corrupted message.")
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
    
    else:
        print("Invalid choice. Please enter 'e' for encrypt or 'd' for decrypt.")

if __name__ == "__main__":
    main()