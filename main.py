import hashlib
import secrets
import base64
from typing import Tuple

class NovelEncryption:
    def __init__(self):
        self.seed = secrets.token_bytes(32)
        
    def _generate_key(self, message: str, salt: bytes) -> bytes:
        combined = (message.encode() + self.seed + salt).hex().encode()
        key = hashlib.shake_256(combined).digest(32)
        return key
        
    def _custom_transform(self, data: bytes, key: bytes) -> bytes:
        pattern = [key[i % len(key)] for i in range(len(data))]
        transformed = bytearray()
        for i, byte in enumerate(data):
            xor_result = byte ^ pattern[i]
            permuted = ((xor_result << 3) | (xor_result >> 5)) & 0xFF
            transformed.append(permuted)
        return bytes(transformed)
        
    def _reverse_transform(self, data: bytes, key: bytes) -> bytes:
        pattern = [key[i % len(key)] for i in range(len(data))]
        reversed_data = bytearray()
        for i, byte in enumerate(data):
            unpermuted = ((byte << 5) | (byte >> 3)) & 0xFF
            xor_result = unpermuted ^ pattern[i]
            reversed_data.append(xor_result)
        return bytes(reversed_data)
        
    def encrypt(self, message: str, password: str) -> Tuple[str, str]:
        salt = secrets.token_bytes(16)
        key = self._generate_key(password, salt)
        message_bytes = message.encode('utf-8')
        encrypted_data = self._custom_transform(message_bytes, key)
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        return encoded_data, base64.b64encode(salt).decode('utf-8')
        
    def decrypt(self, encrypted_message: str, salt: str, password: str) -> str:
        salt_bytes = base64.b64decode(salt.encode('utf-8'))
        key = self._generate_key(password, salt_bytes)
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted_data = self._reverse_transform(encrypted_data, key)
        return decrypted_data.decode('utf-8')

if __name__ == "__main__":
    encryptor = NovelEncryption()
    
    # Prompt user to choose between encrypt or decrypt
    choice = input("Encrypt or Decrypt? (e/d): ").strip().lower()
    
    if choice == 'e':
        # Encrypt mode
        message = input("Enter the message to encrypt: ")
        password = input("Enter the password: ")
        
        print("\nOriginal message:", message)
        print("Password:", password)
        
        encrypted_msg, salt = encryptor.encrypt(message, password)
        print("\nEncrypted message:", encrypted_msg)
        print("Salt used:", salt)
        
        # Save to a file in the same directory
        with open('encrypted_message.txt', 'w') as f:
            f.write(f"Encrypted Message: {encrypted_msg}\nSalt: {salt}")
        
        print("\nEncrypted message saved to 'encrypted_message.txt'")
    
    elif choice == 'd':
        # Decrypt mode
        try:
            # Read encrypted message and salt from file
            with open('encrypted_message.txt', 'r') as f:
                lines = f.readlines()
                encrypted_msg = lines[0].split(": ")[1].strip()
                salt = lines[1].split(": ")[1].strip()
        
            password = input("Enter the password to decrypt: ")
            
            # Decrypt the message
            decrypted_msg = encryptor.decrypt(encrypted_msg, salt, password)
            print("\nDecrypted message:", decrypted_msg)
            print("Decryption successful:", "Yes" if decrypted_msg else "No")
        
        except FileNotFoundError:
            print("Error: 'encrypted_message.txt' not found. Please encrypt first.")
        except Exception as e:
            print("An error occurred during decryption:", str(e))
    else:
        print("Invalid choice. Please enter 'e' for encrypt or 'd' for decrypt.")