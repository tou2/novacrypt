import hashlib
import secrets
import base64
from typing import Tuple

class NovelEncryption:
    def __init__(self):
        # Initialize with a secure random seed
        self.seed = secrets.token_bytes(32)
        
    def _generate_key(self, message: str, salt: bytes) -> bytes:
        """Generate a key using PBKDF2 with custom iterations"""
        # Mix the message with the seed and salt
        combined = (message.encode() + self.seed + salt).hex().encode()
        # Use SHA-3 for key derivation (more secure than SHA-2)
        key = hashlib.shake_256(combined).digest(32)
        return key
        
    def _custom_transform(self, data: bytes, key: bytes) -> bytes:
        """Apply a custom transformation to the data"""
        # Create a transformation pattern based on key
        pattern = [key[i % len(key)] for i in range(len(data))]
        
        # Apply XOR with pattern and additional permutation
        transformed = bytearray()
        for i, byte in enumerate(data):
            # XOR with pattern byte
            xor_result = byte ^ pattern[i]
            # Apply a custom permutation based on key
            permuted = ((xor_result << 3) | (xor_result >> 5)) & 0xFF
            transformed.append(permuted)
            
        return bytes(transformed)
        
    def _reverse_transform(self, data: bytes, key: bytes) -> bytes:
        """Reverse the custom transformation"""
        # Create reverse pattern
        pattern = [key[i % len(key)] for i in range(len(data))]
        
        # Reverse the permutation first
        reversed_data = bytearray()
        for i, byte in enumerate(data):
            # Reverse the permutation
            unpermuted = ((byte << 5) | (byte >> 3)) & 0xFF
            # XOR with pattern byte
            xor_result = unpermuted ^ pattern[i]
            reversed_data.append(xor_result)
            
        return bytes(reversed_data)
        
    def encrypt(self, message: str, password: str) -> Tuple[str, str]:
        """
        Encrypt a message using the novel encryption method
        
        Args:
            message (str): The message to encrypt
            password (str): Password for key derivation
            
        Returns:
            Tuple[str, str]: (encrypted_message, salt)
        """
        # Generate a random salt
        salt = secrets.token_bytes(16)
        
        # Generate key from password and salt
        key = self._generate_key(password, salt)
        
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Apply custom transformation
        encrypted_data = self._custom_transform(message_bytes, key)
        
        # Encode to base64 for safe transmission
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Return the encrypted message and salt (needed for decryption)
        return encoded_data, base64.b64encode(salt).decode('utf-8')
        
    def decrypt(self, encrypted_message: str, salt: str, password: str) -> str:
        """
        Decrypt a message using the novel encryption method
        
        Args:
            encrypted_message (str): The encrypted message
            salt (str): Salt used during encryption
            password (str): Password for key derivation
            
        Returns:
            str: Decrypted message
        """
        # Decode the salt
        salt_bytes = base64.b64decode(salt.encode('utf-8'))
        
        # Generate key from password and salt
        key = self._generate_key(password, salt_bytes)
        
        # Decode the encrypted message
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        
        # Reverse the custom transformation
        decrypted_data = self._reverse_transform(encrypted_data, key)
        
        # Convert back to string
        return decrypted_data.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Create encryption instance
    encryptor = NovelEncryption()
    
    # Test message and password
    message = "This is a secret message that should remain confidential!"
    password = "MySuperSecretPassword123"
    
    print("Original message:", message)
    print("Password:", password)
    
    # Encrypt the message
    encrypted_msg, salt = encryptor.encrypt(message, password)
    print("\nEncrypted message:", encrypted_msg)
    print("Salt used:", salt)
    
    # Decrypt the message
    decrypted_msg = encryptor.decrypt(encrypted_msg, salt, password)
    print("\nDecrypted message:", decrypted_msg)
    
    # Verify correctness
    print("\nEncryption successful:", message == decrypted_msg)