import os
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

class EncryptedMessagingApp:
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_keypair(self):
        """Generate RSA key pair for User A"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_public_key(self, public_key, filename="public_key.pem"):
        """Save public key to file"""
        with open(filename, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"Public key saved to {filename}")
    
    def load_public_key(self, filename="public_key.pem"):
        """Load public key from file"""
        with open(filename, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=self.backend
            )
        return public_key
    
    def save_private_key(self, private_key, filename="private_key.pem"):
        """Save private key to file"""
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"Private key saved to {filename}")
    
    def load_private_key(self, filename="private_key.pem"):
        """Load private key from file"""
        with open(filename, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=self.backend
            )
        return private_key
    
    def generate_aes_key(self):
        """Generate random AES-256 key"""
        return os.urandom(32)  # 256 bits
    
    def encrypt_message_aes(self, message, aes_key):
        """Encrypt message using AES-256 in GCM mode"""
        # Generate random IV
        iv = os.urandom(12)  # 96 bits for GCM
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Encrypt the message
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Return IV + tag + ciphertext
        return iv + encryptor.tag + ciphertext
    
    def decrypt_message_aes(self, encrypted_data, aes_key):
        """Decrypt message using AES-256"""
        # Extract components
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # Create cipher and decrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message.decode()
    
    def encrypt_aes_key_rsa(self, aes_key, public_key):
        """Encrypt AES key using RSA public key"""
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key
    
    def decrypt_aes_key_rsa(self, encrypted_aes_key, private_key):
        """Decrypt AES key using RSA private key"""
        decrypted_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key

def user_a_setup():
    """User A generates RSA key pair and shares public key"""
    app = EncryptedMessagingApp()
    
    print("User A: Generating RSA key pair...")
    private_key, public_key = app.generate_rsa_keypair()
    
    # Save keys
    app.save_private_key(private_key, "private_key.pem")
    app.save_public_key(public_key, "public_key.pem")
    
    print("User A: Key generation complete. Public key shared with User B.")
    return app, private_key

def user_b_encrypt_message():
    """User B encrypts message using AES and encrypts AES key with RSA"""
    app = EncryptedMessagingApp()
    
    # Load User A's public key
    print("User B: Loading User A's public key...")
    public_key = app.load_public_key("public_key.pem")
    
    # Read the message to encrypt
    with open("message.txt", "r") as f:
        message = f.read()
    
    print(f"User B: Original message: {message}")
    
    # Generate AES key
    print("User B: Generating AES-256 key...")
    aes_key = app.generate_aes_key()
    print(f"User B: AES Key (hex): {aes_key.hex()}")
    
    # Encrypt message with AES
    print("User B: Encrypting message with AES...")
    encrypted_message = app.encrypt_message_aes(message, aes_key)
    
    # Encrypt AES key with RSA
    print("User B: Encrypting AES key with RSA...")
    encrypted_aes_key = app.encrypt_aes_key_rsa(aes_key, public_key)
    
    # Save encrypted files
    with open("encrypted_message.bin", "wb") as f:
        f.write(encrypted_message)
    
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)
    
    print("User B: Encryption complete. Files saved:")
    print("  - encrypted_message.bin")
    print("  - aes_key_encrypted.bin")
    
    return encrypted_message, encrypted_aes_key

def user_a_decrypt_message():
    """User A decrypts the message"""
    app = EncryptedMessagingApp()
    
    # Load private key
    print("User A: Loading private key...")
    private_key = app.load_private_key("private_key.pem")
    
    # Load encrypted files
    print("User A: Loading encrypted files...")
    with open("encrypted_message.bin", "rb") as f:
        encrypted_message = f.read()
    
    with open("aes_key_encrypted.bin", "rb") as f:
        encrypted_aes_key = f.read()
    
    # Decrypt AES key with RSA private key
    print("User A: Decrypting AES key with RSA private key...")
    aes_key = app.decrypt_aes_key_rsa(encrypted_aes_key, private_key)
    print(f"User A: Decrypted AES Key (hex): {aes_key.hex()}")
    
    # Decrypt message with AES key
    print("User A: Decrypting message with AES key...")
    decrypted_message = app.decrypt_message_aes(encrypted_message, aes_key)
    
    # Save decrypted message
    with open("decrypted_message.txt", "w") as f:
        f.write(decrypted_message)
    
    print(f"User A: Decrypted message: {decrypted_message}")
    print("User A: Decryption complete. File saved: decrypted_message.txt")
    
    return decrypted_message

def main():
    """Main function to demonstrate the complete flow"""
    print("=== Encrypted Messaging App Prototype ===\n")
    
    # Step 1: User A setup
    print("STEP 1: User A generates RSA key pair")
    user_a_setup()
    print()
    
    # Step 2: Create sample message
    print("STEP 2: Creating sample message")
    sample_message = "This is a secret message that needs to be encrypted securely!"
    with open("message.txt", "w") as f:
        f.write(sample_message)
    print(f"Sample message saved to message.txt: {sample_message}")
    print()
    
    # Step 3: User B encrypts message
    print("STEP 3: User B encrypts the message")
    user_b_encrypt_message()
    print()
    
    # Step 4: User A decrypts message
    print("STEP 4: User A decrypts the message")
    user_a_decrypt_message()
    print()
    
    # Verification
    print("=== VERIFICATION ===")
    with open("message.txt", "r") as f:
        original = f.read()
    with open("decrypted_message.txt", "r") as f:
        decrypted = f.read()
    
    if original == decrypted:
        print("✓ SUCCESS: Original and decrypted messages match!")
    else:
        print("✗ FAILURE: Messages don't match!")

if __name__ == "__main__":
    main()