import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureFileExchange:
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_keypair(self):
        """Generate RSA key pair for Bob"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_public_key(self, public_key, filename="public.pem"):
        """Save public key to file"""
        with open(filename, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"Public key saved to {filename}")
    
    def save_private_key(self, private_key, filename="private.pem"):
        """Save private key to file"""
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"Private key saved to {filename}")
    
    def load_public_key(self, filename="public.pem"):
        """Load public key from file"""
        with open(filename, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=self.backend
            )
        return public_key
    
    def load_private_key(self, filename="private.pem"):
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
    
    def generate_iv(self):
        """Generate random IV for AES"""
        return os.urandom(16)  # 128 bits for CBC mode
    
    def compute_sha256_hash(self, data):
        """Compute SHA-256 hash of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    def encrypt_file_aes(self, input_file, output_file, aes_key, iv):
        """Encrypt file using AES-256 in CBC mode"""
        # Read plaintext file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # PKCS7 padding
        pad_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([pad_length] * pad_length)
        
        # Encrypt
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Write IV + ciphertext to output file
        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext)
        
        print(f"File encrypted and saved to {output_file}")
        return plaintext  # Return original for hash comparison
    
    def decrypt_file_aes(self, input_file, output_file, aes_key):
        """Decrypt file using AES-256"""
        # Read encrypted file
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher and decrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        pad_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_length]
        
        # Write decrypted file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"File decrypted and saved to {output_file}")
        return plaintext
    
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

def bob_setup():
    """Bob generates RSA key pair"""
    exchange = SecureFileExchange()
    
    print("Bob: Generating RSA key pair...")
    private_key, public_key = exchange.generate_rsa_keypair()
    
    # Save keys
    exchange.save_private_key(private_key, "private.pem")
    exchange.save_public_key(public_key, "public.pem")
    
    print("Bob: Key generation complete.")
    return exchange, private_key

def alice_encrypt_file():
    """Alice encrypts file for Bob"""
    exchange = SecureFileExchange()
    
    # Load Bob's public key
    print("Alice: Loading Bob's public key...")
    public_key = exchange.load_public_key("public.pem")
    
    # Read the message file
    input_file = "alice_message.txt"
    with open(input_file, "r") as f:
        original_message = f.read()
    
    print(f"Alice: Original message: {original_message}")
    
    # Compute original hash
    original_hash = exchange.compute_sha256_hash(original_message)
    print(f"Alice: Original SHA-256 hash: {original_hash}")
    
    # Generate AES key and IV
    print("Alice: Generating AES-256 key and IV...")
    aes_key = exchange.generate_aes_key()
    iv = exchange.generate_iv()
    
    print(f"Alice: AES Key (hex): {aes_key.hex()}")
    print(f"Alice: IV (hex): {iv.hex()}")
    
    # Encrypt file with AES
    print("Alice: Encrypting file with AES...")
    original_data = exchange.encrypt_file_aes(input_file, "encrypted_file.bin", aes_key, iv)
    
    # Encrypt AES key with RSA
    print("Alice: Encrypting AES key with RSA...")
    encrypted_aes_key = exchange.encrypt_aes_key_rsa(aes_key, public_key)
    
    # Save encrypted AES key
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)
    
    print("Alice: Encryption complete. Files saved:")
    print("  - encrypted_file.bin")
    print("  - aes_key_encrypted.bin")
    
    return original_data, original_hash, aes_key, iv

def bob_decrypt_file():
    """Bob decrypts the file from Alice"""
    exchange = SecureFileExchange()
    
    # Load private key
    print("Bob: Loading private key...")
    private_key = exchange.load_private_key("private.pem")
    
    # Load encrypted files
    print("Bob: Loading encrypted files...")
    with open("aes_key_encrypted.bin", "rb") as f:
        encrypted_aes_key = f.read()
    
    # Decrypt AES key with RSA private key
    print("Bob: Decrypting AES key with RSA private key...")
    aes_key = exchange.decrypt_aes_key_rsa(encrypted_aes_key, private_key)
    print(f"Bob: Decrypted AES Key (hex): {aes_key.hex()}")
    
    # Decrypt file with AES key
    print("Bob: Decrypting file with AES key...")
    decrypted_data = exchange.decrypt_file_aes("encrypted_file.bin", "decrypted_message.txt", aes_key)
    
    # Compute hash of decrypted file
    decrypted_hash = exchange.compute_sha256_hash(decrypted_data)
    print(f"Bob: Decrypted SHA-256 hash: {decrypted_hash}")
    
    # Read the decrypted message for display
    with open("decrypted_message.txt", "r") as f:
        decrypted_message = f.read()
    
    print(f"Bob: Decrypted message: {decrypted_message}")
    print("Bob: Decryption complete.")
    
    return decrypted_data, decrypted_hash

def main():
    """Main function to demonstrate the complete secure file exchange"""
    print("=== Secure File Exchange Using RSA + AES ===\n")
    
    # Step 1: Bob setup
    print("STEP 1: Bob generates RSA key pair")
    bob_setup()
    print()
    
    # Step 2: Create Alice's message file
    print("STEP 2: Creating Alice's message file")
    sample_message = "This is Alice's confidential file content that needs secure transmission to Bob!"
    with open("alice_message.txt", "w") as f:
        f.write(sample_message)
    print(f"Alice's message saved to alice_message.txt: {sample_message}")
    print()
    
    # Step 3: Alice encrypts file
    print("STEP 3: Alice encrypts the file for Bob")
    original_data, original_hash, aes_key, iv = alice_encrypt_file()
    print()
    
    # Step 4: Bob decrypts file
    print("STEP 4: Bob decrypts the file from Alice")
    decrypted_data, decrypted_hash = bob_decrypt_file()
    print()
    
    # Integrity verification
    print("=== INTEGRITY VERIFICATION ===")
    print(f"Original SHA-256 hash:    {original_hash}")
    print(f"Decrypted SHA-256 hash:   {decrypted_hash}")
    
    if original_hash == decrypted_hash:
        print("✓ SUCCESS: Hashes match! File integrity verified.")
    else:
        print("✗ FAILURE: Hashes don't match! File may be corrupted or tampered with.")

if __name__ == "__main__":
    main()