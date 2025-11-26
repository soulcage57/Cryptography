# Secure File Exchange Using RSA + AES

## Overview
This project demonstrates a secure file exchange protocol using hybrid encryption (RSA + AES) with integrity verification via SHA-256 hashing.

## Encryption/Decryption Flow

### Step 1: Key Generation (Bob)
- Bob generates an RSA-2048 key pair
- Saves public key as `public.pem` (shared with Alice)
- Saves private key as `private.pem` (kept secret)

### Step 2: File Preparation (Alice)
- Creates plaintext file `alice_message.txt`
- Computes SHA-256 hash for integrity verification

### Step 3: Encryption (Alice)
1. **AES Encryption**:
   - Generates random 256-bit AES key
   - Generates random 128-bit IV for CBC mode
   - Encrypts file using AES-256-CBC with PKCS7 padding
   - Saves IV + ciphertext to `encrypted_file.bin`

2. **Key Encryption**:
   - Encrypts AES key using Bob's RSA public key with OAEP padding
   - Saves encrypted key to `aes_key_encrypted.bin`

### Step 4: Decryption (Bob)
1. **Key Decryption**:
   - Decrypts AES key using RSA private key with OAEP padding
   - Recovers original AES key

2. **File Decryption**:
   - Extracts IV from encrypted file
   - Decrypts file using AES-256-CBC
   - Removes PKCS7 padding
   - Saves decrypted content to `decrypted_message.txt`

### Step 5: Integrity Verification
- Computes SHA-256 hash of decrypted file
- Compares with original hash to verify integrity

## File Descriptions

- `alice_message.txt` - Original plaintext file
- `encrypted_file.bin` - AES-encrypted file (IV + ciphertext)
- `aes_key_encrypted.bin` - RSA-encrypted AES key
- `decrypted_message.txt` - Decrypted plaintext file
- `public.pem` - Bob's RSA public key
- `private.pem` - Bob's RSA private key

## AES vs RSA Comparison

| Aspect | AES (Advanced Encryption Standard) | RSA (Rivest-Shamir-Adleman) |
|--------|-----------------------------------|-----------------------------|
| **Type** | Symmetric Encryption | Asymmetric Encryption |
| **Key Management** | Single shared key | Public/Private key pair |
| **Speed** | Very fast (optimized for hardware) | Slow (mathematical operations) |
| **Use Case** | Bulk data encryption | Key exchange, digital signatures |
| **Key Size** | 128, 192, or 256 bits | Typically 2048+ bits |
| **Security** | Based on substitution-permutation network | Based on integer factorization problem |
| **Performance** | Encrypts MB/s to GB/s | Encrypts KB/s |

## Why Hybrid Encryption?

### Advantages:
1. **Efficiency**: AES handles large files quickly
2. **Security**: RSA provides secure key exchange
3. **Perfect Combination**: Best of both cryptographic worlds

### Security Features:
- **AES-256**: Military-grade symmetric encryption
- **RSA-2048**: Secure key exchange with OAEP padding
- **CBC Mode**: Provides confidentiality with chaining
- **SHA-256**: Integrity verification
- **Random IV**: Prevents pattern analysis