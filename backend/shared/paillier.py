from phe import paillier, EncryptedNumber

# Generate Public & Private Key Pair
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_data(data):
    """Encrypt numeric data for homomorphic computation."""
    return [public_key.encrypt(value) for value in data]

def decrypt_data(encrypted_data):
    """Decrypt numeric data."""
    return [private_key.decrypt(value) for value in encrypted_data]

def homomorphic_addition(enc_num1, enc_num2):
    """Perform homomorphic addition of two encrypted numbers."""
    return enc_num1 + enc_num2

def homomorphic_multiplication(enc_num, scalar):
    """Perform homomorphic scalar multiplication."""
    return enc_num * scalar
