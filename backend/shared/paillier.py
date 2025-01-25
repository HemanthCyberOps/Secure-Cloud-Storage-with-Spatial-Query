from phe import paillier, EncryptedNumber

# Generate Public & Private Key Pair
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_data(data):
    """Encrypt numeric data for homomorphic computation."""
    if isinstance(data, list):
        return [public_key.encrypt(value) for value in data]
    return public_key.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt numeric data."""
    if isinstance(encrypted_data, list):
        return [private_key.decrypt(value) for value in encrypted_data]
    return private_key.decrypt(encrypted_data)

def homomorphic_addition(enc_num1, enc_num2):
    """Perform homomorphic addition of two encrypted numbers."""
    if not isinstance(enc_num1, EncryptedNumber) or not isinstance(enc_num2, EncryptedNumber):
        raise TypeError("Both inputs must be EncryptedNumber instances.")
    return enc_num1 + enc_num2

def homomorphic_multiplication(enc_num, scalar):
    """Perform homomorphic scalar multiplication."""
    if not isinstance(enc_num, EncryptedNumber):
        raise TypeError("First input must be an EncryptedNumber instance.")
    if not isinstance(scalar, (int, float)):
        raise TypeError("Scalar must be an integer or float.")
    return enc_num * scalar
