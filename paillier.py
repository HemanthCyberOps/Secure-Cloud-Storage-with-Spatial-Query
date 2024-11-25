from phe import paillier
from phe import paillier, EncryptedNumber

# Key generation
public_key, private_key = paillier.generate_paillier_keypair()


def encrypt_data(data):
    """Encrypt numeric data."""
    return [public_key.encrypt(value) for value in data]


def decrypt_data(encrypted_data):
    """Decrypt numeric data."""
    if not encrypted_data or not isinstance(encrypted_data, list):
        raise ValueError("Invalid input. Expected a list of encrypted data.")
    return [private_key.decrypt(value) for value in encrypted_data]



def homomorphic_addition(encrypted_values):
    """Perform addition on encrypted values."""
    result = encrypted_values[0]
    for value in encrypted_values[1:]:
        result += value
    return result
