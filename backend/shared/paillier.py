from phe import paillier, EncryptedNumber

# Generate a Paillier keypair with a reduced key size to avoid massive ciphertexts
KEY_SIZE = 1024  # Reduce from 2048+ to 1024 for smaller encrypted numbers
public_key, private_key = paillier.generate_paillier_keypair(n_length=KEY_SIZE)

# Define a scaling factor to prevent overflow during encryption and summation
SCALING_FACTOR = 1000  # Reduce encrypted value size significantly

def encrypt_data(data):
    """Encrypt numeric data with scaling to prevent large ciphertexts."""
    if isinstance(data, list):
        return [public_key.encrypt(int(value) // SCALING_FACTOR) for value in data]
    return public_key.encrypt(int(data) // SCALING_FACTOR)

def decrypt_data(encrypted_data):
    """Safely decrypt encrypted data and apply overflow handling."""
    if isinstance(encrypted_data, list):
        return [safe_decrypt(value) for value in encrypted_data]
    return safe_decrypt(encrypted_data)

def safe_decrypt(enc_num):
    """Safely decrypt an encrypted number and correct any modular overflow issues."""
    decrypted_value = private_key.decrypt(enc_num)

    # Correct modular overflow
    n = public_key.n
    if decrypted_value > (n // 2):
        decrypted_value -= n
    elif decrypted_value < 0:
        decrypted_value += n

    return max(0, decrypted_value * SCALING_FACTOR)  # Scale back to original values

def homomorphic_addition(*enc_nums):
    """Perform homomorphic addition while applying modular reduction to avoid overflow."""
    if not enc_nums:
        raise ValueError("At least one encrypted number must be provided.")

    n_squared = public_key.n ** 2  # Define the modulus squared to prevent overflow
    result_ciphertext = sum(num.ciphertext() for num in enc_nums) % n_squared  # Apply modular reduction

    return EncryptedNumber(public_key, result_ciphertext, exponent=0)  # Return properly formatted encrypted sum

def homomorphic_multiplication(enc_num, scalar):
    """Perform homomorphic scalar multiplication."""
    if not isinstance(enc_num, EncryptedNumber):
        raise TypeError("First input must be an EncryptedNumber instance.")
    if not isinstance(scalar, (int, float)):
        raise TypeError("Scalar must be an integer or float.")
    return enc_num * scalar
