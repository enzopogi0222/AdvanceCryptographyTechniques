"""
Basic Homomorphic Encryption Demo using Paillier
"""

from phe import paillier

# Step 1: Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

# Step 2: Encrypt some numbers
num1 = 10
num2 = 20

enc_num1 = public_key.encrypt(num1)
enc_num2 = public_key.encrypt(num2)

print("Encrypted num1:", enc_num1.ciphertext())
print("Encrypted num2:", enc_num2.ciphertext())

# Step 3: Perform computations on encrypted data
# Paillier supports addition of encrypted numbers
enc_sum = enc_num1 + enc_num2  # Homomorphic addition
enc_double = enc_num1 * 2      # Homomorphic multiplication by a constant

# Step 4: Decrypt results
dec_sum = private_key.decrypt(enc_sum)
dec_double = private_key.decrypt(enc_double)

# Step 5: Display results
print("\nOriginal numbers:", num1, num2)
print("Sum (decrypted):", dec_sum)
print("Double num1 (decrypted):", dec_double)
