"""
Simulated NTRU Post-Quantum Cryptography Demo
This script demonstrates a PQC key exchange using NTRU (simulated),
and then encrypts/decrypts a message using AES-GCM.
All comments use triple quotes.
"""

import os
from Crypto.Cipher import AES

"""
Step 1: Simulate NTRU Key Exchange
"""


alice_secret = os.urandom(32)  
bob_secret = alice_secret

"""
Step 2: Verify shared key equality
In a real PQC scenario, both parties should arrive at the same shared secret
"""
print("Shared secrets equal:", alice_secret == bob_secret)

"""
Step 3: Encrypt a message using AES-GCM with the shared NTRU key
"""

data = b"Message secured with simulated NTRU PQC"


cipher = AES.new(alice_secret, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(data)

"""
Step 4: Bob decrypts the message using the shared key
"""
cipher_dec = AES.new(bob_secret, AES.MODE_GCM, nonce=cipher.nonce)
decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)

"""
Step 5: Display results
"""
print("Original message:", data)
print("Encrypted (hex):", ciphertext.hex())
print("Decrypted message:", decrypted)
print("Decryption successful:", decrypted == data)
