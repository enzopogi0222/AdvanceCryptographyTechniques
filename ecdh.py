from Crypto.PublicKey import ECC
from Crypto.Cipher import AES

"""
ECDH KEY EXCHANGE DEMONSTRATION
"""

print("Testing ECDH Key Exchanges...")

alice_private = ECC.generate(curve='P-256')
alice_public = alice_private.public_key()

bob_private = ECC.generate(curve='P-256')
bob_public = bob_private.public_key()

def derive_shared_secret(private_key, other_public):
    shared_point = other_public.pointQ * private_key.d
    secret = int(shared_point.x).to_bytes(32, 'big')
    return secret

alice_secret = derive_shared_secret(alice_private, bob_public)
bob_secret = derive_shared_secret(bob_private, alice_private)

print("Shared secrets equal:", alice_secret == bob_secret)

data_ecdh = b"This is a message secured with ECDH"
cipher_ecdh = AES.new(alice_secret, AES.MODE_GCM)
ciphertext_ecdh, tag_ecdh = cipher_ecdh.encrypt_and_digest(data_ecdh)

cipher_dec_ecdh = AES.new(bob_secret, AES.MODE_GCM, nonce=cipher_ecdh.nonce)
decrypted_ecdh = cipher_dec_ecdh.decrypt_and_verify(ciphertext_ecdh, tag_ecdh)

print("Original:", data_ecdh)
print("Encrypted (hex):", ciphertext_ecdh.hex())
print("Decrypted:", decrypted_ecdh)
print("Decryption successful:", decrypted_ecdh == data_ecdh)