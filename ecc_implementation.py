import time
from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

"""
SAMPLE DATA
"""

data = b"This is a secret message for encryption testing." * 10000

"""
AES-GCM FUNCTIONS
"""
def aes_gcm_encrypt(data):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, cipher.nonce, ciphertext, tag

def aes_gcm_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted

"""
CHACHA20 FUNCTIONS
"""
def chacha20_encrypt(data):
    key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(data)
    return key, cipher.nonce, ciphertext

def chacha20_decrypt(key, nonce, ciphertext):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

"""
ECC + AES FUNCTIONS
"""
def ecc_aes_encrypt(data):

    private_key =ECC.generate(curve='P-256')
    public_key = private_key.public_key()

    shared_secret = private_key.d.to_bytes(32, 'big')
    key = shared_secret

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return private_key, public_key, key, cipher.nonce, ciphertext, tag

def ecc_aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted

"""
PERFORMANCE TESTS
"""

print("Testing AES-GCM...")
start = time.time()
key, nonce, ciphertext, tag = aes_gcm_encrypt(data)
aes_decrypted = aes_gcm_decrypt(key, nonce, ciphertext, tag)
end = time.time()
aes_time = end - start
print("AES-GCM Time:", aes_time, "seconds")

print("\nTesting ChaCha20...")
start = time.time()
key2, nonce2, ciphertext2 = chacha20_encrypt(data)
chacha_decrypted = chacha20_decrypt(key2, nonce2, ciphertext2)
end = time.time()
chacha_time = end - start
print("ChaCha20 Time:", chacha_time, "seconds")

print("\nTesting ECC + AES...")
start = time.time()
priv, pub, ecc_key, ecc_nonce, ecc_ciphertext, ecc_tag = ecc_aes_encrypt(data)
ecc_decrypted = ecc_aes_decrypt(ecc_key, ecc_nonce, ecc_ciphertext, ecc_tag)
end = time.time()
ecc_time = end - start
print("ECC + AES Time: ", ecc_time, "seconds")

"""
VERIFICATION
"""
print("\nVerification:")
print("AES Correct:", aes_decrypted == data)
print("ChaCha Correct:", chacha_decrypted == data)
print("ECC + AES Correct:", ecc_decrypted == data)