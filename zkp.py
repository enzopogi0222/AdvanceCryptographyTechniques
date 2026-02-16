"""
Zero-Knowledge Proof Demo
Prover proves they know a secret number without revealing it
"""

import hashlib
import random

# Step 1: Prover chooses a secret
secret = 42  # This is the secret only the prover knows
r = random.randint(1, 100)  # Random number for commitment

# Step 2: Prover creates a commitment
commitment = hashlib.sha256(f"{secret}{r}".encode()).hexdigest()
print("Commitment sent to verifier:", commitment)

# Step 3: Verifier sends a random challenge (0 or 1)
challenge = random.randint(0, 1)
print("Verifier challenge:", challenge)

# Step 4: Prover responds based on challenge
if challenge == 0:
    # Reveal r to prove commitment
    response = r
else:
    # Reveal (secret + r) % 100 instead
    response = (secret + r) % 100

print("Prover response:", response)

# Step 5: Verifier checks if the response is consistent
# (In a real ZKP, multiple rounds increase confidence)
