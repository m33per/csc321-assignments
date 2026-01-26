import hashlib
import os
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Helper Functions
def extended_gcd(a, b):
    if a == 0: 
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1: 
        raise Exception('Inverse does not exist')
    return x % phi

# Task 3 Part 1: RSA Implementation 
print("Testing RSA Implementation\n")

# Generate RSA key pair
p = getPrime(1024)
q = getPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = mod_inverse(e, phi)

print(f"Generated RSA key pair. n has {n.bit_length()} bits.\n")

test_messages = [
    "Hello, World!",
    "CSC 321",
    "Cryptography is fun",
    "Test message"
]

for msg in test_messages:
    print(f"Original message: {msg}")
    
    # Convert message to integer
    m = bytes_to_long(msg.encode())
    assert m < n, "Message must be less than n"
    
    # Encrypt
    c = pow(m, e, n)
    print(f"Encrypted (integer):")
    print(c)
    
    # Decrypt
    m_decrypted = pow(c, d, n)
    msg_decrypted = long_to_bytes(m_decrypted).decode()
    print(f"Decrypted: {msg_decrypted}\n")

print("All valid messages were successfully encrypted and decrypted.")

# Task 3 Part 2a
print("\nDemonstrating RSA Encryption Malleability\n")

# Alice generates symmetric key
s_alice = bytes_to_long(os.urandom(16))
print(f"\nAlice's original symmetric key (s): {s_alice}")

# Alice encrypts symmetric key with RSA
c = pow(s_alice, e, n)
print(f"\nEncrypted symmetric key (c):")
print(c)

# Attack Method 1: Multiply by an encrypted factor
r = 2
c_prime = (c * pow(r, e, n)) % n

print(f"\nMallory's modified ciphertext (c'):")
print(c_prime)

# Bob decrypts c'
s_prime = pow(c_prime, d, n)

print(f"\nBob's decrypted value (s'): {s_prime}")

# Mallory recovers original s
s_recovered = (s_prime * mod_inverse(r, n)) % n

print(f"\nMallory's recovered symmetric key: {s_recovered}")
print(f"Attack successful: Mallory recovered the original symmetric key!")

# Alternative attack approach (mentioned in hints)
print("\nAlternative malleability attack approach:\n")
s_prime_chosen = s_alice * 2 
c_prime_alt = pow(s_prime_chosen, e, n)

print(f"Mallory's chosen s': {s_prime_chosen}")
print(f"Mallory's computed c':")
print(c_prime_alt)

s_prime_decrypted = pow(c_prime_alt, d, n)
print(f"\nValue Alice decrypts to: {s_prime_decrypted}")
print(f"Alternative attack successful: Alice decrypted to Mallory's chosen value!")

k = hashlib.sha256(long_to_bytes(s_recovered)).digest()[:16]

# Bob encrypts a message with the derived key
msg = "Secret message from Bob to Alice"
iv = os.urandom(16)
cipher = AES.new(k, AES.MODE_CBC, iv)
c0 = cipher.encrypt(pad(msg.encode(), 16))

print(f"\nBob's encrypted message (c0):")
print((iv + c0).hex())

# Mallory decrypts using the recovered key
cipher_mallory = AES.new(k, AES.MODE_CBC, iv)
decrypted = unpad(cipher_mallory.decrypt(c0), 16).decode()

print(f"\nMallory's decrypted message: {decrypted}")


# Task 3 Part 2b
print("\nDemonstrating RSA Signature Malleability\n")

m1 = 12345
m2 = 67890

print(f"\nOriginal message 1 (m1): {m1}")
print(f"Original message 2 (m2): {m2}")

s1 = pow(m1, d, n)
s2 = pow(m2, d, n)

print(f"\nSignature for m1:")
print(s1)

print(f"\nSignature for m2:")
print(s2)

print(f"\nVerifying original signatures:")
verify_s1 = (pow(s1, e, n) == m1)
verify_s2 = (pow(s2, e, n) == m2)
print(f"Signature 1 is valid: {verify_s1}")
print(f"Signature 2 is valid: {verify_s2}")

# Mallory creates forged signature for m3 = m1 * m2
m3 = (m1 * m2) % n
s3 = (s1 * s2) % n

print(f"\nMallory's new message (m3 = m1 * m2 mod n): {m3}")
print(f"\nMallory's forged signature for m3:")
print(s3)

verify_s3 = (pow(s3, e, n) == m3)

print(f"\nVerifying Mallory's forged signature:")
print(f"Signature 3 is valid: {verify_s3}")
print(f"\nAttack successful: Mallory created a valid signature for a new message!")
