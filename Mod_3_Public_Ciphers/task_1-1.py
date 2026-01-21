import os
from Crypto.Cipher import AES
import hashlib

# public parameters
q = 37
g = 5

print("\nDiffie-Hellman Protocol (q = 37, g = 5)")
print("----------------------------------------------")

# Alice's info
xa = 8
ya = pow(g, xa, q)

# Bob's info
xb = 15
yb = pow(g, xb, q)

# compute secrets
sa = pow(yb, xa, q)
sb = pow(ya, xb, q)

# compute key
ka = bytes(bytearray((hashlib.sha256((sa).to_bytes(16, "big"))).digest())[:16])
kb = bytes(bytearray((hashlib.sha256((sb).to_bytes(16, "big"))).digest())[:16])

# print info
print(f"Alice's private key (XA): {xa}")
print(f"Alice's public key (YA): {ya}")
print(f"Bob's private key (XB): {xb}")
print(f"Bob's public key (YB): {yb}")
print(f"Alices's computed shared secret: {sa}")
print(f"Bob's computed shared secret: {sb}")
print(f"Alice's derived key: {ka.hex()}")
print(f"Bob's derived key: {kb.hex()}")
print(f"Alice and Bob have the same key: {ka == kb}")

# padding function
def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

# Alice encrypts and sends message
ma = b"Hi Bob!"
iv_a = os.urandom(16)
cipher = AES.new(ka, AES.MODE_CBC, iv_a)
c0 = cipher.encrypt(pad(ma))

# Bob decrypts message
cipher = AES.new(kb, AES.MODE_CBC, iv_a)
mb = cipher.decrypt(c0)

# print results
print(f"\nAlice's message: {ma.decode()}")
print(f"Alice's IV: {iv_a.hex()}")
print(f"Alice's ciphertext: {c0.hex()}")
print(f"Bob's decrypted message: {mb.decode()}")

# Bob encrypts and sends message
mb = b"Hi Alice!"
iv_b = os.urandom(16)
cipher = AES.new(kb, AES.MODE_CBC, iv_b)
c1 = cipher.encrypt(pad(mb))

# Alice decrypts message
cipher = AES.new(ka, AES.MODE_CBC, iv_b)
ma = cipher.decrypt(c1)

# print results
print(f"\nBob's message: {mb.decode()}")
print(f"Bob's IV: {iv_b.hex()}")
print(f"Bob's ciphertext: {c1.hex()}")
print(f"Alice's decrypted message: {ma.decode()}")