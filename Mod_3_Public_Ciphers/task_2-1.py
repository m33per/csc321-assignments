import math
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random

# public parameters
q = int.from_bytes(bytes.fromhex('''B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
                9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
                13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
                98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
                A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
                DF1FB2BC 2E4A4371'''))
g = int.from_bytes(bytes.fromhex('''A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
                D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
                160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
                909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
                D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
                855E6EEB 22B3B2E5'''))

print("\nMITM Key Fixing Attack (IETF 1024-bit parameters)")
print("----------------------------------------------")

# Alice's info
xa = random.randint(1, q - 1)
ya = pow(g, xa, q)

# Bob's info
xb = random.randint(1, q - 1)
yb = pow(g, xb, q)

# Mallory's attack
ya_modified = q
yb_modified = q

# compute secrets
sa = pow(yb_modified, xa, q)
sb = pow(ya_modified, xb, q)
sm = pow(q, random.randint(1, q - 1), q)

# compute key
ka = bytes(bytearray((hashlib.sha256((sa).to_bytes(math.ceil(sa.bit_length() / 8)))).digest())[:16])
kb = bytes(bytearray((hashlib.sha256((sb).to_bytes(math.ceil(sb.bit_length() / 8)))).digest())[:16])
km = bytes(bytearray((hashlib.sha256((sm).to_bytes(math.ceil(sm.bit_length() / 8)))).digest())[:16])

# print info
print(f"Alice's private key (XA): {xa}")
print(f"\nAlice's public key (YA): {ya}")
print(f"\nBob's private key (XB): {xb}")
print(f"\nBob's public key (YB): {yb}")
print("\nMallory intercepts and modfies the public keys:")
print(f"\nModified YA (sent to Bob): {ya_modified}")
print(f"\nModified YB (sent to Alice): {yb_modified}")

print(f"\nAlices's computed shared secret: {sa}")
print(f"Bob's computed shared secret: {sb}")
print(f"Alice's derived key: {ka.hex()}")
print(f"Bob's derived key: {kb.hex()}")

print(f"\nMallory's derived key: {km.hex()}")
print(f"Mallory determines the shared secret (s): {sm}")
print(f"All parties have the same key: {ka == kb and kb == km}")

# padding function
def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

# Alice encrypts and sends message
ma = b"Hi Bob!"
iv_alice = os.urandom(16)
cipher = AES.new(ka, AES.MODE_CBC, iv_alice)
c0 = cipher.encrypt(pad(ma))

# Mallory intercepts message
cipher = AES.new(km, AES.MODE_CBC, iv_alice)
ma_int = cipher.decrypt(c0)

# Bob decrypts message
cipher = AES.new(kb, AES.MODE_CBC, iv_alice)
mb = cipher.decrypt(c0)

# print results
print(f"\nAlice's message: {ma.decode()}")
print(f"Alice's IV: {iv_alice.hex()}")
print(f"Alice's ciphertext: {c0.hex()}")
print(f"Mallory's decrypts c0: {ma_int.decode()}")

# Bob encrypts and sends message
mb = b"Hi Alice!"
iv_bob = os.urandom(16)
cipher = AES.new(kb, AES.MODE_CBC, iv_bob)
c1 = cipher.encrypt(pad(mb))

# Mallory intercepts message
cipher = AES.new(km, AES.MODE_CBC, iv_bob)
mb_int = cipher.decrypt(c1)

# Alice decrypts message
cipher = AES.new(ka, AES.MODE_CBC, iv_bob)
ma = cipher.decrypt(c1)

# print results
print(f"\nBob's message: {mb.decode()}")
print(f"Bob's IV: {iv_bob.hex()}")
print(f"Bob's ciphertext: {c1.hex()}")
print(f"Mallory decrypts c1: {ma_int.decode()}")