import math
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random

# padding function
def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

def attack(q, g):
    if g == 1:
        print("\nMITM Generator Attack (alpha = 1)")
    else:
        print(f"\nMITM Generator Attack (alpha = \n{g})")
    print("----------------------------------------------")

    # Alice's info
    xa = random.randint(1, q - 1)
    ya = pow(g, xa, q)

    # Bob's info
    xb = random.randint(1, q - 1)
    yb = pow(g, xb, q)

    # print info
    print(f"Mallory tampers with the generator: alpha = {g}")
    print(f"\nAlice's private key (XA): {xa}")
    print(f"\nAlice's public key (YA): {ya}")
    print(f"\nBob's private key (XB): {xb}")
    print(f"\nBob's public key (YB): {yb}")

    # compute secrets
    sa = pow(yb, xa, q)
    sb = pow(ya, xb, q)
    sm = 1
    if g == q:
        sm = 0

    # compute key
    ka = bytes(bytearray((hashlib.sha256((sa).to_bytes(math.ceil(sa.bit_length() / 8)))).digest())[:16])
    kb = bytes(bytearray((hashlib.sha256((sb).to_bytes(math.ceil(sb.bit_length() / 8)))).digest())[:16])
    km = bytes(bytearray((hashlib.sha256((sm).to_bytes(math.ceil(sm.bit_length() / 8)))).digest())[:16])

    print(f"\nAlices's computed shared secret: {sa}")
    print(f"Bob's computed shared secret: {sb}")
    print(f"Alice's derived key: {ka.hex()}")
    print(f"Bob's derived key: {kb.hex()}")

    if g == 1:
        print(f"\nCase: alpha = 1")
        print(f"Mallory knows the shared secret will always be 1")
        print(f"Mallory determines the possible shared secret (s): {sm}")
        print(f"Mallory's derived key: {km.hex()}")
    elif g == q:
        print(f"\nCase: alpha = q")
        print(f"Mallory knows the shared secret will always be 0")
        print(f"Mallory determines the possible shared secret (s): {sm}")
        print(f"Mallory's derived key: {km.hex()}")
    else:
        print(f"\nCase: alpha = q - 1")
        print(f"Mallory knows the shared secret will be either 1 or q - 1")
        print(f"Mallory determines the possible shared secret (s): {sm}")
        print(f"Mallory's derived key: {km.hex()}")

    # Alice encrypts and sends message
    ma = b"Hi Bob!"
    iv_alice = os.urandom(16)
    cipher = AES.new(ka, AES.MODE_CBC, iv_alice)
    c0 = cipher.encrypt(pad(ma))

    # print results
    print(f"\nAlice's message (m0): {ma.decode()}")
    print(f"Alice's ciphertext (c0): {c0.hex()}")

    # Bob encrypts and sends message
    mb = b"Hi Alice!"
    iv_bob = os.urandom(16)
    cipher = AES.new(kb, AES.MODE_CBC, iv_bob)
    c1 = cipher.encrypt(pad(mb))

    # print results
    print(f"\nBob's message (m1): {mb.decode()}")
    print(f"Bob's ciphertext (c1): {c1.hex()}")

    # Mallory decrypts messages
    cipher = AES.new(km, AES.MODE_CBC, iv_alice)
    ma_int = cipher.decrypt(c0)
    cipher = AES.new(km, AES.MODE_CBC, iv_bob)
    mb_int = cipher.decrypt(c1)

    # print results
    print(f"\nMallory successfully decrypts c0: {ma_int.decode(errors='ignore')}")
    print(f"Mallory successfully decrypts c1: {mb_int.decode(errors='ignore')}\n")

    if g == q - 1:
        sm = q - 1
        km = bytes(bytearray((hashlib.sha256((sm).to_bytes(math.ceil(sm.bit_length() / 8)))).digest())[:16])
        print(f"Mallory determines the other possible shared secret (s): {sm}")
        print(f"Mallory's derived key: {km.hex()}")

        # Mallory decrypts messages
        cipher = AES.new(km, AES.MODE_CBC, iv_alice)
        ma_int = cipher.decrypt(c0)
        cipher = AES.new(km, AES.MODE_CBC, iv_bob)
        mb_int = cipher.decrypt(c1)

        # print results
        print(f"\nMallory decrypts c0: {ma_int.decode(errors='ignore')}")
        print(f"Mallory decrypts c1: {mb_int.decode(errors='ignore')}\n")


def __main__():
    # q param
    q = int.from_bytes(bytes.fromhex('''B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
                    9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
                    13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
                    98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
                    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
                    DF1FB2BC 2E4A4371'''))
    
    # do the three attacks
    attack(q, 1)
    attack(q, q)
    attack(q, q-1)

if __name__ == "__main__":
    __main__()