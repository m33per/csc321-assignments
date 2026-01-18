from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import urllib.parse

def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

# Generate key and IV
key = get_random_bytes(16)
iv = get_random_bytes(16)

# encrypt data that is already padded
def encrypt_data(data, key, iv):
    # Encrypt the image data using cbc
    encrypted_data = b''
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    for i in range(0, len(data), 16):
        pi = data[i:i+16]
        pix = (int.from_bytes(pi, 'big') ^ int.from_bytes(prev, 'big')).to_bytes(16, 'big')
        ci = cipher.encrypt(pix)
        encrypted_data += ci
        prev = ci

    return encrypted_data


# decrypt data
def decrypt_data(data, key, iv):
    # Decrypt the data using cbc
    decrypted_data = b''
    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    for i in range(0, len(data) - 16, 16):
        ci = data[i:i+16]
        pix = cipher.decrypt(ci)
        pi = (int.from_bytes(pix, 'big') ^ int.from_bytes(prev, 'big')).to_bytes(16, 'big')
        decrypted_data += pi
        prev = ci
    # padding
    last_ci = data[-16:]
    last_pix = cipher.decrypt(last_ci)
    last_pi = (int.from_bytes(last_pix, 'big') ^ int.from_bytes(prev, 'big')).to_bytes(16, 'big')
    for i in range(0, 16 - last_pi[-1]):
        decrypted_data += last_pi[i].to_bytes()

    return decrypted_data


# insert user input into a string, URL encoding any ';' and '=' characters
def submit(str):
    semi = urllib.parse.quote(";")
    eq = urllib.parse.quote("=")
    str_new = ""
    for c in str:
        if c == ";":
            str_new += semi
        elif c == "=":
            str_new += eq
        else:
            str_new += c
    p1 = b"userid=456; userdata="
    p2 = b";session-id=31337"
    unpadded = p1 + str_new.encode() + p2
    padded = pad(unpadded)
    return encrypt_data(padded, key, iv)


def verify(str):
    plaintext = decrypt_data(str, key, iv)
    p_str = plaintext.decode(errors='ignore')
    if ";admin=true;" in p_str:
        return True
    return False
    
message = ";admin=true;"
ciphertext = submit(message)
print(f"verify with no bit flip: {verify(ciphertext)}")
print(f"\tdecrypted: {decrypt_data(ciphertext, key, iv)}")

message = "67890123456@admin/true$"
ciphertext = submit(message)

plaintext_sim = b'userid=456; userdata=67890123456@admin/true$;session-id=31337'
modified_ciphertext = bytearray(ciphertext)

# find position of '@'
pos = plaintext_sim.index(b'@')
# Calculate which block needs modification
block_num = (pos // 16) # Block containing the target byte
pos_in_prev_block = pos % 16
prev_block_start = (block_num - 1) * 16 # Start of previous block
# XOR the byte in previous block
modified_ciphertext[prev_block_start + pos_in_prev_block] ^= (ord('@') ^ ord(';'))

# find position of '/'
pos = plaintext_sim.index(b'/')
# Calculate which block needs modification
block_num = (pos // 16) # Block containing the target byte
pos_in_prev_block = pos % 16
prev_block_start = (block_num - 1) * 16 # Start of previous block
# XOR the byte in previous block
modified_ciphertext[prev_block_start + pos_in_prev_block] ^= (ord('/') ^ ord('='))

# find position of '$'
pos = plaintext_sim.index(b'$')
# Calculate which block needs modification
block_num = (pos // 16) # Block containing the target byte
pos_in_prev_block = pos % 16
prev_block_start = (block_num - 1) * 16 # Start of previous block
# XOR the byte in previous block
modified_ciphertext[prev_block_start + pos_in_prev_block] ^= (ord('$') ^ ord(';'))

use_this = bytes(modified_ciphertext)
print(f"\nverify with bit flip: {verify(use_this)}")
print(f"\tdecrypted: {decrypt_data(use_this, key, iv)}")