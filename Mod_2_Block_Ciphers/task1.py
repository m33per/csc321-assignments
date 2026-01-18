from Crypto.Cipher import AES
import random
import os

def read_bmp_header(filename):
    # Open the file in binary mode
    with open(filename, 'rb') as file:
        # Read the header (usually 54 bytes, but accommodate up to 138 bytes)
        header = file.read(54)
        # Return the standard 54-byte header
        return header

def encrypt_image(image_filename, mode, key=None, iv=None):
    
    with open(image_filename, 'rb') as file:
        # Read the BMP header
        file.seek(0)
        header = file.read(54)
        # Read the image data
        data = file.read()
        
    # Generate a random key if not provided
    if not key:
        key = os.urandom(16)
    # Generate a random IV for CBC mode if not provided
    if not iv:
        iv = os.urandom(16)

    # padding
    padding = 16 - (len(data) % 16)
    for i in range(padding):
        data = data + padding.to_bytes()

    # Encrypt the image data using the specified mode (ECB or CBC)
    encrypted_data = b''
    cipher = AES.new(key, AES.MODE_ECB)
    if mode == "EBC":
        for i in range(0, len(data), 16):
            encrypted_data += cipher.encrypt(data[i:i+16])
    elif mode == "CBC":
        prev = iv
        for i in range(0, len(data), 16):
            pi = data[i:i+16]
            pix = (int.from_bytes(pi, 'big') ^ int.from_bytes(prev, 'big')).to_bytes(16, 'big')
            ci = cipher.encrypt(pix)
            encrypted_data += ci
            prev = ci

    # Combine the header, IV (for CBC), and encrypted data
    with open("encryption_" + mode.lower() + ".bmp", 'wb') as f:
        result = b''
        if mode == "EBC":
            result = header + encrypted_data
        elif mode == "CBC":
            result = header + iv + encrypted_data
        # Write the result to a new file
        f.write(result)

    return key

    
def decrypt_image(image_filename, mode, key, iv=None):
    with open(image_filename, 'rb') as file:
        # Read the BMP header
        header = file.read(54)

        # Read the IV (for CBC mode)
        iv = b''
        if mode == "CBC":
            if iv == None:
                iv = file.read(16)
            else:
                file.read(16)
        
        # Read the encrypted image data
        data = file.read()

    # Decrypt the data using the specified mode (ECB or CBC)
    decrypted_data = b''
    cipher = AES.new(key, AES.MODE_ECB)
    if mode == "EBC":
        for i in range(0, len(data) - 16, 16):
            decrypted_data += cipher.decrypt(data[i:i+16])
        # padding
        last = cipher.decrypt(data[-16:])
        for i in range(0, 16 - last[-1]):
            decrypted_data += last[i].to_bytes()

    elif mode == "CBC":
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

    # Combine the header and decrypted data
    with open("decryption_" + mode.lower() + ".bmp", 'wb') as f:
        result = header + decrypted_data
        # Write the result to a new file
        f.write(result)
    

def __main__():
    filename = "mustang.bmp"
    key1 = encrypt_image(filename, "EBC")
    key2 = encrypt_image(filename, "CBC")
    decrypt_image("encryption_ebc.bmp", "EBC", key1)
    decrypt_image("encryption_cbc.bmp", "CBC", key2)

    


if __name__ == "__main__":
    __main__()