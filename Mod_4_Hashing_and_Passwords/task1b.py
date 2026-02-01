import hashlib
import secrets
import string

def sha256_hash(input_string):
    """Calculates SHA256 and returns a hex string."""
    return hashlib.sha256(input_string.encode('utf-8')).hexdigest()

def hamming_distance_bits(h1, h2):
    # XOR the two integers represented by the hex strings
    xor_result = int(h1, 16) ^ int(h2, 16)
    # Count the number of set bits (1s) in the result
    return bin(xor_result).count('1')

def find_hamming_distance_1_input():
    while True:
        # Generate a random 10-character string
        base_str = ''.join(secrets.choice(string.ascii_letters) for _ in range(10))
        byte_arr = bytearray(base_str, 'utf-8')
        
        # Pick a random byte and a random bit to flip 
        byte_idx = secrets.randbelow(len(byte_arr))
        bit_idx = secrets.randbelow(8)
        
        # Flip the bit using XOR
        byte_arr[byte_idx] ^= (1 << bit_idx)
        
        try:
            modified_str = byte_arr.decode('utf-8')
            # Ensure they are actually different strings 
            if base_str != modified_str:
                return base_str, modified_str
        except UnicodeDecodeError:
            continue # Try again if bit flip creates invalid UTF-8

def task_1b():
    print("--- Task 1b: Strings with Hamming distance of 1 ---")
    
    for i in range(1, 4):
        s1, s2 = find_hamming_distance_1_input()
        h1 = sha256_hash(s1)
        h2 = sha256_hash(s2)
        bit_diff = hamming_distance_bits(h1, h2)
        
        print(f"Iteration {i}")
        print(f"  String 1: {s1}")
        print(f"  String 2: {s2}")
        print(f"  SHA256 (1): {h1}")
        print(f"  SHA256 (2): {h2}")
        print(f"  Bit difference in hashes: {bit_diff} bits (Avalanche Effect)\n")

if __name__ == "__main__":
    task_1b()