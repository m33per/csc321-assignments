import hashlib

def task_1a():
    print("--- Task 1a: SHA256 hashes of arbitrary inputs ---")
    
    # Inputs specified in the assignment hints
    test_inputs = ["Hello, World!", "Python", "Cryptography"]
    
    for input_string in test_inputs:
        # Convert the string to bytes before hashing
        input_bytes = input_string.encode('utf-8')
        
        # Calculate the SHA-256 hash [cite: 59]
        sha256_obj = hashlib.sha256(input_bytes)
        
        # Get the hexadecimal representation
        hex_digest = sha256_obj.hexdigest()
        
        print(f"Input: {input_string}")
        print(f"SHA256: {hex_digest}\n")

if __name__ == "__main__":
    task_1a()