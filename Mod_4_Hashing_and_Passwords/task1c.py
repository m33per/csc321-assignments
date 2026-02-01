import hashlib
import time
import secrets
import string
import matplotlib.pyplot as plt

def sha256_hash(input_string):
    return hashlib.sha256(input_string.encode('utf-8')).hexdigest()

def truncate_hash(hash_string, bits):
    num_chars = bits // 4
    substring = hash_string[:num_chars]
    val = int(substring, 16)
    mask = (1 << bits) - 1
    return val & mask

def find_collision(bits, max_attempts=10000000):
    seen = {}
    start_time = time.perf_counter()
    
    for attempts in range(1, max_attempts + 1):
        # Generate random 10-letter string
        s = ''.join(secrets.choice(string.ascii_letters) for _ in range(10))
        h = truncate_hash(sha256_hash(s), bits)
        
        if h in seen:
            if seen[h] != s:  # Ensure it's two different strings
                elapsed_time = time.perf_counter() - start_time
                return seen[h], s, attempts, elapsed_time
        else:
            seen[h] = s
            
    return None, None, max_attempts, time.perf_counter() - start_time

def task_1c():
    print(f"{'Bits':<6} | {'Inputs Tried':<15} | {'Time (s)':<12}")
    print("-" * 40)
    
    bit_range = range(8, 52, 2)  # From 8 to 50 bits
    results = []

    for b in bit_range:
        s1, s2, attempts, duration = find_collision(b)
        if s1:
            print(f"{b:<6} | {attempts:<15,} | {duration:<12.5f}")
            results.append((b, attempts, duration))
        else:
            print(f"{b:<6} | Timeout/Failed")
            break

    bits_list = [r[0] for r in results]
    attempts_list = [r[1] for r in results]
    times_list = [r[2] for r in results]

    plt.figure(figsize=(12, 5))

    # Graph 1: Digest Size vs Collision Time
    plt.subplot(1, 2, 1)
    plt.plot(bits_list, times_list, marker='o')
    plt.title('Digest Size vs Collision Time')
    plt.xlabel('Digest Size (bits)')
    plt.ylabel('Time (s)')
    plt.grid(True)

    # Graph 2: Digest Size vs Number of Inputs
    plt.subplot(1, 2, 2)
    plt.plot(bits_list, attempts_list, marker='o', color='r')
    plt.title('Digest Size vs Number of Inputs')
    plt.xlabel('Digest Size (bits)')
    plt.ylabel('Number of Inputs')
    plt.grid(True)

    plt.tight_layout()
    plt.savefig('collision_analysis.png')
    print("\nGraphs saved as 'collision_analysis.png'")
    plt.show()

if __name__ == "__main__":
    task_1c()
