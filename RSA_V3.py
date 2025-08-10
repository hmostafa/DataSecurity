import random
import time
import math
import sys
import matplotlib.pyplot as plt

# Set random seed for reproducibility
random.seed(42)


def is_prime(n):
    """Check if a number is prime using trial division with 6k ± 1 optimization."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_prime(bits):
    """Generate a prime number of approximately 'bits' bits."""
    while True:
        candidate = random.randrange(2 ** (bits - 1) + 1, 2 ** bits, 2)
        if is_prime(candidate):
            return candidate


def extended_gcd(a, b):
    """Compute GCD and Bezout coefficients using extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


def find_d(e, phi):
    """Find the modular multiplicative inverse of e modulo phi."""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e and phi are not coprime")
    return x % phi


def generate_rsa_keys(bits):
    """Generate RSA public and private keys for a modulus of 'bits' bits."""
    p_bits = bits // 2
    q_bits = bits - p_bits
    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)
        if p != q:
            break
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while math.gcd(e, phi) != 1:
        e += 2
    d = find_d(e, phi)
    return (n, e), (n, d)


def encrypt(m, public_key):
    """Encrypt message m using public key (n, e)."""
    n, e = public_key
    return pow(m, e, n)


def decrypt(c, private_key):
    """Decrypt ciphertext c using private key (n, d)."""
    n, d = private_key
    return pow(c, d, n)


def benchmark_rsa(bits, num_trials=10000):
    """Benchmark RSA operations for a given bit size and return times and space."""
    # Key generation time
    start_time = time.perf_counter()
    public_key, private_key = generate_rsa_keys(bits)
    key_gen_time = time.perf_counter() - start_time

    n, e = public_key
    _, d = private_key
    m = random.randint(0, n - 1)

    # Calculate space usage for n and d
    total_space = sys.getsizeof(n) + sys.getsizeof(d)

    # Encryption time
    encrypt_times = []
    for _ in range(num_trials):
        start = time.perf_counter()
        c = encrypt(m, public_key)
        encrypt_times.append(time.perf_counter() - start)
    avg_encrypt_time = sum(encrypt_times) / num_trials

    # Decryption time
    decrypt_times = []
    for _ in range(num_trials):
        start = time.perf_counter()
        decrypted_m = decrypt(c, private_key)
        decrypt_times.append(time.perf_counter() - start)
    avg_decrypt_time = sum(decrypt_times) / num_trials

    # Verify correctness
    assert decrypted_m == m
    return key_gen_time, avg_encrypt_time, avg_decrypt_time, total_space


# Run benchmarks for different key sizes
key_sizes = [32,64,128]
results = {}
for bits in key_sizes:
    key_gen_time, encrypt_time, decrypt_time, total_space = benchmark_rsa(bits)
    results[bits] = (key_gen_time, encrypt_time, decrypt_time, total_space)
    print(f"For {bits}-bit modulus:")
    print(f"Key generation time: {key_gen_time:.6f} seconds")
    print(f"Average encryption time: {encrypt_time:.6f} seconds")
    print(f"Average decryption time: {decrypt_time:.6f} seconds")
    print(f"Space usage: {total_space} bytes")
    print()

# Extract data for plotting
key_gen_times = [results[bits][0] for bits in key_sizes]
encrypt_times = [results[bits][1] for bits in key_sizes]
decrypt_times = [results[bits][2] for bits in key_sizes]
spaces = [results[bits][3] for bits in key_sizes]

# Plot time complexities
plt.figure(figsize=(10, 6))
plt.plot(key_sizes, key_gen_times, label='Key Generation', marker='o')
plt.plot(key_sizes, encrypt_times, label='Encryption', marker='o')
plt.plot(key_sizes, decrypt_times, label='Decryption', marker='o')
plt.xlabel('Key Size (bits)')
plt.ylabel('Time (seconds)')
plt.title('RSA Time Complexity vs. Key Size')
plt.yscale('log')  # Use logarithmic scale for y-axis
plt.legend()
plt.grid(True)
plt.show()

# Plot space complexity
plt.figure(figsize=(10, 6))
plt.plot(key_sizes, spaces, label='Space Usage', marker='o')
plt.xlabel('Key Size (bits)')
plt.ylabel('Space (bytes)')
plt.title('RSA Space Complexity vs. Key Size')
plt.legend()
plt.grid(True)
plt.show()