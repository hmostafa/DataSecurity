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


def mod_inverse(a, m):
    """Find modular multiplicative inverse of a modulo m."""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"{a} and {m} are not coprime")
    return x % m


class RSAKey:
    """RSA Key class that stores both standard and CRT parameters."""

    def __init__(self, n, e, d, p=None, q=None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

        # Precompute CRT parameters if p and q are available
        if p is not None and q is not None:
            self.dp = d % (p - 1)  # d mod (p-1)
            self.dq = d % (q - 1)  # d mod (q-1)
            self.qinv = mod_inverse(q, p)  # q^(-1) mod p
        else:
            self.dp = None
            self.dq = None
            self.qinv = None


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

    public_key = RSAKey(n, e, None)
    private_key = RSAKey(n, e, d, p, q)

    return public_key, private_key


def encrypt(m, public_key):
    """Encrypt message m using public key."""
    return pow(m, public_key.e, public_key.n)


def decrypt_standard(c, private_key):
    """Standard RSA decryption: m = c^d mod n."""
    return pow(c, private_key.d, private_key.n)


def decrypt_crt(c, private_key):
    """
    CRT-optimized RSA decryption.

    Algorithm:
    1. Compute m1 = c^dp mod p
    2. Compute m2 = c^dq mod q
    3. Compute h = qinv * (m1 - m2) mod p
    4. Return m = m2 + h * q
    """
    if private_key.dp is None:
        raise ValueError("CRT parameters not available")

    # Step 1: Compute m1 = c^dp mod p
    m1 = pow(c, private_key.dp, private_key.p)

    # Step 2: Compute m2 = c^dq mod q
    m2 = pow(c, private_key.dq, private_key.q)

    # Step 3: Compute h = qinv * (m1 - m2) mod p
    h = (private_key.qinv * (m1 - m2)) % private_key.p

    # Step 4: Compute final result m = m2 + h * q
    m = m2 + h * private_key.q

    return m


def benchmark_rsa(bits, num_trials=1000):
    """Benchmark RSA operations comparing standard vs CRT decryption."""
    # Key generation time
    start_time = time.perf_counter()
    public_key, private_key = generate_rsa_keys(bits)
    key_gen_time = time.perf_counter() - start_time

    n = public_key.n
    m = random.randint(0, n - 1)

    # Calculate space usage
    standard_space = sys.getsizeof(private_key.n) + sys.getsizeof(private_key.d)
    crt_space = (sys.getsizeof(private_key.p) + sys.getsizeof(private_key.q) +
                 sys.getsizeof(private_key.dp) + sys.getsizeof(private_key.dq) +
                 sys.getsizeof(private_key.qinv))

    # Encryption time (same for both methods)
    encrypt_times = []
    for _ in range(num_trials):
        start = time.perf_counter()
        c = encrypt(m, public_key)
        encrypt_times.append(time.perf_counter() - start)
    avg_encrypt_time = sum(encrypt_times) / num_trials

    # Standard decryption time
    standard_decrypt_times = []
    for _ in range(num_trials):
        start = time.perf_counter()
        decrypted_m = decrypt_standard(c, private_key)
        standard_decrypt_times.append(time.perf_counter() - start)
    avg_standard_decrypt_time = sum(standard_decrypt_times) / num_trials

    # CRT decryption time
    crt_decrypt_times = []
    for _ in range(num_trials):
        start = time.perf_counter()
        decrypted_m_crt = decrypt_crt(c, private_key)
        crt_decrypt_times.append(time.perf_counter() - start)
    avg_crt_decrypt_time = sum(crt_decrypt_times) / num_trials

    # Verify correctness
    assert decrypt_standard(c, private_key) == m
    assert decrypt_crt(c, private_key) == m

    return (key_gen_time, avg_encrypt_time, avg_standard_decrypt_time,
            avg_crt_decrypt_time, standard_space, crt_space)


# Run benchmarks for different key sizes
key_sizes = [32, 64,128,265,512,1024]
results = {}

print("RSA Performance Comparison: Standard vs CRT Decryption")
print("=" * 60)

for bits in key_sizes:
    print(f"Testing {bits}-bit modulus...")
    (key_gen_time, encrypt_time, standard_decrypt_time,
     crt_decrypt_time, standard_space, crt_space) = benchmark_rsa(bits)

    results[bits] = (key_gen_time, encrypt_time, standard_decrypt_time,
                     crt_decrypt_time, standard_space, crt_space)

    speedup = standard_decrypt_time / crt_decrypt_time
    space_overhead = (crt_space / standard_space - 1) * 100

    print(f"  Key generation time: {key_gen_time:.6f} seconds")
    print(f"  Average encryption time: {encrypt_time:.6f} seconds")
    print(f"  Standard decryption time: {standard_decrypt_time:.6f} seconds")
    print(f"  CRT decryption time: {crt_decrypt_time:.6f} seconds")
    print(f"  CRT Speedup: {speedup:.2f}x")
    print(f"  Standard space usage: {standard_space} bytes")
    print(f"  CRT space usage: {crt_space} bytes")
    print(f"  CRT space overhead: {space_overhead:.1f}%")
    print()

# Extract data for plotting
key_gen_times = [results[bits][0] for bits in key_sizes]
encrypt_times = [results[bits][1] for bits in key_sizes]
standard_decrypt_times = [results[bits][2] for bits in key_sizes]
crt_decrypt_times = [results[bits][3] for bits in key_sizes]
standard_spaces = [results[bits][4] for bits in key_sizes]
crt_spaces = [results[bits][5] for bits in key_sizes]

# Calculate speedup ratios
speedup_ratios = [std / crt for std, crt in zip(standard_decrypt_times, crt_decrypt_times)]

# Plot time complexities
plt.figure(figsize=(15, 10))

# Subplot 1: Time comparison
plt.subplot(2, 2, 1)
plt.plot(key_sizes, key_gen_times, label='Key Generation', marker='o')
plt.plot(key_sizes, encrypt_times, label='Encryption', marker='s')
plt.plot(key_sizes, standard_decrypt_times, label='Standard Decryption', marker='^')
plt.plot(key_sizes, crt_decrypt_times, label='CRT Decryption', marker='v')
plt.xlabel('Key Size (bits)')
plt.ylabel('Time (seconds)')
plt.title('RSA Time Complexity: Standard vs CRT')
plt.yscale('log')
plt.legend()
plt.grid(True)

# Subplot 2: Decryption speedup
plt.subplot(2, 2, 2)
plt.plot(key_sizes, speedup_ratios, label='CRT Speedup', marker='o', color='green')
plt.xlabel('Key Size (bits)')
plt.ylabel('Speedup Factor')
plt.title('CRT Decryption Speedup vs Key Size')
plt.legend()
plt.grid(True)

# Subplot 3: Space comparison
plt.subplot(2, 2, 3)
plt.plot(key_sizes, standard_spaces, label='Standard Storage', marker='o')
plt.plot(key_sizes, crt_spaces, label='CRT Storage', marker='s')
plt.xlabel('Key Size (bits)')
plt.ylabel('Space (bytes)')
plt.title('RSA Space Complexity: Standard vs CRT')
plt.legend()
plt.grid(True)

# Subplot 4: Space overhead percentage
plt.subplot(2, 2, 4)
space_overhead_pct = [(crt / std - 1) * 100 for std, crt in zip(standard_spaces, crt_spaces)]
plt.plot(key_sizes, space_overhead_pct, label='CRT Space Overhead %', marker='o', color='red')
plt.xlabel('Key Size (bits)')
plt.ylabel('Space Overhead (%)')
plt.title('CRT Space Overhead vs Key Size')
plt.legend()
plt.grid(True)

plt.tight_layout()
plt.show()

print("\nSummary:")
print(f"Average CRT speedup across all key sizes: {sum(speedup_ratios) / len(speedup_ratios):.2f}x")
print(f"Average CRT space overhead: {sum(space_overhead_pct) / len(space_overhead_pct):.1f}%")