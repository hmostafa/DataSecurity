import random
import time
import math
from typing import Tuple, List, Dict
import sys
import tracemalloc

try:
    import matplotlib.pyplot as plt
    import numpy as np

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


    def mean(data):
        return sum(data) / len(data)


    def std(data):
        m = mean(data)
        return math.sqrt(sum((x - m) ** 2 for x in data) / len(data))


    def min(data):
        return min(data)


    def max(data):
        return max(data)

try:
    import psutil
    import os

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class RSAComplexityAnalyzer:

    def __init__(self):
        self.benchmark_results = {}
        self.memory_usage = {}

    def measure_time_space(func):

        def wrapper(self, *args, **kwargs):
            # Start memory tracing
            tracemalloc.start()

            # Memory before (fallback method)
            if HAS_PSUTIL:
                process = psutil.Process(os.getpid())
                mem_before = process.memory_info().rss / 1024 / 1024  # MB
            else:
                mem_before = 0

            # Time measurement
            start_time = time.perf_counter()
            result = func(self, *args, **kwargs)
            end_time = time.perf_counter()

            # Memory after
            if HAS_PSUTIL:
                mem_after = process.memory_info().rss / 1024 / 1024  # MB
                memory_used = mem_after - mem_before
            else:
                # Use tracemalloc as fallback
                current, peak = tracemalloc.get_traced_memory()
                memory_used = peak / 1024 / 1024  # Convert to MB

            tracemalloc.stop()

            execution_time = end_time - start_time

            # Store results
            func_name = func.__name__
            if func_name not in self.benchmark_results:
                self.benchmark_results[func_name] = []

            self.benchmark_results[func_name].append({
                'time': execution_time,
                'memory': memory_used,
                'args': args
            })

            return result, execution_time, memory_used

        return wrapper

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """
        Euclidean GCD algorithm
        Time Complexity: O(log min(a,b))
        Space Complexity: O(1) - iterative version
        """
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm
        Time Complexity: O(log min(a,b))
        Space Complexity: O(1)
        Returns: (gcd, x, y) where ax + by = gcd
        """
        if a == 0:
            return b, 0, 1

        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s, old_t

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Modular multiplicative inverse using Extended Euclidean Algorithm
        Time Complexity: O(log m)
        Space Complexity: O(1)
        """
        gcd, x, y = RSAComplexityAnalyzer.extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m

    @staticmethod
    def mod_pow(base: int, exponent: int, modulus: int) -> int:
        """
        Fast modular exponentiation using binary method
        Time Complexity: O(log exponent × log²modulus)
        Space Complexity: O(1)
        """
        if modulus == 1:
            return 0

        result = 1
        base = base % modulus

        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus

        return result

    @staticmethod
    def miller_rabin_test(n: int, k: int = 10) -> bool:
        """
        Miller-Rabin primality test
        Time Complexity: O(k × log³n)
        Space Complexity: O(1)
        """
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        # Write n-1 as 2^r × d
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = RSAComplexityAnalyzer.mod_pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = RSAComplexityAnalyzer.mod_pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    @staticmethod
    def generate_random_odd(bits: int) -> int:
        """
        Generate random odd number of specified bit length
        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        min_val = 1 << (bits - 1)  # 2^(bits-1)
        max_val = (1 << bits) - 1  # 2^bits - 1
        num = random.randint(min_val, max_val)
        return num | 1  # Make odd

    @measure_time_space
    def generate_prime(self, bits: int) -> int:
        """
        Generate a prime number of specified bit length
        Time Complexity: O(bits⁴) - expected, due to primality testing
        Space Complexity: O(1)
        """
        max_attempts = 10000

        for _ in range(max_attempts):
            candidate = self.generate_random_odd(bits)

            # Quick divisibility test for small primes
            small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
            if any(candidate % p == 0 for p in small_primes):
                continue

            if self.miller_rabin_test(candidate):
                return candidate

        raise ValueError(f"Failed to generate {bits}-bit prime after {max_attempts} attempts")

    @measure_time_space
    def generate_keypair(self, key_size: int) -> Tuple[Dict, Dict]:
        """
        Generate RSA key pair
        Time Complexity: O(k³) where k is key_size
        Space Complexity: O(k)
        """
        # Generate two distinct primes
        # Each prime is approximately key_size/2 bits
        prime_bits = key_size // 2

        p, _, _ = self.generate_prime(prime_bits)
        q, _, _ = self.generate_prime(prime_bits)

        print ("P =", p, "\n" )
        print("q = ", q, "\n")

        # Ensure p != q
        while p == q:
            q, _, _ = self.generate_prime(prime_bits)

        # Calculate n and φ(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)

        # print("phi_n = ", phi_n )

        # Choose public exponent e
        # Common choices: 3, 17, 65537
        e = 65537
        if e >= phi_n:
            e = 17
        if e >= phi_n:
            e = 3

        # Ensure gcd(e, φ(n)) = 1
        while self.gcd(e, phi_n) != 1:
            e += 2


        # Calculate private exponent d
        print("e =", e)

        d = self.mod_inverse(e, phi_n)

        public_key = {'n': n, 'e': e}
        private_key = {'n': n, 'd': d}

        return public_key, private_key

    @measure_time_space
    def encrypt(self, message: bytes, public_key: Dict) -> List[int]:
        """
        Encrypt message using RSA public key
        Time Complexity: O(m × log e × log²n) where m is message length
        Space Complexity: O(m)
        """
        n, e = public_key['n'], public_key['e']
        encrypted = []

        for byte in message:
            if byte >= n:
                raise ValueError(f"Message byte {byte} >= modulus {n}")
            ciphertext = self.mod_pow(byte, e, n)
            encrypted.append(ciphertext)

        return encrypted

    @measure_time_space
    def decrypt(self, ciphertext: List[int], private_key: Dict) -> bytes:
        """
        Decrypt ciphertext using RSA private key
        Time Complexity: O(m × log d × log²n) where m is ciphertext length
        Space Complexity: O(m)
        """
        n, d = private_key['n'], private_key['d']
        decrypted = []

        for cipher_byte in ciphertext:
            plaintext = self.mod_pow(cipher_byte, d, n)
            decrypted.append(plaintext)

        return bytes(decrypted)

    def benchmark_key_sizes(self, key_sizes: List[int], iterations: int = 3):
        """
        Benchmark RSA operations across different key sizes
        """
        print("RSA Complexity Analysis and Benchmarking")
        print("=" * 60)

        results = {}
        test_message = b"Hello, RSA benchmarking!"

        for key_size in key_sizes:
            print(f"\n📊 Testing RSA-{key_size}")
            print("-" * 30)

            key_gen_times = []
            encrypt_times = []
            decrypt_times = []
            memory_usage = []

            for i in range(iterations):
                print(f"Iteration {i + 1}/{iterations}...")

                # Key generation
                (pub_key, priv_key), gen_time, gen_memory = self.generate_keypair(key_size)
                key_gen_times.append(gen_time)
                memory_usage.append(gen_memory)

                # Encryption
                ciphertext, enc_time, enc_memory = self.encrypt(test_message, pub_key)
                encrypt_times.append(enc_time)
                memory_usage.append(enc_memory)

                # Decryption
                decrypted, dec_time, dec_memory = self.decrypt(ciphertext, priv_key)
                decrypt_times.append(dec_time)
                memory_usage.append(dec_memory)

                # Verify correctness
                assert decrypted == test_message, "Decryption failed!"

            # Calculate statistics
            if HAS_MATPLOTLIB:
                results[key_size] = {
                    'key_gen': {
                        'mean': np.mean(key_gen_times),
                        'std': np.std(key_gen_times),
                        'min': np.min(key_gen_times),
                        'max': np.max(key_gen_times)
                    },
                    'encrypt': {
                        'mean': np.mean(encrypt_times),
                        'std': np.std(encrypt_times),
                        'min': np.min(encrypt_times),
                        'max': np.max(encrypt_times)
                    },
                    'decrypt': {
                        'mean': np.mean(decrypt_times),
                        'std': np.std(decrypt_times),
                        'min': np.min(decrypt_times),
                        'max': np.max(decrypt_times)
                    },
                    'memory': np.mean(memory_usage),
                    'actual_size': math.floor(math.log2(pub_key['n'])) + 1
                }
            else:
                # Fallback statistics calculation
                results[key_size] = {
                    'key_gen': {
                        'mean': mean(key_gen_times),
                        'std': std(key_gen_times),
                        'min': min(key_gen_times),
                        'max': max(key_gen_times)
                    },
                    'encrypt': {
                        'mean': mean(encrypt_times),
                        'std': std(encrypt_times),
                        'min': min(encrypt_times),
                        'max': max(encrypt_times)
                    },
                    'decrypt': {
                        'mean': mean(decrypt_times),
                        'std': std(decrypt_times),
                        'min': min(decrypt_times),
                        'max': max(decrypt_times)
                    },
                    'memory': mean(memory_usage),
                    'actual_size': math.floor(math.log2(pub_key['n'])) + 1
                }

            # Print results for this key size
            print(
                f"Key Generation: {results[key_size]['key_gen']['mean']:.6f}s ± {results[key_size]['key_gen']['std']:.6f}s")
            print(
                f"Encryption:     {results[key_size]['encrypt']['mean']:.6f}s ± {results[key_size]['encrypt']['std']:.6f}s")
            print(
                f"Decryption:     {results[key_size]['decrypt']['mean']:.6f}s ± {results[key_size]['decrypt']['std']:.6f}s")
            print(f"Memory Usage:   {results[key_size]['memory']:.2f} MB")
            print(f"Actual Key Size: {results[key_size]['actual_size']} bits")

        return results

    def plot_complexity_analysis(self, results: Dict):
        """
        Create visualization of complexity analysis
        """
        if not HAS_MATPLOTLIB:
            print("📊 Matplotlib not available - skipping visualization plots")
            print("Install matplotlib with: pip install matplotlib numpy")
            return None

        key_sizes = list(results.keys())

        # Extract timing data
        key_gen_times = [results[k]['key_gen']['mean'] for k in key_sizes]
        encrypt_times = [results[k]['encrypt']['mean'] for k in key_sizes]
        decrypt_times = [results[k]['decrypt']['mean'] for k in key_sizes]
        memory_usage = [results[k]['memory'] for k in key_sizes]

        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('RSA Complexity Analysis', fontsize=16, fontweight='bold')

        # 1. Execution Time Comparison
        ax1.semilogy(key_sizes, key_gen_times, 'ro-', label='Key Generation', linewidth=2, markersize=8)
        ax1.semilogy(key_sizes, encrypt_times, 'go-', label='Encryption', linewidth=2, markersize=8)
        ax1.semilogy(key_sizes, decrypt_times, 'bo-', label='Decryption', linewidth=2, markersize=8)
        ax1.set_xlabel('Key Size (bits)')
        ax1.set_ylabel('Time (seconds) - Log Scale')
        ax1.set_title('Execution Time vs Key Size')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # 2. Memory Usage
        ax2.plot(key_sizes, memory_usage, 'mo-', linewidth=2, markersize=8)
        ax2.set_xlabel('Key Size (bits)')
        ax2.set_ylabel('Memory Usage (MB)')
        ax2.set_title('Memory Usage vs Key Size')
        ax2.grid(True, alpha=0.3)

        # 3. Theoretical vs Actual Complexity
        theoretical_cubic = [(k / key_sizes[0]) ** 3 * key_gen_times[0] for k in key_sizes]
        ax3.semilogy(key_sizes, key_gen_times, 'ro-', label='Actual Key Gen', linewidth=2)
        ax3.semilogy(key_sizes, theoretical_cubic, 'r--', label='Theoretical O(k³)', linewidth=2)
        ax3.set_xlabel('Key Size (bits)')
        ax3.set_ylabel('Time (seconds) - Log Scale')
        ax3.set_title('Actual vs Theoretical Complexity')
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4. Operation Comparison (normalized)
        normalized_key_gen = [t / key_gen_times[0] for t in key_gen_times]
        normalized_encrypt = [t / encrypt_times[0] for t in encrypt_times]
        normalized_decrypt = [t / decrypt_times[0] for t in decrypt_times]

        width = 0.25
        x = np.arange(len(key_sizes))

        ax4.bar(x - width, normalized_key_gen, width, label='Key Generation', alpha=0.8)
        ax4.bar(x, normalized_encrypt, width, label='Encryption', alpha=0.8)
        ax4.bar(x + width, normalized_decrypt, width, label='Decryption', alpha=0.8)

        ax4.set_xlabel('Key Size (bits)')
        ax4.set_ylabel('Normalized Time (relative to smallest key)')
        ax4.set_title('Normalized Performance Comparison')
        ax4.set_xticks(x)
        ax4.set_xticklabels(key_sizes)
        ax4.legend()
        ax4.grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        plt.show()

        return fig

    def print_complexity_summary(self):
        """
        Print detailed complexity analysis summary
        """
        print("\n" + "=" * 80)
        print("📈 RSA ALGORITHM COMPLEXITY ANALYSIS")
        print("=" * 80)

        print("\n🕐 TIME COMPLEXITY:")
        print("-" * 40)
        print("Key Generation:")
        print("  • Overall: O(k³) where k = key size in bits")
        print("  • Prime generation: O(k⁴) expected (Miller-Rabin testing)")
        print("  • Modular inverse: O(log φ(n)) ≈ O(k)")

        print("\nEncryption:")
        print("  • Per byte: O(log e × log²n)")
        print("  • Full message: O(m × log e × log²n) where m = message length")
        print("  • Note: e is typically small (65537), so effectively O(m × log²n)")

        print("\nDecryption:")
        print("  • Per byte: O(log d × log²n)")
        print("  • Full message: O(m × log d × log²n)")
        print("  • Note: d is large (~k bits), so O(m × k × log²n)")

        print("\n💾 SPACE COMPLEXITY:")
        print("-" * 40)
        print("Key Storage: O(k) per key component (n, e, d)")
        print("Message Processing: O(m) where m = message length")
        print("Temporary Variables: O(log²n) for modular arithmetic")

        print("\n⚡ PERFORMANCE CHARACTERISTICS:")
        print("-" * 40)
        print("• Key generation is the most expensive operation")
        print("• Encryption is faster than decryption (small e vs large d)")
        print("• Memory usage grows linearly with key size")
        print("• Doubling key size roughly increases time by 8x (cubic growth)")

        print("\n🔒 SECURITY vs PERFORMANCE TRADE-OFFS:")
        print("-" * 40)
        print("RSA-1024:  DEPRECATED - Fast but insecure")
        print("RSA-2048:  Current standard - Good security/performance balance")
        print("RSA-3072:  High security - ~3x slower than RSA-2048")
        print("RSA-4096:  Maximum security - ~8x slower than RSA-2048")

        print("\n📊 ASYMPTOTIC BEHAVIOR:")
        print("-" * 40)
        print("As key size k increases:")
        print("• Key generation time: grows as k³")
        print("• Encryption time: grows as k²")
        print("• Decryption time: grows as k³")
        print("• Memory usage: grows as k")
        print("• Security level: grows exponentially")


def main():

    rsa = RSAComplexityAnalyzer()

    # Test with different key sizes
    key_sizes = [64, 128, 256, 512, 1024, 2048]  # Small sizes for demonstration

    print("Starting RSA Complexity Analysis and Benchmarking...")
    print("Note: Using small key sizes for demonstration purposes.")
    print("Production systems should use RSA-2048 or larger.\n")

    results = rsa.benchmark_key_sizes(key_sizes, iterations=3)

    rsa.print_complexity_summary()

    try:
        rsa.plot_complexity_analysis(results)
    except ImportError:
        print("\nNote: Install matplotlib for visualization plots")

    # Demonstrate message encryption/decryption
    print("\n" + "=" * 60)
    print("========DEMONSTRATION WITH RSA-512=======")
    print("=" * 60)

    # Generate keys
    (pub_key, priv_key), gen_time, gen_memory = rsa.generate_keypair(64)
    print(f"Key generation completed in {gen_time:.6f} seconds")
    print(f"Memory usage: {gen_memory:.2f} MB")

    # Test message
    message = b"The quick brown fox jumps over the lazy dog!"
    print(f"\nOriginal message: {message.decode()}")

    # Encrypt
    ciphertext, enc_time, enc_memory = rsa.encrypt(message, pub_key)
    print(f"Encryption completed in {enc_time:.6f} seconds")
    print(f"Ciphertext length: {len(ciphertext)} integers")

    # Decrypt
    decrypted, dec_time, dec_memory = rsa.decrypt(ciphertext, priv_key)
    print(f"Decryption completed in {dec_time:.6f} seconds")
    print(f"Decrypted message: {decrypted.decode()}")

    # Verify
    print(f"Verification: {'SUCCESS' if message == decrypted else 'FAILED'}")

    print(f"\nTotal operation time: {gen_time + enc_time + dec_time:.6f} seconds")
    print(f"Peak memory usage: {max(gen_memory, enc_memory, dec_memory):.2f} MB")


if __name__ == "__main__":
    main()