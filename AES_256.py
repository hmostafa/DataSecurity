#!/usr/bin/env python3
import os
import sys
from typing import List, Tuple


class AES256:
    def __init__(self):
        """Initialize AES-256 with pre-computed S-box and inverse S-box tables"""
        self.s_box = self._generate_s_box()
        self.inv_s_box = self._generate_inv_s_box()
        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]

    def _generate_s_box(self) -> List[List[int]]:
        """
        Generate the AES S-box (16x16 table) for encryption byte substitution.
        Uses the multiplicative inverse in GF(2^8) followed by affine transformation.
        """
        s_box = [[0 for _ in range(16)] for _ in range(16)]

        for i in range(256):
            # Find multiplicative inverse in GF(2^8)
            inv = self._multiplicative_inverse_gf256(i)

            # Apply affine transformation
            s = inv
            for j in range(4):
                s ^= (inv << (j + 1)) ^ (inv >> (7 - j))
            s ^= 0x63  # Add constant
            s &= 0xFF

            # Place in S-box table
            row = i >> 4
            col = i & 0x0F
            s_box[row][col] = s

        return s_box

    def _generate_inv_s_box(self) -> List[List[int]]:
        """Generate the inverse S-box (16x16 table) for decryption byte substitution"""
        inv_s_box = [[0 for _ in range(16)] for _ in range(16)]

        # Create inverse mapping from S-box
        for i in range(16):
            for j in range(16):
                s_val = self.s_box[i][j]
                inv_row = s_val >> 4
                inv_col = s_val & 0x0F
                inv_s_box[inv_row][inv_col] = (i << 4) | j

        return inv_s_box

    def _multiplicative_inverse_gf256(self, a: int) -> int:
        """Find multiplicative inverse of a in GF(2^8) using extended Euclidean algorithm"""
        if a == 0:
            return 0

        # GF(2^8) irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
        def gf_mult(a: int, b: int) -> int:
            result = 0
            while b:
                if b & 1:
                    result ^= a
                a <<= 1
                if a & 0x100:
                    a ^= 0x11B
                b >>= 1
            return result

        # Find inverse using brute force (simpler for GF(2^8))
        for i in range(1, 256):
            if gf_mult(a, i) == 1:
                return i
        return 0

    def _sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Apply S-box substitution to state matrix"""
        for i in range(4):
            for j in range(4):
                byte = state[i][j]
                row = byte >> 4
                col = byte & 0x0F
                state[i][j] = self.s_box[row][col]
        return state

    def _inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Apply inverse S-box substitution to state matrix"""
        for i in range(4):
            for j in range(4):
                byte = state[i][j]
                row = byte >> 4
                col = byte & 0x0F
                state[i][j] = self.inv_s_box[row][col]
        return state

    def _shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Shift rows of state matrix (left circular shift)"""
        # Row 0: no shift
        # Row 1: shift left by 1
        state[1] = state[1][1:] + state[1][:1]
        # Row 2: shift left by 2
        state[2] = state[2][2:] + state[2][:2]
        # Row 3: shift left by 3
        state[3] = state[3][3:] + state[3][:3]
        return state

    def _inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse shift rows (right circular shift)"""
        # Row 0: no shift
        # Row 1: shift right by 1
        state[1] = state[1][-1:] + state[1][:-1]
        # Row 2: shift right by 2
        state[2] = state[2][-2:] + state[2][:-2]
        # Row 3: shift right by 3
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def _mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Mix columns using matrix multiplication in GF(2^8)"""

        def gf_mult(a: int, b: int) -> int:
            result = 0
            while b:
                if b & 1:
                    result ^= a
                a <<= 1
                if a & 0x100:
                    a ^= 0x11B
                b >>= 1
            return result

        for col in range(4):
            c0 = state[0][col]
            c1 = state[1][col]
            c2 = state[2][col]
            c3 = state[3][col]

            state[0][col] = gf_mult(0x02, c0) ^ gf_mult(0x03, c1) ^ c2 ^ c3
            state[1][col] = c0 ^ gf_mult(0x02, c1) ^ gf_mult(0x03, c2) ^ c3
            state[2][col] = c0 ^ c1 ^ gf_mult(0x02, c2) ^ gf_mult(0x03, c3)
            state[3][col] = gf_mult(0x03, c0) ^ c1 ^ c2 ^ gf_mult(0x02, c3)

        return state

    def _inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse mix columns"""

        def gf_mult(a: int, b: int) -> int:
            result = 0
            while b:
                if b & 1:
                    result ^= a
                a <<= 1
                if a & 0x100:
                    a ^= 0x11B
                b >>= 1
            return result

        for col in range(4):
            c0 = state[0][col]
            c1 = state[1][col]
            c2 = state[2][col]
            c3 = state[3][col]

            state[0][col] = gf_mult(0x0e, c0) ^ gf_mult(0x0b, c1) ^ gf_mult(0x0d, c2) ^ gf_mult(0x09, c3)
            state[1][col] = gf_mult(0x09, c0) ^ gf_mult(0x0e, c1) ^ gf_mult(0x0b, c2) ^ gf_mult(0x0d, c3)
            state[2][col] = gf_mult(0x0d, c0) ^ gf_mult(0x09, c1) ^ gf_mult(0x0e, c2) ^ gf_mult(0x0b, c3)
            state[3][col] = gf_mult(0x0b, c0) ^ gf_mult(0x0d, c1) ^ gf_mult(0x09, c2) ^ gf_mult(0x0e, c3)

        return state

    def _add_round_key(self, state: List[List[int]], round_key: List[int]) -> List[List[int]]:
        """XOR state with round key"""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i * 4 + j]
        return state

    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """Expand the 256-bit key into 15 round keys (60 words total)"""
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes for AES-256")

        # Convert key to words (8 words for 256-bit key)
        w = []
        for i in range(8):
            word = [key[i * 4 + j] for j in range(4)]
            w.append(word)

        # Generate remaining 52 words (60 total - 8 initial = 52)
        for i in range(8, 60):
            temp = w[i - 1][:]

            if i % 8 == 0:
                # RotWord
                temp = temp[1:] + temp[:1]
                # SubWord
                for j in range(4):
                    row = temp[j] >> 4
                    col = temp[j] & 0x0F
                    temp[j] = self.s_box[row][col]
                # XOR with Rcon
                temp[0] ^= self.rcon[i // 8 - 1]

            elif i % 8 == 4:
                # Additional SubWord operation for AES-256
                for j in range(4):
                    row = temp[j] >> 4
                    col = temp[j] & 0x0F
                    temp[j] = self.s_box[row][col]

            # XOR with word 8 positions back
            w.append([w[i - 8][j] ^ temp[j] for j in range(4)])

        # Convert to round keys (15 round keys for AES-256)
        round_keys = []
        for round_num in range(15):
            round_key = []
            for col in range(4):
                for row in range(4):
                    round_key.append(w[round_num * 4 + col][row])
            round_keys.append(round_key)

        return round_keys

    def _bytes_to_state(self, data: bytes) -> List[List[int]]:
        """Convert 16 bytes to 4x4 state matrix"""
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = data[i * 4 + j]
        return state

    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        """Convert 4x4 state matrix to 16 bytes"""
        data = []
        for i in range(4):
            for j in range(4):
                data.append(state[j][i])
        return bytes(data)

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt a single 16-byte block using AES-256 (14 rounds)"""
        if len(plaintext) != 16:
            raise ValueError("Plaintext block must be exactly 16 bytes")

        # Key expansion
        round_keys = self._key_expansion(key)

        # Convert to state matrix
        state = self._bytes_to_state(plaintext)

        # Initial round key addition
        state = self._add_round_key(state, round_keys[0])

        # 13 main rounds (rounds 1-13)
        for round_num in range(1, 14):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[round_num])

        # Final round (round 14, no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[14])

        return self._state_to_bytes(state)

    def decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt a single 16-byte block using AES-256 (14 rounds)"""
        if len(ciphertext) != 16:
            raise ValueError("Ciphertext block must be exactly 16 bytes")

        # Key expansion
        round_keys = self._key_expansion(key)

        # Convert to state matrix
        state = self._bytes_to_state(ciphertext)

        # Initial round key addition (last round key)
        state = self._add_round_key(state, round_keys[14])

        # Inverse final round
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)

        # 13 inverse main rounds (rounds 13 down to 1)
        for round_num in range(13, 0, -1):
            state = self._add_round_key(state, round_keys[round_num])
            state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)

        # Final round key addition
        state = self._add_round_key(state, round_keys[0])

        return self._state_to_bytes(state)

    def encrypt_message(self, message: str, key: bytes) -> bytes:
        """Encrypt a message using PKCS#7 padding"""
        # Convert message to bytes
        plaintext = message.encode('utf-8')

        # Apply PKCS#7 padding
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length] * padding_length)

        # Encrypt blocks
        ciphertext = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i + 16]
            encrypted_block = self.encrypt_block(block, key)
            ciphertext += encrypted_block

        return ciphertext

    def decrypt_message(self, ciphertext: bytes, key: bytes) -> str:
        """Decrypt a message and remove PKCS#7 padding"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16 bytes")

        # Decrypt blocks
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = self.decrypt_block(block, key)
            plaintext += decrypted_block

        # Remove PKCS#7 padding
        padding_length = plaintext[-1]
        unpadded_plaintext = plaintext[:-padding_length]

        return unpadded_plaintext.decode('utf-8')

    def print_s_boxes(self):
        """Print the S-box and inverse S-box tables"""
        print("AES S-box (Encryption):")
        print("   ", end="")
        for j in range(16):
            print(f"{j:2x}", end=" ")
        print()

        for i in range(16):
            print(f"{i:2x}: ", end="")
            for j in range(16):
                print(f"{self.s_box[i][j]:02x}", end=" ")
            print()

        print("\nAES Inverse S-box (Decryption):")
        print("   ", end="")
        for j in range(16):
            print(f"{j:2x}", end=" ")
        print()

        for i in range(16):
            print(f"{i:2x}: ", end="")
            for j in range(16):
                print(f"{self.inv_s_box[i][j]:02x}", end=" ")
            print()

    def analyze_security(self):
        """Display security analysis information for AES-256"""
        print("\nAES-256 Security Analysis:")
        print("=" * 40)
        print(f"Key Length: 256 bits (32 bytes)")
        print(f"Key Space: 2^256 ≈ 1.16 × 10^77 possible keys")
        print(f"Number of Rounds: 14")
        print(f"Round Keys Generated: 15")
        print(f"Security Level: ~128 bits (post-quantum resistant)")
        print(f"NIST Classification: Suitable for TOP SECRET information")
        print(f"Brute Force Time (at 10^12 keys/sec): ~3.67 × 10^57 years")
        print(f"Quantum Resistance: ~128 bits effective (Grover's algorithm)")
        print(f"Memory Requirements: ~240 bytes for round keys")
        print(f"Performance: ~40% slower than AES-128 due to additional rounds")


def read_file(filename: str) -> str:
    """Read text content from a file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return ""
    except Exception as e:
        print(f"Error reading file: {e}")
        return ""


def write_file(filename: str, data: bytes):
    """Write binary data to a file"""
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"Data written to '{filename}'")
    except Exception as e:
        print(f"Error writing file: {e}")


def generate_random_key() -> str:

    import secrets
    key_bytes = secrets.token_bytes(32)
    return key_bytes.hex()


def benchmark_aes256():
    """Benchmark AES-256 performance"""
    import time
    aes = AES256()

    # Generate test data
    test_key = bytes.fromhex(generate_random_key())
    test_message = "A" * 1000  # 1KB test message

    print("\nAES-256 Performance Benchmark:")
    print("=" * 40)

    # Encryption benchmark
    start_time = time.time()
    for _ in range(100):
        ciphertext = aes.encrypt_message(test_message, test_key)
    encryption_time = time.time() - start_time

    # Decryption benchmark
    start_time = time.time()
    for _ in range(100):
        plaintext = aes.decrypt_message(ciphertext, test_key)
    decryption_time = time.time() - start_time

    # Key expansion benchmark
    start_time = time.time()
    for _ in range(1000):
        round_keys = aes._key_expansion(test_key)
    key_expansion_time = time.time() - start_time

    print(f"Test Data Size: 1KB")
    print(f"Iterations: 100 (encryption/decryption), 1000 (key expansion)")
    print(f"Encryption Time: {encryption_time:.4f} seconds")
    print(f"Decryption Time: {decryption_time:.4f} seconds")
    print(f"Key Expansion Time: {key_expansion_time:.4f} seconds")
    print(f"Encryption Throughput: {100 * 1000 / encryption_time:.0f} bytes/second")
    print(f"Decryption Throughput: {100 * 1000 / decryption_time:.0f} bytes/second")
    print(f"Key Expansions/Second: {1000 / key_expansion_time:.0f}")


def validate_aes256_test_vectors():
    """Validate AES-256 implementation against known test vectors"""
    aes = AES256()

    # NIST test vectors for AES-256
    test_vectors = [
        {
            "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
            "ciphertext": "f3eed1bdb5d2a03c064b5a7e3db181f8"
        },
        {
            "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "plaintext": "ae2d8a571e03ac9c9eb76fac45af8e51",
            "ciphertext": "591ccb10d410ed26dc5ba74a31362870"
        }
    ]

    print("\nAES-256 Test Vector Validation:")
    print("=" * 40)

    all_passed = True
    for i, vector in enumerate(test_vectors, 1):
        key = bytes.fromhex(vector["key"])
        plaintext = bytes.fromhex(vector["plaintext"])
        expected_ciphertext = bytes.fromhex(vector["ciphertext"])

        # Test encryption
        actual_ciphertext = aes.encrypt_block(plaintext, key)
        encryption_passed = actual_ciphertext == expected_ciphertext

        # Test decryption
        decrypted_plaintext = aes.decrypt_block(expected_ciphertext, key)
        decryption_passed = decrypted_plaintext == plaintext

        print(f"Test Vector {i}:")
        print(f"  Encryption: {'PASS' if encryption_passed else 'FAIL'}")
        print(f"  Decryption: {'PASS' if decryption_passed else 'FAIL'}")

        if not encryption_passed:
            print(f"  Expected: {expected_ciphertext.hex()}")
            print(f"  Actual:   {actual_ciphertext.hex()}")
            all_passed = False

        if not decryption_passed:
            print(f"  Decryption failed for test vector {i}")
            all_passed = False

    print(f"\nOverall Result: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    return all_passed


def compare_aes_variants():
    """Compare AES-128, AES-192, and AES-256"""
    print("\nAES Variants Comparison:")
    print("=" * 60)
    print(f"{'Characteristic':<20} {'AES-128':<12} {'AES-192':<12} {'AES-256':<12}")
    print("-" * 60)
    print(f"{'Key Size (bits)':<20} {'128':<12} {'192':<12} {'256':<12}")
    print(f"{'Key Size (bytes)':<20} {'16':<12} {'24':<12} {'32':<12}")
    print(f"{'Key Size (hex chars)':<20} {'32':<12} {'48':<12} {'64':<12}")
    print(f"{'Number of Rounds':<20} {'10':<12} {'12':<12} {'14':<12}")
    print(f"{'Round Keys':<20} {'11':<12} {'13':<12} {'15':<12}")
    print(f"{'Key Schedule Words':<20} {'44':<12} {'52':<12} {'60':<12}")
    print(f"{'Security Level':<20} {'~128 bits':<12} {'~128 bits':<12} {'~128 bits':<12}")
    print(f"{'Quantum Security':<20} {'~64 bits':<12} {'~96 bits':<12} {'~128 bits':<12}")
    print(f"{'NIST Classification':<20} {'SECRET':<12} {'SECRET':<12} {'TOP SECRET':<12}")
    print(f"{'Performance':<20} {'Fastest':<12} {'Medium':<12} {'Slowest':<12}")
    print(f"{'Memory Usage':<20} {'Lowest':<12} {'Medium':<12} {'Highest':<12}")
    print(f"{'Recommended Use':<20} {'General':<12} {'High Sec.':<12} {'Max Sec.':<12}")

    print(f"\nKey Space Comparison:")
    print(f"AES-128: 2^128 ≈ 3.40 × 10^38 keys")
    print(f"AES-192: 2^192 ≈ 6.28 × 10^57 keys")
    print(f"AES-256: 2^256 ≈ 1.16 × 10^77 keys")

    print(f"\nBrute Force Time (at 10^12 keys/second):")
    print(f"AES-128: ~5.40 × 10^18 years")
    print(f"AES-192: ~9.95 × 10^37 years")
    print(f"AES-256: ~3.67 × 10^57 years")


def main():
    aes = AES256()

    print("AES-256 Encryption/Decryption Tool")
    print("==================================")
    print("Key Length: 256 bits (32 bytes, 64 hex characters)")
    print("Number of Rounds: 14")
    print("Round Keys: 15 (including initial)")
    print("Security Level: Maximum AES security")

    # Display S-boxes
    print("\nGenerated S-box tables:")
    aes.print_s_boxes()

    while True:
        print("\nOptions:")
        print("1. Encrypt message")
        print("2. Decrypt message")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. Show S-boxes")
        print("6. Key expansion")
        print("7. Generate random key")
        print("8. Security analysis")
        print("9. Performance benchmark")
        print("10. Test vector validation")
        print("11. Compare AES variants(128,192, 256)")
        print("12. Exit")

        choice = input("\nEnter your choice (1-12): ").strip()

        if choice == '1':
            # Encrypt message
            message = input("Enter message to encrypt: ")
            key_hex = input("Enter 256-bit key (64 hex characters, or 'r' for random): ").strip()

            try:
                if key_hex.lower() == 'r':
                    key_hex = generate_random_key()
                    print(f"Generated random key: {key_hex}")

                if len(key_hex) != 64:
                    raise ValueError("Key must be exactly 64 hex characters (256 bits)")
                key = bytes.fromhex(key_hex)

                ciphertext = aes.encrypt_message(message, key)
                print(f"Encrypted (hex): {ciphertext.hex()}")

                # Save to file option
                save = input("Save to file? (y/n): ").strip().lower()
                if save == 'y':
                    filename = input("Enter filename: ").strip()
                    write_file(filename, ciphertext)

            except Exception as e:
                print(f"Encryption error: {e}")

        elif choice == '2':
            # Decrypt message
            ciphertext_hex = input("Enter ciphertext (hex): ").strip()
            key_hex = input("Enter 256-bit key (64 hex characters): ").strip()

            try:
                if len(key_hex) != 64:
                    raise ValueError("Key must be exactly 64 hex characters (256 bits)")
                key = bytes.fromhex(key_hex)
                ciphertext = bytes.fromhex(ciphertext_hex)

                plaintext = aes.decrypt_message(ciphertext, key)
                print(f"Decrypted message: {plaintext}")

            except Exception as e:
                print(f"Decryption error: {e}")

        elif choice == '3':
            # Encrypt file
            filename = input("Enter filename to encrypt: ").strip()
            key_hex = input("Enter 256-bit key (64 hex characters, or 'r' for random): ").strip()

            try:
                if key_hex.lower() == 'r':
                    key_hex = generate_random_key()
                    print(f"Generated random key: {key_hex}")
                    print("IMPORTANT: Save this key! You'll need it to decrypt the file.")

                if len(key_hex) != 64:
                    raise ValueError("Key must be exactly 64 hex characters (256 bits)")
                key = bytes.fromhex(key_hex)

                message = read_file(filename)
                if message:
                    ciphertext = aes.encrypt_message(message, key)
                    output_filename = filename + ".aes256"
                    write_file(output_filename, ciphertext)
                    print(f"File encrypted and saved as '{output_filename}'")

                    # Save key to separate file
                    key_filename = filename + ".key"
                    with open(key_filename, 'w') as f:
                        f.write(key_hex)
                    print(f"Key saved to '{key_filename}' (keep this secure!)")

            except Exception as e:
                print(f"File encryption error: {e}")

        elif choice == '4':
            # Decrypt file
            filename = input("Enter filename to decrypt: ").strip()
            key_hex = input("Enter 256-bit key (64 hex characters, or 'f' to read from .key file): ").strip()

            try:
                if key_hex.lower() == 'f':
                    key_filename = filename.replace(".aes256", ".key")
                    try:
                        with open(key_filename, 'r') as f:
                            key_hex = f.read().strip()
                        print(f"Key loaded from '{key_filename}'")
                    except FileNotFoundError:
                        print(f"Key file '{key_filename}' not found.")
                        continue

                if len(key_hex) != 64:
                    raise ValueError("Key must be exactly 64 hex characters (256 bits)")
                key = bytes.fromhex(key_hex)

                with open(filename, 'rb') as f:
                    ciphertext = f.read()

                plaintext = aes.decrypt_message(ciphertext, key)
                output_filename = filename.replace(".aes256", ".decrypted")

                with open(output_filename, 'w', encoding='utf-8') as f:
                    f.write(plaintext)

                print(f"File decrypted and saved as '{output_filename}'")
                print(f"Decrypted content preview: {plaintext[:100]}...")

            except Exception as e:
                print(f"File decryption error: {e}")

        elif choice == '5':
            # Show S-boxes
            aes.print_s_boxes()

        elif choice == '6':
            # Key expansion example
            print("\nKey Expansion Example:")
            print("Enter a 256-bit key to see the key expansion process")
            key_hex = input("Enter 256-bit key (64 hex characters, or 'r' for random): ").strip()

            try:
                if key_hex.lower() == 'r':
                    key_hex = generate_random_key()
                    print(f"Generated random key: {key_hex}")

                if len(key_hex) != 64:
                    raise ValueError("Key must be exactly 64 hex characters (256 bits)")
                key = bytes.fromhex(key_hex)

                print(f"\nOriginal key: {key.hex()}")
                round_keys = aes._key_expansion(key)

                print(f"\nRound Keys (15 total for AES-256):")
                for i, rk in enumerate(round_keys):
                    key_bytes = bytes(rk)
                    print(f"Round {i:2d}: {key_bytes.hex()}")

            except Exception as e:
                print(f"Key expansion error: {e}")

        elif choice == '7':
            # Generate random key
            print("\nRandom 256-bit AES Key Generator:")
            num_keys = input("How many keys to generate? (default: 1): ").strip()

            try:
                num_keys = int(num_keys) if num_keys else 1
                if num_keys < 1 or num_keys > 10:
                    raise ValueError("Number of keys must be between 1 and 10")

                print(f"\nGenerated {num_keys} cryptographically secure 256-bit key(s):")
                for i in range(num_keys):
                    key = generate_random_key()
                    print(f"Key {i + 1}: {key}")

                save = input("\nSave keys to file? (y/n): ").strip().lower()
                if save == 'y':
                    filename = input("Enter filename: ").strip()
                    with open(filename, 'w') as f:
                        for i in range(num_keys):
                            key = generate_random_key()
                            f.write(f"Key {i + 1}: {key}\n")
                    print(f"Keys saved to '{filename}'")

            except Exception as e:
                print(f"Key generation error: {e}")

        elif choice == '8':
            # Security analysis
            aes.analyze_security()

        elif choice == '9':
            # Performance benchmark
            print("\nRunning AES-256 Performance Benchmark...")
            print("This may take a few seconds...")
            benchmark_aes256()

        elif choice == '10':
            # Test vector validation
            print("\nValidating AES-256 implementation against NIST test vectors...")
            validate_aes256_test_vectors()

        elif choice == '11':
            # Compare AES variants
            compare_aes_variants()

        elif choice == '12':
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()