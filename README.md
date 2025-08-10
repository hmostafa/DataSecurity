This repository contains three educational implementations of the Advanced Encryption Standard (AES) in pure Python:
- `AES_128.py`
- `AES_192.py`
- `AES_256.py`

Each script provides:
- A class that implements the AES round functions, key schedule, and ECB-style block processing with PKCS#7 padding for strings and files.
- A simple interactive CLI for encryption/decryption and utility tasks (key generation, key expansion view, benchmarks).
- Helper functions for file I/O and benchmarking.

> ⚠️ **Important:** These implementations are **for learning and experimentation**. Do **not** use them for production security. There are known issues (see **Known Issues & Notes**) and the code is not constant-time nor side-channel hardened.

---

## 1. Quick Start

### 1.1. Run the interactive tool
```bash
python3 AES_128.py
python3 AES_192.py
python3 AES_256.py

You’ll be presented with a menu to:

Encrypt/Decrypt messages (hex in/out)

Encrypt/Decrypt files

Print S-boxes

Inspect key expansion

Generate random keys

Run performance benchmarks

(AES-256 only) Validate against test vectors and compare AES variants

2. What’s Implemented
2.1. Core primitives (shared across the three variants)
State representation (4×4 bytes) and conversions to/from bytes.

SubBytes / InvSubBytes using generated S-box/inverse S-box.

ShiftRows / InvShiftRows (row-wise rotations).

MixColumns / InvMixColumns with GF(2^8) multiplication and the AES reduction polynomial (0x11B).

AddRoundKey (XOR of state with round key).

Key expansion (Rijndael key schedule) tailored for each key size.

2.2. Block and message processing
encrypt_block / decrypt_block process one 16-byte block with the appropriate number of rounds:

AES-128: 10 rounds (11 round keys)

AES-192: 12 rounds (13 round keys)

AES-256: 14 rounds (15 round keys)

encrypt_message / decrypt_message apply PKCS#7 padding and process blocks in ECB style (no IV, no chaining).

2.3. CLI utilities
S-box tables printer

Key expansion visualization

Cryptographically secure key generation (via secrets)

Benchmarks (simple throughput and key-schedule timing)

(AES-256): NIST test vectors check and cross-variant comparison

3. API Reference
3.1. Classes
AES128(), AES192(), AES256()

Common methods
_generate_s_box() -> List[List[int]]
Builds S-box via multiplicative inverse in GF(2^8) and affine transform.

_generate_inv_s_box() -> List[List[int]]
Inverse mapping of the generated S-box.

_sub_bytes(state) -> state, _inv_sub_bytes(state) -> state
Byte-wise substitution using S-box/Inv S-box.

_shift_rows(state) -> state, _inv_shift_rows(state) -> state
Cyclic left/right row shifts.

_mix_columns(state) -> state, _inv_mix_columns(state) -> state
Column mixing using fixed matrices over GF(2^8).

_add_round_key(state, round_key) -> state
XORs the flattened 16-byte round key into the state.

_key_expansion(key: bytes) -> List[List[int]]
Expands the user key into round keys. Words are generated as in Rijndael with RotWord, SubWord, and Rcon; AES-256 performs an extra SubWord on every 4th word.

_bytes_to_state(data: bytes) -> List[List[int]], _state_to_bytes(state) -> bytes
Column-major mapping between byte strings and 4×4 state.

encrypt_block(plaintext: bytes, key: bytes) -> bytes

decrypt_block(ciphertext: bytes, key: bytes) -> bytes

encrypt_message(message: str, key: bytes) -> bytes

decrypt_message(ciphertext: bytes, key: bytes) -> str

print_s_boxes() -> None

AES-256-only helpers
analyze_security() -> None

validate_aes256_test_vectors() -> bool

compare_aes_variants() -> None

3.2. Top-level helper functions
read_file(path: str) -> str

write_file(path: str, data: bytes) -> None

generate_random_key() -> str (size varies per file: 16/24/32 bytes)

benchmark_aes128()/benchmark_aes192()/benchmark_aes256()

4. Usage Examples
4.1. Encrypt and decrypt a file (AES-256)
Run python3 AES_256.py

Choose 3. Encrypt file

Enter file path

Enter a 64-hex-char key, or r to generate a random key

For decryption, choose 4. Decrypt file and provide the same key (or have the tool read *.key if you saved it).

4.2. View key expansion (AES-192)
Run python3 AES_192.py

Choose 6. Key expansion

Enter a 48-hex-char key to print all round keys (13 round keys).

5. Implementation Notes
GF(2^8) arithmetic: Polynomial x^8 + x^4 + x^3 + x + 1 (0x11B) is used for modular reduction.

S-box generation: For each byte a, compute the multiplicative inverse in GF(2^8) and apply an affine transform equivalent to s = inv ⊕ ROTL1(inv) ⊕ ROTL2(inv) ⊕ ROTL3(inv) ⊕ ROTL4(inv) ⊕ 0x63.

Key expansion (Rijndael):

AES-128: Rcon every 4th word.

AES-192: Rcon every 6th word.

AES-256: Rcon every 8th word and SubWord at i ≡ 4 (mod 8).

6. Benchmarks
Each script includes a micro-benchmark that repeatedly encrypts/decrypts a 1 KB message and measures key-schedule cost. Results will vary widely by Python version and hardware; these benchmarks are meant for relative comparison only (e.g., AES-128 tends to run faster than AES-256 due to fewer rounds).

Run via menu: Performance benchmark.

7. Known Issues & Notes
These points help you or future contributors align the code closer to the AES specification and improve usability/safety.

AES-256 NIST test vectors currently fail.
The function validate_aes256_test_vectors() reports failures when comparing to known NIST examples. Likely sources include: (a) packing/layout of round keys vs. state indexing, or (b) S-box/affine transform subtlety. The encryption and decryption remain self-consistent (round-trip success) but are not interoperable with standard AES implementations.
Suggested next steps: Verify state/round-key flattening order (i*4+j mapping) against the AES specification and cross-check S-box bytes against the official table.

Docstrings vs. implementation detail (multiplicative inverse).
Docstrings mention “extended Euclidean algorithm”; implementation uses a brute-force search for the inverse. Consider either updating the docstrings or implementing the EEA version for clarity/performance symmetry.

AES-128 CLI: key-length check in “Key expansion” menu.
The menu path 6. Key expansion expects a 128-bit key (32 hex chars) but the check compares against 16, not 32 hex chars. Update the length check to len(key_hex) == 32 to avoid rejecting valid input.

AES-192 CLI: minor label typo.
The generator prints “Random 191-bit AES Key Generator,” should be 192-bit.

Mode of operation is effectively ECB.
encrypt_message / decrypt_message process consecutive 16-byte blocks independently. For real-world use you should add a secure mode such as CBC (with random IV) or GCM (AEAD), and include authentication (MAC or AEAD).

Side-channel considerations.
Operations are not constant-time; table lookups and Python-level branching leak timing information. For production crypto, use a well-maintained library (e.g., OpenSSL bindings, PyCryptodome) with hardened primitives.

Key management.
AES-256’s file encryption flow can optionally write a .key file next to the ciphertext; emphasize to users that this file must be stored securely and never alongside the ciphertext in the same location in production settings.

8. Extending the Code
Add CBC or GCM modes under a simple AESMode wrapper (keep the block cipher core intact).

Plug standard S-box table (hard-coded) to eliminate dependence on dynamic generation, then validate against test vectors for all variants.

Refactor common code (S-box generation, GF math, byte/state utilities) into a shared module used by the three classes.

Automated tests using Python’s unittest with official NIST test vectors for 128/192/256-bit keys.
