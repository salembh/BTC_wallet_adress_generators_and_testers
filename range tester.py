import hashlib
import struct
import time

# Constants for the Ed25519 curve
b = 256
q = 2**255 - 19
d = -121665 * pow(121666, q-2, q) % q
I = pow(2, (q-1)//4, q)
L = 2**252 + 27742317777372353535851937790883648493

# Ed25519 base point B
B = (
    4 * pow(5, q-2, q) % q,
    2 % q
)

def inv(x):
    """Compute modular inverse."""
    return pow(x, q-2, q)

def edwards_add(P, Q):
    """Add two points P and Q on the Edwards curve."""
    x1, y1 = P
    x2, y2 = Q
    denom = inv(1 + d * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom % q
    y3 = (y1 * y2 - x1 * x2) * denom % q
    return x3, y3

def scalarmult(P, e):
    """Multiply point P by scalar e using double-and-add."""
    if e == 0:
        return (0, 1)
    Q = scalarmult(P, e // 2)
    Q = edwards_add(Q, Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q

def encodepoint(P):
    """Encode the public key point."""
    x, y = P
    # Encode the x-coordinate and set the sign bit of y based on its parity
    return struct.pack('<32s', x.to_bytes(32, 'little'))

def get_public_key_from_private_key(private_key):
    """Derive the public key from the private key."""
    if isinstance(private_key, str):
        private_key = bytes.fromhex(private_key)
    
    assert len(private_key) == 32, "Invalid private key length"

    h = hashlib.sha512(private_key).digest()
    a = int.from_bytes(h[:32], 'little') % q
    A = scalarmult(B, a)
    public_key = encodepoint(A)
    
    return public_key.hex()

def brute_force_private_key(target_public_key, start_hex, end_hex, report_interval=1):
    """Brute force private keys within a given range to find the target public key."""
    start_time = time.time()
    start_value = int(start_hex, 16)
    end_value = int(end_hex, 16)

    for i in range(start_value, end_value + 1):
        # Ensure the private key is exactly 32 bytes
        if i >= 2**256:
            print("Integer exceeds 32 bytes limit.")
            continue
        
        private_key = i.to_bytes(32, 'big')
        derived_public_key = get_public_key_from_private_key(private_key)
        if derived_public_key == target_public_key:
            return private_key.hex()
        
        if i % report_interval == 0:
            elapsed_time = time.time() - start_time
            print(f"Attempt {i}/{end_value} - Elapsed Time: {elapsed_time:.2f} seconds")
    
    return None

# Example usage
target_public_key_hex = 'a0fc7aea306b8735995642aead18964e39c8c1b250a90390d35f72240d58c163'
# Test with a smaller range
start_hex = 'ebed3ba0bbff733564a3286e15d29eb00b5877d47946a136777bb6b5f41b5fbf'
end_hex = 'ebed3ba0bbff733564a3286e15d29eb00b5877d47946a136777bb6b5f41b5fff'  # Small range

found_private_key = brute_force_private_key(target_public_key_hex, start_hex, end_hex)
if found_private_key:
    print("Found Private Key:", found_private_key)
else:
    print("Private key not found within the given attempt limit.")
