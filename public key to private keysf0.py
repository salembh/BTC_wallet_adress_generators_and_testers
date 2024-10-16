import hashlib
import struct
import time

# Constants for the Ed25519 curve
b = 256
q = 2**255 - 19
d = -121665 * pow(121666, q-2, q) % q
I = pow(2, (q-1)//4, q)
L = 2**252 + 27742317777372353535851937790883648493
B = (4*pow(5, q-2, q) % q, 2 % q)
B = (B[0], (pow(B[0], 3, q) + 486662*B[0]**2 % q + B[0]) % q)
Bx, By = B

# Utility functions
def inv(x):
    return pow(x, q-2, q)

def edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1*y2 + x2*y1) * inv(1 + d*x1*x2*y1*y2) % q
    y3 = (y1*y2 + x1*x2) * inv(1 - d*x1*x2*y1*y2) % q
    return x3, y3

def scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = scalarmult(P, e // 2)
    Q = edwards_add(Q, Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q

def encodepoint(P):
    x, y = P
    return struct.pack('<32s', y.to_bytes(32, 'little'))

def get_public_key_from_private_key(private_key):
    if isinstance(private_key, str):
        private_key = bytes.fromhex(private_key)
    
    assert len(private_key) == 32, "Invalid private key length"

    h = hashlib.sha512(private_key).digest()
    a = 2**(b-2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, b-2))
    A = scalarmult(B, a)
    public_key = encodepoint(A)
    
    return public_key.hex()

def brute_force_private_key(target_public_key, max_attempts=1000000, report_interval=1):
    start_time = time.time()
    for i in range(max_attempts):
        private_key = i.to_bytes(32, 'big')
        derived_public_key = get_public_key_from_private_key(private_key)
        if derived_public_key == target_public_key:
            return private_key.hex()
        
        if i % report_interval == 0:
            elapsed_time = time.time() - start_time
            print(f"Attempt {i}/{max_attempts} - Elapsed Time: {elapsed_time:.2f} seconds {private_key.hex()}")
    
    return None

# Example usage
target_public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'
found_private_key = brute_force_private_key(target_public_key_hex)
if found_private_key:
    print("Found Private Key:", found_private_key)
else:
    print("Private key not found within the given attempt limit.")
