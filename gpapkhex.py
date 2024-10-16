import hashlib
import struct
import secrets

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

# Generate a random 32-byte private key
private_key = secrets.token_bytes(32)
private_key_hex = private_key.hex()

# Derive the public key from the private key
public_key_hex = get_public_key_from_private_key(private_key_hex)

# Print the keys
print(f"Private Key: {private_key_hex}")
print(f"Public Key: {public_key_hex}")
