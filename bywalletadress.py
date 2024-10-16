import hashlib
import struct
import time
import base58

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

def base58_decode(address):
    """Decode a Base58Check encoded address."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base58_map = {char: index for index, char in enumerate(alphabet)}
    
    num = 0
    for char in address:
        num = num * 58 + base58_map[char]
    
    num_bytes = num.to_bytes(25, byteorder='big')
    
    # Validate checksum
    checksum = num_bytes[-4:]
    if hashlib.sha256(hashlib.sha256(num_bytes[:-4]).digest()).digest()[:4] != checksum:
        raise ValueError("Invalid checksum")

    return num_bytes[:-4]

def get_public_key_hash_from_address(address):
    """Get the public key hash from a Bitcoin address."""
    decoded = base58_decode(address)
    return decoded[1:]  # Strip version byte and return public key hash

def brute_force_private_key(target_public_key_hash, start_hex, end_hex, report_interval=10):
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
        derived_public_key_hash = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(derived_public_key)).digest()).hexdigest()
        if derived_public_key_hash == target_public_key_hash:
            return private_key.hex()
        
        if i % report_interval == 0:
            elapsed_time = time.time() - start_time
            print(f"Attempt {i}/{end_value} - Elapsed Time: {elapsed_time:.2f} seconds. Private key: {private_key.hex()}")
    
    return None

# Example usage
bitcoin_address = '13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so'
target_public_key_hash = get_public_key_hash_from_address(bitcoin_address).hex()
# Test with a smaller range
start_hex = '20000000000000000'
end_hex = '3ffffffffffffffff'  # Adjust range as needed

found_private_key = brute_force_private_key(target_public_key_hash, start_hex, end_hex)
if found_private_key:
    print("Found Private Key:", found_private_key)
else:
    print("Private key not found within the given attempt limit.")
