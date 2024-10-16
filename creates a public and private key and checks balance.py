import os
import binascii
import base58
import hashlib
import requests
from ecdsa import SECP256k1, SigningKey

def private_key_to_public_key(private_key):
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()
    return public_key

def public_key_to_address(public_key):
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    ripemd160_digest = ripemd160.digest()
    network_byte = b'\x00'  # Mainnet address
    checksum = hashlib.sha256(hashlib.sha256(network_byte + ripemd160_digest).digest()).digest()[:4]
    address = base58.b58encode(network_byte + ripemd160_digest + checksum)
    return address.decode('utf-8')

def get_balance(address):
    try:
        url = f'https://blockchain.info/q/addressbalance/{address}'
        response = requests.get(url)
        balance_satoshis = int(response.text)
        return balance_satoshis / 1e8  # Convert to BTC
    except Exception as e:
        print(f"Error fetching balance: {e}")
        return 0

def save_key_info(private_key, public_key, balance):
    with open('keys.txt', 'a') as f:
        f.write(f'Private Key: {binascii.hexlify(private_key).decode()}\n')
        f.write(f'Public Key: {binascii.hexlify(public_key).decode()}\n')
        f.write(f'Address: {public_key_to_address(public_key)}\n')
        f.write(f'Balance: ${balance:.2f}\n\n')

def generate_keypair():
    private_key = SigningKey.generate(curve=SECP256k1).to_string()
    public_key = private_key_to_public_key(private_key)
    return private_key, public_key

def main():
    while True:
        private_key, public_key = generate_keypair()
        address = public_key_to_address(public_key)
        
        balance = get_balance(address)
        if balance > 0:
            save_key_info(private_key, public_key, balance)
            print(f"Found address with balance: {balance:.2f} BTC")
            break
        else:
            print(f"Address {address} has no balance.")

if __name__ == '__main__':
    if not os.path.exists('keys.txt'):
        open('keys.txt', 'w').close()  # Create the file if it doesn't exist
    main()
